"""Integration checks that run against a real PostgreSQL service in CI."""
from __future__ import annotations

import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from alembic import command
from alembic.config import Config

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.engine import make_url

from app.core.config import settings
from app.db.database import Base
from app.models.account_token import AccountToken
from app.models.analysis_job import AnalysisJob  # noqa: F401  # Registers the queue table in shared metadata.
from app.models.audit import AuditRecord
from app.models.user import User
from app.models.user_session import UserSession
from app.services.analysis_queue import AnalysisQuotaExceeded, enqueue_analysis


@pytest.fixture()
def postgres_engine(monkeypatch):
    url = os.getenv("VULNSCAN_TEST_DATABASE_URL")
    if not url or not url.startswith(("postgresql://", "postgresql+psycopg://")):
        pytest.skip("VULNSCAN_TEST_DATABASE_URL is not configured for PostgreSQL integration tests")
    root_engine = create_engine(url, pool_pre_ping=True)
    schema = f"vulnscan_test_{uuid.uuid4().hex}"
    assert re.fullmatch(r"[a-z0-9_]+", schema)
    with root_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    migration_url = make_url(url).set(
        query={"options": f"-csearch_path={schema}"}
    ).render_as_string(hide_password=False)
    monkeypatch.setattr(settings, "database_url", migration_url)
    alembic_config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    command.upgrade(alembic_config, "head")

    engine = create_engine(
        url,
        connect_args={"options": f"-csearch_path={schema}"},
        pool_pre_ping=True,
    )
    try:
        with engine.connect() as connection:
            assert connection.scalar(text("SELECT version_num FROM alembic_version")) == "0005_mfa"
        yield engine
    finally:
        engine.dispose()
        with root_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        root_engine.dispose()


def test_postgres_enforces_unique_account_email(postgres_engine):
    with Session(postgres_engine) as db:
        db.add(User(email="same@example.test", password_hash="hash"))
        db.commit()
        db.add(User(email="same@example.test", password_hash="another-hash"))
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()


def test_postgres_foreign_key_policies_and_json_round_trip(postgres_engine):
    now = datetime.now(timezone.utc)
    with Session(postgres_engine) as db:
        user = User(email="owner@example.test", password_hash="hash")
        db.add(user)
        db.flush()
        session = UserSession(user_id=user.id, token_hash="a" * 64, expires_at=now, created_at=now)
        token = AccountToken(user_id=user.id, token_hash="b" * 64, purpose="verify_email", expires_at=now, created_at=now)
        audit = AuditRecord(user_id=user.id, analysis_type="static_source_analysis", target="source.zip",
            status="completed", finding_count=1,
            result={"findings": [{"rule_id": "TEST001"}], "coverage": {"overall": "completed"}})
        db.add_all([session, token, audit])
        db.commit()
        audit_id, session_id, token_id = audit.id, session.id, token.id
        assert db.get(AuditRecord, audit_id).result["findings"][0]["rule_id"] == "TEST001"
        db.delete(user)
        db.commit()
        assert db.get(UserSession, session_id) is None
        assert db.get(AccountToken, token_id) is None
        retained_audit = db.get(AuditRecord, audit_id)
        assert retained_audit is not None and retained_audit.user_id is None


def test_postgres_session_token_hash_is_unique(postgres_engine):
    now = datetime.now(timezone.utc)
    with Session(postgres_engine) as db:
        user = User(email="session@example.test", password_hash="hash")
        db.add(user)
        db.flush()
        db.add_all([
            UserSession(user_id=user.id, token_hash="c" * 64, expires_at=now, created_at=now),
            UserSession(user_id=user.id, token_hash="c" * 64, expires_at=now, created_at=now),
        ])
        with pytest.raises(IntegrityError):
            db.commit()
        db.rollback()



def test_postgres_serializes_per_account_concurrent_quota_checks(postgres_engine, monkeypatch):
    monkeypatch.setattr(settings, "max_concurrent_analyses", 1)
    monkeypatch.setattr(settings, "monthly_analysis_limit", 10)
    monkeypatch.setattr(settings, "max_queued_storage_mb", 10)
    sessions = sessionmaker(bind=postgres_engine, expire_on_commit=False)
    with sessions() as db:
        user = User(email="quota@example.test", password_hash="hash")
        db.add(user)
        db.commit()
        user_id = user.id

    def enqueue(index: int) -> bool:
        with sessions() as db:
            try:
                enqueue_analysis(
                    db,
                    user_id=user_id,
                    filename=f"parallel-{index}.zip",
                    archive_data=b"archive",
                )
                return True
            except AnalysisQuotaExceeded:
                return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(enqueue, (1, 2)))
    assert sum(outcomes) == 1


def test_postgres_worker_claims_are_exclusive(postgres_engine, monkeypatch):
    from app.jobs import runner

    sessions = sessionmaker(bind=postgres_engine, expire_on_commit=False)
    monkeypatch.setattr(runner, "SessionLocal", sessions)
    now = datetime.now(timezone.utc)
    with sessions() as db:
        user = User(email="worker@example.test", password_hash="hash")
        db.add(user)
        db.flush()
        job = AnalysisJob(
            user_id=user.id,
            filename="once.zip",
            status="queued",
            archive_data=b"archive",
            attempts=0,
            max_attempts=3,
            created_at=now,
            available_at=now,
        )
        db.add(job)
        db.commit()
        job_id = job.id

    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda _: runner.claim_next_job(), (1, 2)))
    claimed_ids = [claim[0] for claim in claims if claim is not None]
    assert claimed_ids == [job_id]
    with sessions() as db:
        job = db.get(AnalysisJob, job_id)
        assert job.status == "running"
        assert job.attempts == 1
