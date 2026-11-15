"""Integration checks that run against a real PostgreSQL service in CI."""
from __future__ import annotations

import os
import re
import uuid

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.database import Base
from app.models.account_token import AccountToken
from app.models.audit import AuditRecord
from app.models.user import User
from app.models.user_session import UserSession


@pytest.fixture()
def postgres_engine():
    url = os.getenv("VULNSCAN_TEST_DATABASE_URL")
    if not url or not url.startswith(("postgresql://", "postgresql+psycopg://")):
        pytest.skip("VULNSCAN_TEST_DATABASE_URL is not configured for PostgreSQL integration tests")

    root_engine = create_engine(url, pool_pre_ping=True)
    schema = f"vulnscan_test_{uuid.uuid4().hex}"
    assert re.fullmatch(r"[a-z0-9_]+", schema)
    with root_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    engine = create_engine(
        url,
        connect_args={"options": f"-csearch_path={schema}"},
        pool_pre_ping=True,
    )
    try:
        Base.metadata.create_all(engine)
        yield engine
    finally:
        Base.metadata.drop_all(engine)
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
    with Session(postgres_engine) as db:
        user = User(email="owner@example.test", password_hash="hash")
        db.add(user)
        db.flush()
        session = UserSession(
            user_id=user.id,
            token_hash="a" * 64,
            expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        )
        token = AccountToken(
            user_id=user.id,
            token_hash="b" * 64,
            purpose="verify_email",
            expires_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
        )
        audit = AuditRecord(
            user_id=user.id,
            analysis_type="static_source_analysis",
            target="source.zip",
            status="completed",
            finding_count=1,
            result={"findings": [{"rule_id": "TEST001"}], "coverage": {"overall": "completed"}},
        )
        db.add_all([session, token, audit])
        db.commit()
        audit_id = audit.id

        loaded = db.get(AuditRecord, audit_id)
        assert loaded.result["findings"][0]["rule_id"] == "TEST001"

        db.delete(user)
        db.commit()
        assert db.get(UserSession, session.id) is None
        assert db.get(AccountToken, token.id) is None
        retained_audit = db.get(AuditRecord, audit_id)
        assert retained_audit is not None
        assert retained_audit.user_id is None


def test_postgres_session_token_hash_is_unique(postgres_engine):
    from datetime import datetime, timezone

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
