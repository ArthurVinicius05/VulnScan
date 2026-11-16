from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import get_db
from app.db.database import Base
from app.main import app
from app.models.audit import AuditRecord
from app.models.user import User


@pytest.fixture
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'auth.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Generator:
        db = sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    with TestClient(app, client=("127.0.0.11", 12345)) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    engine.dispose()


def test_register_login_me_and_logout(client):
    payload = {"email": "User@Example.com", "password": "correct horse battery staple"}
    created = client.post("/api/auth/register", json=payload)
    assert created.status_code == 201
    assert created.json()["user"]["email"] == "user@example.com"
    cookies = created.cookies
    assert "httponly" in created.headers["set-cookie"].lower()
    csrf = cookies.get("vulnscan_csrf")
    assert client.get("/api/auth/me").json()["email"] == "user@example.com"
    assert client.post("/api/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_duplicate_email_and_invalid_login(client):
    payload = {"email": "user@example.com", "password": "correct horse battery staple"}
    assert client.post("/api/auth/register", json=payload).status_code == 201
    assert client.post("/api/auth/register", json=payload).status_code == 409
    assert client.post("/api/auth/login", json={**payload, "password": "wrong password value"}).status_code == 401


def test_registration_rejects_short_password(client):
    response = client.post("/api/auth/register", json={"email": "user@example.com", "password": "short"})
    assert response.status_code == 422



def test_deleted_account_can_register_again_without_old_history(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'account-deletion.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db() -> Generator:
        db = sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    email = "reused@example.com"
    password = "correct horse battery staple"

    try:
        with TestClient(app) as test_client:
            created = test_client.post("/api/auth/register", json={"email": email, "password": password})
            assert created.status_code == 201
            old_user_id = created.json()["user"]["id"]

            with sessions() as db:
                db.add(AuditRecord(
                    user_id=old_user_id,
                    analysis_type="static_source_analysis",
                    target="old-private-project.zip",
                    status="completed",
                    finding_count=1,
                    result={"findings": [{"rule_id": "OLD001"}]},
                ))
                db.commit()

            csrf = test_client.cookies.get("vulnscan_csrf")
            deleted = test_client.request(
                "DELETE",
                "/api/auth/me",
                json={"password": password},
                headers={"X-CSRF-Token": csrf},
            )
            assert deleted.status_code == 200
            assert test_client.get("/api/auth/me").status_code == 401

            with sessions() as db:
                assert db.get(User, old_user_id) is None
                assert (db.scalar(select(func.count()).select_from(AuditRecord)) or 0) == 0

            recreated = test_client.post("/api/auth/register", json={"email": email, "password": password})
            assert recreated.status_code == 201
            new_user_id = recreated.json()["user"]["id"]
            assert new_user_id != old_user_id

            history = test_client.get("/api/history")
            assert history.status_code == 200
            assert history.json()["items"] == []
            assert history.headers["cache-control"] == "private, no-store, max-age=0"
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
