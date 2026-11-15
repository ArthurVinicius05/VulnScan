from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import get_db
from app.db.database import Base
from app.main import app


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
    with TestClient(app) as test_client:
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
