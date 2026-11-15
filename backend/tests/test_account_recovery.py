import hashlib
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import get_db
from app.db.database import Base
from app.main import app
from app.models.user import User
from app.models.user_session import UserSession
from app.core.passwords import hash_password, verify_password
from app.api.routes import auth as auth_routes


def _client_with_db(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'account-recovery.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        db = sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    return TestClient(app, client=("127.0.0.12", 12345)), sessions, engine


def test_reset_password_token_is_single_use_and_revokes_sessions(tmp_path, monkeypatch):
    client, sessions, engine = _client_with_db(tmp_path)
    sent = []
    monkeypatch.setattr(auth_routes, "email_is_configured", lambda: True)
    monkeypatch.setattr(auth_routes, "send_account_email", lambda email, subject, body: sent.append(body))
    try:
        with sessions() as db:
            user = User(email="reset@example.com", password_hash=hash_password("old-password-123"),
                        email_verified_at=datetime.now(timezone.utc))
            db.add(user)
            db.flush()
            db.add(UserSession(user_id=user.id, token_hash=hashlib.sha256(b"old-session").hexdigest(),
                               created_at=datetime.now(timezone.utc),
                               expires_at=datetime.now(timezone.utc) + timedelta(hours=1)))
            db.commit()

        response = client.post("/api/auth/request-password-reset", json={"email": "reset@example.com"})
        assert response.status_code == 200
        assert len(sent) == 1
        token = sent[0].split("reset=", 1)[1].split()[0]

        changed = client.post("/api/auth/reset-password",
                              json={"token": token, "password": "new-password-456"})
        assert changed.status_code == 200
        with sessions() as db:
            user = db.query(User).filter_by(email="reset@example.com").one()
            assert verify_password("new-password-456", user.password_hash)
            assert db.query(UserSession).filter_by(user_id=user.id).count() == 0

        replay = client.post("/api/auth/reset-password",
                             json={"token": token, "password": "another-password-789"})
        assert replay.status_code == 400
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_password_reset_response_does_not_disclose_unknown_email(tmp_path, monkeypatch):
    client, _, engine = _client_with_db(tmp_path)
    monkeypatch.setattr(auth_routes, "email_is_configured", lambda: True)
    try:
        known = client.post("/api/auth/request-password-reset", json={"email": "unknown@example.com"})
        assert known.status_code == 200
        assert known.json()["message"] == "Se o e-mail estiver cadastrado, enviaremos instruções para redefinir a senha."
    finally:
        app.dependency_overrides.clear()
        engine.dispose()


def test_unverified_account_cannot_login_and_can_verify(tmp_path, monkeypatch):
    client, sessions, engine = _client_with_db(tmp_path)
    sent = []
    monkeypatch.setattr(auth_routes, "email_is_configured", lambda: True)
    monkeypatch.setattr(auth_routes, "send_account_email", lambda email, subject, body: sent.append(body))
    try:
        created = client.post("/api/auth/register",
                              json={"email": "verify@example.com", "password": "strong-password-123"})
        assert created.status_code == 201
        blocked = client.post("/api/auth/login",
                              json={"email": "verify@example.com", "password": "strong-password-123"})
        assert blocked.status_code == 403
        token = sent[0].split("verify=", 1)[1].split()[0]
        verified = client.post("/api/auth/verify-email", json={"token": token})
        assert verified.status_code == 200
        login = client.post("/api/auth/login",
                            json={"email": "verify@example.com", "password": "strong-password-123"})
        assert login.status_code == 200
        replay = client.post("/api/auth/verify-email", json={"token": token})
        assert replay.status_code == 400
    finally:
        app.dependency_overrides.clear()
        engine.dispose()
