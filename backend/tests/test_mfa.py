from datetime import datetime, timezone

import pyotp
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.dependencies import get_db
from app.core.config import settings
from app.core.passwords import hash_password
from app.db.database import Base
from app.main import app
from app.models.mfa_recovery_code import MFARecoveryCode
from app.models.user import User
from app.services.mfa_key_rotation import MFAKeyRotationError, rotate_mfa_encryption_key
from app.services.mfa import (
    consume_recovery_code, decrypt_secret, encrypt_secret, generate_totp_secret,
    issue_recovery_codes, matching_totp_step,
)


def test_totp_encryption_and_replay_protection(monkeypatch):
    monkeypatch.setattr(settings, "mfa_encryption_key", Fernet.generate_key().decode())
    secret = generate_totp_secret()
    assert decrypt_secret(encrypt_secret(secret)) == secret
    now = datetime(2026, 11, 15, 12, 0, 0, tzinfo=timezone.utc)
    code = pyotp.TOTP(secret).at(now)
    step = matching_totp_step(secret, code, now=now)
    assert step is not None
    assert matching_totp_step(secret, code, last_step=step, now=now) is None


def test_recovery_codes_are_single_use(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'mfa-codes.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    with sessions() as db:
        user = User(email="mfa@example.test", password_hash="hash")
        db.add(user)
        db.flush()
        codes = issue_recovery_codes(db, user.id, count=2)
        db.commit()
        assert consume_recovery_code(db, user.id, codes[0])
        db.commit()
        assert not consume_recovery_code(db, user.id, codes[0])
        assert consume_recovery_code(db, user.id, codes[1])
        db.commit()
        assert db.query(MFARecoveryCode).filter_by(user_id=user.id).count() == 0
    engine.dispose()


def test_login_requires_totp_challenge_and_issues_session(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "mfa_encryption_key", Fernet.generate_key().decode())
    engine = create_engine(f"sqlite:///{tmp_path / 'mfa-login.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)
    secret = generate_totp_secret()
    with sessions() as db:
        user = User(email="login-mfa@example.com", password_hash=hash_password("correct-horse-battery"),
            email_verified_at=datetime.now(timezone.utc), mfa_enabled=True,
            mfa_secret_encrypted=encrypt_secret(secret))
        db.add(user)
        db.commit()

    def override_db():
        db = sessions()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            login = client.post("/api/auth/login", json={
                "email": "login-mfa@example.com", "password": "correct-horse-battery"
            })
            assert login.status_code == 200
            challenge = login.json()
            assert challenge["mfa_required"] is True
            assert "vulnscan_session" not in client.cookies
            code = pyotp.TOTP(secret).now()
            completed = client.post("/api/auth/mfa/challenge", json={
                "challenge_token": challenge["challenge_token"], "code": code
            })
            assert completed.status_code == 200
            assert completed.json()["user"]["email"] == "login-mfa@example.com"
            assert client.get("/api/auth/me").json()["mfa_enabled"] is True
    finally:
        app.dependency_overrides.clear()
        engine.dispose()



def test_mfa_key_rotation_supports_dry_run_and_atomic_apply(tmp_path):
    old_key = Fernet.generate_key()
    new_key = Fernet.generate_key()
    old_cipher = Fernet(old_key)
    new_cipher = Fernet(new_key)
    engine = create_engine(f"sqlite:///{tmp_path / 'mfa-rotation.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    with sessions() as db:
        user = User(
            email="rotation@example.test",
            password_hash="hash",
            mfa_enabled=True,
            mfa_secret_encrypted=old_cipher.encrypt(b"active-totp-secret").decode("ascii"),
            mfa_pending_secret_encrypted=old_cipher.encrypt(b"pending-totp-secret").decode("ascii"),
        )
        db.add(user)
        db.commit()
        user_id = user.id

        dry_run = rotate_mfa_encryption_key(
            db,
            old_key=old_key.decode("ascii"),
            new_key=new_key.decode("ascii"),
            apply=False,
        )
        assert dry_run == {"accounts": 1, "secrets": 2}
        unchanged = db.get(User, user_id)
        assert old_cipher.decrypt(unchanged.mfa_secret_encrypted.encode("ascii")) == b"active-totp-secret"

        applied = rotate_mfa_encryption_key(
            db,
            old_key=old_key.decode("ascii"),
            new_key=new_key.decode("ascii"),
            apply=True,
        )
        assert applied == {"accounts": 1, "secrets": 2}
        rotated = db.get(User, user_id)
        assert new_cipher.decrypt(rotated.mfa_secret_encrypted.encode("ascii")) == b"active-totp-secret"
        assert new_cipher.decrypt(rotated.mfa_pending_secret_encrypted.encode("ascii")) == b"pending-totp-secret"

    engine.dispose()


def test_mfa_key_rotation_rolls_back_every_secret_if_one_cannot_decrypt(tmp_path):
    old_key = Fernet.generate_key()
    new_key = Fernet.generate_key()
    other_key = Fernet.generate_key()
    engine = create_engine(f"sqlite:///{tmp_path / 'mfa-rotation-rollback.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, expire_on_commit=False)

    with sessions() as db:
        first = User(
            email="valid-rotation@example.test",
            password_hash="hash",
            mfa_secret_encrypted=Fernet(old_key).encrypt(b"valid-secret").decode("ascii"),
        )
        second = User(
            email="invalid-rotation@example.test",
            password_hash="hash",
            mfa_secret_encrypted=Fernet(other_key).encrypt(b"unknown-secret").decode("ascii"),
        )
        db.add_all([first, second])
        db.commit()
        first_id = first.id
        original = first.mfa_secret_encrypted

        with pytest.raises(MFAKeyRotationError, match="nenhuma chave foi alterada"):
            rotate_mfa_encryption_key(
                db,
                old_key=old_key.decode("ascii"),
                new_key=new_key.decode("ascii"),
                apply=True,
            )
        db.expire_all()
        assert db.get(User, first_id).mfa_secret_encrypted == original

    engine.dispose()
