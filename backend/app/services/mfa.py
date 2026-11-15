from __future__ import annotations
import hashlib
import secrets
from datetime import datetime, timezone
from hmac import compare_digest
import pyotp
from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.mfa_recovery_code import MFARecoveryCode

def _fernet() -> Fernet:
    key = settings.mfa_encryption_key
    if not key:
        raise RuntimeError("MFA_ENCRYPTION_KEY is not configured.")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("MFA_ENCRYPTION_KEY is invalid.") from exc

def encrypt_secret(secret: str) -> str:
    return _fernet().encrypt(secret.encode("utf-8")).decode("ascii")

def decrypt_secret(encrypted: str) -> str:
    try:
        return _fernet().decrypt(encrypted.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeEncodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("Stored MFA secret cannot be decrypted; check MFA_ENCRYPTION_KEY.") from exc

def generate_totp_secret() -> str:
    return pyotp.random_base32()

def matching_totp_step(secret: str, code: str, last_step: int | None = None, now: datetime | None = None) -> int | None:
    if len(code) != 6 or not code.isdigit():
        return None
    moment = now or datetime.now(timezone.utc)
    totp = pyotp.TOTP(secret)
    current_step = totp.timecode(moment)
    for step in (current_step - 1, current_step, current_step + 1):
        if step <= (last_step if last_step is not None else -1):
            continue
        candidate_time = datetime.fromtimestamp(step * totp.interval, tz=timezone.utc)
        if compare_digest(totp.at(candidate_time), code):
            return step
    return None

def issue_recovery_codes(db: Session, user_id: str, count: int = 10) -> list[str]:
    db.query(MFARecoveryCode).filter(MFARecoveryCode.user_id == user_id).delete(synchronize_session=False)
    raw_codes = [secrets.token_hex(8).upper() for _ in range(count)]
    for code in raw_codes:
        db.add(MFARecoveryCode(user_id=user_id, code_hash=hashlib.sha256(code.encode("ascii")).hexdigest()))
    return raw_codes

def consume_recovery_code(db: Session, user_id: str, code: str) -> bool:
    normalized = code.strip().replace("-", "").upper()
    if len(normalized) != 16 or any(char not in "0123456789ABCDEF" for char in normalized):
        return False
    digest = hashlib.sha256(normalized.encode("ascii")).hexdigest()
    record = db.scalar(select(MFARecoveryCode).where(
        MFARecoveryCode.user_id == user_id,
        MFARecoveryCode.code_hash == digest,
    ).with_for_update())
    if record is None:
        return False
    db.delete(record)
    return True
