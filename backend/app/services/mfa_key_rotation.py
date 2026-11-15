from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.user import User


class MFAKeyRotationError(RuntimeError):
    """Raised when an MFA key rotation cannot be completed safely."""


def rotate_mfa_encryption_key(
    db: Session,
    *,
    old_key: str,
    new_key: str,
    apply: bool = False,
) -> dict[str, int]:
    if not old_key or not new_key or old_key == new_key:
        raise MFAKeyRotationError("Informe duas chaves MFA diferentes e não vazias.")
    try:
        old_cipher = Fernet(old_key.encode("ascii"))
        new_cipher = Fernet(new_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise MFAKeyRotationError("Uma das chaves MFA não é uma chave Fernet válida.") from exc

    users = db.scalars(
        select(User)
        .where(
            or_(
                User.mfa_secret_encrypted.is_not(None),
                User.mfa_pending_secret_encrypted.is_not(None),
            )
        )
        .with_for_update()
    ).all()

    replacements: list[tuple[User, str, str]] = []
    try:
        for user in users:
            for field in ("mfa_secret_encrypted", "mfa_pending_secret_encrypted"):
                encrypted = getattr(user, field)
                if encrypted is None:
                    continue
                try:
                    plaintext = old_cipher.decrypt(encrypted.encode("ascii"))
                except (InvalidToken, UnicodeEncodeError) as exc:
                    raise MFAKeyRotationError(
                        "Uma credencial MFA não pôde ser descriptografada; nenhuma chave foi alterada."
                    ) from exc
                replacements.append(
                    (user, field, new_cipher.encrypt(plaintext).decode("ascii"))
                )

        if apply:
            for user, field, encrypted in replacements:
                setattr(user, field, encrypted)
            db.commit()
        else:
            db.rollback()
    except Exception:
        db.rollback()
        raise

    return {"accounts": len(users), "secrets": len(replacements)}
