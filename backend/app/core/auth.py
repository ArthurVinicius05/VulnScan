import secrets

from fastapi import Header, HTTPException

from app.core.config import settings


def require_api_key(authorization: str | None = Header(default=None)) -> None:
    """Protect analysis endpoints when an API key is configured.

    Production fails closed when no key is configured. Local development may
    run without a key to keep the onboarding workflow simple.
    """
    expected = settings.api_key
    if not expected:
        if settings.app_env.lower() in {"production", "prod"}:
            raise HTTPException(
                status_code=503,
                detail="API indisponível: configure uma chave de acesso antes de usar o ambiente de produção.",
            )
        return

    scheme, separator, supplied = (authorization or "").partition(" ")
    if (
        not separator
        or scheme.lower() != "bearer"
        or not supplied
        or not secrets.compare_digest(supplied, expected)
    ):
        raise HTTPException(
            status_code=401,
            detail="Chave de acesso ausente ou inválida.",
            headers={"WWW-Authenticate": "Bearer"},
        )
