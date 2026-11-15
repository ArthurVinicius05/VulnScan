import hashlib
from datetime import datetime, timezone
from hmac import compare_digest

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.db.database import SessionLocal
from app.models.user import User
from app.models.user_session import UserSession

SESSION_COOKIE = "vulnscan_session"
CSRF_COOKIE = "vulnscan_csrf"


class UploadAuthenticationMiddleware(BaseHTTPMiddleware):
    """Reject unauthenticated upload requests before Starlette parses multipart bodies."""

    async def dispatch(self, request: Request, call_next):
        if request.method != "POST" or request.url.path != "/api/analysis/source-zip":
            return await call_next(request)

        origin = request.headers.get("origin")
        allowed_origins = {value.rstrip("/") for value in settings.cors_origins}
        if origin and origin.rstrip("/") not in allowed_origins:
            return JSONResponse({"detail": "Origem não permitida."}, status_code=403)

        max_request_bytes = settings.max_upload_mb * 1024 * 1024 + 1024 * 1024
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > max_request_bytes:
                    return JSONResponse(
                        {"detail": f"Requisição excede o limite de {settings.max_upload_mb} MB."},
                        status_code=413,
                    )
            except ValueError:
                return JSONResponse({"detail": "Content-Length inválido."}, status_code=400)

        session_token = request.cookies.get(SESSION_COOKIE)
        csrf_cookie = request.cookies.get(CSRF_COOKIE)
        csrf_header = request.headers.get("x-csrf-token")
        if not session_token:
            return JSONResponse({"detail": "Autenticação necessária."}, status_code=401)
        if not csrf_cookie or not csrf_header or not compare_digest(csrf_cookie, csrf_header):
            return JSONResponse({"detail": "Token CSRF ausente ou inválido."}, status_code=403)

        db = SessionLocal()
        try:
            session = db.query(UserSession).filter(
                UserSession.token_hash == hashlib.sha256(session_token.encode()).hexdigest()
            ).first()
            if session is None:
                return JSONResponse({"detail": "Sessão inválida ou encerrada."}, status_code=401)
            expires = session.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires <= datetime.now(timezone.utc) or db.get(User, session.user_id) is None:
                return JSONResponse({"detail": "Sessão expirada ou inválida."}, status_code=401)
        finally:
            db.close()

        return await call_next(request)
