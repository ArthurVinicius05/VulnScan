import hashlib
from datetime import datetime, timezone

import anyio
from hmac import compare_digest

from starlette.responses import JSONResponse

from app.core.config import settings
from app.db.database import SessionLocal
from app.models.user import User
from app.models.user_session import UserSession

SESSION_COOKIE = "vulnscan_session"
CSRF_COOKIE = "vulnscan_csrf"


class _UploadTooLarge(Exception):
    pass


class UploadAuthenticationMiddleware:
    """Authenticate uploads before parsing multipart data and cap streamed bodies."""

    def __init__(self, app):
        self.app = app

    @staticmethod
    def _response(scope, receive, send, status_code: int, detail: str):
        response = JSONResponse({"detail": detail}, status_code=status_code)
        return response(scope, receive, send)

    @staticmethod
    def _authenticated(scope) -> tuple[bool, int, str]:
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        origin = headers.get(b"origin")
        allowed_origins = {value.rstrip("/").encode() for value in settings.cors_origins}
        if origin and origin.rstrip(b"/") not in allowed_origins:
            return False, 403, "Origem não permitida."

        cookie_header = headers.get(b"cookie", b"").decode("latin-1")
        cookies = {}
        for item in cookie_header.split(";"):
            key, separator, value = item.strip().partition("=")
            if separator:
                cookies[key] = value

        session_token = cookies.get(SESSION_COOKIE)
        csrf_cookie = cookies.get(CSRF_COOKIE)
        csrf_header = headers.get(b"x-csrf-token", b"").decode("latin-1")
        if not session_token:
            return False, 401, "Autenticação necessária."
        if not csrf_cookie or not csrf_header or not compare_digest(csrf_cookie, csrf_header):
            return False, 403, "Token CSRF ausente ou inválido."

        db = SessionLocal()
        try:
            token_hash = hashlib.sha256(session_token.encode()).hexdigest()
            session = db.query(UserSession).filter(UserSession.token_hash == token_hash).first()
            if session is None:
                return False, 401, "Sessão inválida ou encerrada."
            expires = session.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires <= datetime.now(timezone.utc) or db.get(User, session.user_id) is None:
                return False, 401, "Sessão expirada ou inválida."
        finally:
            db.close()
        return True, 200, ""

    async def __call__(self, scope, receive, send):
        if (
            scope["type"] != "http"
            or scope.get("method") != "POST"
            or scope.get("path") != "/api/analysis/source-zip"
        ):
            await self.app(scope, receive, send)
            return

        max_request_bytes = settings.max_upload_mb * 1024 * 1024 + 1024 * 1024
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > max_request_bytes:
                    await self._response(scope, receive, send, 413,
                        f"Requisição excede o limite de {settings.max_upload_mb} MB.")
                    return
            except ValueError:
                await self._response(scope, receive, send, 400, "Content-Length inválido.")
                return

        authenticated, status_code, detail = await anyio.to_thread.run_sync(
            self._authenticated, scope
        )
        if not authenticated:
            await self._response(scope, receive, send, status_code, detail)
            return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > max_request_bytes:
                    raise _UploadTooLarge
            return message

        response_started = False

        async def tracked_send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _UploadTooLarge:
            if response_started:
                raise
            await self._response(scope, receive, send, 413,
                f"Requisição excede o limite de {settings.max_upload_mb} MB.")
