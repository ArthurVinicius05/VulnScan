import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from hmac import compare_digest

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.config import settings
from app.core.passwords import hash_password, verify_password
from app.models.user import User
from app.models.user_session import UserSession

router = APIRouter(prefix="/auth", tags=["authentication"])
SESSION_HOURS = 12
SESSION_COOKIE = "vulnscan_session"
CSRF_COOKIE = "vulnscan_csrf"


class Credentials(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=128)


def _normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if normalized.count("@") != 1 or "." not in normalized.rsplit("@", 1)[-1]:
        raise HTTPException(status_code=422, detail="Informe um e-mail válido.")
    return normalized


def _validate_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin and origin.rstrip("/") not in {item.rstrip("/") for item in settings.cors_origins}:
        raise HTTPException(status_code=403, detail="Origem não permitida.")


def _set_session_cookies(response: Response, token: str, csrf_token: str) -> None:
    secure = settings.session_cookie_secure or settings.app_env.lower() == "production"
    common = {"max_age": SESSION_HOURS * 3600, "path": "/", "secure": secure, "samesite": "lax"}
    response.set_cookie(SESSION_COOKIE, token, httponly=True, **common)
    response.set_cookie(CSRF_COOKIE, csrf_token, httponly=False, **common)


def _issue_session(db: Session, user: User, response: Response) -> dict:
    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.add(UserSession(
        user_id=user.id,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        created_at=now,
        expires_at=now + timedelta(hours=SESSION_HOURS),
    ))
    db.commit()
    _set_session_cookies(response, token, csrf_token)
    return {"expires_in": SESSION_HOURS * 3600, "user": {"id": user.id, "email": user.email}}


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(credentials: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    _validate_origin(request)
    email = _normalize_email(credentials.email)
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Este e-mail já está cadastrado.")
    user = User(email=email, password_hash=hash_password(credentials.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return _issue_session(db, user, response)


@router.post("/login")
def login(credentials: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    _validate_origin(request)
    email = _normalize_email(credentials.email)
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos.")
    return _issue_session(db, user, response)


def get_current_user(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    db: Session = Depends(get_db),
) -> User:
    _validate_origin(request)
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        if not csrf_cookie or not csrf_header or not compare_digest(csrf_cookie, csrf_header):
            raise HTTPException(status_code=403, detail="Token CSRF ausente ou inválido.")
    if not session_token:
        raise HTTPException(status_code=401, detail="Autenticação necessária.")
    token_hash = hashlib.sha256(session_token.encode()).hexdigest()
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash))
    if session is None:
        raise HTTPException(status_code=401, detail="Sessão inválida ou encerrada.")
    expires = session.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Sessão expirada. Entre novamente.")
    user = db.get(User, session.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Conta não encontrada.")
    return user


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email}


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
    session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    token_hash = hashlib.sha256((session_token or "").encode()).hexdigest()
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash, UserSession.user_id == user.id))
    if session is not None:
        db.delete(session)
        db.commit()
    secure = settings.session_cookie_secure or settings.app_env.lower() == "production"
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, httponly=True, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, httponly=False, samesite="lax")
    return None
