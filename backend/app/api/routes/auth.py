import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from hmac import compare_digest
from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.api.dependencies import get_db
from app.core.config import settings
from app.core.passwords import hash_password, verify_password
from app.models.user import User
from app.models.user_session import UserSession
from app.models.account_token import AccountToken
from app.services.email_sender import email_is_configured, send_account_email

router = APIRouter(prefix="/auth", tags=["authentication"])
SESSION_HOURS = 12
SESSION_COOKIE = "vulnscan_session"
CSRF_COOKIE = "vulnscan_csrf"
TOKEN_MINUTES = 30

class Credentials(BaseModel):
    email: EmailStr = Field(max_length=254)
    password: str = Field(min_length=12, max_length=128)

class EmailRequest(BaseModel):
    email: EmailStr = Field(max_length=254)

class TokenRequest(BaseModel):
    token: str = Field(min_length=32, max_length=128)

class PasswordResetRequest(TokenRequest):
    password: str = Field(min_length=12, max_length=128)

def _normalize_email(email: str) -> str:
    return email.strip().lower()

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
    token, csrf_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.add(UserSession(user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(),
        created_at=now, expires_at=now + timedelta(hours=SESSION_HOURS)))
    db.commit()
    _set_session_cookies(response, token, csrf_token)
    return {"expires_in": SESSION_HOURS * 3600, "user": {"id": user.id, "email": user.email}}

def _create_account_token(db: Session, user: User, purpose: str) -> str:
    raw = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.query(AccountToken).filter(AccountToken.user_id == user.id, AccountToken.purpose == purpose).delete()
    db.add(AccountToken(user_id=user.id, token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        purpose=purpose, created_at=now, expires_at=now + timedelta(minutes=TOKEN_MINUTES)))
    db.commit()
    return raw

def _consume_account_token(db: Session, raw: str, purpose: str) -> AccountToken:
    token = db.scalar(select(AccountToken).where(
        AccountToken.token_hash == hashlib.sha256(raw.encode()).hexdigest(),
        AccountToken.purpose == purpose))
    if token is None:
        raise HTTPException(status_code=400, detail="Link inválido ou expirado.")
    expires = token.expires_at if token.expires_at.tzinfo else token.expires_at.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        db.delete(token)
        db.commit()
        raise HTTPException(status_code=400, detail="Link inválido ou expirado.")
    return token

def _send_link(email: str, purpose: str, raw: str) -> None:
    action = "verify" if purpose == "verify_email" else "reset"
    subject = "Confirme seu e-mail - VulnScan" if action == "verify" else "Redefinição de senha - VulnScan"
    link = f"{settings.frontend_url.rstrip('/')}/#{action}={raw}"
    send_account_email(email, subject, f"Abra este link: {link}\nO link expira em {TOKEN_MINUTES} minutos. Se não solicitou, ignore este e-mail.")

@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(credentials: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    _validate_origin(request)
    email = _normalize_email(str(credentials.email))
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Este e-mail já está cadastrado.")
    configured = email_is_configured()
    if settings.app_env.lower() == "production" and not configured:
        raise HTTPException(status_code=503, detail="Cadastro temporariamente indisponível: serviço de e-mail não configurado.")
    user = User(email=email, password_hash=hash_password(credentials.password),
        email_verified_at=None if configured else datetime.now(timezone.utc))
    db.add(user)
    db.commit()
    db.refresh(user)
    if configured:
        try:
            _send_link(email, "verify_email", _create_account_token(db, user, "verify_email"))
        except Exception as exc:
            db.delete(user)
            db.commit()
            raise HTTPException(status_code=503, detail="Não foi possível enviar o e-mail de confirmação.") from exc
        return {"message": "Conta criada. Verifique seu e-mail para ativá-la."}
    return _issue_session(db, user, response)

@router.post("/verify-email")
def verify_email(payload: TokenRequest, db: Session = Depends(get_db)):
    token = _consume_account_token(db, payload.token, "verify_email")
    user = db.get(User, token.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="Link inválido ou expirado.")
    user.email_verified_at = datetime.now(timezone.utc)
    db.delete(token)
    db.commit()
    return {"message": "E-mail confirmado. Agora você pode entrar."}

@router.post("/resend-verification")
def resend_verification(payload: EmailRequest, request: Request, db: Session = Depends(get_db)):
    _validate_origin(request)
    user = db.scalar(select(User).where(User.email == _normalize_email(str(payload.email))))
    if user and user.email_verified_at is None and email_is_configured():
        try:
            _send_link(user.email, "verify_email", _create_account_token(db, user, "verify_email"))
        except Exception:
            pass
    return {"message": "Se a conta existir e precisar de confirmação, enviaremos um novo link."}

@router.post("/request-password-reset")
def request_password_reset(payload: EmailRequest, request: Request, db: Session = Depends(get_db)):
    _validate_origin(request)
    user = db.scalar(select(User).where(User.email == _normalize_email(str(payload.email))))
    if user and email_is_configured():
        try:
            _send_link(user.email, "password_reset", _create_account_token(db, user, "password_reset"))
        except Exception:
            pass
    return {"message": "Se o e-mail estiver cadastrado, enviaremos instruções para redefinir a senha."}

@router.post("/reset-password")
def reset_password(payload: PasswordResetRequest, db: Session = Depends(get_db)):
    token = _consume_account_token(db, payload.token, "password_reset")
    user = db.get(User, token.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="Link inválido ou expirado.")
    user.password_hash = hash_password(payload.password)
    db.query(UserSession).filter(UserSession.user_id == user.id).delete(synchronize_session=False)
    db.query(AccountToken).filter(AccountToken.user_id == user.id).delete(synchronize_session=False)
    db.commit()
    return {"message": "Senha redefinida. Entre novamente com a nova senha."}

@router.post("/login")
def login(credentials: Credentials, request: Request, response: Response, db: Session = Depends(get_db)):
    _validate_origin(request)
    user = db.scalar(select(User).where(User.email == _normalize_email(str(credentials.email))))
    if user is None or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos.")
    if user.email_verified_at is None:
        raise HTTPException(status_code=403, detail="Confirme seu e-mail antes de entrar.")
    return _issue_session(db, user, response)

def get_current_user(request: Request,
    session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    csrf_cookie: str | None = Cookie(default=None, alias=CSRF_COOKIE),
    csrf_header: str | None = Header(default=None, alias="X-CSRF-Token"),
    db: Session = Depends(get_db)) -> User:
    _validate_origin(request)
    if not session_token:
        raise HTTPException(status_code=401, detail="Autenticação necessária.")
    session = db.scalar(select(UserSession).where(
        UserSession.token_hash == hashlib.sha256(session_token.encode()).hexdigest()))
    if session is None:
        raise HTTPException(status_code=401, detail="Sessão inválida ou encerrada.")
    expires = session.expires_at if session.expires_at.tzinfo else session.expires_at.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc):
        db.delete(session)
        db.commit()
        raise HTTPException(status_code=401, detail="Sessão expirada. Entre novamente.")
    user = db.get(User, session.user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Conta não encontrada.")
    if request.method not in {"GET", "HEAD", "OPTIONS"} and (
        not csrf_cookie or not csrf_header or not compare_digest(csrf_cookie, csrf_header)):
        raise HTTPException(status_code=403, detail="Token CSRF ausente ou inválido.")
    return user

@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "email_verified": user.email_verified_at is not None}

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response, session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE),
    db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    token_hash = hashlib.sha256((session_token or "").encode()).hexdigest()
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash, UserSession.user_id == user.id))
    if session is not None:
        db.delete(session)
        db.commit()
    secure = settings.session_cookie_secure or settings.app_env.lower() == "production"
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, httponly=True, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, httponly=False, samesite="lax")
    return None
