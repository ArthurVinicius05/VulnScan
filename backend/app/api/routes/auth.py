import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from hmac import compare_digest

from fastapi import APIRouter, Cookie, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.config import settings
from app.core.passwords import hash_password, verify_password
from app.models.user import User
from app.models.user_session import UserSession
from app.models.account_token import AccountToken
from app.models.mfa_challenge import MFAChallenge
from app.models.mfa_recovery_code import MFARecoveryCode
from app.models.analysis_job import AnalysisJob
from app.models.audit import AuditRecord
from app.services.email_sender import email_is_configured, send_account_email
from app.services.mfa import (
    consume_recovery_code,
    decrypt_secret,
    encrypt_secret,
    generate_totp_secret,
    issue_recovery_codes,
    matching_totp_step,
)

router = APIRouter(prefix="/auth", tags=["authentication"])
logger = logging.getLogger(__name__)
SESSION_HOURS = 12
SESSION_COOKIE = "vulnscan_session"
CSRF_COOKIE = "vulnscan_csrf"
TOKEN_MINUTES = 30
MFA_CHALLENGE_MINUTES = 5
MFA_MAX_ATTEMPTS = 5


class Credentials(BaseModel):
    email: EmailStr = Field(max_length=254)
    password: str = Field(min_length=12, max_length=128)


class EmailRequest(BaseModel):
    email: EmailStr = Field(max_length=254)


class TokenRequest(BaseModel):
    token: str = Field(min_length=32, max_length=128)


class PasswordResetRequest(TokenRequest):
    password: str = Field(min_length=12, max_length=128)


class MFACodeRequest(BaseModel):
    code: str = Field(min_length=6, max_length=64)


class DeleteAccountRequest(BaseModel):
    password: str = Field(min_length=12, max_length=128)
    mfa_code: str | None = Field(default=None, min_length=6, max_length=64)


class MFAChallengeRequest(MFACodeRequest):
    challenge_token: str = Field(min_length=32, max_length=128)


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


def _verify_mfa_factor(db: Session, user: User, code: str) -> bool:
    if user.mfa_secret_encrypted and len(code) == 6 and code.isdigit():
        try:
            secret = decrypt_secret(user.mfa_secret_encrypted)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail="Não foi possível validar o MFA. Verifique a chave de criptografia.") from exc
        step = matching_totp_step(secret, code, user.mfa_last_used_step)
        if step is not None:
            user.mfa_last_used_step = step
            return True
    return consume_recovery_code(db, user.id, code)


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
            logger.warning("Email dispatch failed for account verification or reset.", exc_info=True)
    return {"message": "Se a conta existir e precisar de confirmação, enviaremos um novo link."}


@router.post("/request-password-reset")
def request_password_reset(payload: EmailRequest, request: Request, db: Session = Depends(get_db)):
    _validate_origin(request)
    user = db.scalar(select(User).where(User.email == _normalize_email(str(payload.email))))
    if user and email_is_configured():
        try:
            _send_link(user.email, "password_reset", _create_account_token(db, user, "password_reset"))
        except Exception:
            logger.warning("Email dispatch failed for account verification or reset.", exc_info=True)
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
    db.query(MFAChallenge).filter(MFAChallenge.user_id == user.id).delete(synchronize_session=False)
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
    if user.mfa_enabled:
        if not user.mfa_secret_encrypted:
            raise HTTPException(status_code=503, detail="MFA da conta está inconsistente. Contate o suporte.")
        now = datetime.now(timezone.utc)
        db.query(MFAChallenge).filter(MFAChallenge.user_id == user.id).delete(synchronize_session=False)
        challenge = secrets.token_urlsafe(32)
        db.add(MFAChallenge(user_id=user.id, token_hash=hashlib.sha256(challenge.encode()).hexdigest(),
            attempts=0, created_at=now, expires_at=now + timedelta(minutes=MFA_CHALLENGE_MINUTES)))
        db.commit()
        return {"mfa_required": True, "challenge_token": challenge, "expires_in": MFA_CHALLENGE_MINUTES * 60}
    return _issue_session(db, user, response)


@router.post("/mfa/challenge")
def complete_mfa_login(payload: MFAChallengeRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    _validate_origin(request)
    digest = hashlib.sha256(payload.challenge_token.encode()).hexdigest()
    challenge = db.scalar(select(MFAChallenge).where(MFAChallenge.token_hash == digest).with_for_update())
    if challenge is None:
        raise HTTPException(status_code=401, detail="Desafio MFA inválido ou expirado.")
    expires = challenge.expires_at if challenge.expires_at.tzinfo else challenge.expires_at.replace(tzinfo=timezone.utc)
    if expires <= datetime.now(timezone.utc) or challenge.attempts >= MFA_MAX_ATTEMPTS:
        db.delete(challenge)
        db.commit()
        raise HTTPException(status_code=401, detail="Desafio MFA inválido ou expirado.")
    user = db.get(User, challenge.user_id)
    if user is None or not user.mfa_enabled or not _verify_mfa_factor(db, user, payload.code):
        challenge.attempts += 1
        if challenge.attempts >= MFA_MAX_ATTEMPTS:
            db.delete(challenge)
        db.commit()
        raise HTTPException(status_code=401, detail="Código MFA inválido.")
    db.delete(challenge)
    db.commit()
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
        not csrf_cookie or not csrf_header or not compare_digest(
            csrf_cookie.encode("utf-8"), csrf_header.encode("utf-8")
        )):
        raise HTTPException(status_code=403, detail="Token CSRF ausente ou inválido.")
    return user


@router.get("/me")
def me(response: Response, user: User = Depends(get_current_user)):
    response.headers["Cache-Control"] = "private, no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return {"id": user.id, "email": user.email,
        "email_verified": user.email_verified_at is not None, "mfa_enabled": user.mfa_enabled}


@router.delete("/me")
def delete_account(payload: DeleteAccountRequest, response: Response,
    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    locked_user = db.scalar(select(User).where(User.id == user.id).with_for_update())
    if not verify_password(payload.password, locked_user.password_hash):
        raise HTTPException(status_code=401, detail="Senha atual incorreta.")
    running_jobs = db.scalar(select(func.count()).select_from(AnalysisJob).where(
        AnalysisJob.user_id == user.id, AnalysisJob.status == "running"
    )) or 0
    if running_jobs:
        raise HTTPException(status_code=409, detail="Aguarde as análises em execução terminarem antes de excluir a conta.")
    if locked_user.mfa_enabled and (not payload.mfa_code or not _verify_mfa_factor(db, locked_user, payload.mfa_code)):
        raise HTTPException(status_code=401, detail="Código MFA inválido.")
    db.query(AuditRecord).filter(AuditRecord.user_id == user.id).delete(synchronize_session=False)
    db.query(AnalysisJob).filter(AnalysisJob.user_id == user.id).delete(synchronize_session=False)
    db.query(UserSession).filter(UserSession.user_id == user.id).delete(synchronize_session=False)
    db.query(AccountToken).filter(AccountToken.user_id == user.id).delete(synchronize_session=False)
    db.query(MFAChallenge).filter(MFAChallenge.user_id == user.id).delete(synchronize_session=False)
    db.query(MFARecoveryCode).filter(MFARecoveryCode.user_id == user.id).delete(synchronize_session=False)
    db.delete(locked_user)
    db.commit()
    secure = settings.session_cookie_secure or settings.app_env.lower() == "production"
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, httponly=True, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, httponly=False, samesite="lax")
    return {"message": "Conta e dados associados foram excluídos."}


@router.post("/mfa/setup")
def setup_mfa(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA já está ativado nesta conta.")
    if not settings.mfa_encryption_key:
        raise HTTPException(status_code=503, detail="Configure MFA_ENCRYPTION_KEY antes de ativar MFA.")
    locked_user = db.scalar(select(User).where(User.id == user.id).with_for_update())
    secret = generate_totp_secret()
    try:
        locked_user.mfa_pending_secret_encrypted = encrypt_secret(secret)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Chave de criptografia MFA inválida.") from exc
    db.commit()
    import pyotp
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="VulnScan")
    return {"secret": secret, "otpauth_url": uri, "message": "Adicione a chave ao seu aplicativo autenticador e confirme o código para concluir."}


@router.post("/mfa/enable")
def enable_mfa(payload: MFACodeRequest, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    locked_user = db.scalar(select(User).where(User.id == user.id).with_for_update())
    if locked_user.mfa_enabled or not locked_user.mfa_pending_secret_encrypted:
        raise HTTPException(status_code=409, detail="Inicie a configuração de MFA antes de confirmar.")
    try:
        secret = decrypt_secret(locked_user.mfa_pending_secret_encrypted)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail="Não foi possível recuperar a configuração MFA.") from exc
    step = matching_totp_step(secret, payload.code)
    if step is None:
        raise HTTPException(status_code=400, detail="Código TOTP inválido ou expirado.")
    locked_user.mfa_enabled = True
    locked_user.mfa_secret_encrypted = locked_user.mfa_pending_secret_encrypted
    locked_user.mfa_pending_secret_encrypted = None
    locked_user.mfa_last_used_step = step
    recovery_codes = issue_recovery_codes(db, locked_user.id)
    db.commit()
    return {"mfa_enabled": True, "recovery_codes": recovery_codes,
        "message": "MFA ativado. Guarde os códigos de recuperação; eles serão exibidos apenas uma vez."}


@router.post("/mfa/disable")
def disable_mfa(payload: MFACodeRequest, response: Response,
    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    locked_user = db.scalar(select(User).where(User.id == user.id).with_for_update())
    if not locked_user.mfa_enabled or not _verify_mfa_factor(db, locked_user, payload.code):
        raise HTTPException(status_code=401, detail="Código MFA inválido.")
    locked_user.mfa_enabled = False
    locked_user.mfa_secret_encrypted = None
    locked_user.mfa_pending_secret_encrypted = None
    locked_user.mfa_last_used_step = None
    db.query(MFARecoveryCode).filter(MFARecoveryCode.user_id == user.id).delete(synchronize_session=False)
    db.query(MFAChallenge).filter(MFAChallenge.user_id == user.id).delete(synchronize_session=False)
    db.query(UserSession).filter(UserSession.user_id == user.id).delete(synchronize_session=False)
    db.commit()
    secure = settings.session_cookie_secure or settings.app_env.lower() == "production"
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, httponly=True, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, httponly=False, samesite="lax")
    return {"mfa_enabled": False, "message": "MFA desativado. Todas as sessões foram encerradas."}


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
