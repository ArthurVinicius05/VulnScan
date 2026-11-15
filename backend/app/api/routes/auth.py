import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.core.passwords import hash_password, verify_password
from app.models.user import User
from app.models.user_session import UserSession

router = APIRouter(prefix="/auth", tags=["authentication"])
SESSION_HOURS = 12


class Credentials(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=128)


def _normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if normalized.count("@") != 1 or "." not in normalized.rsplit("@", 1)[-1]:
        raise HTTPException(status_code=422, detail="Informe um e-mail válido.")
    return normalized


def _issue_session(db: Session, user: User) -> dict:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    db.add(UserSession(
        user_id=user.id,
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        created_at=now,
        expires_at=now + timedelta(hours=SESSION_HOURS),
    ))
    db.commit()
    return {"access_token": token, "token_type": "bearer", "expires_in": SESSION_HOURS * 3600,
            "user": {"id": user.id, "email": user.email}}


@router.post("/register", status_code=status.HTTP_201_CREATED)
def register(credentials: Credentials, db: Session = Depends(get_db)):
    email = _normalize_email(credentials.email)
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status_code=409, detail="Este e-mail já está cadastrado.")
    user = User(email=email, password_hash=hash_password(credentials.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    return _issue_session(db, user)


@router.post("/login")
def login(credentials: Credentials, db: Session = Depends(get_db)):
    email = _normalize_email(credentials.email)
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="E-mail ou senha incorretos.", headers={"WWW-Authenticate": "Bearer"})
    return _issue_session(db, user)


def get_current_user(authorization: str | None = Header(default=None), db: Session = Depends(get_db)) -> User:
    scheme, separator, token = (authorization or "").partition(" ")
    if not separator or scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Autenticação necessária.", headers={"WWW-Authenticate": "Bearer"})
    token_hash = hashlib.sha256(token.encode()).hexdigest()
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
def logout(authorization: str | None = Header(default=None), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scheme, _, token = (authorization or "").partition(" ")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    session = db.scalar(select(UserSession).where(UserSession.token_hash == token_hash, UserSession.user_id == user.id))
    if session is not None:
        db.delete(session)
        db.commit()
    return None
