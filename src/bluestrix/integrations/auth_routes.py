"""Production auth HTTP routes for FastAPI."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from bluestrix.core import repository as repo
from bluestrix.core.auth import (
    ROLES,
    authenticate_user,
    create_session,
    decode_token,
    revoke_all_sessions,
    revoke_session,
    rotate_refresh,
)
from bluestrix.core.database import get_db
from bluestrix.core.mfa import (
    decrypt_secret,
    encrypt_secret,
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_codes,
    verify_totp,
)
from bluestrix.core.models_db import PasswordResetToken, User
from bluestrix.core.rate_limit import check_rate_limit
from bluestrix.core.security import generate_token, hash_password, hash_token, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_COOKIE = "bluestrix_refresh"


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10)
    role: str = "security_analyst"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_code: Optional[str] = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=10)


class MfaEnableRequest(BaseModel):
    password: str


class MfaVerifyRequest(BaseModel):
    code: str


def _client_meta(request: Request) -> tuple[Optional[str], Optional[str]]:
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    return ip, ua


def _set_refresh_cookie(response: Response, refresh: str, max_age: int) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE,
        value=refresh,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=max_age,
        path="/auth",
    )


def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(REFRESH_COOKIE, path="/auth")


@router.post("/register")
def register(body: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    # Bootstrap only: first user may be admin; later registrations default analyst unless admin-created
    allowed, retry = check_rate_limit(f"register:{request.client.host if request.client else 'x'}", limit=3)
    if not allowed:
        raise HTTPException(status_code=429, detail=f"rate limited; retry in {retry}s")
    role = body.role if body.role in ROLES else "security_analyst"
    existing = db.scalar(select(User).where(User.email == body.email.lower()))
    if existing:
        raise HTTPException(status_code=409, detail="email already registered")
    count = db.scalar(select(User).limit(1))
    if count is not None and role == "admin":
        # only first account may self-assign admin without existing admin token
        raise HTTPException(status_code=403, detail="admin role requires existing admin")
    if count is None:
        role = "admin"  # first user is bootstrap admin
    user = User(
        email=body.email.lower(),
        password_hash=hash_password(body.password),
        role=role,
        is_active=True,
        mfa_enabled=False,
        mfa_recovery_hashes=[],
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    repo.create_audit_event(
        db,
        actor=user.email,
        action="user_registered",
        target=str(user.id),
        decision="ALLOWED",
        reason=f"role={user.role}",
    )
    return {"id": str(user.id), "email": user.email, "role": user.role}


@router.post("/login")
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    ip, ua = _client_meta(request)
    allowed, retry = check_rate_limit(f"login:{body.email.lower()}:{ip}", limit=5, window_seconds=300)
    if not allowed:
        repo.create_audit_event(
            db,
            actor=body.email,
            action="login_failed",
            target=body.email,
            decision="RATE_LIMITED",
            reason="too many attempts",
        )
        raise HTTPException(status_code=429, detail=f"rate limited; retry in {retry}s")

    user = authenticate_user(db, body.email, body.password)
    if user is None:
        repo.create_audit_event(
            db,
            actor=body.email,
            action="login_failed",
            target=body.email,
            decision="DENIED",
            reason="invalid credentials",
        )
        raise HTTPException(status_code=401, detail="invalid credentials")

    if user.role == "admin" or user.mfa_enabled:
        if not body.mfa_code:
            raise HTTPException(status_code=401, detail="mfa_required")
        if not user.mfa_secret_encrypted:
            raise HTTPException(status_code=401, detail="mfa_not_configured")
        secret = decrypt_secret(user.mfa_secret_encrypted)
        if not verify_totp(secret, body.mfa_code):
            repo.create_audit_event(
                db,
                actor=user.email,
                action="login_failed",
                target=user.email,
                decision="DENIED",
                reason="invalid mfa",
            )
            raise HTTPException(status_code=401, detail="invalid mfa")

    pair = create_session(db, user, ip_address=ip, user_agent=ua)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()
    _set_refresh_cookie(response, pair.refresh_token, pair.refresh_expires_in)
    repo.create_audit_event(
        db,
        actor=user.email,
        action="login_success",
        target=str(user.id),
        decision="ALLOWED",
        reason="login",
    )
    return {
        "access_token": pair.access_token,
        "token_type": "bearer",
        "expires_in": pair.access_expires_in,
        "role": user.role,
        "email": user.email,
        "mfa_enabled": user.mfa_enabled,
    }


@router.post("/refresh")
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(REFRESH_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail="missing refresh cookie")
    ip, ua = _client_meta(request)
    try:
        pair = rotate_refresh(db, token, ip_address=ip, user_agent=ua)
    except ValueError:
        _clear_refresh_cookie(response)
        raise HTTPException(status_code=401, detail="invalid refresh") from None
    _set_refresh_cookie(response, pair.refresh_token, pair.refresh_expires_in)
    return {
        "access_token": pair.access_token,
        "token_type": "bearer",
        "expires_in": pair.access_expires_in,
    }


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    auth = request.headers.get("authorization", "")
    actor = "unknown"
    if auth.lower().startswith("bearer "):
        try:
            claims = decode_token(auth.split(" ", 1)[1])
            actor = claims.get("email", "unknown")
            sid = claims.get("sid")
            if sid:
                revoke_session(db, UUID(sid))
        except ValueError:
            pass
    refresh = request.cookies.get(REFRESH_COOKIE)
    if refresh:
        from bluestrix.core.models_db import AuthSession

        row = db.scalar(
            select(AuthSession).where(AuthSession.refresh_token_hash == hash_token(refresh))
        )
        if row:
            revoke_session(db, row.id)
    _clear_refresh_cookie(response)
    repo.create_audit_event(
        db, actor=actor, action="logout", target=actor, decision="ALLOWED", reason="logout"
    )
    return {"status": "logged_out"}


@router.get("/session")
def session_info(request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    try:
        claims = decode_token(auth.split(" ", 1)[1])
    except ValueError:
        raise HTTPException(status_code=401, detail="invalid token") from None
    user = db.get(User, UUID(claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="inactive")
    return {
        "email": user.email,
        "role": user.role,
        "mfa_enabled": user.mfa_enabled,
        "session_id": claims.get("sid"),
    }


@router.post("/password-reset/request")
def password_reset_request(
    body: PasswordResetRequest, request: Request, db: Session = Depends(get_db)
):
    allowed, retry = check_rate_limit(
        f"pwreset:{body.email.lower()}", limit=3, window_seconds=600
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=f"rate limited; retry in {retry}s")
    user = db.scalar(select(User).where(User.email == body.email.lower()))
    # Always generic response (no user enumeration)
    if user:
        raw = generate_token(32)
        row = PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(raw),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        db.add(row)
        db.commit()
        repo.create_audit_event(
            db,
            actor=user.email,
            action="password_reset_requested",
            target=str(user.id),
            decision="ALLOWED",
            reason="token issued",
        )
        # Production: send email. Dev returns token only when BLUESTRIX_DEV_RETURN_RESET_TOKEN=1
        import os

        if os.getenv("BLUESTRIX_DEV_RETURN_RESET_TOKEN") == "1":
            return {"status": "ok", "dev_token": raw}
    return {"status": "ok"}


@router.post("/password-reset/confirm")
def password_reset_confirm(body: PasswordResetConfirm, db: Session = Depends(get_db)):
    th = hash_token(body.token)
    row = db.scalar(select(PasswordResetToken).where(PasswordResetToken.token_hash == th))
    if row is None or row.used_at is not None:
        raise HTTPException(status_code=400, detail="invalid token")
    if row.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="token expired")
    user = db.get(User, row.user_id)
    if user is None:
        raise HTTPException(status_code=400, detail="invalid token")
    user.password_hash = hash_password(body.new_password)
    row.used_at = datetime.now(timezone.utc)
    db.commit()
    revoke_all_sessions(db, user.id)
    repo.create_audit_event(
        db,
        actor=user.email,
        action="password_reset_completed",
        target=str(user.id),
        decision="ALLOWED",
        reason="password updated; sessions revoked",
    )
    return {"status": "password_updated"}


@router.post("/mfa/setup")
def mfa_setup(body: MfaEnableRequest, request: Request, db: Session = Depends(get_db)):
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="unauthorized")
    claims = decode_token(auth.split(" ", 1)[1])
    user = db.get(User, UUID(claims["sub"]))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid password")
    secret = generate_totp_secret()
    codes = generate_recovery_codes()
    user.mfa_secret_encrypted = encrypt_secret(secret)
    user.mfa_recovery_hashes = hash_recovery_codes(codes)
    user.mfa_enabled = False  # enable after verify
    db.commit()
    repo.create_audit_event(
        db,
        actor=user.email,
        action="mfa_enabled",
        target=str(user.id),
        decision="PENDING_VERIFY",
        reason="secret issued",
    )
    return {
        "totp_secret": secret,
        "recovery_codes": codes,
        "note": "Store recovery codes offline. Confirm with /auth/mfa/verify",
    }


@router.post("/mfa/verify")
def mfa_verify(body: MfaVerifyRequest, request: Request, db: Session = Depends(get_db)):
    allowed, retry = check_rate_limit(
        f"mfa:{request.client.host if request.client else 'x'}", limit=10, window_seconds=300
    )
    if not allowed:
        raise HTTPException(status_code=429, detail=f"rate limited; retry in {retry}s")
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="unauthorized")
    claims = decode_token(auth.split(" ", 1)[1])
    user = db.get(User, UUID(claims["sub"]))
    if user is None or not user.mfa_secret_encrypted:
        raise HTTPException(status_code=400, detail="mfa not setup")
    if not verify_totp(decrypt_secret(user.mfa_secret_encrypted), body.code):
        raise HTTPException(status_code=401, detail="invalid code")
    user.mfa_enabled = True
    db.commit()
    repo.create_audit_event(
        db,
        actor=user.email,
        action="mfa_enabled",
        target=str(user.id),
        decision="ALLOWED",
        reason="totp verified",
    )
    return {"mfa_enabled": True}
