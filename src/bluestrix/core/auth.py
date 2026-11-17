"""JWT access/refresh session management. Tokens stored only as hashes."""

from __future__ import annotations

import json
import base64
import hashlib
import hmac
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from bluestrix.core.models_db import AuthSession, User
from bluestrix.core.security import generate_token, get_jwt_secret, hash_token, verify_password

ACCESS_TTL_SECONDS = 15 * 60
REFRESH_TTL_SECONDS = 30 * 24 * 3600
ENROLLMENT_TTL_SECONDS = 10 * 60  # short-lived MFA enrollment only

ROLES = {"admin", "security_analyst", "protocol_owner", "incident_responder"}

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_ENROLL = "mfa_enroll"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _sign(payload: dict[str, Any], ttl: int) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    body = {**payload, "iat": now, "exp": now + ttl}
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(body, separators=(",", ":")).encode())
    sig = hmac.new(get_jwt_secret().encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def decode_token(token: str) -> dict[str, Any]:
    """Verify signature and expiry. Does not check session revocation."""
    try:
        h, p, s = token.split(".")
        expect = hmac.new(get_jwt_secret().encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expect, _b64url_decode(s)):
            raise ValueError("bad signature")
        body = json.loads(_b64url_decode(p))
        if int(body.get("exp", 0)) < int(time.time()):
            raise ValueError("expired")
        return body
    except Exception as exc:
        raise ValueError("invalid token") from exc


def resolve_access_claims(
    session: Session,
    token: str,
    *,
    allowed_types: frozenset[str] | set[str] | None = None,
) -> tuple[dict[str, Any], User, Optional[AuthSession]]:
    """Decode token, enforce type, and validate DB session when present.

    Full access tokens must carry typ=access and a non-revoked session (sid).
    Enrollment tokens (typ=mfa_enroll) have no sid and must not be used on data routes.
    """
    if allowed_types is None:
        allowed_types = frozenset({TOKEN_TYPE_ACCESS})
    claims = decode_token(token)
    typ = claims.get("typ")
    if typ not in allowed_types:
        raise ValueError("wrong token type")
    user = session.get(User, uuid.UUID(str(claims["sub"])))
    if user is None or not user.is_active:
        raise ValueError("user inactive")

    auth_session: Optional[AuthSession] = None
    sid = claims.get("sid")
    if typ == TOKEN_TYPE_ACCESS:
        if not sid:
            raise ValueError("missing session")
        auth_session = session.get(AuthSession, uuid.UUID(str(sid)))
        if auth_session is None or auth_session.revoked_at is not None:
            raise ValueError("session revoked")
        expires = auth_session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < datetime.now(timezone.utc):
            raise ValueError("session expired")
        if auth_session.user_id != user.id:
            raise ValueError("session mismatch")
    elif typ == TOKEN_TYPE_ENROLL:
        # Enrollment tokens must not reference a full session.
        if sid:
            raise ValueError("enrollment token must not carry sid")
    return claims, user, auth_session


@dataclass
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_in: int
    refresh_expires_in: int
    session_id: uuid.UUID


def create_session(
    session: Session,
    user: User,
    *,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> TokenPair:
    refresh = generate_token(48)
    auth_session = AuthSession(
        user_id=user.id,
        refresh_token_hash=hash_token(refresh),
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=REFRESH_TTL_SECONDS),
        ip_address=ip_address,
        user_agent=(user_agent or "")[:512] or None,
    )
    session.add(auth_session)
    session.commit()
    session.refresh(auth_session)
    access = _sign(
        {
            "sub": str(user.id),
            "email": user.email,
            "role": user.role,
            "sid": str(auth_session.id),
            "typ": TOKEN_TYPE_ACCESS,
        },
        ACCESS_TTL_SECONDS,
    )
    return TokenPair(
        access_token=access,
        refresh_token=refresh,
        access_expires_in=ACCESS_TTL_SECONDS,
        refresh_expires_in=REFRESH_TTL_SECONDS,
        session_id=auth_session.id,
    )


def create_enrollment_token(user: User) -> tuple[str, int]:
    """Short-lived token that only unlocks MFA setup/verify endpoints."""
    token = _sign(
        {
            "sub": str(user.id),
            "email": user.email,
            "role": user.role,
            "typ": TOKEN_TYPE_ENROLL,
            "purpose": "mfa_enrollment",
        },
        ENROLLMENT_TTL_SECONDS,
    )
    return token, ENROLLMENT_TTL_SECONDS


def rotate_refresh(
    session: Session,
    refresh_token: str,
    *,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> TokenPair:
    th = hash_token(refresh_token)
    row = session.scalar(select(AuthSession).where(AuthSession.refresh_token_hash == th))
    if row is None or row.revoked_at is not None:
        raise ValueError("invalid refresh token")
    if row.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise ValueError("refresh expired")
    user = session.get(User, row.user_id)
    if user is None or not user.is_active:
        raise ValueError("user inactive")
    # revoke old
    row.revoked_at = datetime.now(timezone.utc)
    session.commit()
    return create_session(session, user, ip_address=ip_address, user_agent=user_agent)


def revoke_session(session: Session, session_id: uuid.UUID) -> bool:
    row = session.get(AuthSession, session_id)
    if row is None:
        return False
    row.revoked_at = datetime.now(timezone.utc)
    session.commit()
    return True


def revoke_all_sessions(session: Session, user_id: uuid.UUID) -> int:
    rows = session.scalars(
        select(AuthSession).where(
            AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None)
        )
    ).all()
    now = datetime.now(timezone.utc)
    for r in rows:
        r.revoked_at = now
    session.commit()
    return len(rows)


def authenticate_user(session: Session, email: str, password: str) -> Optional[User]:
    user = session.scalar(select(User).where(User.email == email.lower().strip()))
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user
