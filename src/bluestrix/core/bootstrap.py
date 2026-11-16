"""Server-side bootstrap for the first admin's MFA.

The login route requires an MFA code for admins, and /auth/mfa/setup requires a login token.
That loop leaves the first admin unable to enable MFA. This module breaks the loop by issuing
the TOTP secret from the server console, where the operator already has trust. It never runs
over the network.
"""

from __future__ import annotations

from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from bluestrix.core import repository as repo
from bluestrix.core.exceptions import BlueStrixError
from bluestrix.core.mfa import (
    encrypt_secret,
    generate_recovery_codes,
    generate_totp_secret,
    hash_recovery_codes,
)
from bluestrix.core.models_db import User

ISSUER = "BlueStrix"


def build_otpauth_uri(email: str, secret_b32: str) -> str:
    label = quote(f"{ISSUER}:{email}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(ISSUER)}"


def bootstrap_admin_mfa(db: Session, email: str, *, force: bool = False) -> dict[str, object]:
    """Issue a TOTP secret and recovery codes for an existing admin.

    Returns the secret, otpauth URI, and recovery codes. They are shown once and not stored in
    plaintext. Only the encrypted secret and hashed recovery codes are saved.
    """
    user = db.scalar(select(User).where(User.email == email.lower().strip()))
    if user is None:
        raise BlueStrixError("no user with that email")
    if user.role != "admin":
        raise BlueStrixError("bootstrap is only for admin accounts")
    if user.mfa_enabled and not force:
        raise BlueStrixError("MFA is already enabled; pass --force to reset it")

    secret = generate_totp_secret()
    codes = generate_recovery_codes()
    user.mfa_secret_encrypted = encrypt_secret(secret)
    user.mfa_recovery_hashes = hash_recovery_codes(codes)
    user.mfa_enabled = True
    db.commit()

    repo.create_audit_event(
        db,
        actor="cli",
        action="mfa_bootstrap",
        target=str(user.id),
        decision="ALLOWED",
        reason="admin MFA issued from server console" + (" (reset)" if force else ""),
    )
    return {
        "email": user.email,
        "totp_secret": secret,
        "otpauth_uri": build_otpauth_uri(user.email, secret),
        "recovery_codes": codes,
        "note": "Shown once. Add the secret to an authenticator app and store recovery codes offline.",
    }
