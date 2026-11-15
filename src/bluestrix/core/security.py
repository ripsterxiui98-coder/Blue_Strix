"""Password hashing and token helpers. Never store plaintext secrets."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional

# Prefer argon2; fall back to bcrypt; then PBKDF2-HMAC-SHA256 for tests without extras.


def _pbkdf2_hash(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return "pbkdf2$" + base64.b64encode(salt + dk).decode("ascii")


def _pbkdf2_verify(password: str, encoded: str) -> bool:
    try:
        raw = base64.b64decode(encoded.split("$", 1)[1].encode("ascii"))
        salt, expected = raw[:16], raw[16:]
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def hash_password(password: str) -> str:
    if not password or len(password) < 10:
        raise ValueError("Password must be at least 10 characters")
    try:
        from argon2 import PasswordHasher

        return "argon2$" + PasswordHasher().hash(password)
    except ImportError:
        pass
    try:
        import bcrypt

        return "bcrypt$" + bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("ascii")
    except ImportError:
        return _pbkdf2_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    if password_hash.startswith("argon2$"):
        try:
            from argon2 import PasswordHasher
            from argon2.exceptions import VerifyMismatchError

            try:
                PasswordHasher().verify(password_hash[7:], password)
                return True
            except VerifyMismatchError:
                return False
        except ImportError:
            return False
    if password_hash.startswith("bcrypt$"):
        try:
            import bcrypt

            return bcrypt.checkpw(password.encode("utf-8"), password_hash[7:].encode("ascii"))
        except ImportError:
            return False
    if password_hash.startswith("pbkdf2$"):
        return _pbkdf2_verify(password, password_hash)
    return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def get_jwt_secret() -> str:
    secret = os.getenv("BLUESTRIX_JWT_SECRET") or os.getenv("NEXTAUTH_SECRET")
    if not secret or secret in {"change-me", "change-me-generate-a-long-random-string"}:
        # Dev-only ephemeral secret — production MUST set BLUESTRIX_JWT_SECRET
        return os.getenv("BLUESTRIX_DEV_JWT_SECRET", secrets.token_hex(32))
    return secret


def get_mfa_fernet_key() -> bytes:
    """Derive a 32-byte key for encrypting MFA secrets (not stored plaintext)."""
    material = os.getenv("BLUESTRIX_MFA_KEY") or get_jwt_secret()
    return hashlib.sha256(material.encode("utf-8")).digest()


def encrypt_mfa_secret(secret: str) -> str:
    key = get_mfa_fernet_key()
    # Simple XOR+HMAC envelope without requiring cryptography package
    nonce = secrets.token_bytes(16)
    data = secret.encode("utf-8")
    stream = hashlib.sha256(key + nonce).digest()
    while len(stream) < len(data):
        stream += hashlib.sha256(stream).digest()
    cipher = bytes(a ^ b for a, b in zip(data, stream))
    tag = hmac.new(key, nonce + cipher, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(nonce + tag + cipher).decode("ascii")


def decrypt_mfa_secret(blob: str) -> str:
    key = get_mfa_fernet_key()
    raw = base64.urlsafe_b64decode(blob.encode("ascii"))
    nonce, tag, cipher = raw[:16], raw[16:32], raw[32:]
    expect = hmac.new(key, nonce + cipher, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expect):
        raise ValueError("Invalid MFA secret envelope")
    stream = hashlib.sha256(key + nonce).digest()
    while len(stream) < len(cipher):
        stream += hashlib.sha256(stream).digest()
    data = bytes(a ^ b for a, b in zip(cipher, stream))
    return data.decode("utf-8")
