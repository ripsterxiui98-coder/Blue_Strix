"""Password hashing and token helpers. Never store plaintext secrets."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional

# Prefer argon2; fall back to bcrypt; then PBKDF2-HMAC-SHA256 for tests without extras.

# Placeholders that must never be used as real secrets.
_PLACEHOLDER_SECRETS = frozenset(
    {
        "",
        "change-me",
        "change-me-generate-a-long-random-string",
        "changeme",
        "secret",
        "jwt-secret",
    }
)

# Process-stable development fallback (generated once per process, not per request).
_DEV_JWT_SECRET: Optional[str] = None

# Deterministic secret used only when BLUESTRIX_ENV=test.
_TEST_JWT_SECRET = "test-only-jwt-secret-do-not-use-in-prod-32b"


def _env_name() -> str:
    """Return normalized environment name.

    Unset or unknown values are treated as production (fail-secure).
    Only explicit development/test enable softer rules.
    """
    raw = (os.getenv("BLUESTRIX_ENV") or "").strip().lower()
    if raw in {"development", "dev"}:
        return "development"
    if raw in {"test", "testing"}:
        return "test"
    # production, empty, or anything else → production rules
    return "production"


def _is_placeholder(value: Optional[str]) -> bool:
    if value is None:
        return True
    v = value.strip()
    if not v:
        return True
    if v.lower() in _PLACEHOLDER_SECRETS:
        return True
    return False


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
    """Return the HMAC secret for JWT signing.

    Required env vars (see .env.example):
      BLUESTRIX_JWT_SECRET  — primary (preferred)
      NEXTAUTH_SECRET       — accepted fallback for shared deployments
      BLUESTRIX_MFA_KEY     — separate material for MFA encryption (optional)
      BLUESTRIX_ENV         — development | test | production

    Behaviour:
      - production (default for unset/unknown): rejects empty or placeholder secrets
        at call time with RuntimeError (startup should call validate_secrets_or_die).
      - development: process-stable ephemeral secret if none configured
        (changes on restart; differs across workers — not for multi-worker prod).
      - test: deterministic fixed secret for reproducible tests.

    Changing the secret invalidates all existing access tokens immediately.
    """
    env = _env_name()
    secret = os.getenv("BLUESTRIX_JWT_SECRET") or os.getenv("NEXTAUTH_SECRET")

    if env == "test":
        if secret and not _is_placeholder(secret):
            return secret
        return os.getenv("BLUESTRIX_DEV_JWT_SECRET") or _TEST_JWT_SECRET

    if secret and not _is_placeholder(secret):
        return secret

    if env == "production":
        raise RuntimeError(
            "BLUESTRIX_JWT_SECRET (or NEXTAUTH_SECRET) must be set to a non-placeholder "
            "value in production. Generate with: python3 -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )

    # development only: process-stable fallback (once per process, not per request)
    global _DEV_JWT_SECRET
    explicit_dev = os.getenv("BLUESTRIX_DEV_JWT_SECRET")
    if explicit_dev and not _is_placeholder(explicit_dev):
        return explicit_dev
    if _DEV_JWT_SECRET is None:
        _DEV_JWT_SECRET = secrets.token_hex(32)
    return _DEV_JWT_SECRET


def validate_secrets_or_die() -> None:
    """Call at application startup. Production refuses to start with bad secrets."""
    env = _env_name()
    if env != "production":
        # Touch once so development caches a stable secret early.
        get_jwt_secret()
        return
    # Force evaluation — raises RuntimeError if missing/placeholder.
    get_jwt_secret()
    mfa = os.getenv("BLUESTRIX_MFA_KEY")
    if mfa is not None and _is_placeholder(mfa):
        raise RuntimeError(
            "BLUESTRIX_MFA_KEY is set to a placeholder; unset it or provide a strong value."
        )


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
