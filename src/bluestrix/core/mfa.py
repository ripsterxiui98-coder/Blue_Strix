"""TOTP MFA helpers. Secrets are encrypted at rest via security.encrypt_mfa_secret."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from typing import Iterable, Optional

from bluestrix.core.security import decrypt_mfa_secret, encrypt_mfa_secret, generate_token, hash_token


def generate_totp_secret() -> str:
    return base64.b32encode(generate_token(20).encode("utf-8")[:20]).decode("ascii").rstrip("=")


def _totp(secret_b32: str, timestep: Optional[int] = None, digits: int = 6) -> str:
    # Pad base32
    pad = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + pad, casefold=True)
    counter = int(time.time() // 30) if timestep is None else timestep
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1) -> bool:
    if not code or not code.isdigit():
        return False
    now = int(time.time() // 30)
    for delta in range(-window, window + 1):
        if hmac.compare_digest(_totp(secret_b32, now + delta), code.strip()):
            return True
    return False


def encrypt_secret(secret_b32: str) -> str:
    return encrypt_mfa_secret(secret_b32)


def decrypt_secret(blob: str) -> str:
    return decrypt_mfa_secret(blob)


def generate_recovery_codes(n: int = 8) -> list[str]:
    return [generate_token(8) for _ in range(n)]


def hash_recovery_codes(codes: Iterable[str]) -> list[str]:
    return [hash_token(c) for c in codes]


def consume_recovery_code(code: str, hashed_codes: list[str]) -> list[str] | None:
    """Return remaining hashes after consuming ``code``, or None if not found.

    Callers must persist the returned list in the same DB transaction that
    grants access, so concurrent requests cannot both succeed on the same code.
    Comparison uses hmac.compare_digest via membership of pre-hashed values.
    """
    if not code or not hashed_codes:
        return None
    h = hash_token(code.strip())
    if h not in hashed_codes:
        return None
    return [c for c in hashed_codes if c != h]
