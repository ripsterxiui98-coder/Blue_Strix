"""Rule-pack integrity: verify HMAC signatures. Private keys are never stored."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Optional


def canonical_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def sign_payload(payload: dict[str, Any], secret: str) -> str:
    """Create HMAC-SHA256 hex digest. Caller supplies secret from env — never commit it."""
    if not secret:
        raise ValueError("signing secret required")
    return hmac.new(secret.encode("utf-8"), canonical_bytes(payload), hashlib.sha256).hexdigest()


def verify_hmac(payload: dict[str, Any], signature: str, secret: str) -> bool:
    if not secret or not signature:
        return False
    expected = sign_payload(payload, secret)
    return hmac.compare_digest(expected, signature.strip().lower())


def verify_rule_pack_signature(
    manifest: dict[str, Any],
    *,
    signature: Optional[str] = None,
    secret: Optional[str] = None,
    require_signature: bool = False,
) -> bool:
    """Verify community/custom pack signature.

    - secret from BLUESTRIX_RULE_PACK_HMAC (env) or argument
    - if require_signature and no valid sig → False
    - unsigned local custom packs allowed when require_signature is False
    """
    sig = signature or manifest.get("signature") or manifest.get("hmac")
    key = secret if secret is not None else os.getenv("BLUESTRIX_RULE_PACK_HMAC", "")
    body = {k: v for k, v in manifest.items() if k not in {"signature", "hmac"}}

    if not sig:
        return not require_signature
    if not key:
        return False
    return verify_hmac(body, str(sig), key)
