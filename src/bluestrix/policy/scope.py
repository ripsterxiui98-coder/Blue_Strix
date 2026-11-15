from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from bluestrix.core.audit import AuditLog
from bluestrix.core.exceptions import ScopeViolationError
from bluestrix.core.models import AuditEvent


class ScopeEnforcer:
    """Deny-by-default scope enforcement."""

    def __init__(self, scope_config: dict[str, Any], audit_log: AuditLog | None = None) -> None:
        self.scope_config = scope_config
        self.audit_log = audit_log or AuditLog()
        self.authorized = scope_config.get("authorized_targets", {})
        self.default_action = scope_config.get("default_action", "deny")

    def is_authorized(self, target: str) -> bool:
        if self.default_action != "deny":
            return False
        return (
            self._matches_domain(target)
            or self._matches_ip(target)
            or self._matches_address(target, "evm_addresses")
            or self._matches_address(target, "solana_addresses")
            or self._matches_path(target)
        )

    def enforce(self, target: str, action: str = "access") -> None:
        allowed = self.is_authorized(target)
        self.audit_log.record(
            action=action,
            target=target,
            decision="ALLOWED" if allowed else "BLOCKED",
            reason="Target is within authorized scope" if allowed else "Target is outside authorized scope",
        )

        if not allowed:
            raise ScopeViolationError(f"Target is not authorized: {target}")

    def _matches_domain(self, target: str) -> bool:
        allowed = {d.lower() for d in self.authorized.get("domains", [])}
        hostname = urlparse(target).hostname or target
        return hostname.lower() in allowed

    def _matches_ip(self, target: str) -> bool:
        allowed = self.authorized.get("ipv4_cidrs", [])
        try:
            address = ipaddress.ip_address(target.split("/")[0])
        except ValueError:
            return False
        for cidr in allowed:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _matches_address(self, target: str, key: str) -> bool:
        allowed = {item.lower() for item in self.authorized.get(key, [])}
        return target.lower() in allowed

    def _matches_path(self, target: str) -> bool:
        candidate = Path(target).resolve()
        for root in self.authorized.get("repository_paths", []):
            allowed_root = Path(root).resolve()
            try:
                candidate.relative_to(allowed_root)
                return True
            except ValueError:
                continue
        return False
