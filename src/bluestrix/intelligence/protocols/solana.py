from __future__ import annotations

from typing import Any

from bluestrix.core.models import CheckStatus, Evidence, Finding, Severity
from bluestrix.integrations.http_client import SafeHttpClient
from bluestrix.security_controls.input_validation import InputValidator


class SolanaProtocolInspector:
    ALLOWED_METHODS = {"getAccountInfo", "getBalance", "getBlockHeight", "getVersion"}

    def __init__(self, rpc_url: str, timeout_seconds: int = 15) -> None:
        self.validator = InputValidator()
        self.rpc_url = self.validator.validate_http_url(rpc_url)
        self.client = SafeHttpClient(timeout_seconds=timeout_seconds)

    def _rpc(self, method: str, params: list[Any]) -> dict[str, Any]:
        if method not in self.ALLOWED_METHODS:
            raise ValueError(f"RPC method not allowed: {method}")
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        response = self.client.post_json(self.rpc_url, payload)
        if "error" in response:
            raise RuntimeError(f"Solana RPC error: {response['error']}")
        return response

    def inspect_account(self, address: str) -> Finding:
        address = self.validator.validate_solana_address(address)
        response = self._rpc("getAccountInfo", [address, {"encoding": "base64", "commitment": "confirmed"}])
        value = response.get("result", {}).get("value")
        exists = value is not None
        return Finding(
            title="Solana account inspection",
            description="Read-only inspection of account.",
            severity=Severity.INFO,
            status=CheckStatus.PASS if exists else CheckStatus.INCOMPLETE,
            category="protocol_protection",
            target=address,
            evidence=[Evidence(source="solana_rpc", kind="getAccountInfo", value={"exists": exists})],
            recommendation="Validate owning program." if exists else "Account not found.",
            metadata={"exists": exists},
        )
