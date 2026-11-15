from __future__ import annotations

from typing import Any

from bluestrix.core.models import CheckStatus, Evidence, Finding, Severity
from bluestrix.integrations.http_client import SafeHttpClient
from bluestrix.security_controls.input_validation import InputValidator


class EVMProtocolInspector:
    def __init__(self, rpc_url: str, timeout_seconds: int = 15) -> None:
        self.validator = InputValidator()
        self.rpc_url = self.validator.validate_http_url(rpc_url)
        self.client = SafeHttpClient(timeout_seconds=timeout_seconds)

    def _rpc(self, method: str, params: list[Any]) -> dict[str, Any]:
        if not method.startswith("eth_"):
            raise ValueError("Only eth_* read methods are permitted")
        payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        response = self.client.post_json(self.rpc_url, payload)
        if "error" in response:
            raise RuntimeError(f"RPC error: {response['error']}")
        return response

    def inspect_address(self, address: str) -> Finding:
        address = self.validator.validate_evm_address(address)
        result = self._rpc("eth_getCode", [address, "latest"])
        code = str(result.get("result", "0x"))
        is_contract = bool(code and code != "0x")
        return Finding(
            title="EVM address inspection",
            description="Determines whether address contains bytecode.",
            severity=Severity.INFO,
            status=CheckStatus.PASS,
            category="protocol_protection",
            target=address,
            evidence=[Evidence(source="evm_rpc", kind="eth_getCode", value={"is_contract": is_contract})],
            recommendation="Review contract if bytecode found." if is_contract else "EOA or no bytecode.",
            metadata={"is_contract": is_contract},
        )
