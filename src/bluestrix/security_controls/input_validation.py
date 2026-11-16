from __future__ import annotations

import re
from urllib.parse import urlparse

EVM_ADDRESS = re.compile(r"^0x[a-fA-F0-9]{40}$")
SOLANA_ADDRESS = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")


class InputValidator:
    """Centralized validation and sanitization."""

    def clean_text(self, value: str, max_length: int = 1024) -> str:
        if not isinstance(value, str):
            raise ValueError("Expected text input")
        return value.strip()[:max_length]

    def truncate(self, value: str, max_length: int = 240) -> str:
        value = self.clean_text(value, max_length * 4)
        return value if len(value) <= max_length else value[: max_length - 3] + "..."

    def redact(self, value: str) -> str:
        value = self.clean_text(value, 512)
        if len(value) <= 8:
            return "[REDACTED]"
        return f"{value[:4]}...{value[-4:]} [REDACTED]"

    def validate_http_url(self, url: str) -> str:
        url = self.clean_text(url, 2048)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("URL must use HTTP or HTTPS")
        if not parsed.hostname:
            raise ValueError("URL must contain a hostname")
        if parsed.username or parsed.password:
            raise ValueError("URL credentials are not permitted")
        return url

    def validate_evm_address(self, address: str) -> str:
        address = self.clean_text(address, 64)
        if not EVM_ADDRESS.match(address):
            raise ValueError("Invalid EVM address format")
        return address

    def validate_solana_address(self, address: str) -> str:
        address = self.clean_text(address, 64)
        if not SOLANA_ADDRESS.match(address):
            raise ValueError("Invalid Solana address format")
        return address

    def is_probable_blockchain_address(self, address: str) -> bool:
        address = self.clean_text(address, 64)
        return bool(EVM_ADDRESS.match(address) or SOLANA_ADDRESS.match(address))

    def validate_identifier(self, identifier: str) -> str:
        identifier = self.clean_text(identifier, 256)
        if not SAFE_IDENTIFIER.match(identifier):
            raise ValueError("Identifier contains unsupported characters")
        return identifier

    def validate_path_within_root(self, path: str, root: str = ".") -> str:
        from pathlib import Path

        root_path = Path(root).expanduser().resolve()
        candidate = Path(path).expanduser().resolve()
        try:
            candidate.relative_to(root_path)
        except ValueError as exc:
            raise ValueError("Path escapes authorized root") from exc
        return str(candidate)

    def validate_cli_arguments(self, arguments: list[str]) -> list[str]:
        allowed_flags = {
            "--checklist", "--print", "--detect", "--exclude",
            "--solc", "--solc-args", "--legacy-ast", "--skip-assembly",
        }
        validated = []
        for argument in arguments:
            argument = self.clean_text(str(argument), 256)
            if argument.startswith("--"):
                flag = argument.split("=", 1)[0]
                if flag not in allowed_flags:
                    raise ValueError(f"CLI flag is not allowed: {flag}")
            validated.append(argument)
        return validated
