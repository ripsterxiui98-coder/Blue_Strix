from __future__ import annotations

import re

from bluestrix.core.models import CheckStatus, Evidence, Finding, Severity
from bluestrix.security_controls.input_validation import InputValidator

EVM_ADDRESS = re.compile(r"^0x[a-fA-F0-9]{40}$")
SOLANA_ADDRESS = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
PRIVATE_KEY_PATTERN = re.compile(r"(?i)(private[_ -]?key|seed[_ -]?phrase|mnemonic|recover[yY][_ -]?phrase)")


class AssetProtectionEngine:
    def __init__(self) -> None:
        self.validator = InputValidator()

    def analyze_address(self, address: str, chain: str) -> Finding:
        address = self.validator.clean_text(address, 128)
        chain = self.validator.clean_text(chain, 32).lower()

        if chain in {"evm", "ethereum", "bnb", "polygon", "arbitrum", "base", "optimism"}:
            valid = bool(EVM_ADDRESS.match(address))
        elif chain == "solana":
            valid = bool(SOLANA_ADDRESS.match(address))
        else:
            raise ValueError(f"Unsupported chain: {chain}")

        return Finding(
            title=f"{chain.upper()} address format check",
            description="Validates address format without accessing balances or private keys.",
            severity=Severity.INFO if valid else Severity.MEDIUM,
            status=CheckStatus.PASS if valid else CheckStatus.FAIL,
            category="asset_protection",
            target=address,
            evidence=[Evidence(source="address_validator", kind="format_check", value=valid)],
            recommendation="Address format valid." if valid else "Verify address before interaction.",
            confidence=0.99 if valid else 0.9,
        )

    def scan_text_for_secrets(self, text: str, source: str = "inline_text") -> list[Finding]:
        findings = []
        text = self.validator.clean_text(text, 1_000_000)
        for match in PRIVATE_KEY_PATTERN.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(Finding(
                title="Potential sensitive credential reference",
                description="Text contains terminology associated with private keys or recovery phrases.",
                severity=Severity.CRITICAL,
                status=CheckStatus.FAIL,
                category="secret_exposure",
                target=source,
                evidence=[Evidence(source="secret_scanner", kind="keyword_match",
                                   value=self.validator.redact(match.group(0)),
                                   location=f"{source}:{line}")],
                recommendation="Never store private keys or seed phrases in code or logs.",
                confidence=0.75,
            ))
        return findings
