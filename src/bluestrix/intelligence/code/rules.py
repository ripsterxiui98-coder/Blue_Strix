from __future__ import annotations

from dataclasses import dataclass
from bluestrix.core.models import Severity


@dataclass(frozen=True)
class CodeRule:
    rule_id: str
    title: str
    description: str
    pattern: str
    severity: Severity
    language: str
    recommendation: str
    references: tuple[str, ...] = ()
    cwe_id: str | None = None


SOLIDITY_RULES = (
    CodeRule("BSX-SOL-001", "Potential unrestricted low-level call",
             "Low-level call may return success even when callee reverts.",
             r"\.call\{value:", Severity.HIGH, "solidity",
             "Prefer typed interfaces and validate return data.",
             ("https://docs.soliditylang.org/en/latest/security-considerations.html",), "CWE-20"),
    CodeRule("BSX-SOL-002", "Potential delegatecall usage",
             "delegatecall executes callee logic in caller storage context.",
             r"\.delegatecall\(", Severity.HIGH, "solidity",
             "Restrict delegatecall to audited implementations.", (), "CWE-284"),
    CodeRule("BSX-SOL-003", "Potential selfdestruct usage",
             "selfdestruct is high-impact lifecycle operation.",
             r"\bselfdestruct\s*\(", Severity.HIGH, "solidity",
             "Remove selfdestruct unless necessary.", (), "CWE-284"),
    CodeRule("BSX-SOL-004", "Potential tx.origin authorization",
             "Authorization based on tx.origin can be abused.",
             r"tx\.origin\s*==", Severity.HIGH, "solidity",
             "Use msg.sender instead of tx.origin.", (), "CWE-290"),
    CodeRule("BSX-SOL-005", "Potential unbounded loop",
             "Unbounded loop may cause gas exhaustion.",
             r"for\s*\(.*;\s*.*<\s*(?:users|accounts|depositors|holders)\b",
             Severity.MEDIUM, "solidity",
             "Use pagination or pull-based pattern.", (), "CWE-400"),
)

RUST_RULES = (
    CodeRule("BSX-RS-001", "Potential unsafe Rust block",
             "Unsafe Rust bypasses safety guarantees.",
             r"\bunsafe\s*\{", Severity.MEDIUM, "rust",
             "Minimize unsafe scope and add tests.", (), "CWE-787"),
    CodeRule("BSX-RS-002", "Potential unwrap on fallible operation",
             "unwrap may panic.",
             r"\.unwrap\(\)", Severity.LOW, "rust",
             "Handle errors explicitly.", (), "CWE-754"),
)

MOVE_RULES = (
    CodeRule("BSX-MV-001", "Potential generic abort",
             "Generic abort makes failures hard to diagnose.",
             r"\babort\s+0\b", Severity.LOW, "move",
             "Use descriptive error codes.", (), None),
)

TYPESCRIPT_RULES = (
    CodeRule("BSX-TS-001", "Potential eval usage",
             "eval can execute untrusted input.",
             r"\beval\s*\(", Severity.HIGH, "typescript",
             "Remove eval.", (), "CWE-95"),
    CodeRule("BSX-TS-002", "Potential hardcoded secret",
             "Likely secret embedded in source.",
             r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
             Severity.HIGH, "typescript",
             "Move secrets to environment variable.", (), "CWE-798"),
)

PYTHON_RULES = (
    CodeRule("BSX-PY-001", "Potential hardcoded secret",
             "Likely secret embedded in source.",
             r"(?i)(api[_-]?key|secret|password|token)\s*=\s*[\"'][^\"']{8,}[\"']",
             Severity.HIGH, "python",
             "Move secrets to environment variable.", (), "CWE-798"),
    CodeRule("BSX-PY-002", "Potential unsafe deserialization",
             "Pickle can execute attacker-controlled code.",
             r"\bpickle\.loads?\s*\(", Severity.HIGH, "python",
             "Use JSON or schema-validated format.", (), "CWE-502"),
    CodeRule("BSX-PY-003", "Potential shell injection",
             "Passing untrusted input to shell can enable injection.",
             r"\bos\.system\s*\(|\bsubprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True",
             Severity.HIGH, "python",
             "Avoid shell=True.", (), "CWE-78"),
)

RULES_BY_LANGUAGE = {
    "solidity": SOLIDITY_RULES,
    "rust": RUST_RULES,
    "move": MOVE_RULES,
    "typescript": TYPESCRIPT_RULES,
    "python": PYTHON_RULES,
}

LANGUAGE_EXTENSIONS = {
    ".sol": "solidity",
    ".rs": "rust",
    ".move": "move",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
}
