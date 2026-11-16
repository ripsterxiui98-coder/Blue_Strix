"""Evidence-based risk scoring for findings and assets (read-only)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional, Sequence

SEVERITY_SCORE = {
    "INFO": 0.1,
    "LOW": 0.25,
    "MEDIUM": 0.5,
    "HIGH": 0.75,
    "CRITICAL": 1.0,
}

# Weights sum to 1.0 — defensive prioritization, not exploit tooling
DEFAULT_WEIGHTS = {
    "technical_severity": 0.20,
    "financial_impact": 0.15,
    "exploitability": 0.15,
    "asset_exposure": 0.10,
    "governance_risk": 0.10,
    "upgrade_risk": 0.10,
    "oracle_risk": 0.08,
    "bridge_risk": 0.07,
    "historical_similarity": 0.05,
}


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


@dataclass
class RiskFactors:
    technical_severity: float = 0.0
    financial_impact: float = 0.0
    exploitability: float = 0.0
    asset_exposure: float = 0.0
    governance_risk: float = 0.0
    upgrade_risk: float = 0.0
    oracle_risk: float = 0.0
    bridge_risk: float = 0.0
    historical_similarity: float = 0.0

    def normalized(self) -> "RiskFactors":
        return RiskFactors(
            **{k: _clamp01(v) for k, v in asdict(self).items()}
        )


@dataclass
class RiskScore:
    score: float
    band: str
    factors: dict[str, float]
    weights: dict[str, float]
    priority: int
    suggestions: list[str] = field(default_factory=list)
    notes: str = "Score is advisory only. No automatic remediation."


def band_for_score(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.4:
        return "MEDIUM"
    if score >= 0.2:
        return "LOW"
    return "INFO"


def priority_rank(score: float) -> int:
    """1 = highest priority."""
    if score >= 0.85:
        return 1
    if score >= 0.65:
        return 2
    if score >= 0.4:
        return 3
    if score >= 0.2:
        return 4
    return 5


def factors_from_finding(finding: dict[str, Any]) -> RiskFactors:
    sev = str(finding.get("severity") or "INFO").upper()
    tech = SEVERITY_SCORE.get(sev, 0.1)
    category = str(finding.get("category") or finding.get("rule_id") or "").lower()
    title = str(finding.get("title") or "").lower()
    blob = f"{category} {title} {finding.get('rule_id', '')}".lower()

    financial = _clamp01(float(finding.get("financial_impact") or finding.get("tvl_fraction") or 0.0))
    if financial == 0 and sev in {"HIGH", "CRITICAL"}:
        financial = 0.4 if sev == "HIGH" else 0.7

    exploitability = _clamp01(float(finding.get("exploitability") or finding.get("confidence") or 0.5))
    exposure = _clamp01(float(finding.get("asset_exposure") or 0.3))

    gov = 0.8 if any(k in blob for k in ("owner", "governance", "role", "authority", "admin")) else 0.1
    upgrade = 0.85 if any(k in blob for k in ("upgrade", "proxy", "implementation")) else 0.1
    oracle = 0.9 if "oracle" in blob else 0.05
    bridge = 0.9 if any(k in blob for k in ("bridge", "ibc")) else 0.05
    hist = _clamp01(float(finding.get("historical_similarity") or 0.0))
    if hist == 0 and sev == "CRITICAL":
        hist = 0.35

    return RiskFactors(
        technical_severity=tech,
        financial_impact=financial,
        exploitability=exploitability,
        asset_exposure=exposure,
        governance_risk=gov,
        upgrade_risk=upgrade,
        oracle_risk=oracle,
        bridge_risk=bridge,
        historical_similarity=hist,
    ).normalized()


def compute_risk_score(
    factors: RiskFactors,
    weights: Optional[dict[str, float]] = None,
) -> RiskScore:
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)
    total_w = sum(w.values()) or 1.0
    f = factors.normalized()
    fd = asdict(f)
    score = sum(fd[k] * (w.get(k, 0.0) / total_w) for k in fd)
    score = _clamp01(score)
    suggestions = remediation_suggestions(f, score)
    return RiskScore(
        score=round(score, 4),
        band=band_for_score(score),
        factors={k: round(v, 4) for k, v in fd.items()},
        weights={k: round(v / total_w, 4) for k, v in w.items()},
        priority=priority_rank(score),
        suggestions=suggestions,
    )


def score_finding(finding: dict[str, Any], weights: Optional[dict[str, float]] = None) -> dict[str, Any]:
    result = compute_risk_score(factors_from_finding(finding), weights=weights)
    return {
        "finding_id": finding.get("finding_id") or finding.get("rule_id"),
        "title": finding.get("title"),
        **asdict(result),
    }


def rank_findings(
    findings: Sequence[dict[str, Any]],
    weights: Optional[dict[str, float]] = None,
) -> list[dict[str, Any]]:
    scored = [score_finding(f, weights=weights) for f in findings]
    scored.sort(key=lambda x: (-x["score"], x.get("finding_id") or ""))
    for i, row in enumerate(scored, start=1):
        row["rank"] = i
    return scored


def remediation_suggestions(factors: RiskFactors, score: float) -> list[str]:
    """Human-gated suggestions only — never auto-applied."""
    tips: list[str] = []
    if factors.governance_risk >= 0.5:
        tips.append("Verify admin/multisig ownership and recent role grants on-chain.")
    if factors.upgrade_risk >= 0.5:
        tips.append("Diff proxy implementation / package bytecode against last approved release.")
    if factors.oracle_risk >= 0.5:
        tips.append("Cross-check secondary price feeds; consider human-gated circuit breaker.")
    if factors.bridge_risk >= 0.5:
        tips.append("Coordinate with bridge operators; do not move funds automatically.")
    if factors.financial_impact >= 0.5:
        tips.append("Quantify exposed TVL and notify treasury / protocol owner.")
    if factors.exploitability >= 0.6:
        tips.append("Prioritize evidence collection and incident playbook; no auto-remediation.")
    if score >= 0.65 and not tips:
        tips.append("Escalate to security_analyst for manual review and approval workflow.")
    if not tips:
        tips.append("Monitor and track as informational finding.")
    return tips
