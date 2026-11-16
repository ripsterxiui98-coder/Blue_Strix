from bluestrix.intelligence.risk import factors_from_finding, rank_findings, score_finding


def test_critical_owner_change_scores_high():
    finding = {
        "finding_id": "F1",
        "title": "Ownership transferred",
        "severity": "CRITICAL",
        "category": "governance",
        "rule_id": "ONCHAIN-EVM-OWNER-CHANGE",
        "confidence": 0.9,
    }
    scored = score_finding(finding)
    assert scored["score"] >= 0.5
    assert scored["band"] in {"HIGH", "CRITICAL", "MEDIUM"}
    assert scored["suggestions"]
    assert scored["priority"] <= 3


def test_rank_orders_by_score():
    findings = [
        {"finding_id": "a", "severity": "LOW", "title": "n"},
        {"finding_id": "b", "severity": "CRITICAL", "title": "proxy upgrade", "category": "upgrade"},
    ]
    ranked = rank_findings(findings)
    assert ranked[0]["finding_id"] == "b"
    assert ranked[0]["rank"] == 1


def test_factors_bridge_oracle():
    f = factors_from_finding({"severity": "HIGH", "title": "oracle deviation", "category": "oracle"})
    assert f.oracle_risk >= 0.5
