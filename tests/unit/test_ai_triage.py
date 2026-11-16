from bluestrix.intelligence.ai_triage import local_triage, triage_findings


def test_local_triage_critical():
    r = local_triage(
        {
            "finding_id": "F1",
            "title": "Ownership transferred",
            "severity": "CRITICAL",
            "category": "governance",
            "rule_id": "ONCHAIN-EVM-OWNER-CHANGE",
        }
    )
    assert r.severity == "CRITICAL"
    assert r.priority == 1
    assert r.auto_actions == []
    assert any("Privileged" in n or "admin" in n.lower() for n in r.attack_path_notes)


def test_llm_requires_human_approval_flag():
    findings = [{"finding_id": "a", "severity": "HIGH", "title": "x"}]
    out = triage_findings(findings, use_llm=True, human_approved=False)
    assert out[0].get("llm_skipped")
    assert out[0]["auto_actions"] == []
