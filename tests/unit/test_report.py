from bluestrix.intelligence.report import (
    executive_summary,
    generate_full_report,
    post_incident_report,
    remediation_plan,
    technical_detail,
)


def test_report_sections():
    findings = [
        {
            "finding_id": "1",
            "title": "Proxy upgrade",
            "severity": "CRITICAL",
            "category": "upgrade",
            "description": "Implementation changed",
        }
    ]
    triage = None
    exe = executive_summary(findings)
    assert ex["finding_count"] == 1
    assert ex["auto_actions"] == []
    tech = technical_detail(findings)
    assert tech["items"][0]["finding_id"] == "1"
    plan = remediation_plan(findings)
    assert plan["steps"][0]["requires_human_approval"] is True
    pir = post_incident_report(incident_id="INC-1", title="t", severity="HIGH", findings=findings)
    assert pir["type"] == "post_incident_report"
    full = generate_full_report(findings, title="Test")
    assert "executive_summary" in full
    assert full["auto_actions"] == []
