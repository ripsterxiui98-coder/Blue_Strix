"""Unit tests for findings storage using in-memory SQLite."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session, sessionmaker

from bluestrix.core.database import Base, create_db_engine
from bluestrix.core import repository as repo
from bluestrix.core.models_db import (  # noqa: F401
    ApprovalRecord,
    AuditEventRecord,
    FindingRecord,
    RemediationProposal,
    ScanRun,
)
from bluestrix.intelligence.verification.persistence import (
    deduplicate_findings,
    mark_finding_as_false_positive,
    mark_finding_as_fixed,
    save_scan_results,
)


@pytest.fixture()
def db_session() -> Session:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_models_create_tables(db_session: Session) -> None:
    assert db_session is not None


def test_save_and_read_finding(db_session: Session) -> None:
    run = repo.create_scan_run(db_session, target="./src")
    saved = repo.save_findings(
        db_session,
        [
            {
                "finding_id": "BSX-TEST-001",
                "title": "Hardcoded secret",
                "description": "dummy",
                "severity": "HIGH",
                "status": "open",
                "target": "./src/app.py",
                "rule_id": "BSX-PY-001",
            }
        ],
        scan_run_id=run.id,
    )
    assert len(saved) == 1
    found = repo.get_finding(db_session, "BSX-TEST-001")
    assert found is not None
    assert found.severity == "HIGH"


def test_update_finding_status(db_session: Session) -> None:
    repo.save_findings(
        db_session,
        [{"finding_id": "BSX-TEST-002", "title": "x", "target": "t", "status": "open"}],
    )
    updated = repo.update_finding_status(db_session, "BSX-TEST-002", "fixed")
    assert updated is not None
    assert updated.status == "fixed"


def test_audit_event(db_session: Session) -> None:
    event = repo.create_audit_event(
        db_session,
        actor="analyst",
        action="review",
        target="BSX-TEST",
        decision="ALLOWED",
        reason="ok",
    )
    events = repo.list_audit_events(db_session)
    assert any(e.id == event.id for e in events)


def test_remediation_and_approval(db_session: Session) -> None:
    proposal = repo.create_remediation_proposal(
        db_session,
        finding_id="BSX-TEST-003",
        title="Remove secret",
        target="./src",
        proposed_change="use env var",
    )
    approval = repo.create_approval_record(
        db_session,
        finding_id="BSX-TEST-003",
        owner="protocol_owner",
        status="approved",
        proposal_id=proposal.id,
        approval_token="super-secret-token",
    )
    assert approval.approval_token_hash is not None
    assert approval.approval_token_hash != "super-secret-token"


def test_deduplicate_and_persist(db_session: Session) -> None:
    findings = [
        {"finding_id": "A", "title": "Dup", "target": "f.py", "rule_id": "R1", "metadata": {"line": 1}},
        {"finding_id": "B", "title": "Dup", "target": "f.py", "rule_id": "R1", "metadata": {"line": 1}},
        {"finding_id": "C", "title": "Other", "target": "f.py", "rule_id": "R2"},
    ]
    assert len(deduplicate_findings(findings)) == 2
    run, saved = save_scan_results(db_session, target="./src", findings=findings)
    assert run.status == "completed"
    assert len(saved) == 2


def test_mark_fixed_and_fp(db_session: Session) -> None:
    repo.save_findings(
        db_session,
        [{"finding_id": "BSX-FP", "title": "noise", "target": "t"}],
    )
    assert mark_finding_as_fixed(db_session, "BSX-FP").status == "fixed"
    assert mark_finding_as_false_positive(db_session, "BSX-FP").status == "false_positive"
