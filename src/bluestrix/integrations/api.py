from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from bluestrix.core import repository as repo
from bluestrix.core.audit import AuditLog
from bluestrix.core.config import load_config
from bluestrix.core.database import get_db
from bluestrix.core.models import ActionType
from bluestrix.intelligence.assets.wallet import AssetProtectionEngine
from bluestrix.intelligence.code.analyzer import CodeIntelligenceEngine
from bluestrix.intelligence.verification.engine import VerificationEngine
from bluestrix.intelligence.verification.persistence import (
    compare_with_previous_scan,
    save_scan_results,
)
from bluestrix.integrations.auth_routes import router as auth_router
from bluestrix.policy.engine import PolicyEngine
from bluestrix.policy.scope import ScopeEnforcer


class CodeScanRequest(BaseModel):
    path: str
    languages: list[str] | None = None
    persist: bool = False


class WalletRequest(BaseModel):
    address: str
    chain: str = "evm"


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|fixed|false_positive|accepted_risk)$")


class RemediationProposalRequest(BaseModel):
    finding_id: str
    title: str
    target: str
    proposed_change: str = ""
    severity: str = "INFO"
    rule_id: str | None = None


class ApprovalRequest(BaseModel):
    finding_id: str
    proposal_id: UUID | None = None
    status: str = Field(default="approved", pattern="^(pending|approved|rejected)$")


def _require_operator(
    x_bluestrix_operator: Optional[str] = Header(default=None, alias="X-BlueStrix-Operator"),
    x_bluestrix_approval_token: Optional[str] = Header(
        default=None, alias="X-BlueStrix-Approval-Token"
    ),
) -> tuple[str, Optional[str]]:
    if not x_bluestrix_operator:
        raise HTTPException(
            status_code=401,
            detail="Write endpoints require X-BlueStrix-Operator header",
        )
    return x_bluestrix_operator, x_bluestrix_approval_token


def create_app(config_path: str = "config/bluestrix.yaml") -> FastAPI:
    config = load_config(config_path)
    audit_log = AuditLog()
    scope = ScopeEnforcer(config.get("scope", {}), audit_log=audit_log)
    policy_engine = PolicyEngine(config, scope)
    asset_engine = AssetProtectionEngine()
    verifier = VerificationEngine()

    app = FastAPI(title="BlueStrix v8.0", version="8.0.0")
    app.include_router(auth_router)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "defensive", "execution": "restricted"}

    @app.post("/scan/code")
    def scan_code(
        request: CodeScanRequest,
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        try:
            policy_engine.scope.enforce(request.path, action=ActionType.READ.value)
            findings = CodeIntelligenceEngine().analyze_path(request.path, request.languages)
            findings = verifier.verify(findings)
            payload = [f.model_dump(mode="json") for f in findings]
            summary = verifier.summarize(findings)
            result: dict[str, Any] = {
                "summary": summary,
                "findings": payload,
            }
            if request.persist:
                comparison = compare_with_previous_scan(db, request.path, payload)
                run, _ = save_scan_results(
                    db, target=request.path, findings=payload, summary=summary
                )
                result["scan_run_id"] = str(run.id)
                result["comparison"] = comparison
                audit_log.record(
                    "code_scan_persisted", request.path, "COMPLETED", f"{len(payload)} findings"
                )
            return result
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/asset/wallet")
    def analyze_wallet(request: WalletRequest) -> dict[str, Any]:
        try:
            policy_engine.scope.enforce(request.address, action=ActionType.READ.value)
            finding = asset_engine.analyze_address(request.address, request.chain)
            return finding.model_dump(mode="json")
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/findings")
    def list_findings(
        status: Optional[str] = None,
        severity: Optional[str] = None,
        target: Optional[str] = None,
        limit: int = 100,
        db: Session = Depends(get_db),
    ) -> dict[str, Any]:
        rows = repo.list_findings(
            db, status=status, severity=severity, target=target, limit=min(limit, 500)
        )
        return {
            "count": len(rows),
            "findings": [
                {
                    "finding_id": r.finding_id,
                    "rule_id": r.rule_id,
                    "title": r.title,
                    "severity": r.severity,
                    "status": r.status,
                    "category": r.category,
                    "target": r.target,
                    "confidence": float(r.confidence),
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
                for r in rows
            ],
        }

    @app.get("/findings/{finding_id}")
    def get_finding(finding_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
        row = repo.get_finding(db, finding_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        return {
            "finding_id": row.finding_id,
            "rule_id": row.rule_id,
            "title": row.title,
            "description": row.description,
            "severity": row.severity,
            "status": row.status,
            "category": row.category,
            "target": row.target,
            "evidence": row.evidence,
            "recommendation": row.recommendation,
            "references": row.references,
            "confidence": float(row.confidence),
            "metadata": row.metadata_,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        }

    @app.patch("/findings/{finding_id}/status")
    def patch_finding_status(
        finding_id: str,
        body: FindingStatusUpdate,
        db: Session = Depends(get_db),
        operator: tuple[str, Optional[str]] = Depends(_require_operator),
    ) -> dict[str, Any]:
        op_name, _token = operator
        row = repo.update_finding_status(db, finding_id, body.status)
        if row is None:
            raise HTTPException(status_code=404, detail="Finding not found")
        repo.create_audit_event(
            db,
            actor=op_name,
            action="update_finding_status",
            target=finding_id,
            decision="ALLOWED",
            reason=f"status set to {body.status}",
        )
        return {"finding_id": finding_id, "status": row.status}

    @app.get("/audit")
    def get_audit(limit: int = 50, db: Session = Depends(get_db)) -> dict[str, Any]:
        events = repo.list_audit_events(db, limit=min(limit, 200))
        return {
            "count": len(events),
            "events": [
                {
                    "id": str(e.id),
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "actor": e.actor,
                    "action": e.action,
                    "target": e.target,
                    "decision": e.decision,
                    "reason": e.reason,
                }
                for e in events
            ],
        }

    @app.post("/remediation/proposals")
    def post_remediation_proposal(
        body: RemediationProposalRequest,
        db: Session = Depends(get_db),
        operator: tuple[str, Optional[str]] = Depends(_require_operator),
    ) -> dict[str, Any]:
        op_name, _token = operator
        proposal = repo.create_remediation_proposal(
            db,
            finding_id=body.finding_id,
            title=body.title,
            target=body.target,
            proposed_change=body.proposed_change,
            severity=body.severity,
            rule_id=body.rule_id,
        )
        repo.create_audit_event(
            db,
            actor=op_name,
            action="create_remediation_proposal",
            target=body.finding_id,
            decision="PROPOSED",
            reason=body.title,
        )
        return {
            "id": str(proposal.id),
            "finding_id": proposal.finding_id,
            "status": proposal.status,
        }

    @app.get("/remediation/proposals")
    def get_remediation_proposals(
        limit: int = 50, db: Session = Depends(get_db)
    ) -> dict[str, Any]:
        rows = repo.list_remediation_proposals(db, limit=min(limit, 200))
        return {
            "count": len(rows),
            "proposals": [
                {
                    "id": str(r.id),
                    "finding_id": r.finding_id,
                    "title": r.title,
                    "severity": r.severity,
                    "status": r.status,
                    "target": r.target,
                }
                for r in rows
            ],
        }

    @app.post("/remediation/approvals")
    def post_remediation_approval(
        body: ApprovalRequest,
        db: Session = Depends(get_db),
        operator: tuple[str, Optional[str]] = Depends(_require_operator),
    ) -> dict[str, Any]:
        op_name, token = operator
        record = repo.create_approval_record(
            db,
            finding_id=body.finding_id,
            owner=op_name,
            status=body.status,
            proposal_id=body.proposal_id,
            approval_token=token,
        )
        action = "approval_granted" if body.status == "approved" else "approval_denied"
        repo.create_audit_event(
            db,
            actor=op_name,
            action=action,
            target=body.finding_id,
            decision=body.status.upper(),
            reason="human governance approval recorded",
        )
        return {
            "id": str(record.id),
            "finding_id": record.finding_id,
            "status": record.status,
            "token_stored": "hash_only" if record.approval_token_hash else "none",
        }

    return app
