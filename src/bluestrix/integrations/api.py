from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from bluestrix.core.audit import AuditLog
from bluestrix.core.config import load_config
from bluestrix.core.models import ActionType
from bluestrix.intelligence.assets.wallet import AssetProtectionEngine
from bluestrix.intelligence.code.analyzer import CodeIntelligenceEngine
from bluestrix.intelligence.verification.engine import VerificationEngine
from bluestrix.policy.engine import PolicyEngine
from bluestrix.policy.scope import ScopeEnforcer


class CodeScanRequest(BaseModel):
    path: str
    languages: list[str] | None = None


class WalletRequest(BaseModel):
    address: str
    chain: str = "evm"


def create_app(config_path: str = "config/bluestrix.yaml") -> FastAPI:
    config = load_config(config_path)
    audit_log = AuditLog()
    scope = ScopeEnforcer(config.get("scope", {}), audit_log=audit_log)
    policy_engine = PolicyEngine(config, scope)
    asset_engine = AssetProtectionEngine()
    verifier = VerificationEngine()

    app = FastAPI(title="BlueStrix v8.0", version="8.0.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": "defensive", "execution": "restricted"}

    @app.post("/scan/code")
    def scan_code(request: CodeScanRequest) -> dict[str, Any]:
        try:
            policy_engine.scope.enforce(request.path, action=ActionType.READ.value)
            findings = CodeIntelligenceEngine().analyze_path(request.path, request.languages)
            findings = verifier.verify(findings)
            return {"summary": verifier.summarize(findings),
                    "findings": [f.model_dump(mode="json") for f in findings]}
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

    return app
