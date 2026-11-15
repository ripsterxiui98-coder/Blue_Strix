from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from bluestrix import __version__
from bluestrix.core.audit import AuditLog
from bluestrix.core.config import load_config
from bluestrix.core.exceptions import BlueStrixError
from bluestrix.core.models import ActionType
from bluestrix.governance.approval import HumanApprovalGate
from bluestrix.intelligence.assets.wallet import AssetProtectionEngine
from bluestrix.intelligence.code.analyzer import CodeIntelligenceEngine
from bluestrix.intelligence.verification.engine import VerificationEngine
from bluestrix.policy.engine import PolicyEngine
from bluestrix.policy.scope import ScopeEnforcer
from bluestrix.reporting.generator import ReportGenerator


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bluestrix", description="BlueStrix v8.0")
    parser.add_argument("--config", default="config/bluestrix.yaml")
    parser.add_argument("--version", action="version", version=f"BlueStrix {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    policy_parser = subparsers.add_parser("policy")
    policy_sub = policy_parser.add_subparsers(dest="policy_command", required=True)
    policy_sub.add_parser("validate")

    scope_parser = subparsers.add_parser("scope")
    scope_sub = scope_parser.add_subparsers(dest="scope_command", required=True)
    scope_check = scope_sub.add_parser("check")
    scope_check.add_argument("target")

    scan_parser = subparsers.add_parser("scan")
    scan_sub = scan_parser.add_subparsers(dest="scan_command", required=True)
    code_scan = scan_sub.add_parser("code")
    code_scan.add_argument("path")
    code_scan.add_argument("--languages", nargs="*", default=None)
    code_scan.add_argument("--output", default="reports/findings")

    asset_parser = subparsers.add_parser("asset")
    asset_sub = asset_parser.add_subparsers(dest="asset_command", required=True)
    wallet = asset_sub.add_parser("analyze-wallet")
    wallet.add_argument("address")
    wallet.add_argument("--chain", default="evm", choices=["evm", "solana"])

    control_parser = subparsers.add_parser("controls")
    control_parser.add_argument("--output", default="reports/control_findings")

    slither_parser = subparsers.add_parser("slither")
    slither_parser.add_argument("target")
    slither_parser.add_argument("--output", default="reports/slither_findings")
    slither_parser.add_argument("--timeout", type=int, default=300)

    remediation_parser = subparsers.add_parser("remediation")
    remediation_sub = remediation_parser.add_subparsers(dest="remediation_command", required=True)
    plan = remediation_sub.add_parser("plan")
    plan.add_argument("--findings", required=True)
    plan.add_argument("--repository", default=".")
    plan.add_argument("--output", default="reports/remediation_plan.json")

    audit_parser = subparsers.add_parser("audit")
    audit_sub = audit_parser.add_subparsers(dest="audit_command", required=True)
    audit_tail = audit_sub.add_parser("tail")
    audit_tail.add_argument("--limit", type=int, default=20)

    api_parser = subparsers.add_parser("api")
    api_parser.add_argument("--host", default="127.0.0.1")
    api_parser.add_argument("--port", type=int, default=8787)

    return parser


def _load_context(config_path: str):
    config = load_config(config_path)
    audit_log = AuditLog()
    scope = ScopeEnforcer(config.get("scope", {}), audit_log=audit_log)
    policy_engine = PolicyEngine(config, scope, HumanApprovalGate())
    return config, policy_engine, audit_log


def _print_json(data):
    print(json.dumps(data, indent=2, default=str))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "policy" and args.policy_command == "validate":
            config, policy_engine, _ = _load_context(args.config)
            errors = policy_engine.validate_files()
            _print_json({"status": "PASS" if not errors else "FAIL", "errors": errors})
            return 0 if not errors else 2

        if args.command == "scope" and args.scope_command == "check":
            config, policy_engine, audit_log = _load_context(args.config)
            allowed = policy_engine.scope.is_authorized(args.target)
            audit_log.record("scope_check", args.target, "ALLOWED" if allowed else "BLOCKED", "Scope evaluation")
            _print_json({"target": args.target, "authorized": allowed})
            return 0 if allowed else 2

        if args.command == "scan" and args.scan_command == "code":
            config, policy_engine, audit_log = _load_context(args.config)
            policy_engine.scope.enforce(str(Path(args.path).resolve()), action=ActionType.READ.value)
            findings = CodeIntelligenceEngine().analyze_path(args.path, args.languages)
            findings = VerificationEngine().verify(findings)
            generator = ReportGenerator()
            json_path = generator.save_json(findings, args.output)
            markdown_path = generator.save_markdown(findings, Path(args.output).name)
            audit_log.record("code_scan", str(Path(args.path).resolve()), "COMPLETED", f"{len(findings)} findings")
            _print_json({"status": "COMPLETED", "findings": len(findings),
                         "json_report": str(json_path), "markdown_report": str(markdown_path)})
            return 0

        if args.command == "asset" and args.asset_command == "analyze-wallet":
            config, policy_engine, audit_log = _load_context(args.config)
            policy_engine.scope.enforce(args.address, action=ActionType.READ.value)
            finding = AssetProtectionEngine().analyze_address(args.address, args.chain)
            audit_log.record("wallet_analysis", args.address, "COMPLETED", finding.status.value)
            _print_json(finding.model_dump(mode="json"))
            return 0

        if args.command == "controls":
            from bluestrix.security_controls.examples import build_default_controls
            findings = build_default_controls().run_all()
            findings = VerificationEngine().verify(findings)
            generator = ReportGenerator()
            generator.save_json(findings, args.output)
            generator.save_markdown(findings, Path(args.output).name)
            _print_json({"status": "COMPLETED", "controls": len(findings)})
            return 0

        if args.command == "slither":
            from bluestrix.integrations.slither_adapter import SlitherAdapter
            adapter = SlitherAdapter(timeout_seconds=args.timeout)
            findings = adapter.analyze(args.target)
            findings = VerificationEngine().verify(findings)
            generator = ReportGenerator()
            generator.save_json(findings, args.output)
            generator.save_markdown(findings, Path(args.output).name)
            _print_json({"status": "COMPLETED", "findings": len(findings)})
            return 0

        if args.command == "remediation" and args.remediation_command == "plan":
            from bluestrix.intelligence.remediation.planner import RemediationPlanner
            payload = json.loads(Path(args.findings).read_text(encoding="utf-8"))
            findings = [Finding.model_validate(item) for item in payload.get("findings", [])]
            plan = RemediationPlanner().create_plan(findings, args.repository)
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
            _print_json({"status": "PROPOSED", "plan": str(output_path)})
            return 0

        if args.command == "audit" and args.audit_command == "tail":
            _, _, audit_log = _load_context(args.config)
            events = audit_log.tail(args.limit)
            _print_json([e.model_dump(mode="json") for e in events])
            return 0

        if args.command == "api":
            try:
                import uvicorn
            except ImportError:
                raise BlueStrixError("Install API deps: pip install 'bluestrix[api]'")
            from bluestrix.integrations.api import create_app
            uvicorn.run(create_app(args.config), host=args.host, port=args.port)
            return 0

    except BlueStrixError as exc:
        print(f"BlueStrix error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"BlueStrix error: {exc}", file=sys.stderr)
        return 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
