from __future__ import annotations

import hashlib
import os
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bluestrix.core.exceptions import PolicyViolationError
from bluestrix.core.models import Finding
from bluestrix.intelligence.remediation.approval import RemediationApproval
from bluestrix.security_controls.runtime_guard import RuntimeGuard


@dataclass(frozen=True)
class SafePatch:
    finding_id: str
    rule_id: str
    file_path: Path
    original_sha256: str
    patched_sha256: str
    original_content: str
    patched_content: str
    unified_diff: str
    created_at: str
    approval_required: bool = True


class SafePatcher:
    AUTO_FIX_ALLOWED_RULES = {"BSX-PY-001", "BSX-TS-002"}
    PROTECTED_PATH_PATTERNS = (
        r"(^|/)\.github/workflows/", r"(^|/)\.gitlab-ci\.yml$",
        r"(^|/)Dockerfile$", r"(^|/)docker-compose\.ya?ml$",
        r"(^|/)k8s/", r"(^|/)terraform/", r"(^|/)policies/", r"(^|/)config/",
    )

    def __init__(self, repository_root: str | Path, approval_gate: RemediationApproval | None = None) -> None:
        self.repository_root = Path(repository_root).expanduser().resolve()
        self.approval_gate = approval_gate or RemediationApproval()
        self.runtime_guard = RuntimeGuard()

    def create_patch(self, finding: Finding) -> SafePatch:
        if finding.status.value != "FAIL":
            raise ValueError("Only FAIL findings can generate patch")
        rule_id = str(finding.metadata.get("rule_id", ""))
        if rule_id not in self.AUTO_FIX_ALLOWED_RULES:
            raise PolicyViolationError(f"Auto-patch not allowed for: {rule_id}")

        target = str(finding.metadata.get("target") or finding.target)
        line_number = int(finding.metadata.get("line", 0))
        file_path = Path(target).expanduser().resolve()
        self.runtime_guard.assert_path_within_root(str(file_path), root=str(self.repository_root))
        self._assert_not_protected(file_path)

        original = file_path.read_text(encoding="utf-8")
        lines = original.splitlines()
        original_line = lines[line_number - 1]
        patched_line = self._build_replacement(rule_id, original_line)
        patched_lines = lines.copy()
        patched_lines[line_number - 1] = patched_line
        patched = "\n".join(patched_lines) + "\n"

        return SafePatch(
            finding_id=finding.finding_id, rule_id=rule_id, file_path=file_path,
            original_sha256=self._sha256(original), patched_sha256=self._sha256(patched),
            original_content=original, patched_content=patched,
            unified_diff=self._render_diff(file_path, original, patched),
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def apply_patch(self, patch: SafePatch, finding_id: str, owner: str, approval_token: str, dry_run: bool = True) -> dict[str, Any]:
        decision = self.approval_gate.approve(finding_id, owner, approval_token)
        if not decision.allowed:
            raise PolicyViolationError(decision.reason)

        current = patch.file_path.read_text(encoding="utf-8")
        if self._sha256(current) != patch.original_sha256:
            raise PolicyViolationError("File changed after patch created")

        if dry_run:
            return {"status": "DRY_RUN_SUCCESS", "applied": False}

        backup = self._create_backup(patch.file_path)
        try:
            self._atomic_write(patch.file_path, patch.patched_content)
        except Exception:
            shutil.copy2(backup, patch.file_path)
            raise

        return {"status": "APPLIED", "applied": True, "backup": str(backup)}

    def _assert_not_protected(self, file_path: Path) -> None:
        relative = file_path.relative_to(self.repository_root).as_posix()
        for pattern in self.PROTECTED_PATH_PATTERNS:
            if re.search(pattern, relative):
                raise PolicyViolationError(f"Protected path: {relative}")

    def _build_replacement(self, rule_id: str, original_line: str) -> str:
        if rule_id == "BSX-PY-001":
            return re.sub(r"(?i)(api[_-]?key|secret|password|token)\s*=\s*[\"'][^\"']{8,}[\"']",
                          r'\1 = os.environ.get("\1", "")', original_line)
        if rule_id == "BSX-TS-002":
            return re.sub(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']",
                          r'\1: process.env.\1 ?? ""', original_line)
        raise PolicyViolationError(f"Rule not approved: {rule_id}")

    def _render_diff(self, file_path: Path, original: str, patched: str) -> str:
        old_lines = original.splitlines()
        new_lines = patched.splitlines()
        diff = [f"--- a/{file_path.relative_to(self.repository_root).as_posix()}",
                f"+++ b/{file_path.relative_to(self.repository_root).as_posix()}"]
        for i, (o, n) in enumerate(zip(old_lines, new_lines), 1):
            if o != n:
                diff.extend([f"@@ -{i},1 +{i},1 @@", f"-{o}", f"+{n}"])
        return "\n".join(diff) + "\n"

    def _create_backup(self, file_path: Path) -> Path:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_dir = self.repository_root / ".bluestrix" / "backups"
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup = backup_dir / f"{file_path.name}.{timestamp}.bak"
        shutil.copy2(file_path, backup)
        return backup

    def _atomic_write(self, target: Path, content: str) -> None:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=target.parent,
                                         prefix=f".{target.name}.", suffix=".tmp", delete=False) as tmp:
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
            tmp_path = Path(tmp.name)
        os.replace(tmp_path, target)

    @staticmethod
    def _sha256(content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
