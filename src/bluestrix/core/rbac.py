"""Role -> permission matrix for the BlueStrix API.

Mirrors dashboard/src/lib/roles.ts. Keep both files in sync when a role or permission changes.
"""

from __future__ import annotations

ALL_PERMISSIONS = frozenset(
    {
        "view_dashboard",
        "view_findings",
        "view_scans",
        "view_audit",
        "view_approvals",
        "propose_remediation",
        "approve_remediation",
        "update_finding_status",
    }
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin": ALL_PERMISSIONS,
    "security_analyst": frozenset(
        {
            "view_dashboard",
            "view_findings",
            "view_scans",
            "view_audit",
            "view_approvals",
            "propose_remediation",
            "update_finding_status",
        }
    ),
    "protocol_owner": frozenset(
        {"view_dashboard", "view_findings", "view_approvals", "approve_remediation"}
    ),
    "incident_responder": frozenset(
        {"view_dashboard", "view_findings", "view_audit", "view_scans"}
    ),
}


def has_permission(role: str | None, permission: str) -> bool:
    if not role:
        return False
    return permission in ROLE_PERMISSIONS.get(role, frozenset())
