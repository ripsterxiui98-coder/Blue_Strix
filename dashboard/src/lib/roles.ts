export type Role =
  | "admin"
  | "security_analyst"
  | "protocol_owner"
  | "incident_responder";

export const ALL_ROLES: Role[] = [
  "admin",
  "security_analyst",
  "protocol_owner",
  "incident_responder",
];

export type Permission =
  | "view_dashboard"
  | "view_findings"
  | "view_scans"
  | "view_audit"
  | "view_approvals"
  | "propose_remediation"
  | "approve_remediation"
  | "update_finding_status";

const matrix: Record<Role, Permission[]> = {
  admin: [
    "view_dashboard",
    "view_findings",
    "view_scans",
    "view_audit",
    "view_approvals",
    "propose_remediation",
    "approve_remediation",
    "update_finding_status",
  ],
  security_analyst: [
    "view_dashboard",
    "view_findings",
    "view_scans",
    "view_audit",
    "view_approvals",
    "propose_remediation",
    "update_finding_status",
  ],
  protocol_owner: [
    "view_dashboard",
    "view_findings",
    "view_approvals",
    "approve_remediation",
  ],
  incident_responder: [
    "view_dashboard",
    "view_findings",
    "view_audit",
    "view_scans",
  ],
};

export function can(role: Role | undefined, permission: Permission): boolean {
  if (!role) return false;
  return matrix[role]?.includes(permission) ?? false;
}
