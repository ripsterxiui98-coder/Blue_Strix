const API_URL =
  process.env.NEXT_PUBLIC_BLUESTRIX_API_URL?.replace(/\/$/, "") ||
  "http://127.0.0.1:8787";

export type FindingSummary = {
  finding_id: string;
  rule_id?: string | null;
  title: string;
  severity: string;
  status: string;
  category?: string;
  target: string;
  confidence?: number;
  created_at?: string | null;
};

/** Access token for read requests. Set by Providers from the NextAuth session. */
let apiAccessToken = "";

export function setApiAccessToken(token: string): void {
  apiAccessToken = token;
}

async function apiGet<T>(path: string): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (apiAccessToken) {
    headers["Authorization"] = `Bearer ${apiAccessToken}`;
  }
  const res = await fetch(`${API_URL}${path}`, { cache: "no-store", headers });
  if (!res.ok) {
    throw new Error(`API ${path} failed: ${res.status}`);
  }
  return res.json() as Promise<T>;
}

async function apiWrite<T>(
  path: string,
  method: string,
  body: unknown,
  accessToken: string,
  approvalToken?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  // Identity comes from the server-verified session token, never from a client-chosen name.
  if (accessToken) {
    headers["Authorization"] = `Bearer ${accessToken}`;
  }
  if (approvalToken) {
    headers["X-BlueStrix-Approval-Token"] = approvalToken;
  }
  const res = await fetch(`${API_URL}${path}`, {
    method,
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`API ${path} failed: ${res.status} ${detail}`);
  }
  return res.json() as Promise<T>;
}

/** Pull the access token NextAuth stored in the session (empty string when signed out). */
export function accessTokenOf(session: unknown): string {
  return (session as { accessToken?: string } | null)?.accessToken ?? "";
}

export async function fetchHealth() {
  return apiGet<{ status: string; mode: string; execution: string }>("/health");
}

export async function fetchFindings(params?: {
  status?: string;
  severity?: string;
  target?: string;
}) {
  const q = new URLSearchParams();
  if (params?.status) q.set("status", params.status);
  if (params?.severity) q.set("severity", params.severity);
  if (params?.target) q.set("target", params.target);
  const qs = q.toString();
  return apiGet<{ count: number; findings: FindingSummary[] }>(
    `/findings${qs ? `?${qs}` : ""}`,
  );
}

export async function fetchFinding(id: string) {
  return apiGet<Record<string, unknown>>(`/findings/${encodeURIComponent(id)}`);
}

export async function fetchAudit(limit = 50) {
  return apiGet<{ count: number; events: Record<string, unknown>[] }>(
    `/audit?limit=${limit}`,
  );
}

export async function fetchProposals() {
  return apiGet<{ count: number; proposals: Record<string, unknown>[] }>(
    "/remediation/proposals",
  );
}

export async function updateFindingStatus(
  findingId: string,
  status: string,
  accessToken: string,
) {
  return apiWrite(
    `/findings/${encodeURIComponent(findingId)}/status`,
    "PATCH",
    { status },
    accessToken,
  );
}

export async function createProposal(
  payload: {
    finding_id: string;
    title: string;
    target: string;
    proposed_change?: string;
    severity?: string;
  },
  accessToken: string,
) {
  return apiWrite("/remediation/proposals", "POST", payload, accessToken);
}

export async function createApproval(
  payload: {
    finding_id: string;
    proposal_id?: string;
    status: string;
  },
  accessToken: string,
  approvalToken?: string,
) {
  return apiWrite(
    "/remediation/approvals",
    "POST",
    payload,
    accessToken,
    approvalToken,
  );
}

export { API_URL };
