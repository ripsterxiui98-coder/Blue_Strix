# BlueStrix Dashboard

Defensive web UI for findings, scan history, remediation approvals, and audit trail.

## Principles

- Read-only by default
- No private keys or wallet seeds
- No auto-apply of patches
- Operator identity sent only as `X-BlueStrix-Operator` for write actions
- Approval tokens are never displayed after submit; backend stores SHA-256 only

## Roles

| Role | Capabilities |
|------|----------------|
| `admin` | Full UI access |
| `security_analyst` | Findings, scans, audit, propose remediation |
| `protocol_owner` | Approvals, findings review |
| `incident_responder` | Findings, audit, high-severity focus |

## Setup

```bash
cd dashboard
cp .env.example .env.local
npm install
npm run dev
```

Requires BlueStrix API on `NEXT_PUBLIC_BLUESTRIX_API_URL` (default `http://127.0.0.1:8787`).

## Pages

- `/login` — role selection + demo credential
- `/dashboard` — severity summary
- `/findings` — list + filters
- `/findings/[id]` — detail
- `/scans` — scan history (from API when available)
- `/approvals` — remediation proposals & approvals
- `/audit` — audit trail
- `/settings` — operator preferences (no secrets)
