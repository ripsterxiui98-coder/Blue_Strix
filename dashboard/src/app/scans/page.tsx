"use client";

import { useQuery } from "@tanstack/react-query";
import { RequireAuth } from "@/components/RequireAuth";
import { fetchFindings, fetchHealth } from "@/lib/api";

/**
 * Scan history is derived from persisted findings until a dedicated /scans
 * list endpoint is added. Shows API health and finding volume as proxy.
 */
export default function ScansPage() {
  const health = useQuery({ queryKey: ["health"], queryFn: fetchHealth });
  const findings = useQuery({ queryKey: ["findings"], queryFn: () => fetchFindings() });

  return (
    <RequireAuth permission="view_scans">
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold">Scan history</h1>
        <p className="text-sm text-slate-400">
          Persisted scan runs are stored in PostgreSQL via the BlueStrix API. This view shows
          connectivity and current finding inventory (read-only).
        </p>
        <div className="rounded border border-slate-800 bg-slate-900 p-4 text-sm space-y-2">
          <div>
            API status:{" "}
            {health.isError ? "down" : health.data?.status ?? "…"} (
            {health.data?.mode ?? "n/a"})
          </div>
          <div>Tracked findings: {findings.data?.count ?? 0}</div>
          <div className="text-slate-500">
            Trigger new scans via CLI:{" "}
            <code>bluestrix scan code ./src</code> or API <code>POST /scan/code</code> with{" "}
            <code>persist: true</code>.
          </div>
        </div>
      </div>
    </RequireAuth>
  );
}
