"use client";

import { useQuery } from "@tanstack/react-query";
import { RequireAuth } from "@/components/RequireAuth";
import { fetchFindings, fetchHealth } from "@/lib/api";

function SeverityCard({ label, count, tone }: { label: string; count: number; tone: string }) {
  return (
    <div className={`rounded-lg border border-slate-800 bg-slate-900 p-4 ${tone}`}>
      <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
      <div className="text-3xl font-semibold mt-1">{count}</div>
    </div>
  );
}

export default function DashboardPage() {
  const health = useQuery({ queryKey: ["health"], queryFn: fetchHealth, retry: 1 });
  const findings = useQuery({ queryKey: ["findings"], queryFn: () => fetchFindings() });

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, other: 0 };
  for (const f of findings.data?.findings ?? []) {
    const s = (f.severity || "INFO").toUpperCase();
    if (s in counts) counts[s as keyof typeof counts] += 1;
    else counts.other += 1;
  }
  const open = (findings.data?.findings ?? []).filter((f) => f.status === "open").length;

  return (
    <RequireAuth permission="view_dashboard">
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-semibold">Risk overview</h1>
          <p className="text-slate-400 text-sm">
            API:{" "}
            {health.isLoading
              ? "checking…"
              : health.isError
                ? "unreachable (start bluestrix api)"
                : `${health.data?.status} / ${health.data?.mode}`}
          </p>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          <SeverityCard label="Critical" count={counts.CRITICAL} tone="border-red-900/60" />
          <SeverityCard label="High" count={counts.HIGH} tone="border-orange-900/60" />
          <SeverityCard label="Medium" count={counts.MEDIUM} tone="border-yellow-900/40" />
          <SeverityCard label="Low" count={counts.LOW} tone="" />
          <SeverityCard label="Info" count={counts.INFO} tone="" />
          <SeverityCard label="Open" count={open} tone="border-brand-700/40" />
        </div>
        <div className="rounded-lg border border-slate-800 bg-slate-900 p-4 text-sm text-slate-300">
          Total findings: <strong>{findings.data?.count ?? 0}</strong>. Dashboard is read-only by
          default; remediation requires human approval.
        </div>
      </div>
    </RequireAuth>
  );
}
