"use client";

import Link from "next/link";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { RequireAuth } from "@/components/RequireAuth";
import { fetchFindings } from "@/lib/api";

export default function FindingsPage() {
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const query = useQuery({
    queryKey: ["findings", severity, status],
    queryFn: () =>
      fetchFindings({
        severity: severity || undefined,
        status: status || undefined,
      }),
  });

  return (
    <RequireAuth permission="view_findings">
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold">Findings</h1>
        <div className="flex flex-wrap gap-3">
          <select
            className="rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
          >
            <option value="">All severities</option>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
          <select
            className="rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="">All statuses</option>
            {["open", "fixed", "false_positive", "accepted_risk"].map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        {query.isError && (
          <p className="text-sm text-amber-400">Unable to load findings from API.</p>
        )}
        <div className="overflow-x-auto rounded border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-left text-slate-400">
              <tr>
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">Title</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Target</th>
              </tr>
            </thead>
            <tbody>
              {(query.data?.findings ?? []).map((f) => (
                <tr key={f.finding_id} className="border-t border-slate-800 hover:bg-slate-900/60">
                  <td className="px-3 py-2 font-mono text-xs">
                    <Link href={`/findings/${encodeURIComponent(f.finding_id)}`}>
                      {f.finding_id}
                    </Link>
                  </td>
                  <td className="px-3 py-2">{f.title}</td>
                  <td className="px-3 py-2">{f.severity}</td>
                  <td className="px-3 py-2">{f.status}</td>
                  <td className="px-3 py-2 font-mono text-xs">{f.target}</td>
                </tr>
              ))}
              {!query.isLoading && (query.data?.findings?.length ?? 0) === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                    No findings
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </RequireAuth>
  );
}
