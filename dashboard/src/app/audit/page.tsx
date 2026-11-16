"use client";

import { useQuery } from "@tanstack/react-query";
import { RequireAuth } from "@/components/RequireAuth";
import { fetchAudit } from "@/lib/api";

export default function AuditPage() {
  const audit = useQuery({ queryKey: ["audit"], queryFn: () => fetchAudit(100) });

  return (
    <RequireAuth permission="view_audit">
      <div className="space-y-4">
        <h1 className="text-2xl font-semibold">Audit trail</h1>
        <p className="text-sm text-slate-400">Append-only style events from the BlueStrix API.</p>
        <div className="overflow-x-auto rounded border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-left text-slate-400">
              <tr>
                <th className="px-3 py-2">Time</th>
                <th className="px-3 py-2">Actor</th>
                <th className="px-3 py-2">Action</th>
                <th className="px-3 py-2">Target</th>
                <th className="px-3 py-2">Decision</th>
              </tr>
            </thead>
            <tbody>
              {(audit.data?.events ?? []).map((e, i) => (
                <tr key={String(e.id ?? i)} className="border-t border-slate-800">
                  <td className="px-3 py-2 text-xs">{String(e.timestamp ?? "")}</td>
                  <td className="px-3 py-2">{String(e.actor ?? "")}</td>
                  <td className="px-3 py-2">{String(e.action ?? "")}</td>
                  <td className="px-3 py-2 font-mono text-xs">{String(e.target ?? "")}</td>
                  <td className="px-3 py-2">{String(e.decision ?? "")}</td>
                </tr>
              ))}
              {!audit.isLoading && (audit.data?.events?.length ?? 0) === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-6 text-center text-slate-500">
                    No audit events
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
