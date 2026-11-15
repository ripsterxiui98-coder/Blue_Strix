"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSession } from "next-auth/react";
import { useState } from "react";
import { RequireAuth } from "@/components/RequireAuth";
import { createApproval, createProposal, fetchProposals } from "@/lib/api";
import { can } from "@/lib/roles";

export default function ApprovalsPage() {
  const { data: session } = useSession();
  const qc = useQueryClient();
  const proposals = useQuery({ queryKey: ["proposals"], queryFn: fetchProposals });
  const [findingId, setFindingId] = useState("");
  const [title, setTitle] = useState("");
  const [target, setTarget] = useState("./");
  const [token, setToken] = useState("");

  const propose = useMutation({
    mutationFn: () =>
      createProposal(
        { finding_id: findingId, title, target, proposed_change: "See proposal title" },
        session?.user?.name || "operator",
      ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["proposals"] });
      setTitle("");
    },
  });

  const approve = useMutation({
    mutationFn: (payload: { finding_id: string; proposal_id?: string }) =>
      createApproval(
        { ...payload, status: "approved" },
        session?.user?.name || "operator",
        token || undefined,
      ),
    onSuccess: () => {
      setToken("");
      qc.invalidateQueries({ queryKey: ["proposals"] });
    },
  });

  return (
    <RequireAuth permission="view_approvals">
      <div className="space-y-6">
        <h1 className="text-2xl font-semibold">Remediation approvals</h1>
        <p className="text-sm text-slate-400">
          Human governance required. Approval tokens are sent once and stored as SHA-256 only on
          the server. No auto-apply.
        </p>

        {can(session?.user?.role, "propose_remediation") && (
          <div className="rounded border border-slate-800 bg-slate-900 p-4 space-y-2 max-w-lg">
            <h2 className="font-medium">Propose remediation</h2>
            <input
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
              placeholder="Finding ID"
              value={findingId}
              onChange={(e) => setFindingId(e.target.value)}
            />
            <input
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
              placeholder="Title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
            <input
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
              placeholder="Target path"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
            <button
              type="button"
              className="rounded bg-brand-700 px-3 py-2 text-sm"
              disabled={!findingId || !title || propose.isPending}
              onClick={() => propose.mutate()}
            >
              Submit proposal
            </button>
          </div>
        )}

        {can(session?.user?.role, "approve_remediation") && (
          <div className="rounded border border-slate-800 bg-slate-900 p-4 space-y-2 max-w-lg">
            <h2 className="font-medium">Approval token (optional)</h2>
            <input
              type="password"
              className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
              placeholder="Token is hashed server-side"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              autoComplete="off"
            />
          </div>
        )}

        <div className="overflow-x-auto rounded border border-slate-800">
          <table className="min-w-full text-sm">
            <thead className="bg-slate-900 text-left text-slate-400">
              <tr>
                <th className="px-3 py-2">ID</th>
                <th className="px-3 py-2">Finding</th>
                <th className="px-3 py-2">Title</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Action</th>
              </tr>
            </thead>
            <tbody>
              {(proposals.data?.proposals ?? []).map((p) => (
                <tr key={String(p.id)} className="border-t border-slate-800">
                  <td className="px-3 py-2 font-mono text-xs">{String(p.id).slice(0, 8)}</td>
                  <td className="px-3 py-2 font-mono text-xs">{String(p.finding_id)}</td>
                  <td className="px-3 py-2">{String(p.title)}</td>
                  <td className="px-3 py-2">{String(p.status)}</td>
                  <td className="px-3 py-2">
                    {can(session?.user?.role, "approve_remediation") && (
                      <button
                        type="button"
                        className="text-brand-500 text-xs"
                        onClick={() =>
                          approve.mutate({
                            finding_id: String(p.finding_id),
                            proposal_id: String(p.id),
                          })
                        }
                      >
                        Approve
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </RequireAuth>
  );
}
