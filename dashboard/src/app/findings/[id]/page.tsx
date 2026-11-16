"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSession } from "next-auth/react";
import { useParams } from "next/navigation";
import { RequireAuth } from "@/components/RequireAuth";
import { accessTokenOf, fetchFinding, updateFindingStatus } from "@/lib/api";
import { can } from "@/lib/roles";

export default function FindingDetailPage() {
  const params = useParams();
  const id = decodeURIComponent(String(params.id));
  const { data: session } = useSession();
  const qc = useQueryClient();
  const query = useQuery({ queryKey: ["finding", id], queryFn: () => fetchFinding(id) });

  const mutation = useMutation({
    mutationFn: (status: string) =>
      updateFindingStatus(id, status, accessTokenOf(session)),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["finding", id] }),
  });

  const f = query.data;

  return (
    <RequireAuth permission="view_findings">
      <div className="space-y-4 max-w-3xl">
        <h1 className="text-2xl font-semibold font-mono">{id}</h1>
        {query.isError && <p className="text-amber-400 text-sm">Finding not found or API error.</p>}
        {f && (
          <>
            <div className="rounded border border-slate-800 bg-slate-900 p-4 space-y-2 text-sm">
              <div>
                <span className="text-slate-400">Title:</span> {String(f.title)}
              </div>
              <div>
                <span className="text-slate-400">Severity:</span> {String(f.severity)}
              </div>
              <div>
                <span className="text-slate-400">Status:</span> {String(f.status)}
              </div>
              <div>
                <span className="text-slate-400">Target:</span>{" "}
                <code>{String(f.target)}</code>
              </div>
              <p className="text-slate-300 whitespace-pre-wrap">{String(f.description || "")}</p>
              {f.recommendation ? (
                <p className="text-slate-400">
                  <span className="text-slate-500">Recommendation:</span>{" "}
                  {String(f.recommendation)}
                </p>
              ) : null}
            </div>
            {can(session?.user?.role, "update_finding_status") && (
              <div className="flex flex-wrap gap-2">
                {["open", "fixed", "false_positive", "accepted_risk"].map((s) => (
                  <button
                    key={s}
                    type="button"
                    className="rounded border border-slate-700 px-3 py-1 text-sm hover:bg-slate-800"
                    onClick={() => mutation.mutate(s)}
                    disabled={mutation.isPending}
                  >
                    Mark {s}
                  </button>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </RequireAuth>
  );
}
