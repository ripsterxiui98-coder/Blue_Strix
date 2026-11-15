"use client";

import { useSession } from "next-auth/react";
import { RequireAuth } from "@/components/RequireAuth";
import { API_URL } from "@/lib/api";

export default function SettingsPage() {
  const { data } = useSession();

  return (
    <RequireAuth permission="view_dashboard">
      <div className="space-y-4 max-w-xl">
        <h1 className="text-2xl font-semibold">Settings</h1>
        <div className="rounded border border-slate-800 bg-slate-900 p-4 text-sm space-y-2">
          <div>
            Operator: <strong>{data?.user?.name}</strong>
          </div>
          <div>
            Role: <code>{data?.user?.role}</code>
          </div>
          <div>
            API base: <code>{API_URL}</code>
          </div>
          <p className="text-slate-400 pt-2">
            BlueStrix does not store private keys, mnemonics, or seed phrases in the dashboard.
            Remediation is proposal-only until human approval.
          </p>
        </div>
      </div>
    </RequireAuth>
  );
}
