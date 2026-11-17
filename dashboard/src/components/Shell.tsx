"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import { useState } from "react";
import { can, type Permission } from "@/lib/roles";
import { accessTokenOf } from "@/lib/api";

const nav: { href: string; label: string; permission: Permission }[] = [
  { href: "/dashboard", label: "Dashboard", permission: "view_dashboard" },
  { href: "/findings", label: "Findings", permission: "view_findings" },
  { href: "/scans", label: "Scans", permission: "view_scans" },
  { href: "/approvals", label: "Approvals", permission: "view_approvals" },
  { href: "/audit", label: "Audit", permission: "view_audit" },
  { href: "/settings", label: "Settings", permission: "view_dashboard" },
];

async function secureSignOut(accessToken: string) {
  // 1) Revoke server session + refresh cookie
  try {
    await fetch("/api/auth/logout", {
      method: "POST",
      headers: {
        Authorization: accessToken ? `Bearer ${accessToken}` : "",
        Accept: "application/json",
      },
    });
  } catch {
    // Continue — client session must still be cleared
  }
  // 2) Clear NextAuth JWT / cookies
  await signOut({ callbackUrl: "/login" });
}

export function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { data } = useSession();
  const role = data?.user?.role;
  const [loggingOut, setLoggingOut] = useState(false);

  async function handleLogout() {
    if (loggingOut) return;
    setLoggingOut(true);
    await secureSignOut(accessTokenOf(data));
  }

  return (
    <div className="min-h-screen flex">
      <aside className="w-56 border-r border-slate-800 bg-slate-900/80 p-4 flex flex-col gap-2">
        <div className="mb-4">
          <div className="text-lg font-semibold text-brand-100">BlueStrix</div>
          <div className="text-xs text-slate-400">Defensive dashboard</div>
        </div>
        {nav.map((item) => {
          if (!can(role, item.permission)) return null;
          const active =
            pathname === item.href || pathname.startsWith(item.href + "/");
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`rounded px-3 py-2 text-sm ${
                active
                  ? "bg-brand-700 text-white"
                  : "text-slate-300 hover:bg-slate-800"
              }`}
            >
              {item.label}
            </Link>
          );
        })}
        <div className="mt-auto pt-4 border-t border-slate-800 text-xs text-slate-400">
          <div className="truncate">{data?.user?.name}</div>
          <div className="font-mono">{role}</div>
          <button
            type="button"
            className="mt-2 text-brand-500 hover:text-brand-400 disabled:opacity-50"
            onClick={handleLogout}
            disabled={loggingOut}
          >
            {loggingOut ? "Signing out…" : "Sign out"}
          </button>
        </div>
      </aside>
      <main className="flex-1 p-6 overflow-auto">{children}</main>
    </div>
  );
}
