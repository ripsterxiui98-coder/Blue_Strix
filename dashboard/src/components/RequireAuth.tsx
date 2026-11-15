"use client";

import { useSession } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { Shell } from "./Shell";
import { can, type Permission } from "@/lib/roles";

export function RequireAuth({
  children,
  permission,
}: {
  children: React.ReactNode;
  permission?: Permission;
}) {
  const { data, status } = useSession();
  const router = useRouter();

  useEffect(() => {
    if (status === "unauthenticated") {
      router.replace("/login");
    }
  }, [status, router]);

  if (status === "loading") {
    return <div className="p-8 text-slate-400">Loading session…</div>;
  }
  if (!data?.user) return null;

  if (permission && !can(data.user.role, permission)) {
    return (
      <Shell>
        <div className="rounded border border-amber-700/50 bg-amber-950/30 p-4">
          Access denied for role <code>{data.user.role}</code>.
        </div>
      </Shell>
    );
  }

  return <Shell>{children}</Shell>;
}
