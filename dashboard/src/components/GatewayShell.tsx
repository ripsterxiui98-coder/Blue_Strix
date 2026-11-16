"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import { AnimatePresence, motion } from "framer-motion";
import { useEffect, useState, type ReactNode } from "react";
import {
  Bot,
  CreditCard,
  LayoutDashboard,
  LogOut,
  Menu,
  MessageSquare,
  Puzzle,
  User,
  X,
  type LucideIcon,
} from "lucide-react";
import { can } from "@/lib/roles";
import { BlueStrixMark } from "@/components/BlueStrixMark";

type NavItem = {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Match the path exactly (needed because /dashboard is a prefix of /dashboard/integrations). */
  exact?: boolean;
  /** Page does not exist yet. */
  disabled?: boolean;
};

const NAV: NavItem[] = [
  { href: "/overview", label: "Dashboard", icon: LayoutDashboard },
  { href: "/dashboard", label: "Agents", icon: Bot, exact: true },
  { href: "/dashboard/integrations", label: "Integrations", icon: Puzzle },
  { href: "/settings", label: "Account", icon: User },
  { href: "#", label: "Billing", icon: CreditCard, disabled: true },
];

type AgentSession = { id: string; title: string; when: string };

/** Dummy history — wire to the API when agent sessions are persisted. */
const SESSIONS: AgentSession[] = [
  { id: "s1", title: "Audit ERC-20 approval flow", when: "2m ago" },
  { id: "s2", title: "Review gateway redaction rules", when: "1h ago" },
  { id: "s3", title: "Explain Slither finding #42", when: "Yesterday" },
  { id: "s4", title: "Draft patch for tx.origin usage", when: "Yesterday" },
  { id: "s5", title: "Triage Solana wallet alerts", when: "3d ago" },
];

function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <BlueStrixMark className="h-9 w-9 shrink-0 drop-shadow-[0_0_10px_rgba(59,130,246,0.6)]" />
      <div className="leading-tight">
        <div className="text-base font-semibold tracking-tight text-white">BlueStrix</div>
        <div className="font-mono text-[10px] uppercase tracking-widest text-blue-400/80">
          AI Security Gateway
        </div>
      </div>
    </div>
  );
}

function SidebarContent({
  idPrefix,
  onNavigate,
}: {
  idPrefix: string;
  onNavigate?: () => void;
}) {
  const pathname = usePathname();
  const { data } = useSession();

  return (
    <div className="flex h-full flex-col">
      <div className="px-5 py-5">
        <Logo />
      </div>

      <nav className="flex flex-col gap-1 px-3" aria-label="Main">
        {NAV.map((item) => {
          const Icon = item.icon;
          const active =
            !item.disabled &&
            (item.exact
              ? pathname === item.href
              : pathname === item.href || pathname.startsWith(item.href + "/"));

          if (item.disabled) {
            return (
              <span
                key={item.label}
                aria-disabled="true"
                className="flex cursor-not-allowed items-center gap-3 rounded-lg px-3 py-2 text-sm text-slate-600"
              >
                <Icon className="h-4 w-4" aria-hidden="true" />
                {item.label}
                <span className="ml-auto rounded bg-slate-900 px-1.5 py-0.5 font-mono text-[10px] text-slate-500">
                  soon
                </span>
              </span>
            );
          }

          return (
            <Link
              key={item.label}
              href={item.href}
              onClick={onNavigate}
              aria-current={active ? "page" : undefined}
              className={`relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
                active ? "text-blue-100" : "text-slate-400 hover:bg-slate-900/80 hover:text-slate-100"
              }`}
            >
              {active && (
                <motion.span
                  layoutId={`${idPrefix}-active`}
                  className="absolute inset-0 rounded-lg border border-blue-800/60 bg-blue-950/80 shadow-[0_0_15px_rgba(59,130,246,0.25)]"
                  transition={{ type: "spring", stiffness: 380, damping: 32 }}
                />
              )}
              <Icon
                className={`relative h-4 w-4 ${active ? "text-blue-400" : ""}`}
                aria-hidden="true"
              />
              <span className="relative">{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <div className="mt-auto space-y-3 p-3">
        <div className="rounded-xl border border-blue-900/50 bg-slate-900/50 p-3 backdrop-blur-xl">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs font-medium text-slate-200">Agent Sessions</span>
            <span className="font-mono text-[10px] text-slate-500">{SESSIONS.length}</span>
          </div>
          <ul className="max-h-44 space-y-0.5 overflow-y-auto pr-1">
            {SESSIONS.map((s) => (
              <li key={s.id}>
                <button
                  type="button"
                  disabled
                  title="Session history is not available yet"
                  className="group flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left transition enabled:hover:bg-slate-800/70 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <MessageSquare
                    className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500 transition group-hover:text-blue-400"
                    aria-hidden="true"
                  />
                  <span className="min-w-0">
                    <span className="block truncate text-xs text-slate-300">{s.title}</span>
                    <span className="block font-mono text-[10px] text-slate-600">{s.when}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>

        <div className="flex items-center gap-2 border-t border-slate-800 px-1 pt-3">
          <div className="min-w-0 flex-1">
            <div className="truncate text-xs text-slate-300">{data?.user?.name}</div>
            <div className="font-mono text-[10px] text-slate-500">{data?.user?.role}</div>
          </div>
          <button
            type="button"
            onClick={() => signOut({ callbackUrl: "/login" })}
            aria-label="Sign out"
            className="rounded-md p-2 text-slate-500 transition hover:bg-slate-800 hover:text-blue-400"
          >
            <LogOut className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Layout for the gateway pages: auth gate + fixed sidebar (desktop) / drawer (mobile).
 * Mirrors RequireAuth's behaviour (session check + `view_dashboard` permission).
 */
export function GatewayShell({ children }: { children: ReactNode }) {
  const { data, status } = useSession();
  const router = useRouter();
  const pathname = usePathname();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (status === "unauthenticated") router.replace("/login");
  }, [status, router]);

  // Close the drawer after navigating.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  if (status === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#09090b] text-sm text-slate-400">
        Loading session…
      </div>
    );
  }
  if (!data?.user) return null;

  const allowed = can(data.user.role, "view_dashboard");

  return (
    <div className="relative min-h-screen bg-[#09090b] font-sans text-slate-100">
      {/* ambient glow */}
      <div
        aria-hidden="true"
        className="pointer-events-none fixed inset-x-0 top-0 h-80 bg-[radial-gradient(ellipse_at_top,rgba(37,99,235,0.14),transparent_70%)]"
      />

      {/* Desktop sidebar */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 border-r border-slate-800 bg-black/70 backdrop-blur-xl lg:block">
        <SidebarContent idPrefix="desktop" />
      </aside>

      {/* Mobile top bar */}
      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-slate-800 bg-black/60 px-4 py-3 backdrop-blur-xl lg:hidden">
        <Logo />
        <button
          type="button"
          onClick={() => setOpen(true)}
          aria-label="Open menu"
          aria-expanded={open}
          className="rounded-lg border border-slate-800 p-2 text-slate-300 transition hover:border-blue-500/60 hover:text-blue-400"
        >
          <Menu className="h-5 w-5" aria-hidden="true" />
        </button>
      </header>

      {/* Mobile drawer */}
      <AnimatePresence>
        {open && (
          <>
            <motion.div
              key="overlay"
              className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm lg:hidden"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setOpen(false)}
              aria-hidden="true"
            />
            <motion.aside
              key="drawer"
              className="fixed inset-y-0 left-0 z-50 w-64 border-r border-slate-800 bg-[#050507] lg:hidden"
              initial={{ x: -256 }}
              animate={{ x: 0 }}
              exit={{ x: -256 }}
              transition={{ type: "spring", stiffness: 380, damping: 36 }}
            >
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-label="Close menu"
                className="absolute right-3 top-4 rounded-md p-1.5 text-slate-500 transition hover:text-slate-200"
              >
                <X className="h-4 w-4" aria-hidden="true" />
              </button>
              <SidebarContent idPrefix="mobile" onNavigate={() => setOpen(false)} />
            </motion.aside>
          </>
        )}
      </AnimatePresence>

      <main className="relative lg:pl-64">
        <div className="mx-auto max-w-5xl px-4 py-8 sm:px-8 lg:py-12">
          {allowed ? (
            children
          ) : (
            <div className="rounded-xl border border-amber-700/50 bg-amber-950/30 p-4 text-sm">
              Access denied for role <code className="font-mono">{data.user.role}</code>.
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
