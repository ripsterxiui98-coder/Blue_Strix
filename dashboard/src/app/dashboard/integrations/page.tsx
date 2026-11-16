"use client";

import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Bug,
  CheckCircle2,
  FileText,
  Github,
  HardDrive,
  ListChecks,
  Loader2,
  Search,
  Slack,
  Webhook,
  type LucideIcon,
} from "lucide-react";
import { GatewayShell } from "@/components/GatewayShell";

type ConnectState = "idle" | "connecting" | "connected";

type Integration = {
  id: string;
  name: string;
  description: string;
  icon: LucideIcon;
};

/** Dummy catalog — wire to the BlueStrix API when integration endpoints are exposed. */
const INTEGRATIONS: Integration[] = [
  { id: "github", name: "GitHub", description: "Sync repositories and pull requests", icon: Github },
  { id: "slack", name: "Slack", description: "Send finding alerts to your channels", icon: Slack },
  { id: "notion", name: "Notion", description: "Export reports to your workspace", icon: FileText },
  { id: "linear", name: "Linear", description: "Create issues from security findings", icon: ListChecks },
  { id: "gdrive", name: "Google Drive", description: "Store and share audit reports", icon: HardDrive },
  { id: "sentry", name: "Sentry", description: "Correlate runtime errors with findings", icon: Bug },
];

const CONNECT_DELAY_MS = 1500;

function ConnectControl({ state, onConnect }: { state: ConnectState; onConnect: () => void }) {
  return (
    <AnimatePresence mode="wait" initial={false}>
      {state === "connected" ? (
        <motion.span
          key="connected"
          initial={{ opacity: 0, scale: 0.85 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.85 }}
          transition={{ duration: 0.15 }}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-400"
        >
          <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
          Connected
        </motion.span>
      ) : (
        <motion.button
          key={state}
          type="button"
          onClick={onConnect}
          disabled={state === "connecting"}
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.9 }}
          transition={{ duration: 0.15 }}
          whileTap={state === "idle" ? { scale: 0.95 } : undefined}
          className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-blue-600 px-3 py-1.5 text-sm font-medium text-white transition-shadow enabled:hover:bg-blue-500 enabled:hover:shadow-[0_0_15px_rgba(59,130,246,0.5)] disabled:cursor-wait disabled:opacity-80"
        >
          {state === "connecting" && <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" />}
          {state === "connecting" ? "Connecting..." : "Connect"}
        </motion.button>
      )}
    </AnimatePresence>
  );
}

function IntegrationCard({
  item,
  state,
  onConnect,
}: {
  item: Integration;
  state: ConnectState;
  onConnect: (id: string) => void;
}) {
  const Icon = item.icon;
  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.95 }}
      whileHover={{ y: -2 }}
      transition={{ duration: 0.2 }}
      className="group flex items-center gap-4 rounded-xl border border-slate-800 bg-slate-900/60 p-4 backdrop-blur-xl transition-[border-color,box-shadow] duration-200 hover:border-blue-500 hover:shadow-[0_0_15px_rgba(59,130,246,0.5)]"
    >
      <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-blue-950 ring-1 ring-blue-500/20 transition group-hover:ring-blue-500/60">
        <Icon className="h-5 w-5 text-blue-400" aria-hidden="true" />
      </div>
      <div className="min-w-0 flex-1">
        <div className="truncate font-medium text-slate-100">{item.name}</div>
        <p className="truncate text-sm text-slate-400">{item.description}</p>
      </div>
      <ConnectControl state={state} onConnect={() => onConnect(item.id)} />
    </motion.div>
  );
}

function WebhookCard() {
  const [url, setUrl] = useState("");
  const [saved, setSaved] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    setSaved(false);
    try {
      const parsed = new URL(url.trim());
      if (parsed.protocol !== "https:") throw new Error("https only");
      // UI preview: persist through the BlueStrix API once an endpoint exists.
      setError(null);
      setSaved(true);
    } catch {
      setError("Enter a valid https:// URL.");
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: 0.1 }}
      className="rounded-xl border border-blue-900/50 bg-slate-900/60 p-5 backdrop-blur-xl transition-[border-color,box-shadow] duration-200 hover:border-blue-500 hover:shadow-[0_0_15px_rgba(59,130,246,0.5)]"
    >
      <div className="flex items-center gap-4">
        <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-blue-950 ring-1 ring-blue-500/20">
          <Webhook className="h-5 w-5 text-blue-400" aria-hidden="true" />
        </div>
        <div>
          <div className="font-medium text-slate-100">Custom Webhook</div>
          <p className="text-sm text-slate-400">Send BlueStrix events to any endpoint you control</p>
        </div>
      </div>

      <form onSubmit={onSubmit} className="mt-4 flex flex-col gap-2 sm:flex-row">
        <input
          type="url"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            setSaved(false);
            setError(null);
          }}
          placeholder="https://example.com/hooks/bluestrix"
          aria-label="Webhook URL"
          className="flex-1 rounded-lg border border-slate-700 bg-black/60 px-3 py-2 font-mono text-sm text-slate-100 placeholder:text-slate-600 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
        />
        <button
          type="submit"
          disabled={!url.trim()}
          className="inline-flex items-center justify-center gap-1.5 rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white transition-shadow enabled:hover:bg-blue-500 enabled:hover:shadow-[0_0_15px_rgba(59,130,246,0.5)] disabled:cursor-not-allowed disabled:opacity-50"
        >
          Save Webhook
        </button>
      </form>

      <div aria-live="polite" className="mt-2 text-xs">
        {error && <p className="text-red-400">{error}</p>}
        {saved && (
          <p className="inline-flex items-center gap-1.5 text-emerald-400">
            <CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" />
            Webhook saved (preview only, not persisted yet).
          </p>
        )}
      </div>
    </motion.div>
  );
}

export default function IntegrationsPage() {
  const [query, setQuery] = useState("");
  const [states, setStates] = useState<Record<string, ConnectState>>({});
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => {
    const pending = timers.current;
    return () => pending.forEach(clearTimeout);
  }, []);

  function connect(id: string) {
    if (states[id] === "connecting" || states[id] === "connected") return;
    setStates((s) => ({ ...s, [id]: "connecting" }));
    const t = setTimeout(() => setStates((s) => ({ ...s, [id]: "connected" })), CONNECT_DELAY_MS);
    timers.current.push(t);
  }

  const items = useMemo(() => {
    const q = query.trim().toLowerCase();
    return INTEGRATIONS.filter(
      (i) => !q || i.name.toLowerCase().includes(q) || i.description.toLowerCase().includes(q),
    );
  }, [query]);

  return (
    <GatewayShell>
      <div className="space-y-6">
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}>
          <h1 className="text-2xl font-semibold tracking-tight text-white">Integrations</h1>
          <p className="mt-1 text-sm text-slate-400">Connect your favorite tools to BlueStrix</p>
        </motion.div>

        <div className="relative">
          <Search
            className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500"
            aria-hidden="true"
          />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search integrations..."
            aria-label="Search integrations"
            className="w-full rounded-xl border border-slate-800 bg-slate-900/60 py-2.5 pl-9 pr-3 text-sm text-slate-100 backdrop-blur-xl placeholder:text-slate-500 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
          />
        </div>

        {items.length > 0 ? (
          <motion.div layout className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <AnimatePresence mode="popLayout">
              {items.map((item) => (
                <IntegrationCard key={item.id} item={item} state={states[item.id] ?? "idle"} onConnect={connect} />
              ))}
            </AnimatePresence>
          </motion.div>
        ) : (
          <div className="rounded-xl border border-dashed border-slate-800 p-8 text-center text-sm text-slate-500">
            No integrations match &ldquo;{query}&rdquo;.
          </div>
        )}

        <WebhookCard />
      </div>
    </GatewayShell>
  );
}
