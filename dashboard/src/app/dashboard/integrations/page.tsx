"use client";

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  Bug,
  FileText,
  Github,
  HardDrive,
  ListChecks,
  Search,
  Slack,
  Webhook,
  type LucideIcon,
} from "lucide-react";
import { GatewayShell } from "@/components/GatewayShell";

type Integration = {
  id: string;
  name: string;
  description: string;
  icon: LucideIcon;
};

/**
 * Integration catalog. None of these connectors are wired to the BlueStrix API yet,
 * so Connect is disabled instead of simulating a connection.
 */
const INTEGRATIONS: Integration[] = [
  { id: "github", name: "GitHub", description: "Sync repositories and pull requests", icon: Github },
  { id: "slack", name: "Slack", description: "Send finding alerts to your channels", icon: Slack },
  { id: "notion", name: "Notion", description: "Export reports to your workspace", icon: FileText },
  { id: "linear", name: "Linear", description: "Create issues from security findings", icon: ListChecks },
  { id: "gdrive", name: "Google Drive", description: "Store and share audit reports", icon: HardDrive },
  { id: "sentry", name: "Sentry", description: "Correlate runtime errors with findings", icon: Bug },
];

function IntegrationCard({ item }: { item: Integration }) {
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
      <button
        type="button"
        disabled
        aria-label={`Connect ${item.name} (not available yet)`}
        title="Integration is not available yet"
        className="inline-flex shrink-0 cursor-not-allowed items-center rounded-lg border border-slate-700 px-3 py-1.5 text-sm text-slate-500"
      >
        Not available yet
      </button>
    </motion.div>
  );
}

function WebhookCard() {
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: 0.1 }}
      className="rounded-xl border border-blue-900/50 bg-slate-900/60 p-5 backdrop-blur-xl"
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
      <p className="mt-4 text-sm text-slate-500">
        Webhook delivery is not available yet. The BlueStrix API needs a storage endpoint for webhooks first.
      </p>
      <div className="mt-2 flex flex-col gap-2 sm:flex-row">
        <input
          type="url"
          disabled
          placeholder="https://example.com/hooks/bluestrix"
          aria-label="Webhook URL"
          className="flex-1 rounded-lg border border-slate-700 bg-black/60 px-3 py-2 font-mono text-sm text-slate-100 placeholder:text-slate-600 disabled:cursor-not-allowed disabled:opacity-50"
        />
        <button
          type="button"
          disabled
          title="Webhook saving is not available yet"
          className="inline-flex items-center justify-center rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-500 disabled:cursor-not-allowed"
        >
          Save Webhook
        </button>
      </div>
    </motion.div>
  );
}

export default function IntegrationsPage() {
  const [query, setQuery] = useState("");

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
            {items.map((item) => (
              <IntegrationCard key={item.id} item={item} />
            ))}
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
