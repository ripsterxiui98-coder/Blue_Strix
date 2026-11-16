"use client";

import Link from "next/link";
import { useMemo, useState } from "react";

/** Static catalog preview — wire to API when marketplace endpoints are exposed. */
const SAMPLE = [
  {
    plugin_id: "bluestrix-community-examples",
    name: "Community examples",
    version: "1.0.0",
    kind: "custom",
    description: "Example declarative rules (tx.origin, eval).",
    chains: ["evm"],
  },
  {
    plugin_id: "multichain-signals",
    name: "Multi-chain signal pack",
    version: "0.1.0",
    kind: "community",
    description: "Sui / Aptos / TON / Cosmos classifiers metadata.",
    chains: ["sui", "aptos", "ton", "cosmos"],
  },
];

export default function MarketplacePage() {
  const [q, setQ] = useState("");
  const items = useMemo(() => {
    const qq = q.toLowerCase();
    return SAMPLE.filter(
      (p) =>
        !qq ||
        p.name.toLowerCase().includes(qq) ||
        p.description.toLowerCase().includes(qq) ||
        p.plugin_id.includes(qq),
    );
  }, [q]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
      <div className="max-w-3xl mx-auto space-y-6">
        <div>
          <h1 className="text-2xl font-semibold">Plugin marketplace</h1>
          <p className="text-sm text-slate-400 mt-1">
            Defensive rule packs only. Install runs through BlueStrix sandbox + signature checks.
            No auto-remediation.
          </p>
        </div>
        <input
          className="w-full rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
          placeholder="Search plugins…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <ul className="space-y-3">
          {items.map((p) => (
            <li
              key={p.plugin_id}
              className="rounded border border-slate-800 bg-slate-900 p-4 hover:border-slate-600"
            >
              <Link href={`/marketplace/${encodeURIComponent(p.plugin_id)}`} className="block">
                <div className="flex justify-between gap-2">
                  <span className="font-medium">{p.name}</span>
                  <span className="text-xs text-slate-400">{p.version}</span>
                </div>
                <p className="text-sm text-slate-400 mt-1">{p.description}</p>
                <div className="text-xs text-slate-500 mt-2">
                  {p.kind} · {p.chains.join(", ") || "any"}
                </div>
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
