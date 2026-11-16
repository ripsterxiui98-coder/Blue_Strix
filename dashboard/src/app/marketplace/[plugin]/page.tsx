"use client";

import Link from "next/link";
import { useParams } from "next/navigation";

export default function MarketplacePluginPage() {
  const params = useParams();
  const pluginId = decodeURIComponent(String(params.plugin || ""));

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-6">
      <div className="max-w-xl mx-auto space-y-4">
        <Link href="/marketplace" className="text-sm text-sky-400">
          ← Marketplace
        </Link>
        <h1 className="text-2xl font-semibold font-mono">{pluginId}</h1>
        <p className="text-sm text-slate-400">
          Install / update / uninstall are performed by the BlueStrix CLI or API using{" "}
          <code>PluginLoader</code> (sandbox mandatory). Community packs need HMAC signature.
        </p>
        <div className="rounded border border-slate-800 bg-slate-900 p-4 space-y-2">
          <h2 className="font-medium">Rate</h2>
          <p className="text-sm text-slate-500">
            Ratings are not available yet. They need the <code>POST /marketplace/rate</code> endpoint.
          </p>
          <input
            type="number"
            disabled
            placeholder="1-5"
            aria-label="Rating"
            className="w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm disabled:opacity-50"
          />
          <button
            type="button"
            disabled
            title="Ratings are not available yet"
            className="ml-2 rounded bg-sky-700 px-3 py-1 text-sm disabled:cursor-not-allowed disabled:opacity-50"
          >
            Submit rating
          </button>
        </div>
        <div className="rounded border border-slate-800 bg-slate-900 p-4 space-y-2">
          <h2 className="font-medium">Review</h2>
          <p className="text-sm text-slate-500">
            Reviews are not available yet. They need the marketplace review endpoint.
          </p>
          <textarea
            disabled
            aria-label="Review"
            className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm disabled:opacity-50"
            rows={3}
            placeholder="Evidence-based review…"
          />
          <button
            type="button"
            disabled
            title="Reviews are not available yet"
            className="rounded bg-sky-700 px-3 py-1 text-sm disabled:cursor-not-allowed disabled:opacity-50"
          >
            Submit review
          </button>
        </div>
      </div>
    </div>
  );
}
