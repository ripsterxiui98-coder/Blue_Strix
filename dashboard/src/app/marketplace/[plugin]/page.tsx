"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useState } from "react";

export default function MarketplacePluginPage() {
  const params = useParams();
  const pluginId = decodeURIComponent(String(params.plugin || ""));
  const [score, setScore] = useState(5);
  const [review, setReview] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  function onRate() {
    setMsg(`Rating ${score}/5 recorded locally (wire to API POST /marketplace/rate).`);
  }

  function onReview() {
    setMsg("Review staged locally (wire to API). Install still requires signed pack + sandbox.");
    setReview("");
  }

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
          <input
            type="number"
            min={1}
            max={5}
            value={score}
            onChange={(e) => setScore(Number(e.target.value))}
            className="w-20 rounded border border-slate-700 bg-slate-950 px-2 py-1 text-sm"
          />
          <button
            type="button"
            onClick={onRate}
            className="ml-2 rounded bg-sky-700 px-3 py-1 text-sm"
          >
            Submit rating
          </button>
        </div>
        <div className="rounded border border-slate-800 bg-slate-900 p-4 space-y-2">
          <h2 className="font-medium">Review</h2>
          <textarea
            className="w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
            rows={3}
            value={review}
            onChange={(e) => setReview(e.target.value)}
            placeholder="Evidence-based review…"
          />
          <button
            type="button"
            onClick={onReview}
            className="rounded bg-sky-700 px-3 py-1 text-sm"
          >
            Submit review
          </button>
        </div>
        {msg && <p className="text-sm text-amber-200/90">{msg}</p>}
      </div>
    </div>
  );
}
