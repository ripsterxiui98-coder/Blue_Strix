"use client";

import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { BlueStrixMark } from "@/components/BlueStrixMark";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const res = await signIn("credentials", {
      email,
      password,
      mfaCode: mfaCode || undefined,
      redirect: false,
    });
    setLoading(false);
    if (res?.error) {
      setError("Login failed. Check email, password, MFA, or rate limits.");
      return;
    }
    router.replace("/dashboard");
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-6">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-md space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-8 shadow-xl"
      >
        <div>
          <BlueStrixMark className="mb-3 h-12 w-12" />
          <h1 className="text-2xl font-semibold">BlueStrix Login</h1>
          <p className="text-sm text-slate-400 mt-1">
            Production auth via API. No default passwords. Admin requires MFA TOTP.
          </p>
        </div>
        <label className="block text-sm">
          Email
          <input
            type="email"
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="username"
          />
        </label>
        <label className="block text-sm">
          Password
          <input
            type="password"
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
          />
        </label>
        <label className="block text-sm">
          MFA code (required for admin)
          <input
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value)}
            inputMode="numeric"
            autoComplete="one-time-code"
          />
        </label>
        {error && <p className="text-sm text-red-400">{error}</p>}
        <button
          type="submit"
          disabled={loading}
          className="w-full rounded bg-brand-700 py-2 font-medium hover:bg-brand-500 disabled:opacity-50"
        >
          {loading ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
