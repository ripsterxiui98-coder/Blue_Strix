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
      email: email.trim().toLowerCase(),
      password,
      mfaCode: mfaCode.trim() || undefined,
      redirect: false,
    });

    setLoading(false);

    if (res?.error) {
      setError(
        "Login gagal. Periksa email, password, kode MFA (wajib untuk admin), atau coba lagi setelah rate limit.",
      );
      return;
    }

    // Controlled redirect only after successful session
    router.replace("/dashboard");
    router.refresh();
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-6 bg-[#09090b]">
      <form
        onSubmit={onSubmit}
        className="w-full max-w-md space-y-4 rounded-xl border border-slate-800 bg-slate-900/90 p-8 shadow-xl backdrop-blur"
        noValidate
      >
        <div>
          <BlueStrixMark className="mb-3 h-12 w-12" />
          <h1 className="text-2xl font-semibold text-white">BlueStrix Login</h1>
          <p className="text-sm text-slate-400 mt-1">
            Auth produksi via API. Tidak ada password default. Admin wajib MFA TOTP.
          </p>
        </div>

        <label className="block text-sm text-slate-300">
          Email
          <input
            type="email"
            name="email"
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            autoComplete="username"
            autoFocus
            disabled={loading}
          />
        </label>

        <label className="block text-sm text-slate-300">
          Password
          <input
            type="password"
            name="password"
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete="current-password"
            disabled={loading}
            minLength={8}
          />
        </label>

        <label className="block text-sm text-slate-300">
          MFA code <span className="text-slate-500">(wajib untuk admin)</span>
          <input
            type="text"
            name="mfa"
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            value={mfaCode}
            onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, "").slice(0, 8))}
            inputMode="numeric"
            pattern="[0-9]*"
            autoComplete="one-time-code"
            disabled={loading}
            placeholder="000000"
          />
        </label>

        {error && (
          <p className="text-sm text-red-400 rounded border border-red-900/50 bg-red-950/30 px-3 py-2" role="alert">
            {error}
          </p>
        )}

        <button
          type="submit"
          disabled={loading || !email.trim() || !password}
          className="w-full rounded bg-blue-600 py-2.5 font-medium text-white hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed transition"
        >
          {loading ? "Signing in…" : "Sign in"}
        </button>

        <p className="text-center text-xs text-slate-500">
          Sesi terbatas 15 menit. Logout akan mencabut token di server.
        </p>
      </form>
    </div>
  );
}
