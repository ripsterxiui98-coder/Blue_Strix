"use client";

import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { ALL_ROLES, type Role } from "@/lib/roles";

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState("analyst");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("security_analyst");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    const res = await signIn("credentials", {
      username,
      password,
      role,
      redirect: false,
    });
    setLoading(false);
    if (res?.error) {
      setError("Invalid credentials or role");
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
          <h1 className="text-2xl font-semibold">BlueStrix Login</h1>
          <p className="text-sm text-slate-400 mt-1">
            Defensive access only. No private keys. Demo password from{" "}
            <code>DASHBOARD_DEMO_PASSWORD</code>.
          </p>
        </div>
        <label className="block text-sm">
          Operator name
          <input
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
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
          />
        </label>
        <label className="block text-sm">
          Role
          <select
            className="mt-1 w-full rounded border border-slate-700 bg-slate-950 px-3 py-2"
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
          >
            {ALL_ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
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
