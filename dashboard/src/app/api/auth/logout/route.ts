import { NextRequest, NextResponse } from "next/server";

const API_URL =
  process.env.NEXT_PUBLIC_BLUESTRIX_API_URL?.replace(/\/$/, "") ||
  "http://127.0.0.1:8787";

/**
 * Proxy logout to BlueStrix API so the server session (and refresh cookie) is revoked.
 * Always returns a safe response so the client can clear the NextAuth cookie even if
 * the backend is unreachable.
 */
export async function POST(req: NextRequest) {
  const auth = req.headers.get("authorization") || "";
  try {
    const res = await fetch(`${API_URL}/auth/logout`, {
      method: "POST",
      headers: {
        Authorization: auth,
        Accept: "application/json",
      },
    });
    const body = await res.text();
    return new NextResponse(body || JSON.stringify({ status: "logged_out" }), {
      status: res.ok ? 200 : res.status,
      headers: { "Content-Type": "application/json" },
    });
  } catch {
    // Backend unreachable — still allow client-side session clear
    return NextResponse.json(
      { status: "logged_out", warning: "backend_unreachable" },
      { status: 200 },
    );
  }
}
