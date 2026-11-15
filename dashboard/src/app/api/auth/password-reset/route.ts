import { NextRequest, NextResponse } from "next/server";

const API_URL =
  process.env.NEXT_PUBLIC_BLUESTRIX_API_URL?.replace(/\/$/, "") ||
  "http://127.0.0.1:8787";

export async function POST(req: NextRequest) {
  const body = await req.json();
  const path =
    body.token && body.new_password
      ? "/auth/password-reset/confirm"
      : "/auth/password-reset/request";
  const res = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return new NextResponse(await res.text(), { status: res.status });
}
