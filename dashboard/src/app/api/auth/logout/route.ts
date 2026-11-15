import { NextRequest, NextResponse } from "next/server";

const API_URL =
  process.env.NEXT_PUBLIC_BLUESTRIX_API_URL?.replace(/\/$/, "") ||
  "http://127.0.0.1:8787";

export async function POST(req: NextRequest) {
  const auth = req.headers.get("authorization") || "";
  const res = await fetch(`${API_URL}/auth/logout`, {
    method: "POST",
    headers: { Authorization: auth },
  });
  return new NextResponse(await res.text(), { status: res.status });
}
