import NextAuth from "next-auth";
import { authOptions } from "@/lib/auth";

/**
 * Production NextAuth handler.
 * Credentials are verified exclusively by BlueStrix FastAPI (/auth/login).
 * No hardcoded users, no always-success bypass, no embedded secrets.
 */
const handler = NextAuth(authOptions);

export { handler as GET, handler as POST };
