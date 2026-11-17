import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import type { Role } from "./roles";

const API_URL =
  process.env.NEXT_PUBLIC_BLUESTRIX_API_URL?.replace(/\/$/, "") ||
  "http://127.0.0.1:8787";

/**
 * Production auth: credentials are verified by BlueStrix FastAPI (/auth/login).
 * No default passwords, no hardcoded users. Role comes from the backend database.
 * Session is short-lived JWT (15 min) — refresh is handled server-side via refresh cookie.
 */
export const authOptions: NextAuthOptions = {
  session: {
    strategy: "jwt",
    maxAge: 15 * 60, // 15 minutes — matches short-lived access tokens
    updateAge: 5 * 60,
  },
  pages: {
    signIn: "/login",
    error: "/login",
  },
  providers: [
    CredentialsProvider({
      name: "BlueStrix",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
        mfaCode: { label: "MFA", type: "text" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          return null;
        }
        try {
          const res = await fetch(`${API_URL}/auth/login`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Accept: "application/json",
            },
            body: JSON.stringify({
              email: credentials.email,
              password: credentials.password,
              mfa_code: credentials.mfaCode || null,
            }),
          });

          if (!res.ok) {
            // Map backend status for clearer client errors (still return null for NextAuth)
            return null;
          }

          const data = (await res.json()) as {
            access_token: string;
            email: string;
            role: Role;
            mfa_enabled?: boolean;
          };

          if (!data.access_token || !data.email || !data.role) {
            return null;
          }

          return {
            id: data.email,
            name: data.email,
            email: data.email,
            role: data.role,
            accessToken: data.access_token,
          };
        } catch {
          return null;
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.role = (user as { role?: Role }).role;
        token.accessToken = (user as { accessToken?: string }).accessToken;
        token.name = user.email || user.name;
        token.email = user.email;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        (session.user as { role?: Role }).role = token.role as Role;
        session.user.name = (token.name as string) || (token.email as string);
        session.user.email = (token.email as string) || (token.name as string);
        (session as { accessToken?: string }).accessToken =
          token.accessToken as string;
      }
      return session;
    },
  },
  // Must be set via environment — never hardcode
  secret: process.env.NEXTAUTH_SECRET,
  useSecureCookies: process.env.NODE_ENV === "production",
};
