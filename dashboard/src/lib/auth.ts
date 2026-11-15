import type { NextAuthOptions } from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";
import { ALL_ROLES, type Role } from "./roles";

/**
 * Demo credential gate for local dashboard access.
 * Production should replace this with SSO / IdP.
 * Password is compared against DASHBOARD_DEMO_PASSWORD env only.
 */
export const authOptions: NextAuthOptions = {
  session: { strategy: "jwt" },
  pages: { signIn: "/login" },
  providers: [
    CredentialsProvider({
      name: "BlueStrix",
      credentials: {
        username: { label: "Operator", type: "text" },
        password: { label: "Password", type: "password" },
        role: { label: "Role", type: "text" },
      },
      async authorize(credentials) {
        if (!credentials?.username || !credentials?.password || !credentials?.role) {
          return null;
        }
        const expected = process.env.DASHBOARD_DEMO_PASSWORD || "change-me";
        if (credentials.password !== expected) {
          return null;
        }
        const role = credentials.role as Role;
        if (!ALL_ROLES.includes(role)) {
          return null;
        }
        return {
          id: credentials.username,
          name: credentials.username,
          email: `${credentials.username}@bluestrix.local`,
          role,
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.role = (user as { role?: Role }).role;
        token.name = user.name;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user) {
        (session.user as { role?: Role }).role = token.role as Role;
        session.user.name = token.name as string;
      }
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
};
