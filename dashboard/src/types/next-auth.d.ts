import type { DefaultSession } from "next-auth";
import type { Role } from "@/lib/roles";

declare module "next-auth" {
  interface Session {
    user: DefaultSession["user"] & { role?: Role };
    accessToken?: string;
  }
  interface User {
    role?: Role;
    accessToken?: string;
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    role?: Role;
    accessToken?: string;
  }
}
