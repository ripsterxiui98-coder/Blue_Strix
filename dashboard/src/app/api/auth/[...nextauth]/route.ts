import NextAuth from "next-auth";
import CredentialsProvider from "next-auth/providers/credentials";

const handler = NextAuth({
  providers: [
    CredentialsProvider({
      name: "Credentials",
      credentials: {
        username: { label: "Username", type: "text" },
        password: { label: "Password", type: "password" }
      },
      async authorize() {
        // Kita paksa selalu berhasil login sebagai "Admin Palsu"
        return { id: "1", name: "Admin BlueStrix", email: "admin@bluestrix.local" };
      }
    })
  ],
  callbacks: {
    async session({ session }) {
      // Paksa sesi selalu ada
      return session;
    }
  },
  secret: "rahasia_negara_super_aman_123",
});

export { handler as GET, handler as POST };
