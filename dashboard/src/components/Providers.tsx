"use client";

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { SessionProvider, useSession } from "next-auth/react";
import { useState } from "react";
import { accessTokenOf, setApiAccessToken } from "@/lib/api";

/**
 * Publishes the session access token to the API client. It renders before {children}, so the
 * token is set before any child query runs. Setting it during render (not in an effect) avoids
 * a race where a query fires before the effect has run.
 */
function ApiTokenSync() {
  const { data } = useSession();
  setApiAccessToken(accessTokenOf(data));
  return null;
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(() => new QueryClient());
  return (
    <SessionProvider>
      <ApiTokenSync />
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    </SessionProvider>
  );
}
