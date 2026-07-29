// React entry for the bongtu public wallet (SPEC §7 public app). The whole UI is one
// React SPA mounted into #app; all security-critical logic still lives in the PURE,
// unit-tested lib modules (derive / spend / balance / prove-assets) — this tree is the
// browser wiring around them. See src/ui/App.tsx for the screen router + wallet state.
//
// The provider stack is the wallet-connection layer: wagmi (chain + connectors, one
// config in lib/wagmi.ts), react-query (wagmi v2's required cache), RainbowKit (the
// connect modal listing every installed extension via EIP-6963 + WalletConnect when
// the build carries VITE_WC_PROJECT_ID). `reconnectOnMount` is OFF: the silent
// restore is driven explicitly by App's session-restore effect (lib/wagmi.ts),
// so a page load can never pop anything.

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { WagmiProvider } from "wagmi";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RainbowKitProvider } from "@rainbow-me/rainbowkit";
import "@rainbow-me/rainbowkit/styles.css";
import { wagmiConfig } from "./lib/wagmi.js";
import { App } from "./ui/App.js";
import "./styles.css";

const root = document.getElementById("app");
if (!root) throw new Error("no #app root in index.html");

const queryClient = new QueryClient();

createRoot(root).render(
  <StrictMode>
    <WagmiProvider config={wagmiConfig} reconnectOnMount={false}>
      <QueryClientProvider client={queryClient}>
        <RainbowKitProvider modalSize="compact">
          <App />
        </RainbowKitProvider>
      </QueryClientProvider>
    </WagmiProvider>
  </StrictMode>,
);
