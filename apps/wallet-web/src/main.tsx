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
import { Analytics } from "@vercel/analytics/react";
import { isMobileDevice } from "@bongtu/client/device";
import { wagmiConfig } from "@bongtu/ui/wagmi";
import { App } from "./ui/App.js";
import "./styles.css";

const root = document.getElementById("app");
if (!root) throw new Error("no #app root in index.html");

/** The desktop-only door — the wallet's extension connectors and circuit
 *  downloads break halfway on a phone, so refuse at the root, BEFORE the
 *  wagmi/RainbowKit stack mounts; device.ts owns the verdict. */
function DesktopOnly() {
  return (
    <div className="min-h-full flex items-center justify-center p-6">
      <div className="w-full max-w-[420px] bg-surface border border-border rounded-2xl p-8 flex flex-col gap-3 text-center">
        <div className="text-lg font-bold">
          <span className="text-primary">Bongtu</span> Wallet
        </div>
        <div className="text-[14px] font-semibold">This wallet is desktop-only.</div>
        <div className="text-[12.5px] text-muted">Please open this page on a PC.</div>
      </div>
    </div>
  );
}

const queryClient = new QueryClient();

createRoot(root).render(
  <StrictMode>
    {isMobileDevice(navigator.userAgent, navigator.maxTouchPoints) ? (
      <DesktopOnly />
    ) : (
      <WagmiProvider config={wagmiConfig} reconnectOnMount={false}>
        <QueryClientProvider client={queryClient}>
          <RainbowKitProvider modalSize="compact">
            <App />
          </RainbowKitProvider>
        </QueryClientProvider>
      </WagmiProvider>
    )}
    <Analytics />
  </StrictMode>,
);
