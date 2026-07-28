// The one wagmi Config for the app: GIWA Sepolia only, every installed extension
// via EIP-6963 discovery (wagmi's multiInjectedProviderDiscovery, on by default),
// and WalletConnect for phones/QR — the RainbowKit connect modal lists all of them.
//
// BUILD FLAG. WalletConnect is dark unless `VITE_WC_PROJECT_ID` is set at build
// time: without it `buildConnectors` contributes NO WalletConnect connector, the
// modal lists only installed extensions, and the WC SDK is never fetched (the
// wagmi connector reaches `@walletconnect/ethereum-provider` through a dynamic
// `import()` only, so it stays out of the entry chunk either way). The id comes
// from a Reown Cloud project (docs/wallet.md); it is public — it only identifies
// the dapp to the relay, and there is no secret half.

import { createConfig, http } from "wagmi";
import type { CreateConnectorFn } from "wagmi";
import { connectorsForWallets } from "@rainbow-me/rainbowkit";
import { walletConnectWallet } from "@rainbow-me/rainbowkit/wallets";
import { giwaSepolia } from "./chain.js";

/**
 * The Reown Cloud project id, or null when this build has none. `import.meta.env`
 * is a Vite build-time inject and is undefined under the plain node test runner,
 * hence the defensive read (same pattern as config.ts).
 */
export function walletConnectProjectId(): string | null {
  const id = (import.meta.env?.VITE_WC_PROJECT_ID ?? "").trim();
  return id.length > 0 ? id : null;
}

/** Whether this build offers WalletConnect at all (drives onboarding copy only —
 *  the modal itself simply has one fewer row without it). */
export function walletConnectEnabled(): boolean {
  return walletConnectProjectId() !== null;
}

/**
 * The EXPLICIT connectors for the config — WalletConnect alone, and only when the
 * build carries a project id. Installed extensions are deliberately NOT listed
 * here: wagmi discovers them per-page via EIP-6963 and RainbowKit renders every
 * announcement in its "Installed" section, so a hardcoded wallet list could only
 * drift from what the user actually has. Pure in `projectId` so the guard is
 * testable headlessly.
 */
export function buildConnectors(projectId: string | null): CreateConnectorFn[] {
  if (!projectId) return [];
  return connectorsForWallets(
    [{ groupName: "Mobile & QR", wallets: [walletConnectWallet] }],
    { appName: "bongtu", projectId },
  );
}

/** The app's one wagmi config. `reconnectOnMount` is disabled in main.tsx — the
 *  silent restore is driven explicitly by App's session-restore effect
 *  (connection.ts restoreConnection), so a QR modal or popup can never appear
 *  from a mere page load. */
export const wagmiConfig = createConfig({
  chains: [giwaSepolia],
  connectors: buildConnectors(walletConnectProjectId()),
  transports: { [giwaSepolia.id]: http() },
});
