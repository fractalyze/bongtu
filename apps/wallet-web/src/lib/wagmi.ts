// The wagmi edge — how the browser REACHES a wallet, in one file: the wagmi Config
// (the live chain only, every installed extension via EIP-6963 discovery — wagmi's
// multiInjectedProviderDiscovery, on by default — and WalletConnect for phones/QR;
// the RainbowKit connect modal lists all of them), plus the functions that turn
// whatever wagmi connected into the `Connection` shape the protocol engine
// (@bongtu/client/connection) consumes. Everything security-relevant (key
// derivation, balance, witness assembly, submits) lives in @bongtu/client and is
// unit-tested; this file is the thin I/O edge (no wallet in the headless env).
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
import { disconnect, getAccount, reconnect, watchAccount } from "wagmi/actions";
import { connectorsForWallets } from "@rainbow-me/rainbowkit";
import { walletConnectWallet } from "@rainbow-me/rainbowkit/wallets";
import { createPublicClient, createWalletClient, custom, type PublicClient } from "viem";
import { liveChain } from "@bongtu/client/chain";
import { accountWatchHandler, type Connection, type WalletEdge, type WalletWatchHandlers } from "@bongtu/client/connection";

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
 *  (restoreConnection below), so a QR modal or popup can never appear
 *  from a mere page load. */
export const wagmiConfig = createConfig({
  chains: [liveChain],
  connectors: buildConnectors(walletConnectProjectId()),
  transports: { [liveChain.id]: http() },
});

// --- turning wagmi state into the engine's `Connection` ----------------------------

interface Eip1193 {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

/** Whether an EIP-1193 provider is injected — true in extension browsers AND in
 *  MetaMask Mobile's in-app browser; false in a plain mobile browser, where the
 *  paths to a connection are WalletConnect or the deep link below. */
export function hasInjectedWallet(): boolean {
  return Boolean((globalThis as { ethereum?: unknown }).ethereum);
}

/** MetaMask Mobile deep link that reopens THIS page inside the app's dapp
 *  browser (which injects window.ethereum). Universal-link form, so it also
 *  routes to the app store when the app is missing. Onboarding's last resort
 *  when there is neither an extension nor WalletConnect in the build. */
export function metamaskDeepLink(): string {
  const { host, pathname } = window.location;
  return `https://metamask.app.link/dapp/${host}${pathname}`;
}

/** The one public client — receipts and view reads go to the chain's RPC directly,
 *  never through the wallet (a phone over WalletConnect shouldn't relay eth_call). */
const publicClient: PublicClient = createPublicClient({ chain: liveChain, transport: http() });

/** Wrap the connector wagmi has live into the `Connection` the app consumes, or
 *  null when nothing is connected. The wallet client rides the connector's raw
 *  EIP-1193 provider, so signatures and txs reach whichever wallet the user
 *  actually picked in the modal; reads ride the app's own public client. */
export async function currentConnection(): Promise<Connection | null> {
  const account = getAccount(wagmiConfig);
  if (account.status !== "connected" || !account.connector || !account.address) return null;
  const injected = (await account.connector.getProvider()) as Eip1193;
  const walletClient = createWalletClient({
    account: account.address,
    chain: liveChain,
    transport: custom(injected),
  });
  return {
    address: account.address,
    walletClient,
    publicClient,
    injected,
    transport: account.connector.type === "walletConnect" ? "walletconnect" : "injected",
  };
}

/** The login's connection source (loginFlow.runLogin): the wallet the RainbowKit
 *  modal just connected. Throws readably when pressed before any wallet is live —
 *  the Onboarding wiring opens the modal first, so this is a belt, not a path. */
export async function requireConnection(): Promise<Connection> {
  const connection = await currentConnection();
  if (!connection) throw new Error("No wallet connected. Connect a wallet first.");
  return connection;
}

/**
 * SILENT reconnect for a stored session: wagmi re-opens its remembered connector
 * (eth_accounts for an extension — never a popup; the WalletConnect connector
 * reloads its own stored session — never a QR modal), and the same account must
 * still be reported. Returns null when nothing reconnects or the account changed —
 * the caller then falls back to the normal connect flow. Deliberately does NOT
 * switch chains (that can prompt); the action flows call `ensureChain` before
 * anything chain-dependent.
 */
export async function restoreConnection(expectedAddress: string): Promise<Connection | null> {
  try {
    await reconnect(wagmiConfig);
  } catch {
    return null;
  }
  const connection = await currentConnection();
  if (!connection || connection.address.toLowerCase() !== expectedAddress.toLowerCase()) return null;
  return connection;
}

/** Silent, fire-and-forget reconnect with no session to check against: lets the
 *  Onboarding Connect button skip the modal when wagmi still holds an authorised
 *  connector from a previous visit. Never prompts (same guarantee as above). */
export function warmReconnect(): void {
  void reconnect(wagmiConfig).catch(() => {});
}

/**
 * End the wallet connection on an explicit sign-out: wagmi disconnects the live
 * connector (for WalletConnect that ends the session — without it the wallet app
 * keeps showing bongtu as connected) and forgets it, so the next visit cannot
 * silently reconnect a pairing the user believes they closed. Best-effort:
 * signing out must not fail because a relay is down.
 */
export async function endWalletConnection(): Promise<void> {
  try {
    await disconnect(wagmiConfig);
  } catch {
    // the local state is cleared either way; a WC relay will time the pairing out.
  }
}

/**
 * The account the connected wallet has selected RIGHT NOW, lowercased; null when
 * none is connected. wagmi tracks the connector's accountsChanged events, so this
 * follows the wallet live while `connection.address` is frozen at connect time —
 * making this the only honest answer to "whose key would a derivation produce?"
 * after a mid-session account switch (keyCache.ts).
 */
export async function currentAccount(): Promise<string | null> {
  return getAccount(wagmiConfig).address?.toLowerCase() ?? null;
}

/**
 * Subscribe to wallet-account changes through wagmi's one account store; returns
 * one unsubscribe. `accountsChanged` fires on a switch to a DIFFERENT address —
 * even when the switch transits a disconnected state (see accountWatchHandler);
 * `disconnected` when a live connection ends (the WalletConnect peer hanging up,
 * an extension revoking access). What `disconnected` should DO stays the
 * CALLER's choice: App signs out only a WalletConnect session (a remote peer
 * ending the session is a real sign-out; an extension hiccup is not).
 */
export function watchWallet(handlers: WalletWatchHandlers): () => void {
  return watchAccount(wagmiConfig, { onChange: accountWatchHandler(handlers) });
}

/** This app's WalletEdge — the wagmi implementations of the engine's adapter
 *  quartet in one typed object, so falling out of step with the interface is a
 *  tsc error here rather than a runtime surprise in the lock or the login. */
export const walletEdge: WalletEdge = {
  hasInjectedWallet,
  openConnection: requireConnection,
  currentAccount,
  watchAccount: watchWallet,
};
