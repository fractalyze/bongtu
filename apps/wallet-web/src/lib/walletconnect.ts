// The WalletConnect edge: a `Connection` (metamask.ts) over a wallet that is not in
// this browser — a phone, or a desktop wallet without an extension.
//
// BUILD FLAG. Everything here is dark unless `VITE_WC_PROJECT_ID` is set at build
// time. Without it `walletConnectEnabled()` is false, the second connect button is
// never rendered, and the SDK is never fetched — the wallet behaves exactly as it did
// when the injected extension was the only way in. The id comes from a Reown Cloud
// project (see docs/wallet.md); it is public, it only identifies the dapp to the
// relay, and there is no secret half.
//
// LAZY BY CONSTRUCTION. `@walletconnect/ethereum-provider` (plus its relay client and
// QR modal) is a large dependency for a feature most visitors never touch, so it is
// reached ONLY through the `import()` below — never a static import, anywhere in the
// app. That is what keeps it out of the default chunk, and test/walletconnect.test.ts
// walks the static import graph to keep it that way.
//
// Measured: the entry chunk carries no SDK code at all — the provider, its relay client
// and the Reown modal land in ~1.8 MB of separate chunks (the entry grows by ~14 KB,
// which is this module plus the loader machinery for them). Those chunks are still
// EMITTED with the flag off, because the bundler cannot prove an `import()` behind a
// runtime env read unreachable — but nothing FETCHES them: the button that would is
// never rendered, and the silent restore only reaches here for a session that recorded
// `transport: "walletconnect"`, which such a build cannot have written. Dead weight in
// `dist/`, zero bytes for the visitor.
//
// SAME SHAPE, DIFFERENT WALLET. `connectionOver` wraps the WC provider in the same
// ethers Web3Provider the injected path uses, so identity.ts, keyCache.ts, the flows
// and every submit helper are untouched: they see a Connection and cannot tell. The
// two things that DO differ are handled explicitly — the login signs twice the first
// time (loginGuard.ts, because a randomised signature would silently rotate the user's
// key), and a refused network switch gets its own message (metamask.chainSwitchMessage).

import { ethers } from "ethers";
import { CHAIN_ID, RPC_URL } from "@bongtu/core/network";
import { registerAnnouncedWallet } from "./eip6963.js";
import type { Connection } from "./metamask.js";

/**
 * The Reown Cloud project id, or null when this build has none. `import.meta.env` is a
 * Vite build-time inject and is undefined under the plain node test runner, hence the
 * defensive read (same pattern as config.ts).
 */
export function walletConnectProjectId(): string | null {
  const id = (import.meta.env?.VITE_WC_PROJECT_ID ?? "").trim();
  return id.length > 0 ? id : null;
}

/** Whether this build offers WalletConnect at all. Drives the second connect button. */
export function walletConnectEnabled(): boolean {
  return walletConnectProjectId() !== null;
}

export const WALLETCONNECT_UNCONFIGURED_MESSAGE =
  "WalletConnect isn't configured in this build.";

export const WALLETCONNECT_NO_ACCOUNT_MESSAGE =
  "Your wallet connected but didn't share an account. Approve the connection in the wallet app and try again.";

/** The slice of `@walletconnect/ethereum-provider` this module drives. Declared here
 *  rather than imported so that no type import can smuggle the SDK into the bundle,
 *  and so a test can hand in a plain object that satisfies it. */
export interface WalletConnectProvider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
  /** Opens the QR / deep-link modal and waits for the wallet to approve. */
  connect(): Promise<void>;
  disconnect(): Promise<void>;
  on(event: string, handler: (...args: unknown[]) => void): void;
  removeListener(event: string, handler: (...args: unknown[]) => void): void;
  /** Accounts of the live session; empty when there is none. */
  accounts: string[];
  /** Present only while a session exists — the silent-restore test, and where the
   *  peer's self-description lives. */
  session?: { peer?: { metadata?: { name?: unknown; icons?: unknown } } };
}

/** The one I/O edge, injectable so the whole seam gates headlessly with a fake wallet
 *  and no relay. */
export interface WalletConnectDeps {
  projectId: () => string | null;
  /** Builds the provider — which also RESTORES an existing session from WalletConnect's
   *  own storage, without any user interaction. */
  createProvider: (projectId: string) => Promise<WalletConnectProvider>;
}

// One provider per page: `connect` after a failed silent restore must reuse the
// instance that already read WalletConnect's storage, not open a second relay client.
let live: WalletConnectProvider | null = null;

async function initEthereumProvider(projectId: string): Promise<WalletConnectProvider> {
  if (live) return live;
  // THE dynamic import (see the header) — the only reference to the SDK in the app.
  const { EthereumProvider } = await import("@walletconnect/ethereum-provider");
  const provider = await EthereumProvider.init({
    projectId,
    chains: [CHAIN_ID],
    // The pool exists on GIWA alone, so GIWA is not optional; the map lets the SDK
    // answer reads itself instead of relaying every eth_call to the phone.
    optionalChains: [CHAIN_ID],
    rpcMap: { [CHAIN_ID]: RPC_URL },
    // eth_signTypedData_v4 is the derivation signature: a wallet that does not offer
    // it cannot produce a bongtu key at all, so it is requested up front rather than
    // discovered at the first login.
    methods: [
      "eth_sendTransaction",
      "eth_signTypedData_v4",
      "wallet_switchEthereumChain",
      "wallet_addEthereumChain",
    ],
    events: ["accountsChanged", "chainChanged"],
    showQrModal: true,
    metadata: {
      name: "bongtu",
      description: "The privacy wallet for kKRW on GIWA.",
      url: typeof window === "undefined" ? "https://bongtu.fractalyze.io" : window.location.origin,
      icons: [],
    },
  });
  live = provider as unknown as WalletConnectProvider;
  return live;
}

const DEFAULT_DEPS: WalletConnectDeps = {
  projectId: walletConnectProjectId,
  createProvider: initEthereumProvider,
};

/**
 * Tell the rest of the app what this wallet calls itself, using the same registry the
 * EIP-6963 announcements land in (eip6963.ts) — so the name reaches the copy and the
 * mark through the existing describeWallet path, sanitised by the existing rules. Peer
 * icons are conventionally remote https URLs, which that path drops on sight; the
 * result is the wallet's real name beside the generic glyph, never a vendor fetch.
 */
function registerPeer(wc: WalletConnectProvider): void {
  const metadata = wc.session?.peer?.metadata;
  const icons = metadata?.icons;
  registerAnnouncedWallet(wc, {
    name: metadata?.name,
    icon: Array.isArray(icons) ? icons[0] : undefined,
  });
}

/** The Connection the rest of the app sees. The signer is pinned to the session
 *  account (a remote wallet has no "currently selected" account to follow). */
function connectionOver(wc: WalletConnectProvider, address: string): Connection {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const provider = new ethers.providers.Web3Provider(wc as any, "any");
  return {
    address,
    provider,
    signer: provider.getSigner(address),
    transport: "walletconnect",
  };
}

function firstAccount(wc: WalletConnectProvider): string | null {
  const addr = wc.accounts?.[0];
  return typeof addr === "string" && addr.length > 0 ? addr : null;
}

/**
 * Connect a remote wallet: opens the QR / deep-link modal (or reuses a session that is
 * already live) and returns the same Connection shape the injected path returns.
 */
export async function connectWalletConnect(
  deps: WalletConnectDeps = DEFAULT_DEPS,
): Promise<Connection> {
  const projectId = deps.projectId();
  if (!projectId) throw new Error(WALLETCONNECT_UNCONFIGURED_MESSAGE);
  const wc = await deps.createProvider(projectId);
  if (!wc.session) await wc.connect();
  const address = firstAccount(wc);
  if (!address) throw new Error(WALLETCONNECT_NO_ACCOUNT_MESSAGE);
  registerPeer(wc);
  return connectionOver(wc, address);
}

/**
 * SILENT restore for a stored WalletConnect session, the mirror of metamask.reconnect:
 * the SDK reloads its own session from storage, and a session for the same account is
 * a connection. Never calls `connect()`, so a returning visit cannot pop a QR modal at
 * someone; null means "log in normally".
 */
export async function reconnectWalletConnect(
  expectedAddress: string,
  deps: WalletConnectDeps = DEFAULT_DEPS,
): Promise<Connection | null> {
  const projectId = deps.projectId();
  if (!projectId) return null;
  let wc: WalletConnectProvider;
  try {
    wc = await deps.createProvider(projectId);
  } catch {
    return null; // relay unreachable / storage unreadable — fall back to a fresh login
  }
  if (!wc.session) return null;
  const address = firstAccount(wc);
  if (!address || address.toLowerCase() !== expectedAddress.toLowerCase()) return null;
  registerPeer(wc);
  return connectionOver(wc, address);
}

/**
 * End the WalletConnect session on sign-out. Without this the wallet app keeps showing
 * bongtu as connected and the next login silently reuses a pairing the user believes
 * they closed. Best-effort: signing out must not fail because the relay is down.
 */
export async function disconnectWalletConnect(): Promise<void> {
  const wc = live;
  if (!wc) return;
  live = null;
  try {
    await wc.disconnect();
  } catch {
    // the local session is gone either way; the relay will time the pairing out.
  }
}
