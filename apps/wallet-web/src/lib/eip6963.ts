// The registry of what each wallet says about ITSELF — its display name and its icon.
// Vendor flags (walletBrand.ts) only recognise wallets we hardcoded; a self-description
// is the only way a user on something we have never heard of sees their wallet's name
// and mark instead of a generic guess.
//
// Two sources feed it, keyed the same way and read the same way:
//   EIP-6963 announcements from injected extensions. Wallets announce on page load AND
//     in reply to a request event, so starting late is fine: the request below makes
//     every compliant extension announce again.
//   WalletConnect peer metadata, registered by walletconnect.ts when a remote wallet
//     completes a session.
//
// Neither source is sanitised HERE. Both are untrusted strings from someone else's
// software, and describeWallet (walletBrand.ts) is the ONE place that flattens control
// characters, caps the length and refuses a non-`data:` icon — so a remote peer's icon
// URL is dropped rather than fetched, by the same rule, for both sources.

import type { AnnouncedWallet } from "./walletBrand.js";

interface AnnounceDetail {
  info?: { name?: unknown; icon?: unknown };
  provider?: unknown;
}

// Keyed by the provider OBJECT the wallet announced, which is the same object the
// ethers Web3Provider wraps — that identity is what ties an announcement to the
// connection actually in use when several wallets are installed.
const announced = new Map<unknown, AnnouncedWallet>();
const listeners = new Set<() => void>();
let version = 0;
let started = false;

/**
 * Record what `provider` says it is. Values are stored RAW (see the header): the
 * describe path sanitises. Bumping the version repaints anything showing the wallet,
 * which is what lets a name that arrives after first paint still reach the copy.
 */
export function registerAnnouncedWallet(provider: unknown, wallet: AnnouncedWallet): void {
  if (provider === null || provider === undefined) return;
  announced.set(provider, wallet);
  version += 1;
  for (const l of listeners) l();
}

function onAnnounce(e: Event): void {
  const detail = (e as CustomEvent<AnnounceDetail>).detail;
  const provider = detail?.provider;
  if (!provider) return;
  registerAnnouncedWallet(provider, { name: detail?.info?.name, icon: detail?.info?.icon });
}

/** Begin (once) collecting announcements and ask every installed wallet to announce. */
export function startWalletDiscovery(): void {
  if (started || typeof window === "undefined") return;
  started = true;
  window.addEventListener("eip6963:announceProvider", onAnnounce);
  window.dispatchEvent(new Event("eip6963:requestProvider"));
}

/** What `injected` announced about itself, or null when it announced nothing. */
export function announcedWallet(injected: unknown): AnnouncedWallet | null {
  if (injected === null || injected === undefined) return null;
  return announced.get(injected) ?? null;
}

/** Subscribe to arriving announcements (useSyncExternalStore in ui/hooks.ts). */
export function subscribeWallets(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Bumps on every announcement — the store snapshot a late arrival re-renders on. */
export function walletDiscoveryVersion(): number {
  return version;
}
