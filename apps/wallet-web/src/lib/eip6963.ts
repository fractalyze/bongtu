// EIP-6963 wallet discovery — the browser edge that learns each injected wallet's own
// name and icon. Vendor flags (walletBrand.ts) only recognise wallets we hardcoded;
// the announcement event carries a display name and a data-URI icon for every
// compliant wallet, so a user on something we have never heard of still sees their
// wallet's name and mark instead of a generic guess.
//
// Wallets announce on page load AND in reply to a request event, so starting late is
// fine: the request below makes every compliant extension announce again.

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

function onAnnounce(e: Event): void {
  const detail = (e as CustomEvent<AnnounceDetail>).detail;
  const provider = detail?.provider;
  if (!provider) return;
  announced.set(provider, { name: detail?.info?.name, icon: detail?.info?.icon });
  version += 1;
  for (const l of listeners) l();
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
