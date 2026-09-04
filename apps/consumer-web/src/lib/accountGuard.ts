// The account-switch guard and the disconnect cleanup as PURE sequences over
// injected sinks, so both contracts gate headlessly (test/discovery.test.ts)
// and App.tsx only wires state setters in.
//
// The switch contract: a held spending key belongs to ONE wallet account, so
// any accountsChanged locks it at the moment it happens AND detaches the
// in-memory scan state — the cached scan was proven under the account that
// derived it, and after a switch the next pass must resume from the per-owner
// STORE (keyed by pubkey, scanStore.ts) rather than trust a ref whose owner
// can no longer be re-checked against the live wallet. The screen keeps its
// last snapshot under the calm locked notice (the locked rule: a background
// event never blanks data).
//
// The disconnect contract: `disconnected` signs out for WalletConnect ONLY —
// there it is the phone ending the session; an extension's disconnect can be a
// mere provider hiccup, and signing a user out over a hiccup was rejected UX.

import type { Connection, WalletWatchHandlers } from "@bongtu/client/connection";

/** What the app tells a user whose wallet hung up the WalletConnect pairing. */
export const WALLET_ENDED_NOTICE =
  "Your wallet ended the connection. Connect again to continue.";

export interface AccountGuardSinks {
  /** keyCache.lock — drops the spending key (and the stealth hold with it). */
  lock(): void;
  /** drop the in-memory scan ref for the old owner (the store row stays: it is
   *  keyed per owner and another account can never resume it). */
  detachScan(): void;
  /** the forced sign-out route, carrying the notice onboarding shows. */
  signOut(notice: string): void;
}

/** The wallet-event handlers App hands to watchWallet, with the sequences
 *  fixed here. `transportOf` reads the LIVE connection's transport (the
 *  handler outlives any single connection object). */
export function accountGuard(
  sinks: AccountGuardSinks,
  transportOf: () => Connection["transport"] | null,
): WalletWatchHandlers {
  return {
    accountsChanged: () => {
      sinks.lock();
      sinks.detachScan();
    },
    disconnected: () => {
      if (transportOf() === "walletconnect") sinks.signOut(WALLET_ENDED_NOTICE);
    },
  };
}

/** The explicit-Disconnect extras beyond the shared sign-out: the user asked
 *  for a clean device, so the account→pubkey determinism bindings, the stored
 *  scan (decrypted amounts), and the wallet pairing all go. */
export interface ForgetSinks {
  clearKeyBindings(): void;
  clearStoredScan(): void;
  endWalletLink(): void;
}

export function forgetDevice(sinks: ForgetSinks): void {
  sinks.clearKeyBindings();
  sinks.clearStoredScan();
  sinks.endWalletLink();
}
