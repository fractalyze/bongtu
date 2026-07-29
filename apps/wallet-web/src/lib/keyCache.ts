// The wallet's ONE lock instance. The lock itself — the in-memory-only KeyCache
// state machine with its idle wipe and session-account refusals — lives in
// @bongtu/client/keyCache; this file is the app wiring that brings it to life:
// the lazy re-derive under THIS deployment's KDF config, and wagmi's live-account
// read (the only honest answer to "whose key would a derivation produce?" after a
// mid-session account switch).
//
// KEY-CUSTODY RULE (user-mandated): the bjj private key may live in memory only —
// this instance is the one place that holds it across calls, and nothing here is
// persisted (see the class's own contract in @bongtu/client/keyCache).

import { KeyCache } from "@bongtu/client/keyCache";
import { KEY_DERIVATION, deriveTransientIdentity } from "@bongtu/client/identity";
import type { Connection } from "@bongtu/client/connection";
import type { WalletIdentity } from "@bongtu/client/derive";
import { currentAccount } from "./wagmi.js";

/** The wallet's one cache. Flows take it through their deps seam so tests can run
 *  their own instance with a fake clock. */
export const keyCache = new KeyCache({
  derive: (connection: Connection): Promise<WalletIdentity> =>
    deriveTransientIdentity(connection, KEY_DERIVATION),
  currentAccount,
});

// Stable module-level bindings for useSyncExternalStore (a fresh closure per render
// would resubscribe on every paint).
export const subscribeLock = (listener: () => void): (() => void) => keyCache.subscribe(listener);
export const isWalletUnlocked = (): boolean => keyCache.isUnlocked();
