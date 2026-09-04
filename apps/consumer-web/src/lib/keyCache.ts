// KEY-CUSTODY RULE (user-mandated): the bjj private key may live in memory only —
// this instance is the one place that holds it across calls (the contract lives
// with the class: @bongtu/client/keyCache). Construction goes through the shared
// createKeyCache so the stealth seam and the deployment's KDF config cannot be
// wired differently here than in payroll-web.

import { createKeyCache } from "@bongtu/client/keyCache";
import { walletEdge } from "./wagmi.js";

/** The wallet's one cache; flows take it through their deps seam so tests can
 *  run their own instance with a fake clock. */
export const keyCache = createKeyCache(walletEdge);

// Stable module-level bindings for useSyncExternalStore (a fresh closure per render
// would resubscribe on every paint).
export const subscribeLock = (listener: () => void): (() => void) => keyCache.subscribe(listener);
export const isWalletUnlocked = (): boolean => keyCache.isUnlocked();
