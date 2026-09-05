// The consumer login record — the app-layer replacement for the engine
// SessionStore's session row, which this profile cannot use: that store's
// loadSession DROPS tokenless records by contract (its record is a read
// credential), while a consumer login is tokenless BY DESIGN — every read the
// wallet performs is public, so there is nothing to authenticate and nothing
// credential-shaped to persist. What survives a reload here is routing data
// only: which account logged in, which receive pubkey it derived, and which
// transport to silently reopen. A restored session starts LOCKED (the spending
// key never persists, keyCache.ts) and serves the last completed scan.
//
// Deployment-scoped like the engine's SESSION_KEY (session.ts): the record
// holds the bjj pubkey this account derived, and the KDF domain is
// (chainId, pool) — on a chain move the stored pubkey names a key this build
// can no longer derive, so a record from another pair must read as ABSENT.
// Key bindings are NOT duplicated here: runLogin's engine store still owns the
// account→pubkey determinism record.

import { DEPLOYMENT_TAG } from "@bongtu/core/network";
import type { StorageLike, StoredSession } from "@bongtu/client/session";

export const CONSUMER_SESSION_KEY = `bongtu.consumer.session.${DEPLOYMENT_TAG}`;

function defaultStorage(): StorageLike | null {
  try {
    return (globalThis as { localStorage?: StorageLike }).localStorage ?? null;
  } catch {
    return null; // storage blocked (private mode / hard privacy settings)
  }
}

/** What the consumer wallet persists about a login: no credential, no expiry —
 *  the record is only a pointer back to the same account + derived pubkey. */
export type ConsumerSessionRecord = Pick<
  StoredSession,
  "eoaAddress" | "compressedPubkey" | "transport"
>;

/** Persist the login record. Best-effort: a blocked/full storage just means the
 *  next visit reconnects normally. */
export function saveConsumerSession(
  record: ConsumerSessionRecord,
  storage: StorageLike | null = defaultStorage(),
): void {
  try {
    storage?.setItem(CONSUMER_SESSION_KEY, JSON.stringify(record));
  } catch {
    // quota/privacy-mode write failure — session persistence is a convenience only.
  }
}

/**
 * Load the stored session in the engine's StoredSession shape (token "" and
 * exp 0 are the tokenless truth, not a fallback), or null when absent or
 * malformed (broken records are removed so the next visit starts clean).
 */
export function loadConsumerSession(
  storage: StorageLike | null = defaultStorage(),
): StoredSession | null {
  if (!storage) return null;
  const raw = ((): string | null => {
    try {
      return storage.getItem(CONSUMER_SESSION_KEY);
    } catch {
      return null;
    }
  })();
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as ConsumerSessionRecord;
    if (typeof s.eoaAddress !== "string" || typeof s.compressedPubkey !== "string") {
      storage.removeItem(CONSUMER_SESSION_KEY);
      return null;
    }
    return {
      eoaAddress: s.eoaAddress,
      compressedPubkey: s.compressedPubkey,
      token: "",
      exp: 0,
      // An unrecognised transport is treated as absent rather than trusted: the
      // restore would open a transport this build has no code for.
      transport: s.transport === "walletconnect" ? "walletconnect" : "injected",
    };
  } catch {
    storage.removeItem(CONSUMER_SESSION_KEY);
    return null;
  }
}

/** Drop the stored login record (the Settings Disconnect button, and a restore
 *  whose account no longer matches). */
export function clearConsumerSession(storage: StorageLike | null = defaultStorage()): void {
  try {
    storage?.removeItem(CONSUMER_SESSION_KEY);
  } catch {
    // nothing to clean if storage is unreachable
  }
}
