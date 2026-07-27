// The ONE browser-persisted login record (localStorage). SECURITY INVARIANT
// (user-mandated): the bjj private key is NEVER written to any browser storage in
// ANY form — the only stored credential is the indexer's VIEW-ONLY token (it can
// read this owner's balance/activity and nothing else; no write path accepts it).
// The spending key lives in memory only (keyCache.ts): a login hands it the identity
// the connect signature produced, and a page that did not log in re-derives it from a
// fresh signature at ACTION time. Losing this record loses nothing but a login.
//
// Pure + storage-injected so expiry/shape handling is unit-tested headlessly
// (test/session.test.ts); the app passes the real window.localStorage.

/** What survives a page reload: enough to show Home + read data, nothing that spends. */
export interface StoredSession {
  /** the connected MetaMask account (checked against eth_accounts on restore). */
  eoaAddress: string;
  /** compressed bjj pubkey hex — the receive address; public by definition. */
  compressedPubkey: string;
  /** the indexer's opaque view token ("" when the indexer issued none). */
  token: string;
  /** token expiry, unix seconds (0 when tokenless). */
  exp: number;
}

/** The subset of window.localStorage the session uses (injectable in tests). */
export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export const SESSION_KEY = "bongtu.session.v1";

function defaultStorage(): StorageLike | null {
  try {
    return (globalThis as { localStorage?: StorageLike }).localStorage ?? null;
  } catch {
    return null; // storage blocked (private mode / hard privacy settings)
  }
}

/** Persist the login record. Best-effort: a blocked/full storage just means the
 *  next visit reconnects normally. */
export function saveSession(session: StoredSession, storage: StorageLike | null = defaultStorage()): void {
  try {
    storage?.setItem(SESSION_KEY, JSON.stringify(session));
  } catch {
    // quota/privacy-mode write failure — session persistence is a convenience only.
  }
}

/**
 * Load the stored session, or null when absent, malformed, tokenless, or expired
 * (expired/broken records are removed so the next visit starts clean). `now` is
 * unix seconds, injectable for expiry tests.
 */
export function loadSession(
  now: number = Math.floor(Date.now() / 1000),
  storage: StorageLike | null = defaultStorage(),
): StoredSession | null {
  if (!storage) return null;
  let raw: string | null = null;
  try {
    raw = storage.getItem(SESSION_KEY);
  } catch {
    return null;
  }
  if (!raw) return null;
  try {
    const s = JSON.parse(raw) as StoredSession;
    if (
      typeof s.eoaAddress !== "string" ||
      typeof s.compressedPubkey !== "string" ||
      typeof s.token !== "string" ||
      typeof s.exp !== "number" ||
      s.token === "" ||
      s.exp <= now
    ) {
      storage.removeItem(SESSION_KEY);
      return null;
    }
    return { eoaAddress: s.eoaAddress, compressedPubkey: s.compressedPubkey, token: s.token, exp: s.exp };
  } catch {
    storage.removeItem(SESSION_KEY);
    return null;
  }
}

/** Drop the stored login record (the Settings Disconnect button). */
export function clearSession(storage: StorageLike | null = defaultStorage()): void {
  try {
    storage?.removeItem(SESSION_KEY);
  } catch {
    // nothing to clean if storage is unreachable
  }
}
