// What the wallet persists about a login (localStorage): the session record below, and
// the account→pubkey binding at the bottom of this file. SECURITY INVARIANT
// (user-mandated): the bjj private key is NEVER written to any browser storage in
// ANY form — the only stored credential is the indexer's VIEW-ONLY token (it can
// read this owner's balance/activity and nothing else; no write path accepts it).
// The spending key lives in memory only (keyCache.ts): a login hands it the identity
// the connect signature produced, and a page that did not log in re-derives it from a
// fresh signature at ACTION time. Losing this record loses nothing but a login.
//
// Pure + storage-injected so expiry/shape handling is unit-tested headlessly
// (test/session.test.ts); the app passes the real window.localStorage.

import type { WalletTransport } from "./loginGuard.js";

/** What survives a page reload: enough to show Home + read data, nothing that spends. */
export interface StoredSession {
  /** the connected wallet account (checked against eth_accounts on restore). */
  eoaAddress: string;
  /** compressed bjj pubkey hex — the receive address; public by definition. */
  compressedPubkey: string;
  /** the indexer's opaque view token ("" when the indexer issued none). */
  token: string;
  /** token expiry, unix seconds (0 when tokenless). */
  exp: number;
  /** how the login reached the wallet, so the silent restore knows which transport to
   *  re-open. Absent on records written before WalletConnect existed — read as
   *  "injected", which is what they were. */
  transport?: WalletTransport;
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
    return {
      eoaAddress: s.eoaAddress,
      compressedPubkey: s.compressedPubkey,
      token: s.token,
      exp: s.exp,
      // An unrecognised transport is treated as absent rather than trusted: the restore
      // would open a transport this build has no code for.
      transport: s.transport === "walletconnect" ? "walletconnect" : "injected",
    };
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

// --- which key an account derived here last time -----------------------------------
//
// A SECOND record, deliberately outliving the session one. The session is dropped the
// moment its token expires, but "account 0xa1 derives bjj key K" stays true forever —
// and it is the only evidence that catches a wallet whose signatures are randomised
// (loginGuard.ts): derive a different key from the same account and the login is
// refused instead of silently presenting an empty balance.
//
// Public data only: an ethereum address and a compressed bjj PUBLIC key, the same pair
// the session record already holds. Cleared on an explicit Disconnect — a user asking
// to sign out gets a clean device, and re-deriving on the next login is exactly what
// the first-login determinism check covers.

export const KEY_BINDING_KEY = "bongtu.keybinding.v1";

/** More accounts than anyone uses on one device: past this the map is restarted rather
 *  than grown without bound. */
const MAX_BINDINGS = 16;

type Bindings = Record<string, string>;

function readBindings(storage: StorageLike | null): Bindings {
  if (!storage) return {};
  try {
    const raw = storage.getItem(KEY_BINDING_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw) as unknown;
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
    const out: Bindings = {};
    for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof v === "string") out[k] = v;
    }
    return out;
  } catch {
    return {};
  }
}

/** The compressed bjj pubkey `eoaAddress` derived here last time, or null. */
export function loadKeyBinding(
  eoaAddress: string,
  storage: StorageLike | null = defaultStorage(),
): string | null {
  return readBindings(storage)[eoaAddress.trim().toLowerCase()] ?? null;
}

/** Remember what this account derives, so a later login can be checked against it. */
export function saveKeyBinding(
  eoaAddress: string,
  compressedPubkey: string,
  storage: StorageLike | null = defaultStorage(),
): void {
  if (!storage) return;
  const current = readBindings(storage);
  const bindings = Object.keys(current).length >= MAX_BINDINGS ? {} : current;
  bindings[eoaAddress.trim().toLowerCase()] = compressedPubkey;
  try {
    storage.setItem(KEY_BINDING_KEY, JSON.stringify(bindings));
  } catch {
    // A browser that cannot store this just loses the check, not the login.
  }
}

/** Forget every remembered account (explicit Disconnect only). */
export function clearKeyBindings(storage: StorageLike | null = defaultStorage()): void {
  try {
    storage?.removeItem(KEY_BINDING_KEY);
  } catch {
    // nothing to clean if storage is unreachable
  }
}
