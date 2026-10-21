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
// (test/session.test.ts): the StorageLike is SessionStore's constructor dep, and
// the app constructs over the real window.localStorage.

import { DEPLOYMENT_TAG } from "@bongtu/core/network";

import type { WalletTransport } from "@bongtu/client/loginGuard";

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

// SCOPED TO THE DEPLOYMENT, not just to "bongtu": the record holds the bjj pubkey
// this account derived, and the KDF domain is (chainId, pool) — so on a chain move
// or a redeploy the stored pubkey names a key this build can no longer derive.
// Read under an unscoped name it would be RESTORED (the restore matches on the EOA
// alone) and the user would be shown a receive address whose notes are unspendable
// here. Under the tag it is simply not found, and the login re-derives cleanly.
export const SESSION_KEY = `bongtu.session.${DEPLOYMENT_TAG}`;

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

// Scoped to the deployment for the same reason as SESSION_KEY, and here the cost of
// NOT scoping it is worse: the binding is a REFUSAL, so a pre-move entry would make
// every returning user's login fail with "this wallet produced a different signing
// key than last time" (loginGuard.ts) — accusing a perfectly good wallet, with no
// in-app way out, when the truth is that the KDF domain moved. Deliberately NOT
// migrated forward: carrying the old pubkey over is exactly that false mismatch.
// Stale entries under a previous tag are left to linger; they are two public values.
export const KEY_BINDING_KEY = `bongtu.keybinding.${DEPLOYMENT_TAG}`;

/** More accounts than anyone uses on one device: past this the map is restarted rather
 *  than grown without bound. */
const MAX_BINDINGS = 16;

type Bindings = Record<string, string>;

function defaultStorage(): StorageLike | null {
  try {
    return (globalThis as { localStorage?: StorageLike }).localStorage ?? null;
  } catch {
    return null; // storage blocked (private mode / hard privacy settings)
  }
}

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

/**
 * Both persisted records behind one receiver. The store itself holds NO state —
 * the StorageLike IS the state, so two stores over the same storage see each
 * other's writes and constructing one is free. The storage arrives once, as a
 * constructor dep (the KeyCache wiring pattern: required deps up front, defaults
 * for the rest), instead of trailing every call as a defaulted param. Methods are
 * arrow properties so a caller (loginFlow's DEFAULT_DEPS) can pluck them off an
 * instance without losing `this`.
 */
export class SessionStore {
  private readonly storage: StorageLike | null;

  constructor(storage: StorageLike | null = defaultStorage()) {
    this.storage = storage;
  }

  /** Persist the login record. Best-effort: a blocked/full storage just means the
   *  next visit reconnects normally. */
  readonly saveSession = (session: StoredSession): void => {
    try {
      this.storage?.setItem(SESSION_KEY, JSON.stringify(session));
    } catch {
      // quota/privacy-mode write failure — session persistence is a convenience only.
    }
  };

  /**
   * Load the stored session, or null when absent, malformed, tokenless, or expired
   * (expired/broken records are removed so the next visit starts clean). `now` is
   * unix seconds, injectable for expiry tests.
   */
  readonly loadSession = (now: number = Math.floor(Date.now() / 1000)): StoredSession | null => {
    const storage = this.storage;
    if (!storage) return null;
    const raw = ((): string | null => {
      try {
        return storage.getItem(SESSION_KEY);
      } catch {
        return null;
      }
    })();
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
  };

  /** Drop the stored login record (the Settings Disconnect button). */
  readonly clearSession = (): void => {
    try {
      this.storage?.removeItem(SESSION_KEY);
    } catch {
      // nothing to clean if storage is unreachable
    }
  };

  /** The compressed bjj pubkey `eoaAddress` derived here last time, or null. */
  readonly loadKeyBinding = (eoaAddress: string): string | null => {
    return readBindings(this.storage)[eoaAddress.trim().toLowerCase()] ?? null;
  };

  /** Remember what this account derives, so a later login can be checked against it. */
  readonly saveKeyBinding = (eoaAddress: string, compressedPubkey: string): void => {
    const storage = this.storage;
    if (!storage) return;
    const current = readBindings(storage);
    const bindings = Object.keys(current).length >= MAX_BINDINGS ? {} : current;
    bindings[eoaAddress.trim().toLowerCase()] = compressedPubkey;
    try {
      storage.setItem(KEY_BINDING_KEY, JSON.stringify(bindings));
    } catch {
      // A browser that cannot store this just loses the check, not the login.
    }
  };

  /** Forget every remembered account (explicit Disconnect only). */
  readonly clearKeyBindings = (): void => {
    try {
      this.storage?.removeItem(KEY_BINDING_KEY);
    } catch {
      // nothing to clean if storage is unreachable
    }
  };
}
