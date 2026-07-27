// The wallet's LOCK: where the spending key lives between actions.
//
// KEY-CUSTODY RULE (user-mandated): the bjj private key may live in memory only.
// This module is the one place that holds it across calls — a module-level object
// reference, never localStorage / sessionStorage / IndexedDB / cookies / a URL, and
// never anything a page reload survives. Every path that ends the hold (logout, an
// account switch, the idle wipe) drops the reference outright.
//
// Why hold it at all: deriving is one MetaMask signature popup, and asking for it on
// every send/withdraw/deposit was rejected UX. Logging in already spends that popup —
// connect derives the identity to sign the indexer token handshake — so the login hands
// the identity straight to this cache (seed()), and the wallet is unlocked from the
// first screen with no extra popup. A page that did NOT log in this session (a silently
// restored session, a reload) starts locked, and its first action derives (unlock()).
// Either way, later actions in the same page session reuse the identity — only the
// transaction popup remains.
//
// What ends the hold:
//   - lock() — logout/disconnect, and the injected wallet's accountsChanged event.
//   - the idle wipe, in TWO layers. (1) An armed timer fires ~10 min after the last
//     use, drops the key and notifies subscribers so the UI says "Locked" at that
//     moment. (2) A timestamp check when the key is about to be used, because a
//     background tab's timers are throttled by the browser and a late timer must
//     never let an expired key be used.
//   - a page reload, for free: nothing here is persisted.
//
// The account the key was derived under is held alongside it. MetaMask's selected
// account can change under a live page (`connection.address` is frozen at connect
// time), and the derivation follows the CURRENT account — so a cached key whose
// account no longer matches is refused, without a popup, because that cached key
// already passed the session check and no other account can reproduce it.

import type { WalletIdentity } from "./derive.js";
import { ACCOUNT_MISMATCH_MESSAGE, assertSessionIdentity, deriveTransientIdentity } from "./identity.js";
import { currentAccount, type Connection } from "./metamask.js";

/** How long an unused spending key is kept before the wallet re-locks itself. */
export const IDLE_WIPE_MS = 10 * 60 * 1000;

/** The I/O + clock the cache depends on, injectable so the whole state machine —
 *  including both idle-wipe layers — gates headlessly (test/keyCache.test.ts). */
export interface KeyCacheDeps {
  derive: (connection: Connection) => Promise<WalletIdentity>;
  currentAccount: (connection: Connection) => Promise<string | null>;
  now: () => number;
  idleMs: number;
  /** Arms the idle wipe and returns its canceller. A test can pass a no-op to
   *  simulate a throttled background tab whose timer never fires. */
  arm: (fn: () => void, ms: number) => () => void;
}

const DEFAULT_DEPS: KeyCacheDeps = {
  derive: deriveTransientIdentity,
  currentAccount,
  now: () => Date.now(),
  idleMs: IDLE_WIPE_MS,
  arm: (fn, ms) => {
    const id = setTimeout(fn, ms);
    return () => clearTimeout(id);
  },
};

interface HeldKey {
  identity: WalletIdentity;
  /** lowercased eth account the identity was derived under. */
  account: string;
  /** compressed bjj pubkey of the session it was checked against. */
  sessionPubkey: string;
  lastUsedAt: number;
}

export class KeyCache {
  private readonly deps: KeyCacheDeps;
  private held: HeldKey | null = null;
  private disarm: (() => void) | null = null;
  private readonly listeners = new Set<() => void>();

  constructor(deps: Partial<KeyCacheDeps> = {}) {
    this.deps = { ...DEFAULT_DEPS, ...deps };
  }

  /** Whether a usable spending key is held. A key past its idle deadline reads as
   *  locked even if its timer hasn't fired yet — the use-time belt, so the indicator
   *  and the flows agree. */
  isUnlocked(): boolean {
    return this.held !== null && !this.expired(this.held);
  }

  /** Subscribe to lock/unlock changes (the lock indicator's data path). */
  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /** Drop the key now: logout/disconnect, or an account switch. */
  lock(): void {
    this.disarm?.();
    this.disarm = null;
    if (!this.held) return;
    this.held = null;
    this.notify();
  }

  /**
   * Take an identity the LOGIN just derived (App.connectWallet signs the token
   * handshake with it) so the wallet is unlocked without a second popup.
   *
   * It goes through the same session check `unlock` applies to a freshly derived key:
   * an identity that is not `sessionPubkey`'s is refused and nothing is held. The
   * account is the one connect just returned — a later switch fires accountsChanged,
   * which locks, and `unlock` re-checks the account on every use anyway.
   *
   * The seeded key is an ordinary hold: same idle deadline, same wipe, same lock().
   */
  seed(identity: WalletIdentity, account: string, sessionPubkey: string): void {
    assertSessionIdentity(identity.compressedPubkey, sessionPubkey);
    this.held = {
      identity,
      account: account.toLowerCase(),
      sessionPubkey,
      lastUsedAt: this.deps.now(),
    };
    this.rearm();
    this.notify();
  }

  /**
   * The spending key for `sessionPubkey`, derived if the wallet is locked and reused
   * if it is not. `onDerive` fires only when a signature popup is about to appear.
   *
   * Throws ACCOUNT_MISMATCH_MESSAGE when the account selected in the connected
   * wallet is not the one this session's key belongs to — before any popup when a
   * cached key already proves the mismatch, and only after deriving otherwise,
   * because with an empty cache the derived key IS the evidence.
   */
  async unlock(
    connection: Connection,
    sessionPubkey: string,
    onDerive?: () => void,
  ): Promise<WalletIdentity> {
    const account = await this.deps.currentAccount(connection);
    const held = this.held;
    if (held) {
      if (account !== null && account !== held.account) {
        // The held key passed the session check under held.account, so no other
        // account can derive it — refuse here rather than spend a popup proving it.
        this.lock();
        throw new Error(ACCOUNT_MISMATCH_MESSAGE);
      }
      // Unreadable account, a different session, or an idle-expired key: no popup
      // is saved by keeping this one.
      if (account === null || held.sessionPubkey !== sessionPubkey || this.expired(held)) this.lock();
    }
    if (this.held) {
      this.held.lastUsedAt = this.deps.now();
      this.rearm();
      return this.held.identity;
    }
    onDerive?.();
    const identity = await this.deps.derive(connection);
    assertSessionIdentity(identity.compressedPubkey, sessionPubkey);
    this.held = {
      identity,
      account: account ?? connection.address.toLowerCase(),
      sessionPubkey,
      lastUsedAt: this.deps.now(),
    };
    this.rearm();
    this.notify();
    return identity;
  }

  private expired(held: HeldKey): boolean {
    return this.deps.now() - held.lastUsedAt >= this.deps.idleMs;
  }

  private rearm(): void {
    this.disarm?.();
    this.disarm = this.deps.arm(() => this.lock(), this.deps.idleMs);
  }

  private notify(): void {
    for (const l of this.listeners) l();
  }
}

/** The wallet's one cache. Flows take it through their deps seam so tests can run
 *  their own instance with a fake clock. */
export const keyCache = new KeyCache();

// Stable module-level bindings for useSyncExternalStore (a fresh closure per render
// would resubscribe on every paint).
export const subscribeLock = (listener: () => void): (() => void) => keyCache.subscribe(listener);
export const isWalletUnlocked = (): boolean => keyCache.isUnlocked();
