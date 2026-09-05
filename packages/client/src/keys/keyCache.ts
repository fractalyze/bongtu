// The wallet's LOCK: where the spending key — and the stealth identity derived
// beside it — lives between actions.
//
// KEY-CUSTODY RULE (user-mandated): the bjj private key may live in memory only.
// This module is the one place that holds it across calls — a module-level object
// reference, never localStorage / sessionStorage / IndexedDB / cookies / a URL, and
// never anything a page reload survives. Every path that ends the hold (logout, an
// account switch, the idle wipe) drops the reference outright.
//
// The stealth meta keys (stealthKeys.ts) are custody-equivalent — whoever holds
// them controls the user's one-time addresses — so they live under the SAME rules,
// as a second derived value INSIDE the same hold: one state machine, one idle
// deadline, one lock() — never a parallel cache that could drift out of step.
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
// "Last use" means a USER action. A background poll reads the key through peek(),
// which deliberately does not push the deadline out — otherwise a console left open
// on a refreshing screen would never re-lock.
//
// The account the key was derived under is held alongside it. MetaMask's selected
// account can change under a live page (`connection.address` is frozen at connect
// time), and the derivation follows the CURRENT account — so a cached key whose
// account no longer matches is refused, without a popup, because that cached key
// already passed the session check and no other account can reproduce it.

import type { StealthKeys } from "@bongtu/core/stealth";
import type { WalletIdentity } from "@bongtu/client/derive";
import { ACCOUNT_MISMATCH_MESSAGE, assertSessionIdentity } from "@bongtu/client/identity";
import type { Connection } from "@bongtu/client/rail";

/** How long an unused spending key is kept before the wallet re-locks itself. */
export const IDLE_WIPE_MS = 10 * 60 * 1000;

/** The lock as the FLOWS consume it (issue #27): exactly the two methods a
 *  prove+submit orchestration calls — the running-state read and the
 *  session-checked key handout. Flow deps type against THIS, not the concrete
 *  class, so a headless suite can hand a flow a plain-object fake without
 *  constructing the whole state machine; the real KeyCache below satisfies it
 *  implicitly (structural typing — no `implements` to drift). peek/seed/
 *  subscribe/lock stay class-only on purpose: they are shell (login/indicator)
 *  concerns no flow may touch. */
export interface KeyCacheLike {
  isUnlocked(): boolean;
  unlock(
    connection: Connection,
    sessionPubkey: string,
    onDerive?: () => void,
  ): Promise<WalletIdentity>;
}

/** The I/O + clock the cache depends on, injectable so the whole state machine —
 *  including both idle-wipe layers — gates headlessly (test/keyCache.test.ts).
 *  The two derivations are METHOD-style over the structural rail Connection so
 *  a rail client's implementations (typed over its own wider Connection) are
 *  assignable — the rail wiring itself lives in @bongtu/client-evm/keyCache
 *  createKeyCache. */
export interface KeyCacheDeps {
  derive(connection: Connection): Promise<WalletIdentity>;
  /** The stealth meta-key derivation (its own EIP-712 popup — deriveStealthKeys
   *  partially applied by the app), unlocked lazily on the first stealth action. */
  deriveStealth(connection: Connection): Promise<StealthKeys>;
  currentAccount: () => Promise<string | null>;
  now: () => number;
  idleMs: number;
  /** Arms the idle wipe and returns its canceller. A test can pass a no-op to
   *  simulate a throttled background tab whose timer never fires. */
  arm: (fn: () => void, ms: number) => () => void;
}

/** What a KeyCache must be handed to exist: `derive` (the identity derivation,
 *  carrying the deployment's KDF config), `deriveStealth` (the stealth meta-key
 *  derivation — required so no app can hold stealth keys outside the lock for
 *  lack of a seam), and `currentAccount` (the wallet edge's live-account read).
 *  Clock/timer deps default to the real ones. Apps construct through
 *  createKeyCache below; this wiring seam exists for tests, which need to fake
 *  the derivations and the clock. */
export type KeyCacheWiring = Pick<KeyCacheDeps, "derive" | "deriveStealth" | "currentAccount"> &
  Partial<KeyCacheDeps>;

const DEFAULT_DEPS: Omit<KeyCacheDeps, "derive" | "deriveStealth" | "currentAccount"> = {
  now: () => Date.now(),
  idleMs: IDLE_WIPE_MS,
  arm: (fn, ms) => {
    const id = setTimeout(fn, ms);
    return () => clearTimeout(id);
  },
};

interface HeldKey {
  identity: WalletIdentity;
  /** The stealth identity, once its first action derived it — a FIELD of this
   *  hold, so every path that drops the hold (lock, wipe, switch) drops it too.
   *  null until unlockStealth pays its one popup. */
  stealth: StealthKeys | null;
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

  constructor(deps: KeyCacheWiring) {
    this.deps = { ...DEFAULT_DEPS, ...deps };
  }

  /** Whether a usable spending key is held. A key past its idle deadline reads as
   *  locked even if its timer hasn't fired yet — the use-time belt, so the indicator
   *  and the flows agree. */
  isUnlocked(): boolean {
    return this.held !== null && !this.expired(this.held);
  }

  /**
   * The held identity for `sessionPubkey`, or null — read WITHOUT touching the idle
   * deadline and without asking the wallet which account is selected.
   *
   * For BACKGROUND reads only: a poll that signs an indexer request with a key the
   * lock already has. It must not go through unlock(), for two reasons. The wipe
   * deadline has to measure what the USER did — a 3-second refresh that re-armed it
   * would keep an unattended console unlocked forever, which is exactly what the
   * 10-minute wipe exists to prevent. And the account round-trip would only re-prove
   * what the accountsChanged watcher already enforces by emptying the lock on a
   * switch. A background read never derives either, so there is no popup to decide
   * about: an empty or expired lock simply means "no read right now".
   */
  peek(sessionPubkey: string): WalletIdentity | null {
    const held = this.held;
    if (!held || held.sessionPubkey !== sessionPubkey || this.expired(held)) return null;
    return held.identity;
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
      stealth: null,
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
    const account = await this.deps.currentAccount();
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
      stealth: null,
      account: account ?? connection.address.toLowerCase(),
      sessionPubkey,
      lastUsedAt: this.deps.now(),
    };
    this.rearm();
    this.notify();
    return identity;
  }

  /**
   * The stealth meta keys for `sessionPubkey`, derived on the first stealth action
   * and reused from the hold after that.
   *
   * The gate is LITERALLY unlock(): a stealth unlock first takes (or derives) the
   * spending key under the very same account / session / idle-expiry checks, so a
   * stealth action under a switched account refuses with the same
   * ACCOUNT_MISMATCH_MESSAGE — before any stealth popup — and an idle-expired or
   * signed-out hold has already dropped the stealth keys along with the spending
   * key. Making stealth subordinate to the spending session (rather than a peer
   * hold with its own bookkeeping) is what keeps this ONE state machine.
   *
   * The stealth popup can sit open across an account switch, and unlike the
   * spending key the derived value cannot be checked against the session pubkey —
   * so after deriving, the account is read AGAIN and the keys are refused outright
   * if the hold moved or the account no longer matches: a mid-popup switch must
   * never cache (or hand out) the new account's stealth identity under the old
   * session.
   */
  async unlockStealth(
    connection: Connection,
    sessionPubkey: string,
    onDerive?: () => void,
  ): Promise<StealthKeys> {
    await this.unlock(connection, sessionPubkey, onDerive);
    const held = this.held;
    if (!held) throw new Error(ACCOUNT_MISMATCH_MESSAGE); // hold vanished mid-flight
    if (held.stealth) {
      held.lastUsedAt = this.deps.now();
      this.rearm();
      return held.stealth;
    }
    onDerive?.();
    const stealth = await this.deps.deriveStealth(connection);
    const account = await this.deps.currentAccount();
    if (this.held !== held || account === null || account !== held.account) {
      this.lock();
      throw new Error(ACCOUNT_MISMATCH_MESSAGE);
    }
    held.stealth = stealth;
    held.lastUsedAt = this.deps.now();
    this.rearm();
    return stealth;
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

// The one sanctioned app construction (createKeyCache) moved to the EVM rail
// client (@bongtu/client-evm/keyCache): it wires THIS state machine to the
// rail's derivations, which the rail-agnostic engine may not import.
