// scan/session.ts — the ScanSession: the ONE owner of the self-scan round-trip
// both wallet shells used to hand-copy into App.tsx (state read, key peek,
// identity gate, runSelfScan, ref + store writeback, notice — issue #53).
// House shape (the sanctioned class bar): state is exactly the scan state + the owner
// stamp (the shells' old scanRef/scanOwnerRef pair); injected are the
// SelfScanIo, the per-owner store seam, and the key source. The engine
// (selfscan/run.ts) stays the primitive layer — every pass DELEGATES to
// runSelfScan — and the resumability contract it documents (cursor + notes +
// pending are ONE state) gets its owner here: the whole state a pass produced
// is written back through the store seam in the same call, never a field at a
// time. React-free by construction: the shells keep their own state wiring and
// consume the returned outcome.

import type { WalletIdentity } from "@bongtu/client/derive";
import { isConsumerIdentity, type ScanNote } from "./selfscan/engine.js";
import {
  EMPTY_SCAN_STATE,
  SELF_SCAN_LOCKED_NOTICE,
  SELF_SCAN_PENDING_NOTICE,
  runSelfScan,
  selfScanSnapshot,
  type SelfScanIo,
  type SelfScanState,
} from "./selfscan/run.js";

/** The per-owner persistence seam — the APP-LAYER half of the run.ts contract
 *  (each app's scanStore wires its localStorage functions here; a fake store
 *  gates the round-trip headlessly). `load` returning null means "no usable
 *  state" (absent, malformed, or storage blocked) — the next scan starts from
 *  the feed's beginning, which the codec's defensive decode already makes the
 *  safe default. */
export interface ScanStateStore {
  load(ownerCompressed: string): SelfScanState | null;
  save(ownerCompressed: string, state: SelfScanState): void;
  clear(ownerCompressed: string): void;
}

/** The lock's non-extending read (keyCache.peek satisfies this structurally):
 *  a background scan must never pop a signature or refresh the idle deadline,
 *  so this is the ONLY key access a pass makes. Null means locked. */
export interface ScanKeySource {
  peek(ownerCompressed: string): WalletIdentity | null;
}

/** What one completed pass hands the shell. */
export interface ScanOutcome {
  /** the completed scan in the arbiter snapshot's shape (selfScanSnapshot) —
   *  what the shell hands applySnapshot unchanged, so everything downstream
   *  (snapshotChanged, sumUnspent) stays engine-blind. */
  snapshot: ReturnType<typeof selfScanSnapshot>;
  /** the freshness stamp — the state's scannedNextLeafIndex, the sync dot's
   *  coverage reference. */
  scannedNextLeafIndex: number;
  /** the calm-strip verdict (scanNotice below), decided against whether the
   *  key source held an identity for THIS pass. */
  notice: string | null;
}

/**
 * The calm-strip verdict one completed scan implies, in ONE pure place so no
 * shell can re-derive the precedence inline (and so it gates headlessly).
 * Pending wins over locked: kem chunks still in flight mean money may exist
 * that no unlock could reveal yet — the more actionable fact. A locked wallet
 * (no identity in the memory lock) is serving its last completed scan, which
 * the locked notice says plainly; an unlocked, fully-delivered scan needs no
 * strip at all.
 */
export function scanNotice(state: SelfScanState, identityHeld: boolean): string | null {
  if (state.pending.length > 0) return SELF_SCAN_PENDING_NOTICE;
  return identityHeld ? null : SELF_SCAN_LOCKED_NOTICE;
}

/**
 * Construct once per page (beside the IndexerClient whose reads it consumes),
 * call per refresh tick. The three session verbs below map one-to-one onto
 * the shells' lifecycle sites: `detach` is the account-switch guard, `end`
 * the plain sign-out, `forgetOwner` the explicit-Disconnect clean device.
 */
export class ScanSession {
  /** the last completed scan held in memory (null = resume from the store). */
  private state: SelfScanState | null = null;
  /** the owner stamp: whose scan `state` is, and which stored row a
   *  clean-device forget clears — resolved at forget time, so no caller has
   *  to thread session state into a sign-out path. */
  private owner: string | null = null;

  constructor(
    private readonly io: SelfScanIo,
    private readonly store: ScanStateStore,
    private readonly keys: ScanKeySource,
  ) {}

  /**
   * ONE scan for `ownerCompressed`: resume memory-first (the store is read
   * only when memory is empty or stamped for another owner), peek the lock,
   * run the incremental §3.6 pass when the consumer identity is held — a
   * LOCKED session, or an enterprise-only identity that cannot self-scan,
   * serves the previous state untouched, because a background read must never
   * pop a signature — then write the WHOLE resulting state back through the
   * store seam and stamp the owner.
   */
  async scan(ownerCompressed: string): Promise<ScanOutcome> {
    const prev =
      (this.owner === ownerCompressed ? this.state : null) ??
      this.store.load(ownerCompressed) ??
      EMPTY_SCAN_STATE;
    const identity = this.keys.peek(ownerCompressed);
    const state =
      identity !== null && isConsumerIdentity(identity)
        ? await runSelfScan(this.io, identity, prev)
        : prev;
    this.state = state;
    this.owner = ownerCompressed;
    this.store.save(ownerCompressed, state);
    return {
      snapshot: selfScanSnapshot(state, ownerCompressed),
      scannedNextLeafIndex: state.scannedNextLeafIndex,
      notice: scanNotice(state, identity !== null),
    };
  }

  /** The wallet's discovered notes as of the last pass — the ConsumerNoteSource
   *  `notes()` read (empty before any pass, and after end/forgetOwner). */
  notes(): ScanNote[] {
    return this.state?.notes ?? [];
  }

  /** Account-switch guard: drop only the IN-MEMORY state — the next pass
   *  resumes from the per-owner store, never from memory whose owner the live
   *  wallet no longer vouches for. The owner stamp survives: it still names
   *  the stored row a clean-device forget must clear. */
  detach(): void {
    this.state = null;
  }

  /** Plain sign-out: drop the in-memory state AND the owner stamp — a stamp
   *  that outlived its session once let a later owner's Disconnect clear the
   *  PREVIOUS owner's stored row. The stored row itself survives for this
   *  owner's next login. */
  end(): void {
    this.state = null;
    this.owner = null;
  }

  /** Explicit-Disconnect clean device: clear the stamped owner's stored row
   *  (a clean device keeps no decrypted amounts), then end the session state.
   *  A no-op when no owner is stamped — precisely so a stale invocation can
   *  never clear another owner's row. */
  forgetOwner(): void {
    if (this.owner !== null) this.store.clear(this.owner);
    this.end();
  }
}
