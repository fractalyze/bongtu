// localStorage wiring for the self-scan cursor state — the APP-LAYER half of
// the persistence contract selfscan.ts defines (the engine owns the shape and
// the codec; this file owns only where it lives). Keyed per owner pubkey so an
// account switch never resumes another account's scan, and every access is
// try/caught: a browser that blocks storage (private mode) just rescans from
// the feed start, which the codec's null-on-anything-malformed rule already
// makes the safe default.
//
// KEY-CUSTODY NOTE: the stored state holds discovered notes' (value, salt) —
// view-side material (amounts), NEVER key material. The bjj/view/kem keys stay
// under keyCache's memory-only rules; nothing here can spend.

import {
  decodeScanState,
  encodeScanState,
  type SelfScanState,
} from "@bongtu/client/selfscan";

const key = (ownerCompressed: string): string => `bongtu.selfscan.${ownerCompressed}`;

/** The stored scan state for this owner, or null (absent/malformed/blocked —
 *  all mean the same thing: the next scan starts from the feed's beginning). */
export function loadScanState(ownerCompressed: string): SelfScanState | null {
  try {
    return decodeScanState(localStorage.getItem(key(ownerCompressed)));
  } catch {
    return null;
  }
}

/** Persist a completed scan (best-effort: a blocked store costs a rescan, not
 *  an error surface). */
export function saveScanState(ownerCompressed: string, state: SelfScanState): void {
  try {
    localStorage.setItem(key(ownerCompressed), encodeScanState(state));
  } catch {
    // storage blocked/full: the in-memory state still serves this page session
  }
}

/** Drop the stored scan — the explicit-Disconnect companion of clearSession
 *  (a clean device must not keep another login's decrypted amounts around). */
export function clearScanState(ownerCompressed: string): void {
  try {
    localStorage.removeItem(key(ownerCompressed));
  } catch {
    // nothing to clear where nothing could be stored
  }
}
