// The once-per-device "why your wallet locks" explainer: whether to show it, and the
// one boolean that records that it was shown.
//
// This is the ONLY thing besides the session record the wallet writes to localStorage,
// and it is deliberately not key material — a seen-flag leaks nothing, so the
// memory-only rule that governs the bjj key (keyCache.ts) does not reach it. Nothing
// here ever touches a key, a token or an address.
//
// Pure + storage-injected like session.ts, so the gating is unit-tested headlessly.

import type { StorageLike } from "@bongtu/client/session";

export const LOCK_INTRO_KEY = "bongtu.lockIntro.v1";

function defaultStorage(): StorageLike | null {
  try {
    return (globalThis as { localStorage?: StorageLike }).localStorage ?? null;
  } catch {
    return null; // storage blocked (private mode / hard privacy settings)
  }
}

/** Whether this device has already been shown the explainer. Unreadable storage
 *  counts as "not seen": showing it twice is a smaller cost than never showing it. */
export function hasSeenLockIntro(storage: StorageLike | null = defaultStorage()): boolean {
  try {
    return storage?.getItem(LOCK_INTRO_KEY) === "1";
  } catch {
    return false;
  }
}

/** Record that the explainer was shown (best-effort — a blocked storage just means
 *  the next login sees it again). */
export function markLockIntroSeen(storage: StorageLike | null = defaultStorage()): void {
  try {
    storage?.setItem(LOCK_INTRO_KEY, "1");
  } catch {
    // quota/privacy-mode write failure — the flag is a convenience only.
  }
}

/**
 * The whole rule, in one place: the explainer belongs to a FRESH login on a device
 * that has not seen it. A restored session never shows it — it explains the unlock
 * the login just performed, and a restore performs none (it starts locked).
 */
export function shouldShowLockIntro(
  origin: "connect" | "restore",
  storage: StorageLike | null = defaultStorage(),
): boolean {
  return origin === "connect" && !hasSeenLockIntro(storage);
}
