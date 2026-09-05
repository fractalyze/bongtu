// The auto-refresh tick gate, pure so it gates headlessly: a hidden tab runs
// NO background pass (the cadence exists for a screen someone is looking at —
// a throttled background tab polling the indexer is pure cost), and a tick
// never overlaps an in-flight one. The pass itself stays peek-only (App reads
// the lock with keyCache.peek): a background read must never extend the idle
// deadline, or a tab left open would never re-lock.

/** Whether an AUTO_REFRESH_MS tick may run a background pass right now. */
export function autoTickAllowed(visibility: string, inflight: boolean): boolean {
  return visibility === "visible" && !inflight;
}
