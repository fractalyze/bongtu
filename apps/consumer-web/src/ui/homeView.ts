// The Home surface as ONE pure fold over the scan world: what the balance hero
// shows, which calm strip (if any) sits under it, and what the sync dot says —
// the whole discovery-state table in a single testable seam. The PIECES are the
// same folds the live wiring consumes (balanceHero → BalanceCard, scanNotice →
// App's dataNotice, selfScanSyncState → SelfScanSyncDot), so each gated row is
// transitively real; the COMPOSITION itself is consumed only by the table in
// test/discovery.test.ts until S6 wires Home through it — App still assembles
// the same pieces through its own state today, so treat the composite as the
// contract the wiring converges on, not proof of it. S6's op screens read
// their world through this seam too.

import { sumUnspent } from "@bongtu/client/balance";
import { formatKkrw } from "@bongtu/client/money";
import type { SelfScanState } from "@bongtu/client/selfscan";
import type { Head } from "@bongtu/client/indexerClient";
import { scanNotice } from "../lib/scanStore.js";
import { selfScanSyncState, type SyncState } from "./components/SyncDot.js";

/** What the balance hero renders. The three states exist because a null balance
 *  must NEVER read as zero: until the first completed pass lands there is no
 *  number to show — only the loading ellipsis (a scan is running) or the dash
 *  (nothing is). A LOADED zero is an amount like any other: the scan's truth. */
export type BalanceHero =
  | { kind: "loading" }
  | { kind: "unloaded" }
  | { kind: "amount"; text: string };

export function balanceHero(balance: bigint | null, loading: boolean): BalanceHero {
  if (balance !== null) return { kind: "amount", text: formatKkrw(balance) };
  return loading ? { kind: "loading" } : { kind: "unloaded" };
}

export interface HomeViewInput {
  /** the last COMPLETED scan pass, or null before one lands (the app keeps the
   *  balance null until a snapshot has actually been applied). */
  scan: SelfScanState | null;
  /** whether the memory lock holds the identity (keyCache) — false is the
   *  locked wallet serving its last scan. */
  identityHeld: boolean;
  loading: boolean;
  dataError: boolean;
  /** the public /head as the dot's poll last saw it. */
  head: Head | null;
  headErrored: boolean;
}

export interface HomeView {
  hero: BalanceHero;
  /** the calm strip (pending kem delivery / locked), or null — never an error. */
  strip: string | null;
  dot: SyncState;
}

/**
 * One world in, one screen-state out. The stale dot is the partial-coverage
 * honesty: a scan that stopped short of /head (a maxPages-capped run stamps
 * only what it covered — selfscan.ts) keeps its number on screen but marks it
 * stale, never a silently small balance presented as synced.
 */
export function homeView(input: HomeViewInput): HomeView {
  // ScanNote carries {value, spent}, which is all sumUnspent reads — the same
  // sum the app applies from the snapshot, without needing the owner pubkey
  // the snapshot only uses to fill fields the balance never touches.
  const balance = input.scan === null ? null : sumUnspent(input.scan.notes);
  return {
    hero: balanceHero(balance, input.loading),
    strip: input.scan === null ? null : scanNotice(input.scan, input.identityHeld),
    dot: selfScanSyncState({
      head: input.head,
      headErrored: input.headErrored,
      scannedNextLeafIndex: input.scan?.scannedNextLeafIndex ?? null,
      refreshing: input.loading,
      dataError: input.dataError,
    }),
  };
}
