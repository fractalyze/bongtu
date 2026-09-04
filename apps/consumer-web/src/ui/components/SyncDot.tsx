// The nav's sync indicator: one colored dot that IS the refresh button (the
// wallet-web U-W9 shape, kept so the two wallets read identically). In THIS app
// the freshness reference is the SELF-SCAN CURSOR measured against the public
// `GET /head` — there is no /health coupling and no institutional read anywhere
// in the dot's data path, because /head is the one fact the scan is measured
// against and it is served key-free in every indexer mode.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { getHead, type Head } from "@bongtu/client/indexerClient";

export type SyncState = "synced" | "syncing" | "stale";

/** Hover text — the words the chip used to render. */
const TITLE: Record<SyncState, string> = {
  synced: "Synced",
  syncing: "Syncing…",
  stale: "Out of sync. Tap to refresh",
};

/** Screen-reader name: the dot is a BUTTON, so it has to say what pressing it does. */
const ARIA: Record<SyncState, string> = {
  synced: "Refresh balance (synced)",
  syncing: "Refresh balance (syncing)",
  stale: "Refresh balance (out of sync)",
};

const DOT: Record<SyncState, string> = {
  synced: "bg-pos",
  syncing: "bg-warn animate-pulse-soft",
  stale: "bg-err",
};

/** The dot itself, state in / refresh out — pure, so every state gates headlessly. */
export function SyncDot({ state, onRefresh }: { state: SyncState; onRefresh: () => void }): ReactNode {
  return (
    <button
      type="button"
      className="bg-transparent border-0 cursor-pointer inline-flex items-center justify-center rounded-lg p-[7px] transition-colors hover:bg-surface-2 disabled:cursor-not-allowed"
      title={TITLE[state]}
      aria-label={ARIA[state]}
      disabled={state === "syncing"}
      onClick={onRefresh}
    >
      <span className={`w-[9px] h-[9px] rounded-full ${DOT[state]}`} />
    </button>
  );
}

/**
 * One state out of the scan's coverage vs the public head: the dot is green only
 * when the last completed scan covered everything /head says exists
 * (`scannedNextLeafIndex >= head.nextLeafIndex`); a tree that has grown past the
 * scan reads stale — tap to rescan. A load in flight wins (it is the most recent
 * truth about the data on screen), then any failure. Before either side has
 * answered, nothing is confirmed: syncing — a user who sees green must be able
 * to trust the number above it.
 */
export function selfScanSyncState(input: {
  head: Head | null;
  headErrored: boolean;
  /** the last completed scan's /head.nextLeafIndex (null until one lands). */
  scannedNextLeafIndex: number | null;
  refreshing: boolean;
  dataError: boolean;
}): SyncState {
  if (input.refreshing) return "syncing";
  if (input.dataError || input.headErrored) return "stale";
  if (input.head === null || input.scannedNextLeafIndex === null) return "syncing";
  return input.head.nextLeafIndex > input.scannedNextLeafIndex ? "stale" : "synced";
}

/**
 * The dot Home renders: polls the public `GET /head` every 15 s and compares it
 * against the scan cursor's freshness stamp. `onRefresh` is the SAME manual-
 * refresh path every other retry lands on.
 */
export function SelfScanSyncDot({
  indexerUrl,
  scannedNextLeafIndex,
  refreshing,
  dataError,
  onRefresh,
}: {
  indexerUrl: string;
  scannedNextLeafIndex: number | null;
  refreshing: boolean;
  dataError: boolean;
  onRefresh: () => void;
}): ReactNode {
  const [head, setHead] = useState<Head | null>(null);
  const [headErrored, setHeadErrored] = useState(false);

  useEffect(() => {
    const alive = { current: true };
    const poll = async (): Promise<void> => {
      try {
        const h = await getHead(indexerUrl);
        if (alive.current) {
          setHead(h);
          setHeadErrored(false);
        }
      } catch {
        if (alive.current) setHeadErrored(true);
      }
    };
    void poll();
    const id = setInterval(poll, 15_000);
    return () => {
      alive.current = false;
      clearInterval(id);
    };
  }, [indexerUrl]);

  return (
    <SyncDot
      state={selfScanSyncState({ head, headErrored, scannedNextLeafIndex, refreshing, dataError })}
      onRefresh={onRefresh}
    />
  );
}
