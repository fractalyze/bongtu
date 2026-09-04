// The nav's sync indicator: one colored dot that IS the refresh button. It replaced a
// word-chip plus a separate refresh button (U-W9) — the header is icons only now, so
// the state lives in the color and the words live in the tooltip.
//
// Two things feed one dot. The arbiter indexer's own liveness (GET /health, SPEC §6b)
// says whether the mirror is caught up with the chain; the wallet's read state says
// whether THIS page is mid-load or showing a failed read. Either being unhappy makes
// the dot unhappy — a user who sees green must be able to trust the number above it.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { fetchHealth, getHead, type Head, type Health } from "@bongtu/core/indexerApi";

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

/**
 * One state out of the two inputs. A load in flight wins (it is the most recent
 * truth about the data on screen), then any failure — the read's own error, an
 * unreachable /health, or an indexer that reports itself behind. A health check that
 * has not answered yet reads as syncing, not as green: nothing is confirmed yet.
 */
export function syncState(input: {
  health: Health | null;
  healthErrored: boolean;
  refreshing: boolean;
  dataError: boolean;
}): SyncState {
  if (input.refreshing) return "syncing";
  if (input.dataError || input.healthErrored || (input.health !== null && !input.health.ok)) {
    return "stale";
  }
  return input.health === null ? "syncing" : "synced";
}

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
 * The selfscan twin of syncState: the freshness reference is the SCAN CURSOR,
 * not the indexer's self-report. The dot is green only when the last completed
 * scan covered everything /head says exists (`scannedNextLeafIndex >=
 * head.nextLeafIndex`); a tree that has grown past the scan reads stale — tap
 * to rescan. Before either side has answered, nothing is confirmed: syncing.
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
 * The dot Home renders: polls the indexer's health every 15 s and folds it together
 * with the page's own read state. `onRefresh` is the SAME manual-refresh path the
 * post-action poll lands on.
 */
export function IndexerSyncDot({
  indexerUrl,
  refreshing,
  dataError,
  onRefresh,
}: {
  indexerUrl: string;
  refreshing: boolean;
  dataError: boolean;
  onRefresh: () => void;
}): ReactNode {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthErrored, setHealthErrored] = useState(false);

  useEffect(() => {
    const alive = { current: true };
    const poll = async (): Promise<void> => {
      try {
        const h = await fetchHealth(indexerUrl);
        if (alive.current) {
          setHealth(h);
          setHealthErrored(false);
        }
      } catch {
        if (alive.current) setHealthErrored(true);
      }
    };
    void poll();
    const id = setInterval(poll, 15_000);
    return () => {
      alive.current = false;
      clearInterval(id);
    };
  }, [indexerUrl]);

  return <SyncDot state={syncState({ health, healthErrored, refreshing, dataError })} onRefresh={onRefresh} />;
}

/**
 * The dot a SELFSCAN-mode Home renders: polls the public `GET /head` every 15 s
 * and compares it against the scan cursor's freshness stamp. No /health
 * dependency — /head is the one fact the scan is measured against, and it is
 * served key-free in every indexer mode.
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
