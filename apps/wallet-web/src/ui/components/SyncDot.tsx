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
import { fetchHealth, type Health } from "../../lib/indexerClient.js";

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
    let alive = true;
    const poll = async (): Promise<void> => {
      try {
        const h = await fetchHealth(indexerUrl);
        if (alive) {
          setHealth(h);
          setHealthErrored(false);
        }
      } catch {
        if (alive) setHealthErrored(true);
      }
    };
    void poll();
    const id = setInterval(poll, 15_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [indexerUrl]);

  return <SyncDot state={syncState({ health, healthErrored, refreshing, dataError })} onRefresh={onRefresh} />;
}
