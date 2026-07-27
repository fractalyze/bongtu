// A small live indexer-health chip. Polls the arbiter-mode indexer's GET /health
// (SPEC §6b honest liveness) and renders a colored dot + a one-word state. This is
// pure decoration around fetchHealth — the balance path already surfaces its own
// dataError; this just tells the user at a glance whether the mirror is synced.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { fetchHealth, type Health } from "../../lib/indexerClient.js";

type ChipState = "checking" | "synced" | "degraded" | "offline";

function classify(h: Health | null, errored: boolean): ChipState {
  if (errored) return "offline";
  if (!h) return "checking";
  if (!h.ok) return "degraded";
  return "synced";
}

const LABEL: Record<ChipState, string> = {
  checking: "checking…",
  synced: "synced",
  degraded: "degraded",
  offline: "offline",
};

const DOT: Record<ChipState, string> = {
  checking: "bg-muted animate-pulse-soft",
  synced: "bg-pos",
  degraded: "bg-warn",
  offline: "bg-err",
};

export function StatusChip({ indexerUrl }: { indexerUrl: string }): ReactNode {
  const [health, setHealth] = useState<Health | null>(null);
  const [errored, setErrored] = useState(false);

  useEffect(() => {
    let alive = true;
    const poll = async (): Promise<void> => {
      try {
        const h = await fetchHealth(indexerUrl);
        if (alive) {
          setHealth(h);
          setErrored(false);
        }
      } catch {
        if (alive) setErrored(true);
      }
    };
    void poll();
    const id = setInterval(poll, 15_000);
    return () => {
      alive = false;
      clearInterval(id);
    };
  }, [indexerUrl]);

  const state = classify(health, errored);
  return (
    <span
      className="inline-flex items-center gap-1.5 text-xs text-muted"
      title={`indexer ${indexerUrl}`}
    >
      <span className={`w-[7px] h-[7px] rounded-full ${DOT[state]}`} />
      {LABEL[state]}
    </span>
  );
}
