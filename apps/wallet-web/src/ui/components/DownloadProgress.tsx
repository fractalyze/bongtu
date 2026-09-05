// The one-time proving-key download card (Deposit/Send/Withdraw screen open, cold
// cache): a real progress bar + ETA instead of a bare banner line, because the
// multi-MB zkey takes long enough on ordinary links that a static notice reads as
// a hang. While this renders, the owning screen also disables every proof-reaching
// button (the download and the proof share the same assets).

import type { ReactNode } from "react";
import type { CircuitDownloadView } from "../hooks.js";
import { downloadOnceSubtitle } from "../format.js";

function mb(bytes: number): string {
  return (bytes / (1024 * 1024)).toFixed(1);
}

export function DownloadProgress({ view }: { view: CircuitDownloadView }): ReactNode {
  if (!view.active) return null;
  const pct = view.total !== null && view.total > 0 ? Math.min(100, (view.received / view.total) * 100) : null;
  return (
    <div
      className="flex flex-col gap-2 bg-surface border border-border rounded-xl px-3.5 py-3"
      role="status"
      aria-live="polite"
    >
      <div className="flex flex-col gap-0.5">
        <span className="text-sm font-semibold">Downloading security files</span>
        <span className="text-xs text-muted">{downloadOnceSubtitle(view.total)}</span>
      </div>
      <div className="h-1.5 rounded-full bg-surface-2 overflow-hidden">
        <div
          className={
            pct === null
              ? "h-full rounded-full bg-primary w-[35%] animate-dl-sweep"
              : "h-full rounded-full bg-primary transition-[width] duration-[250ms]"
          }
          style={pct === null ? undefined : { width: `${pct}%` }}
        />
      </div>
      <div className="flex justify-between text-[0.78rem] text-muted tabular-nums">
        <span>
          {mb(view.received)}
          {view.total !== null ? ` / ${mb(view.total)} MB` : " MB"}
        </span>
        {view.etaSeconds !== null && <span>~{view.etaSeconds}s left</span>}
      </div>
    </div>
  );
}
