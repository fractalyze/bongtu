// The one-time proving-key download card (Deposit/Send/Withdraw screen open, cold
// cache): a real progress bar + ETA instead of a bare banner line, because the
// ~28 MB zkey takes long enough on ordinary links that a static notice reads as a
// hang. While this renders, the owning screen also disables every proof-reaching
// button (the download and the proof share the same assets).

import type { ReactNode } from "react";
import type { CircuitDownloadView } from "../hooks.js";

function mb(bytes: number): string {
  return (bytes / (1024 * 1024)).toFixed(1);
}

export function DownloadProgress({ view }: { view: CircuitDownloadView }): ReactNode {
  if (!view.active) return null;
  const pct = view.total !== null && view.total > 0 ? Math.min(100, (view.received / view.total) * 100) : null;
  return (
    <div className="dl" role="status" aria-live="polite">
      <div className="dl-head">
        <span className="dl-title">Downloading proving keys</span>
        <span className="dl-note">one-time · cached for next visits</span>
      </div>
      <div className="dl-track">
        <div
          className={pct === null ? "dl-fill dl-fill-indeterminate" : "dl-fill"}
          style={pct === null ? undefined : { width: `${pct}%` }}
        />
      </div>
      <div className="dl-meta">
        <span>
          {mb(view.received)}
          {view.total !== null ? ` / ${mb(view.total)} MB` : " MB"}
        </span>
        {view.etaSeconds !== null && <span>~{view.etaSeconds}s left</span>}
      </div>
    </div>
  );
}
