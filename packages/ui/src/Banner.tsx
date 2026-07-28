// The banner — the STATE surface of the error standard (.dev/error-surface-design.md:
// "a banner names a condition that HOLDS and stays until it clears"). It renders
// whatever message the app's state slot currently holds; setting and clearing that
// slot (set on a failed background read, cleared by the next success) is the app's
// state logic — the component itself is deliberately stateless.
//
// Background loops never toast: an outage flips this banner on, every further
// failure keeps it on, the next success clears it. The optional Retry hands the user
// the same read the background loop runs, as a MANUAL (toast-on-failure) attempt.
//
// Tones: `warn` for degraded-but-holding state (stale data), `info` for calm
// session notices (signed out because…). Classname-based on the apps' shared
// Tailwind tokens; each app compiles its own CSS.

import type { ReactNode } from "react";

const TONE: Record<"warn" | "info", string> = {
  warn: "border-warn-border bg-warn-bg text-warn",
  info: "border-info-border bg-info-bg text-info-ink",
};

export function Banner({
  message,
  tone = "warn",
  onRetry,
  retryLabel = "Retry",
}: {
  message: string;
  tone?: "warn" | "info";
  /** renders the retry button only when given — a notice banner has no action. */
  onRetry?: () => void;
  retryLabel?: string;
}): ReactNode {
  return (
    <div
      role="status"
      className={`rounded-xl px-3.5 py-3 text-[0.88rem] flex gap-2.5 items-center justify-between flex-wrap border ${TONE[tone]}`}
    >
      {message}
      {onRetry && (
        <button
          type="button"
          className="rounded-xl border font-semibold cursor-pointer transition-colors bg-surface border-border hover:border-border-strong px-2.5 py-1.5 text-[0.82rem] text-ink"
          onClick={onRetry}
        >
          {retryLabel}
        </button>
      )}
    </div>
  );
}
