// The toast host — the render face of ToastQueue (all queue/dedup/timing rules live
// there, headless). One host per app frame, positioned inside it: toasts are EVENTS
// (.dev/error-surface-design.md), announced politely to screen readers (the
// aria-live region is the host, present before any toast, as live regions must be)
// and dismissable by hand ahead of their timer.
//
// Class-5 (bug) toasts carry `details` and grow the "Copy details" affordance: the
// full message + stack to the clipboard for a bug report. That paste is the ONLY way
// error details leave the device — no telemetry, ever (privacy stance, locked).
//
// Styling is classname-based on the apps' shared Tailwind tokens (err/info palette);
// each app compiles its own CSS and must include this package as a Tailwind source.

import { useEffect, useState, useSyncExternalStore } from "react";
import type { ReactNode } from "react";
import type { ToastItem, ToastQueue } from "./toastQueue.js";
import { copyText } from "./clipboard.js";

const CARD: Record<ToastItem["variant"], string> = {
  error: "border-err-border bg-err-bg text-err",
  info: "border-info-border bg-info-bg text-info-ink",
};

function CopyDetailsButton({ details }: { details: string }): ReactNode {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const id = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(id);
  }, [copied]);
  return (
    <button
      type="button"
      className="bg-transparent border-0 p-0 cursor-pointer font-sans font-semibold underline text-[0.8rem] text-inherit"
      onClick={() => {
        void copyText(details).then((ok) => {
          if (ok) setCopied(true);
        });
      }}
    >
      {copied ? "Copied" : "Copy details"}
    </button>
  );
}

function ToastCard({ item, onDismiss }: { item: ToastItem; onDismiss: () => void }): ReactNode {
  return (
    <div
      role="status"
      className={`pointer-events-auto rounded-xl border px-3.5 py-3 text-[0.88rem] shadow-[0_6px_20px_-12px_rgba(17,24,39,0.35)] flex items-start gap-2.5 ${CARD[item.variant]}`}
    >
      <span className="flex-1 min-w-0 [overflow-wrap:anywhere]">
        {item.message}
        {item.details !== null && (
          <span className="block mt-1">
            <CopyDetailsButton details={item.details} />
          </span>
        )}
      </span>
      <button
        type="button"
        aria-label="Dismiss"
        className="bg-transparent border-0 p-0 cursor-pointer text-inherit font-semibold leading-none text-[1rem]"
        onClick={onDismiss}
      >
        ×
      </button>
    </div>
  );
}

/** The one toast surface of an app frame. Mount it once, inside a `relative`
 *  container (the app's frame div); it floats over the bottom edge. */
export function ToastHost({ queue }: { queue: ToastQueue }): ReactNode {
  const items = useSyncExternalStore(queue.subscribe, queue.snapshot, queue.snapshot);
  return (
    <div
      aria-live="polite"
      className="absolute bottom-3 left-3 right-3 z-50 flex flex-col gap-2 pointer-events-none"
    >
      {items.map((t) => (
        <ToastCard key={t.id} item={t} onDismiss={() => queue.dismiss(t.id)} />
      ))}
    </div>
  );
}
