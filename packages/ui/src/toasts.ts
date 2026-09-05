// The wallet's ONE toast queue plus its words for the two toast-worthy classes
// (.dev/error-surface-design.md): class 1 — a user-initiated one-shot failed
// (manual refresh, copy) — and class 5 — an unexpected error (a bug), which grows
// the "Copy details" affordance. Background loops NEVER call anything here; their
// only surface is the dataError banner (refresh.ts runRefresh enforces it).
//
// Module-level instance on purpose: flows and hooks outside the React tree
// (useCopyFeedback, the global handlers below) must reach the same queue the
// <ToastHost> in App renders.

import { ToastQueue } from "./toastQueue.js";
import { describeThrown } from "@bongtu/core/errors";

export const toasts = new ToastQueue();

/** Class-1 event toast: something the user just did failed, retrying is sensible. */
export function toastError(message: string): void {
  toasts.show(message);
}

export const COPY_FAILED_TOAST = "Couldn't copy. Select the text and copy it manually.";

export const BUG_TOAST_MESSAGE =
  "Something unexpected went wrong. If it keeps happening, copy the details for a bug report.";

/** Class-5 bug toast: generic headline + Copy details (message + stack). Longer
 *  lifetime than a plain toast — the user needs time to reach the copy button.
 *  The details never leave the device except by the user's own paste (no error
 *  telemetry, ever — privacy stance). */
export function toastBug(thrown: unknown): void {
  toasts.show(BUG_TOAST_MESSAGE, { details: describeThrown(thrown), durationMs: 15000 });
}

/** The event-target slice the global handlers need (injectable for headless tests). */
export interface GlobalErrorTarget {
  addEventListener(type: string, listener: (ev: object) => void): void;
  removeEventListener(type: string, listener: (ev: object) => void): void;
}

/**
 * Route UNCAUGHT errors — the definitionally unexpected class — to the bug toast.
 * Every deliberate failure path in the app is caught and surfaced by its own
 * class; what still reaches window `error`/`unhandledrejection` is a bug, and
 * silently eating it would hide exactly what Copy details exists for. Dedup in
 * the queue keeps a crash loop at one toast. Returns the uninstaller.
 */
export function installGlobalErrorSurface(
  target: GlobalErrorTarget | null = typeof window !== "undefined" ? window : null,
  toast: (thrown: unknown) => void = toastBug,
): () => void {
  if (!target) return () => {};
  const onError = (ev: object): void => {
    const { error, message } = ev as { error?: unknown; message?: unknown };
    toast(error ?? message ?? ev);
  };
  const onRejection = (ev: object): void => {
    toast((ev as { reason?: unknown }).reason ?? ev);
  };
  target.addEventListener("error", onError);
  target.addEventListener("unhandledrejection", onRejection);
  return () => {
    target.removeEventListener("error", onError);
    target.removeEventListener("unhandledrejection", onRejection);
  };
}
