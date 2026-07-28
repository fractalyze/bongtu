// The toast model, headless (.dev/error-surface-design.md: toast = EVENT — it
// announces something that happened and goes away; state belongs to the Banner).
// Everything behavioral lives here — ordering, the visible cap, dedup, auto-dismiss
// timing — with the timer injectable, so every rule gates under node:test without a
// DOM. Toast.tsx is the thin React face over `subscribe`/`snapshot`.

export type ToastVariant = "error" | "info";

export interface ToastItem {
  id: number;
  message: string;
  variant: ToastVariant;
  /** class-5 (bug) payload for the "Copy details" affordance; null = plain toast.
   *  Details never leave the device except by the user's own paste — no telemetry. */
  details: string | null;
}

export interface ShowOptions {
  variant?: ToastVariant;
  details?: string | null;
  /** overrides the queue's default lifetime for this toast only. */
  durationMs?: number;
}

export interface ToastQueueOptions {
  /** visible lifetime before auto-dismiss (default 6s); a re-shown duplicate
   *  restarts it instead of stacking a second copy. */
  durationMs?: number;
  /** most toasts visible at once (default 3); the oldest is dropped beyond it. */
  max?: number;
  /** injectable timer for tests: schedule(fn, ms) returns a cancel. */
  schedule?: (fn: () => void, ms: number) => () => void;
}

const realSchedule = (fn: () => void, ms: number): (() => void) => {
  const id = setTimeout(fn, ms);
  return () => clearTimeout(id);
};

export class ToastQueue {
  private items: ToastItem[] = [];
  private readonly cancels = new Map<number, () => void>();
  private readonly listeners = new Set<() => void>();
  private nextId = 1;
  private readonly durationMs: number;
  private readonly max: number;
  private readonly schedule: (fn: () => void, ms: number) => () => void;

  constructor(opts: ToastQueueOptions = {}) {
    this.durationMs = opts.durationMs ?? 6000;
    this.max = opts.max ?? 3;
    this.schedule = opts.schedule ?? realSchedule;
  }

  /** Current visible toasts, oldest first. Stable identity between changes, so
   *  React's useSyncExternalStore can diff by reference. */
  snapshot = (): readonly ToastItem[] => this.items;

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };

  /**
   * Show a toast. DEDUP: an identical message+details already on screen is not
   * stacked again — its auto-dismiss timer restarts and its id is returned, so a
   * failure repeating every few seconds occupies one slot instead of a growing pile.
   */
  show(message: string, opts: ShowOptions = {}): number {
    const details = opts.details ?? null;
    const dup = this.items.find((t) => t.message === message && t.details === details);
    const durationMs = opts.durationMs ?? this.durationMs;
    if (dup) {
      this.arm(dup.id, durationMs);
      return dup.id;
    }
    const item: ToastItem = {
      id: this.nextId++,
      message,
      variant: opts.variant ?? "error",
      details,
    };
    let next = [...this.items, item];
    while (next.length > this.max) {
      this.disarm(next[0].id);
      next = next.slice(1);
    }
    this.items = next;
    this.arm(item.id, durationMs);
    this.notify();
    return item.id;
  }

  /** Remove one toast (the × button, or its timer firing). Unknown ids no-op. */
  dismiss(id: number): void {
    this.disarm(id);
    if (!this.items.some((t) => t.id === id)) return;
    this.items = this.items.filter((t) => t.id !== id);
    this.notify();
  }

  /** Drop everything (route-away/sign-out hygiene). */
  clear(): void {
    for (const cancel of this.cancels.values()) cancel();
    this.cancels.clear();
    if (this.items.length === 0) return;
    this.items = [];
    this.notify();
  }

  private arm(id: number, durationMs: number): void {
    this.disarm(id);
    // A non-finite or non-positive duration means sticky: dismiss only by hand.
    if (!Number.isFinite(durationMs) || durationMs <= 0) return;
    this.cancels.set(id, this.schedule(() => this.dismiss(id), durationMs));
  }

  private disarm(id: number): void {
    this.cancels.get(id)?.();
    this.cancels.delete(id);
  }

  private notify(): void {
    for (const listener of this.listeners) listener();
  }
}
