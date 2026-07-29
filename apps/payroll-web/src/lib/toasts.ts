// The console's ONE toast queue (@bongtu/ui — toast = event, banner = state,
// .dev/error-surface-design.md). Module-level on purpose: run callbacks outside
// the React tree must reach the same queue the <ToastHost> in App renders.

import { ToastQueue } from "@bongtu/ui/toastQueue";

export const toasts = new ToastQueue();

/** A user-initiated action failed; retrying is sensible. `details` (the raw thrown
 *  value) grows the "Copy details" affordance, so translating the headline into the
 *  console's Korean never costs the engine's own words for a bug report. */
export function toastError(message: string, details?: string): void {
  toasts.show(message, details !== undefined ? { details } : {});
}
