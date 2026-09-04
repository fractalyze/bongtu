// Everything about the /history feed that is PURE: the row mapping (kind → verb +
// balance direction) and the page-append rule. Kept out of the components so all
// three gate headlessly, like the other lib edges (money, walletBrand). Copy stays
// plain words (the U-TEXT principle): no note/UTXO jargon.

import type { HistoryItem, HistoryKind } from "@bongtu/core/indexerApi";

/** The row's main line: one plain-words phrase per /history kind. */
export const ACTIVITY_VERB: Record<HistoryKind, string> = {
  received: "Received",
  sent: "Sent",
  withdraw: "Withdrawn",
  deposit: "Deposited",
};

/** received / deposit add to the balance ("in"); sent / withdraw remove from it
 *  ("out"); anything else is "none", rendering unsigned and in the neutral ink
 *  color — never as a gain or a loss. */
export type ActivityDirection = "in" | "out" | "none";

export function activityDirection(kind: HistoryKind): ActivityDirection {
  if (kind === "received" || kind === "deposit") return "in";
  if (kind === "sent" || kind === "withdraw") return "out";
  // Any kind this bundle predates: neutral, never a gain or a loss.
  return "none";
}

/**
 * Append the next `/history` page to the feed already on screen, dropping any row
 * the feed already holds.
 *
 * The de-dup is what makes "Load more" safe next to a refresh: a refresh REPLACES
 * the feed with a fresh first page, so an in-flight next-page request can come
 * back holding rows that page already contains (the cursor was taken against the
 * older, shorter feed). Keyed on `seq`, which the indexer assigns once per item
 * and never renumbers — so the same row is the same key across both reads.
 */
export function appendHistoryPage(existing: HistoryItem[], page: HistoryItem[]): HistoryItem[] {
  const seen = new Set(existing.map((h) => h.seq));
  return [...existing, ...page.filter((h) => !seen.has(h.seq))];
}
