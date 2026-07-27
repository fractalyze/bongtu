// The PURE presentation mapping for /history feed rows — kind → verb + balance
// direction — split out of ActivityList so the copy and the sign logic gate
// headlessly like the other lib edges (money, walletBrand). Copy stays plain
// words (the U-TEXT principle): no note/UTXO jargon — a pure self-send reads
// "Moved within your balance", because from the user's side nothing arrived
// and nothing left.

import type { HistoryKind } from "./indexerClient.js";

/** The row's main line: one plain-words phrase per /history kind. */
export const ACTIVITY_VERB: Record<HistoryKind, string> = {
  received: "Received",
  sent: "Sent",
  withdraw: "Withdrawn",
  deposit: "Deposited",
  self: "Moved within your balance",
};

/** received / deposit add to the balance ("in"); sent / withdraw remove from it
 *  ("out"); a self-send leaves it unchanged ("none"), so its amount renders
 *  unsigned and in the neutral ink color — never as a gain or a loss. */
export type ActivityDirection = "in" | "out" | "none";

export function activityDirection(kind: HistoryKind): ActivityDirection {
  if (kind === "received" || kind === "deposit") return "in";
  if (kind === "sent" || kind === "withdraw") return "out";
  // 'self' and any kind this bundle predates: neutral, never a gain or a loss.
  return "none";
}
