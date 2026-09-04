// The activity presenter: every per-row rendering decision — verb, direction,
// signed amount, counterparty display forms, time-or-nothing, explorer target —
// as ONE pure fold from a HistoryItem, so the LIST SEMANTICS gate headlessly
// (test/discovery.test.ts) and the component (ActivityList.tsx) keeps only what
// needs JSX: the icon mapping and the row layout. Row order is the wire order:
// the feed is contractually seq-desc (newest-first), so the presenter maps and
// never re-sorts — an ordering bug upstream must surface, not be papered over.

import { encodeAddress } from "@bongtu/core/pubkey";
import type { HistoryItem, HistoryKind } from "@bongtu/client/indexerClient";
import { ACTIVITY_VERB, activityDirection, type ActivityDirection } from "@bongtu/client/activity";
import { formatKkrw } from "@bongtu/client/money";
import { relativeTime, shortenPubkey } from "./format.js";

/** Everything one activity row renders, precomputed. */
export interface ActivityRowView {
  /** stable list key: (seq, txHash) — seq is assigned once and never renumbered. */
  key: string;
  /** the raw kind, kept for the component's icon mapping (JSX stays there). */
  kind: HistoryKind;
  verb: string;
  direction: ActivityDirection;
  /** signed display amount ("+650", "-250"; unsigned for an unknown kind — the
   *  neutral rendering: never a gain or a loss the bundle cannot vouch for). */
  amount: string;
  /** base58check display forms (users never see hex), or null when the feed has
   *  no single other party — every selfscan-derived row, by design. */
  counterparty: { short: string; full: string } | null;
  /** relative-time text, or null when the item carries no blockTimestamp (the
   *  public feed has none) — the display edge renders NOTHING then, never the
   *  epoch date (the calm-surface rule, docs/errors.md). */
  time: string | null;
  explorerHref: string;
}

const sign = (direction: ActivityDirection): string =>
  direction === "in" ? "+" : direction === "out" ? "-" : "";

/** One row's view. `explorerBase` tolerates a trailing slash (config values do). */
export function presentActivityRow(item: HistoryItem, explorerBase: string): ActivityRowView {
  const direction = activityDirection(item.kind);
  const counterparty = ((): ActivityRowView["counterparty"] => {
    if (item.counterparty === null) return null;
    const full = encodeAddress(item.counterparty);
    return { full, short: shortenPubkey(full) };
  })();
  return {
    key: `${item.seq}-${item.txHash}`,
    kind: item.kind,
    // Runtime fallback: the server can grow kinds this bundle predates ('self'
    // did exactly that to older builds) — an unknown kind degrades to its raw
    // name, never a crash.
    verb: ACTIVITY_VERB[item.kind] ?? item.kind,
    direction,
    amount: `${sign(direction)}${formatKkrw(item.amount)}`,
    counterparty,
    time: item.blockTimestamp === undefined ? null : relativeTime(item.blockTimestamp),
    explorerHref: `${explorerBase.replace(/\/+$/, "")}/tx/${item.txHash}`,
  };
}

/** The whole feed's views, in wire order (no client re-sort — see header). */
export function presentActivity(history: HistoryItem[], explorerBase: string): ActivityRowView[] {
  return history.map((item) => presentActivityRow(item, explorerBase));
}

/** The empty-list line, pinned here so the copy gate and the component cannot
 *  drift: while a scan is running the feed is not known to be empty. */
export const ACTIVITY_LOADING_TEXT = "Loading activity…";
export const ACTIVITY_EMPTY_TEXT = "No activity yet.";

export function activityEmptyLine(loading: boolean): string {
  return loading ? ACTIVITY_LOADING_TEXT : ACTIVITY_EMPTY_TEXT;
}
