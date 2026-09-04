// The activity feed as ONE white card (same treatment as the other home sections) of
// flat rows, newest first — no day headers (feedback: flat list, per-item relative
// time only). Row order is the wire order: the feed is contractually seq-desc
// (newest-first), so no client re-sort. Every per-row rendering decision — verb,
// direction, signed amount, counterparty forms, time-or-nothing, explorer target —
// is the PURE presenter's (activityView.ts, gated headlessly); this file keeps only
// what needs JSX: the icon mapping and the row layout. Each row: a Remix kind icon
// consistent with the action icons, the verb, the shortened counterparty when there
// is one, the signed amount with its token symbol (green only for incoming), a
// relative time when the item carries one, and an external-link icon signalling that
// click opens the explorer tx. The rows are ruled top AND bottom, so the list's
// edges read like the rules between its rows instead of like two wider gaps. Home
// passes a sliced recent feed + onViewAll; the Activity screen passes the full feed.

import type { ReactNode } from "react";
import type { HistoryItem, HistoryKind } from "@bongtu/client/indexerClient";
import { activityEmptyLine, presentActivity, type ActivityRowView } from "../activityView.js";
import { LinkButton } from "./controls.js";
import { IconReceived, IconSend, IconDeposit, IconWithdraw, IconExternalLink } from "./icons.js";

// Kind icons mirror the Home action icons (send-plane / into-pool / out-of-pool) so
// a feed row and the button that caused it read as the same gesture.
const KIND_ICON: Record<HistoryKind, (props: { size?: number }) => ReactNode> = {
  received: IconReceived,
  sent: IconSend,
  deposit: IconDeposit,
  withdraw: IconWithdraw,
};

function Row({ row }: { row: ActivityRowView }): ReactNode {
  // Runtime fallback mirrors the presenter's verb fallback: an unknown kind the
  // server grew must degrade, not crash.
  const Kind = KIND_ICON[row.kind] ?? IconSend;
  // Only the external-link icon navigates (user decision): a whole-row anchor made
  // every stray tap an explorer round-trip.
  return (
    <div className="flex items-center gap-3 py-[11px] border-t border-border">
      <span
        className={`w-[34px] h-[34px] rounded-full grid place-items-center flex-none ${
          row.direction === "in" ? "bg-pos-bg text-pos" : "bg-surface-2 text-muted"
        }`}
      >
        <Kind size={16} />
      </span>
      <span className="flex-1 min-w-0 flex flex-col gap-0.5">
        <span className="font-semibold text-[0.92rem]">{row.verb}</span>
        {row.counterparty && (
          <span
            className="font-mono text-[0.74rem] text-muted overflow-hidden text-ellipsis whitespace-nowrap"
            title={row.counterparty.full}
          >
            {row.counterparty.short}
          </span>
        )}
      </span>
      <span className="flex flex-col items-end gap-0 flex-none">
        <span
          className={`font-bold tabular-nums text-[0.92rem] leading-[1.25] ${
            row.direction === "in" ? "text-pos" : "text-ink"
          }`}
        >
          {row.amount}
          {/* muted symbol beside a colored number — the balance hero's idiom */}
          <span className="text-muted font-semibold text-[0.72rem] ml-1">kKRW</span>
        </span>
        {/* A selfscan row carries no timestamp (the public feed has none): the
            presenter emits null and NOTHING renders — the calm-surface rule
            (docs/errors.md): quiet absence, never a fabricated value. */}
        {row.time !== null && (
          <span className="text-xs text-muted leading-[1.2]">{row.time}</span>
        )}
      </span>
      <a
        className="inline-flex text-muted flex-none p-1 -m-1 rounded-md hover:text-primary focus-visible:text-primary"
        href={row.explorerHref}
        target="_blank"
        rel="noreferrer"
        aria-label="View transaction on the explorer"
      >
        <IconExternalLink size={16} />
      </a>
    </div>
  );
}

export function ActivityList({
  history,
  loading,
  explorerBase,
  heading = "Activity",
  onViewAll,
}: {
  history: HistoryItem[];
  loading: boolean;
  explorerBase: string;
  /** null hides the section heading (the full Activity screen has its own title). */
  heading?: string | null;
  /** when set, renders a "View all" link beside the heading (Home's recent slice). */
  onViewAll?: () => void;
}): ReactNode {
  const rows = presentActivity(history, explorerBase);
  return (
    <section className="flex flex-col gap-1.5 bg-surface border border-border rounded-xl px-3.5 py-3">
      {heading !== null && (
        <div className="flex justify-between items-baseline">
          <h2 className="text-xs uppercase tracking-[0.08em] text-muted [font-weight:650]">
            {heading}
          </h2>
          {onViewAll && rows.length > 0 && (
            <LinkButton onClick={onViewAll}>View All</LinkButton>
          )}
        </div>
      )}
      {rows.length === 0 ? (
        <p className="text-muted text-[0.88rem] my-1">{activityEmptyLine(loading)}</p>
      ) : (
        <div className="flex flex-col border-b border-border">
          {rows.map((row) => (
            <Row key={row.key} row={row} />
          ))}
        </div>
      )}
    </section>
  );
}
