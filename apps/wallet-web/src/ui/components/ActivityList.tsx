// The activity feed as ONE white card (same treatment as the other home sections) of
// flat rows, newest first — no day headers (feedback: flat list, per-item relative
// time only). Row order is the wire order: /history is contractually seq-desc
// (newest-first), so no client re-sort. Each row: a Remix kind icon consistent with
// the action icons, the verb, the shortened counterparty when there is one, the
// signed amount (green only for incoming), a relative time, and an external-link
// icon signalling that click opens the explorer tx. Home passes a sliced recent feed
// + onViewAll; the Activity screen passes the full feed.

import type { ReactNode } from "react";
import type { HistoryItem, HistoryKind } from "../../lib/indexerClient.js";
import { formatKkrw } from "../../lib/money.js";
import { relativeTime, shortenPubkey } from "../format.js";
import {
  IconReceived,
  IconSend,
  IconDeposit,
  IconWithdraw,
  IconExternalLink,
} from "./icons.js";

const VERB: Record<HistoryKind, string> = {
  received: "Received",
  sent: "Sent",
  withdraw: "Withdrawn",
  deposit: "Deposited",
};

// received / deposit add to the balance; sent / withdraw remove from it.
function signOf(kind: HistoryKind): "in" | "out" {
  return kind === "received" || kind === "deposit" ? "in" : "out";
}

// Kind icons mirror the Home action icons (send-plane / into-pool / out-of-pool) so
// a feed row and the button that caused it read as the same gesture.
const KIND_ICON: Record<HistoryKind, (props: { size?: number }) => ReactNode> = {
  received: IconReceived,
  sent: IconSend,
  deposit: IconDeposit,
  withdraw: IconWithdraw,
};

function Row({ item, explorerBase }: { item: HistoryItem; explorerBase: string }): ReactNode {
  const dir = signOf(item.kind);
  const Kind = KIND_ICON[item.kind];
  const href = `${explorerBase.replace(/\/+$/, "")}/tx/${item.txHash}`;
  // Only the external-link icon navigates (user decision): a whole-row anchor made
  // every stray tap an explorer round-trip.
  return (
    <div className="activity-row">
      <span className={`activity-icon activity-${dir}`}>
        <Kind size={16} />
      </span>
      <span className="activity-mid">
        <span className="activity-verb">{VERB[item.kind]}</span>
        {item.counterparty && (
          <span className="activity-cpty" title={item.counterparty}>
            {shortenPubkey(item.counterparty)}
          </span>
        )}
      </span>
      <span className="activity-right">
        <span className={`activity-amt activity-${dir}`}>
          {dir === "in" ? "+" : "-"}
          {formatKkrw(item.amount)}
        </span>
        <span className="activity-time">{relativeTime(item.blockTimestamp)}</span>
      </span>
      <a
        className="activity-ext"
        href={href}
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
  return (
    <section className="activity">
      {heading !== null && (
        <div className="activity-head">
          <h2 className="section-title">{heading}</h2>
          {onViewAll && history.length > 0 && (
            <button className="link-btn" onClick={onViewAll}>
              View all
            </button>
          )}
        </div>
      )}
      {history.length === 0 ? (
        <p className="activity-empty">{loading ? "Loading activity…" : "No activity yet."}</p>
      ) : (
        <div className="activity-rows">
          {history.map((it) => (
            <Row key={`${it.seq}-${it.txHash}`} item={it} explorerBase={explorerBase} />
          ))}
        </div>
      )}
    </section>
  );
}
