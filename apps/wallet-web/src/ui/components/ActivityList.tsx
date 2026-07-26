// The activity feed as a card list, grouped under local-day headers (Today /
// Yesterday / date) by the PURE groupByDay. Each card: an SVG kind icon (no glyph
// characters — locked visual language), the verb, the shortened counterparty when
// there is one, the signed amount (green only for incoming), a relative time; the
// whole card links to the explorer tx. Home passes a sliced recent feed + onViewAll;
// the Activity screen passes the full feed.

import type { ReactNode } from "react";
import type { HistoryItem, HistoryKind } from "../../lib/indexerClient.js";
import { groupByDay } from "../../lib/activity.js";
import { formatKkrw } from "../../lib/money.js";
import { relativeTime, shortenPubkey } from "../format.js";

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

const ICON_PATH: Record<HistoryKind, string> = {
  received: "M12 5v14m0 0l-5-5m5 5l5-5",
  sent: "M12 19V5m0 0l-5 5m5-5l5 5",
  deposit: "M12 5v14M5 12h14",
  withdraw: "M12 4v10m0 0l-4-4m4 4l4-4M5 19h14",
};

function KindIcon({ kind }: { kind: HistoryKind }): ReactNode {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true">
      <path
        d={ICON_PATH[kind]}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Card({ item, explorerBase }: { item: HistoryItem; explorerBase: string }): ReactNode {
  const dir = signOf(item.kind);
  const href = `${explorerBase.replace(/\/+$/, "")}/tx/${item.txHash}`;
  return (
    <a className="activity-card" href={href} target="_blank" rel="noreferrer">
      <span className={`activity-icon activity-${dir}`}>
        <KindIcon kind={item.kind} />
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
    </a>
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
  const groups = groupByDay(history);
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
      {groups.length === 0 ? (
        <p className="activity-empty">{loading ? "Loading activity…" : "No activity yet."}</p>
      ) : (
        groups.map((g) => (
          <div className="activity-day" key={g.dayStart}>
            <h3 className="activity-day-label">{g.label}</h3>
            <div className="activity-cards">
              {g.items.map((it) => (
                <Card key={`${it.seq}-${it.txHash}`} item={it} explorerBase={explorerBase} />
              ))}
            </div>
          </div>
        ))
      )}
    </section>
  );
}
