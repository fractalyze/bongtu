// The Home activity feed, rendered from the arbiter-mode indexer's GET /history
// (newest-first). Each item shows a direction glyph, a human line, the counterparty
// handle when there is one, a relative time, and the signed amount. Deposits/withdraws
// have no counterparty. No local journal — an empty feed is an honest empty feed.

import type { ReactNode } from "react";
import type { HistoryItem, HistoryKind } from "../../lib/indexerClient.js";
import { formatAmount, relativeTime, shortenPubkey } from "../format.js";

const GLYPH: Record<HistoryKind, string> = {
  received: "↓",
  sent: "↑",
  withdraw: "⏏",
  deposit: "＋",
};

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

function Row({ item, explorerBase }: { item: HistoryItem; explorerBase: string }): ReactNode {
  const dir = signOf(item.kind);
  const href = `${explorerBase.replace(/\/+$/, "")}/tx/${item.txHash}`;
  return (
    <li className="activity-row">
      <span className={`activity-glyph activity-${dir}`}>{GLYPH[item.kind]}</span>
      <div className="activity-mid">
        <div className="activity-verb">{VERB[item.kind]}</div>
        <div className="activity-sub">
          {item.counterparty ? (
            <span title={item.counterparty}>{shortenPubkey(item.counterparty)}</span>
          ) : (
            <a href={href} target="_blank" rel="noreferrer" className="activity-link">
              view tx
            </a>
          )}
          <span className="activity-dot">·</span>
          {relativeTime(item.blockTimestamp)}
        </div>
      </div>
      <span className={`activity-amt activity-${dir}`}>
        {dir === "in" ? "+" : "−"}
        {formatAmount(item.amount)}
      </span>
    </li>
  );
}

export function ActivityList({
  history,
  loading,
  explorerBase,
}: {
  history: HistoryItem[];
  loading: boolean;
  explorerBase: string;
}): ReactNode {
  return (
    <section className="activity">
      <h2 className="section-title">Activity</h2>
      {history.length === 0 ? (
        <p className="activity-empty">{loading ? "Loading activity…" : "No activity yet."}</p>
      ) : (
        <ul className="activity-list">
          {history.map((it) => (
            <Row key={`${it.seq}-${it.txHash}`} item={it} explorerBase={explorerBase} />
          ))}
        </ul>
      )}
    </section>
  );
}
