// The hero balance card on Home: the big private kKRW balance plus the wallet's
// bongtu receive ID directly under it. The ID is the receive surface — tapping it
// opens the receive modal, the copy icon copies the FULL id (shortened text alone
// would propagate truncated addresses), and a custom hover/focus tooltip reveals the
// full id in place. Values are raw wei; formatKkrw is the one UI edge (never Number).

import type { ReactNode } from "react";
import { formatKkrw } from "../../lib/money.js";
import { shortenPubkey } from "../format.js";
import { useCopyFeedback } from "../hooks.js";
import { IconCheck, IconCopy } from "./icons.js";

export function BalanceCard({
  balance,
  loading,
  pubkey,
  onOpenReceive,
}: {
  balance: bigint | null;
  loading: boolean;
  pubkey: string;
  onOpenReceive: () => void;
}): ReactNode {
  const { copied, copy } = useCopyFeedback(pubkey);
  return (
    <section className="balance-card">
      <div className="balance-label">Private balance</div>
      <div className="balance-value">
        {balance === null ? (
          <span className="balance-dim">{loading ? "…" : "—"}</span>
        ) : (
          <>
            <span className="balance-num">{formatKkrw(balance)}</span>
            <span className="balance-unit">kKRW</span>
          </>
        )}
      </div>
      <div className="balance-id-row">
        <span className="tip-wrap">
          <button
            className="balance-handle"
            onClick={onOpenReceive}
            aria-label="Your bongtu address. Open receive"
            aria-describedby="bongtu-id-tip"
          >
            {shortenPubkey(pubkey)}
          </button>
          <span className="tip mono" role="tooltip" id="bongtu-id-tip">
            {pubkey}
          </span>
        </span>
        <button className={`icon-btn icon-btn-sm${copied ? " icon-btn-ok" : ""}`} onClick={copy} aria-label={copied ? "Copied" : "Copy bongtu address"}>
          {copied ? <IconCheck size={15} /> : <IconCopy size={15} />}
        </button>
      </div>
    </section>
  );
}
