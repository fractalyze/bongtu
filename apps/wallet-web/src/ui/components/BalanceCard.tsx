// The hero balance card on Home: the big private kKRW balance plus the wallet's
// receive handle. Values are raw wei; formatKkrw is the one UI edge (never Number).

import type { ReactNode } from "react";
import { formatKkrw } from "../../lib/money.js";
import { shortenPubkey } from "../format.js";

export function BalanceCard({
  balance,
  loading,
  pubkey,
}: {
  balance: bigint | null;
  loading: boolean;
  pubkey: string;
}): ReactNode {
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
      <div className="balance-handle" title={pubkey}>
        {shortenPubkey(pubkey)}
      </div>
    </section>
  );
}
