// The hero balance card on Home: the big private kKRW balance with a shielded
// affordance, plus the wallet's receive handle. Values are raw field integers, so
// formatAmount groups the decimal string (never Number).

import type { ReactNode } from "react";
import { formatAmount, shortenPubkey } from "../format.js";

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
      <div className="balance-label">
        <span className="shield">◈</span> Private balance
      </div>
      <div className="balance-value">
        {balance === null ? (
          <span className="balance-dim">{loading ? "…" : "—"}</span>
        ) : (
          <>
            <span className="balance-num">{formatAmount(balance)}</span>
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
