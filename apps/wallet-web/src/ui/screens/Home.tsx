// Home: the balance hero, the three primary actions, and the activity feed. This is
// the whole app most of the time — Receive/Send/Withdraw/Settings are pushed on top
// via the hash route. All data (balance, activity) comes from the arbiter indexer; a
// dataError renders a calm "connect an arbiter-mode indexer" panel instead of numbers.

import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { navigate } from "../hooks.js";
import { DEFAULTS } from "../../config.js";
import { readTokenState } from "../../lib/metamask.js";
import { formatAmount } from "../format.js";
import { BalanceCard } from "../components/BalanceCard.js";
import { ActivityList } from "../components/ActivityList.js";
import { StatusChip } from "../components/StatusChip.js";

export function Home(): ReactNode {
  const { identity, connection, balance, history, loading, dataError, indexerUrl, refresh } = useWallet();

  // Public kKRW wallet balance + current pool allowance (view calls, no gas) — the
  // funds available to shield via Deposit. Best-effort: an RPC hiccup just shows "—".
  const [tokenBalance, setTokenBalance] = useState<bigint | null>(null);
  const [allowance, setAllowance] = useState<bigint | null>(null);
  useEffect(() => {
    if (!connection) return;
    let alive = true;
    void readTokenState(connection, DEFAULTS.token, connection.address, DEFAULTS.pool)
      .then((s) => {
        if (alive) {
          setTokenBalance(s.balance);
          setAllowance(s.allowance);
        }
      })
      .catch(() => {
        if (alive) {
          setTokenBalance(null);
          setAllowance(null);
        }
      });
    return () => {
      alive = false;
    };
  }, [connection]);

  if (!identity) return null;

  return (
    <div className="screen home">
      <header className="home-head">
        <div className="brand">
          <span className="brand-mark">◈</span> bongtu
        </div>
        <div className="home-head-right">
          <StatusChip indexerUrl={indexerUrl} />
          <button className="icon-btn" aria-label="Settings" onClick={() => navigate("settings")}>
            ⚙
          </button>
        </div>
      </header>

      <BalanceCard balance={balance} loading={loading} pubkey={identity.compressedPubkey} />

      <div className="actions">
        <button className="action" onClick={() => navigate("receive")}>
          <span className="action-glyph">↓</span>Receive
        </button>
        <button className="action" onClick={() => navigate("send")}>
          <span className="action-glyph">↑</span>Send
        </button>
        <button className="action" onClick={() => navigate("withdraw")}>
          <span className="action-glyph">⏏</span>Withdraw
        </button>
        <button className="action" onClick={() => navigate("deposit")}>
          <span className="action-glyph">⊕</span>Deposit
        </button>
      </div>

      <p className="home-token-line">
        kKRW available: {tokenBalance === null ? "—" : formatAmount(tokenBalance)}
        {" · "}Pool allowance: {allowance === null ? "—" : formatAmount(allowance)}
      </p>

      {dataError ? (
        <div className="banner banner-warn">
          {dataError}
          <button className="btn btn-ghost btn-sm" onClick={() => void refresh()}>
            Retry
          </button>
        </div>
      ) : (
        <ActivityList history={history} loading={loading} explorerBase={DEFAULTS.explorer} />
      )}
    </div>
  );
}
