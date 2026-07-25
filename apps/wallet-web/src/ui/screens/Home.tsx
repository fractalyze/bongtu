// Home: the balance hero, the three primary actions, and the activity feed. This is
// the whole app most of the time — Receive/Send/Withdraw/Settings are pushed on top
// via the hash route. All data (balance, activity) comes from the arbiter indexer; a
// dataError renders a calm "connect an arbiter-mode indexer" panel instead of numbers.

import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { navigate } from "../hooks.js";
import { DEFAULTS } from "../../config.js";
import { BalanceCard } from "../components/BalanceCard.js";
import { ActivityList } from "../components/ActivityList.js";
import { StatusChip } from "../components/StatusChip.js";

export function Home(): ReactNode {
  const { identity, balance, history, loading, dataError, indexerUrl, refresh } = useWallet();
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
      </div>

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
