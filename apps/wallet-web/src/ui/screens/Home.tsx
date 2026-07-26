// Home: the balance hero, the primary actions, and the recent activity head. This is
// the whole app most of the time — other screens are pushed on top via the hash route.
// All private data (balance, activity) comes from the arbiter indexer; a dataError
// renders a calm "connect an arbiter-mode indexer" panel instead of numbers.

import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { navigate } from "../hooks.js";
import { DEFAULTS } from "../../config.js";
import { readTokenState, approveToken } from "../../lib/metamask.js";
import { formatKkrw, allowanceLabel } from "../../lib/money.js";
import { BalanceCard } from "../components/BalanceCard.js";
import { ActivityList } from "../components/ActivityList.js";
import { StatusChip } from "../components/StatusChip.js";

// Home shows the head of the feed; the full day-grouped list lives at #/activity.
const RECENT_COUNT = 4;

export function Home(): ReactNode {
  const { identity, connection, balance, history, loading, dataError, indexerUrl, refresh } =
    useWallet();

  // Public kKRW wallet balance + current pool allowance (view calls, no gas) — the
  // funds available to shield via Deposit. Best-effort: an RPC hiccup just shows "—".
  const [tokenBalance, setTokenBalance] = useState<bigint | null>(null);
  const [allowance, setAllowance] = useState<bigint | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [revokeError, setRevokeError] = useState<string | null>(null);

  const loadTokenState = useCallback(async (): Promise<void> => {
    if (!connection) return;
    try {
      const s = await readTokenState(connection, DEFAULTS.token, connection.address, DEFAULTS.pool);
      setTokenBalance(s.balance);
      setAllowance(s.allowance);
    } catch {
      setTokenBalance(null);
      setAllowance(null);
    }
  }, [connection]);

  useEffect(() => {
    void loadTokenState();
  }, [loadTokenState]);

  // Revoke = approve(pool, 0): after it, deposits fall back to the exact-V approve
  // cycle naturally. A user-rejected popup (4001) is silent by intent; a real
  // RPC/tx failure must NOT look identical to success-with-stale-read.
  async function revoke(): Promise<void> {
    if (!connection) return;
    setRevoking(true);
    setRevokeError(null);
    try {
      await approveToken(connection, DEFAULTS.token, DEFAULTS.pool, 0n);
      await loadTokenState();
    } catch (e) {
      const code = (e as { code?: number }).code;
      if (code !== 4001) setRevokeError("Revoke failed — check MetaMask/RPC and retry.");
    } finally {
      setRevoking(false);
    }
  }

  if (!identity) return null;

  return (
    <div className="screen home">
      <header className="home-head">
        <div className="brand">bongtu</div>
        <div className="home-head-right">
          <StatusChip indexerUrl={indexerUrl} />
          <button className="link-btn" onClick={() => navigate("settings")}>
            Settings
          </button>
        </div>
      </header>

      <BalanceCard balance={balance} loading={loading} pubkey={identity.compressedPubkey} />

      <div className="actions">
        <button className="action" onClick={() => navigate("deposit")}>
          Deposit
        </button>
        <button className="action" onClick={() => navigate("send")}>
          Send
        </button>
        <button className="action" onClick={() => navigate("withdraw")}>
          Withdraw
        </button>
        <button className="action" onClick={() => navigate("receive")}>
          Receive
        </button>
      </div>

      <p className="home-token-line">
        kKRW available: {tokenBalance === null ? "—" : formatKkrw(tokenBalance)}
        {" · "}Pool allowance: {allowance === null ? "—" : allowanceLabel(allowance)}
        {allowance !== null && allowance > 0n && (
          <>
            {" "}
            <button className="link-btn link-btn-sm" disabled={revoking} onClick={() => void revoke()}>
              {revoking ? "Revoking…" : "Revoke"}
            </button>
          </>
        )}
      </p>

      {revokeError ? <div className="banner banner-warn">{revokeError}</div> : null}

      {dataError ? (
        <div className="banner banner-warn">
          {dataError}
          <button className="btn btn-ghost btn-sm" onClick={() => void refresh()}>
            Retry
          </button>
        </div>
      ) : (
        <ActivityList
          history={history.slice(0, RECENT_COUNT)}
          loading={loading}
          explorerBase={DEFAULTS.explorer}
          onViewAll={() => navigate("activity")}
        />
      )}
    </div>
  );
}
