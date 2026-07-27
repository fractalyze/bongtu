// Home: the balance hero, the connected-wallet card, the primary actions, and the
// recent activity head — sibling white cards in one vertical stack. This is the whole
// app most of the time — other screens are pushed on top via the hash route. All
// private data (balance, activity) comes from the arbiter indexer; a dataError
// renders a calm "connect an arbiter-mode indexer" panel instead of numbers. The
// public kKRW token context lives on the Deposit screen only (where the flow needs it).

import { useState } from "react";
import type { ReactNode } from "react";
import { useWallet } from "../App.js";
import { navigate } from "../hooks.js";
import { DEFAULTS } from "../../config.js";
import { walletBrand } from "../../lib/walletBrand.js";
import { shortenPubkey } from "../format.js";
import { BalanceCard } from "../components/BalanceCard.js";
import { ActivityList } from "../components/ActivityList.js";
import { StatusChip } from "../components/StatusChip.js";
import { ReceiveModal } from "../components/ReceiveModal.js";
import {
  EnvelopeLogo,
  IconGear,
  IconLink,
  IconWallet,
  IconSend,
  IconWithdraw,
  IconDeposit,
  MetaMaskFox,
} from "../components/icons.js";

// Home shows the head of the feed; the full flat list lives at #/activity.
const RECENT_COUNT = 4;

export function Home(): ReactNode {
  const { identity, connection, balance, history, loading, dataError, indexerUrl, refresh } =
    useWallet();

  // Receive is a modal over Home (primary path — the #/receive route is a deep link).
  const [receiveOpen, setReceiveOpen] = useState(false);

  if (!identity) return null;

  // The raw injected EIP-1193 provider sits under the ethers Web3Provider.
  const brand = connection ? walletBrand(connection.provider?.provider) : "unknown";

  return (
    <div className="screen home">
      <header className="home-head">
        <div className="brand">
          <EnvelopeLogo size={26} />
          <span className="brand-name">bongtu</span>
        </div>
        <div className="home-head-right">
          <StatusChip indexerUrl={indexerUrl} />
          <button className="icon-btn" aria-label="Settings" onClick={() => navigate("settings")}>
            <IconGear />
          </button>
        </div>
      </header>

      <BalanceCard
        balance={balance}
        loading={loading}
        pubkey={identity.compressedPubkey}
        onOpenReceive={() => setReceiveOpen(true)}
      />

      {connection && (
        <section className="wallet-card" aria-label="Connected wallet">
          <IconLink size={16} />
          {brand === "metamask" ? <MetaMaskFox size={18} /> : <IconWallet size={16} />}
          <span className="tip-wrap">
            <span className="wallet-addr mono" tabIndex={0} aria-describedby="wallet-addr-tip">
              {shortenPubkey(connection.address)}
            </span>
            <span className="tip mono" role="tooltip" id="wallet-addr-tip">
              {connection.address}
            </span>
          </span>
        </section>
      )}

      <div className="actions">
        <button className="action" onClick={() => navigate("send")}>
          <IconSend />
          <span>Send</span>
        </button>
        <button className="action" onClick={() => navigate("withdraw")}>
          <IconWithdraw />
          <span>Withdraw</span>
        </button>
        <button className="action" onClick={() => navigate("deposit")}>
          <IconDeposit />
          <span>Deposit</span>
        </button>
      </div>

      {/* Empty private balance == a first-timer who doesn't know the next move:
          lead them straight into the deposit flow (2026-07-27 user ask). Only when
          the balance is a LOADED zero — never over a spinner or a data error. */}
      {!loading && !dataError && balance === 0n && (
        <section className="get-started">
          <p className="get-started-title">Start by depositing kKRW</p>
          <p className="hint">
            Your private balance is empty. Deposit turns public kKRW into private kKRW you
            can send and withdraw without revealing anything — no kKRW yet? The deposit
            screen mints free testnet kKRW too.
          </p>
          <button className="btn btn-primary btn-block" onClick={() => navigate("deposit")}>
            Deposit kKRW
          </button>
        </section>
      )}

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

      {receiveOpen && (
        <ReceiveModal pubkey={identity.compressedPubkey} onClose={() => setReceiveOpen(false)} />
      )}
    </div>
  );
}
