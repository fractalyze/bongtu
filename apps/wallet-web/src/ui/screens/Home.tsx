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
import { Button, IconButton, TestnetTag } from "../components/controls.js";
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
    <div className="flex flex-col gap-3 px-4.5 pt-4.5 pb-6.5">
      <header className="flex items-center justify-between">
        <div className="inline-flex items-center gap-2 text-primary">
          <EnvelopeLogo size={26} />
          <span className="font-bold text-[1.1rem] tracking-[-0.01em]">bongtu</span>
          {DEFAULTS.testnet && <TestnetTag />}
        </div>
        <div className="flex items-center gap-2">
          <StatusChip indexerUrl={indexerUrl} />
          <IconButton aria-label="Settings" onClick={() => navigate("settings")}>
            <IconGear />
          </IconButton>
        </div>
      </header>

      <BalanceCard
        balance={balance}
        loading={loading}
        pubkey={identity.compressedPubkey}
        onOpenReceive={() => setReceiveOpen(true)}
      />

      {connection && (
        <section
          className="flex items-center justify-center gap-2 text-muted bg-surface border border-border rounded-xl px-3.5 py-[11px]"
          aria-label="Connected wallet"
        >
          <IconLink size={16} />
          {brand === "metamask" ? <MetaMaskFox size={18} /> : <IconWallet size={16} />}
          <span className="relative inline-flex group">
            <span
              className="font-mono text-[0.78rem] rounded-md focus-visible:outline-2 focus-visible:outline-primary focus-visible:outline-offset-2"
              tabIndex={0}
              aria-describedby="wallet-addr-tip"
            >
              {shortenPubkey(connection.address)}
            </span>
            <span
              className="absolute bottom-[calc(100%+8px)] left-1/2 -translate-x-1/2 bg-ink text-white font-mono text-[0.68rem] leading-[1.45] px-[9px] py-1.5 rounded-lg w-max max-w-[250px] [overflow-wrap:anywhere] text-center opacity-0 pointer-events-none transition-opacity z-30 group-hover:opacity-100 group-has-[:focus-visible]:opacity-100"
              role="tooltip"
              id="wallet-addr-tip"
            >
              {connection.address}
            </span>
          </span>
        </section>
      )}

      {/* A LOADED zero balance means Send/Withdraw can only fail — replace all
          three actions with the one move that works: Deposit. Never over a
          spinner or a data error (balance unknown there). */}
      {!loading && !dataError && balance === 0n ? (
        <section className="flex flex-col gap-2 bg-surface border border-border-strong rounded-xl p-3.5">
          <p className="text-[0.95rem] font-bold">Deposit kKRW to get started</p>
          <p className="text-sm text-muted">
            Deposited kKRW becomes private — then send and withdraw freely.
          </p>
          <Button variant="primary" block onClick={() => navigate("deposit")}>
            Deposit kKRW
          </Button>
        </section>
      ) : (
        <div className="grid grid-cols-3 gap-2">
          <button
            className="bg-surface border border-border rounded-xl pt-3 px-1 pb-2.5 text-primary text-sm [font-weight:650] cursor-pointer font-sans flex flex-col items-center gap-1.5 hover:border-border-strong"
            onClick={() => navigate("send")}
          >
            <IconSend />
            <span>Send</span>
          </button>
          <button
            className="bg-surface border border-border rounded-xl pt-3 px-1 pb-2.5 text-primary text-sm [font-weight:650] cursor-pointer font-sans flex flex-col items-center gap-1.5 hover:border-border-strong"
            onClick={() => navigate("withdraw")}
          >
            <IconWithdraw />
            <span>Withdraw</span>
          </button>
          <button
            className="bg-surface border border-border rounded-xl pt-3 px-1 pb-2.5 text-primary text-sm [font-weight:650] cursor-pointer font-sans flex flex-col items-center gap-1.5 hover:border-border-strong"
            onClick={() => navigate("deposit")}
          >
            <IconDeposit />
            <span>Deposit</span>
          </button>
        </div>
      )}

      {dataError ? (
        <div className="rounded-xl px-3.5 py-3 text-[0.88rem] flex gap-2.5 items-center justify-between flex-wrap border border-warn-border bg-warn-bg text-warn">
          {dataError}
          <Button variant="ghost" size="sm" onClick={() => void refresh()}>
            Retry
          </Button>
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
