// Home: the scan-driven balance hero, the connected-wallet card, the four live
// actions, and the recent activity head — sibling white cards in one vertical
// stack, byte-patterned on treasury-web's Home. All private data comes from the
// self-scan of the public feed; a dataError renders the calm retry banner
// instead of numbers, and the calm strip carries the scan's pending/locked
// notices. Receive routes to the identity screen (#/receive): sends are
// registry-name-only, so the thing to share is the NAME, not an address —
// which is why the old share-address modal is gone rather than kept beside it.

import type { ReactNode } from "react";
import { encodeAddress } from "@bongtu/core/pubkey";
import { useWallet } from "../App.js";
import { navigate, type Route } from "../hooks.js";
import { DEFAULTS } from "../../config.js";
import { shortenPubkey } from "../format.js";
import { BalanceCard } from "../components/BalanceCard.js";
import { ActivityList } from "../components/ActivityList.js";
import { SelfScanSyncDot } from "../components/SyncDot.js";
import { LockChip } from "../components/LockChip.js";
import { WalletMark } from "../components/WalletMark.js";
import { IconButton, TestnetTag } from "../components/controls.js";
import { Banner } from "@bongtu/ui/Banner";
import {
  EnvelopeLogo,
  IconGear,
  IconLink,
  IconReceived,
  IconSend,
  IconWithdraw,
  IconDeposit,
} from "../components/icons.js";

// Home shows the head of the feed; the full flat list lives at #/activity.
const RECENT_COUNT = 4;

const ACTIONS: readonly { label: string; route: Route; Icon: (p: { size?: number }) => ReactNode }[] = [
  { label: "Send", route: "send", Icon: IconSend },
  { label: "Receive", route: "receive", Icon: IconReceived },
  { label: "Withdraw", route: "withdraw", Icon: IconWithdraw },
  { label: "Deposit", route: "deposit", Icon: IconDeposit },
] as const;

/** The action grid, LIVE (S6): every op has a real screen behind it. Pure and
 *  prop-free so the copy gate renders it headlessly. */
export function HomeActions(): ReactNode {
  return (
    <section className="grid grid-cols-4 gap-2" aria-label="Actions">
      {ACTIONS.map(({ label, route, Icon }) => (
        <button
          key={label}
          className="bg-surface border border-border rounded-xl pt-3 px-1 pb-2.5 text-primary text-sm [font-weight:650] cursor-pointer font-sans flex flex-col items-center gap-1.5 hover:border-border-strong"
          onClick={() => navigate(route)}
        >
          <Icon />
          <span>{label}</span>
        </button>
      ))}
    </section>
  );
}

export function Home(): ReactNode {
  const {
    session, connection, wallet, balance, history, loading, dataError, dataNotice,
    scannedNextLeafIndex, indexerUrl, refresh,
  } = useWallet();

  if (!session) return null;

  return (
    <div className="flex flex-col gap-3 px-4.5 pt-4.5 pb-6.5">
      <header className="flex items-center justify-between">
        <div className="inline-flex items-center gap-2 text-primary">
          <EnvelopeLogo size={26} />
          <span className="font-bold text-[1.1rem] tracking-[-0.01em]">bongtu</span>
          {DEFAULTS.testnet && <TestnetTag />}
        </div>
        {/* Icons only (the treasury-web U-W9 shape): sync state, lock state,
            settings — each with its words in a hover tooltip. The dot measures the
            SCAN CURSOR against the public /head; it is also the manual refresh. */}
        <div className="flex items-center gap-0.5">
          <SelfScanSyncDot
            indexerUrl={indexerUrl}
            scannedNextLeafIndex={scannedNextLeafIndex}
            refreshing={loading}
            dataError={dataError !== null}
            onRefresh={() => void refresh(true)}
          />
          <LockChip walletName={wallet.name} />
          <IconButton aria-label="Settings" onClick={() => navigate("settings")}>
            <IconGear />
          </IconButton>
        </div>
      </header>

      <BalanceCard
        balance={balance}
        loading={loading}
        // Users only ever see (and copy) the base58check form; hex stays internal.
        pubkey={encodeAddress(session.compressedPubkey)}
        onOpenReceive={() => navigate("receive")}
      />

      {connection && (
        <section
          className="flex items-center justify-center gap-2 text-muted bg-surface border border-border rounded-xl px-3.5 py-[11px]"
          aria-label="Connected wallet"
        >
          <IconLink size={16} />
          {/* ICON-ONLY (user decision, kept): the wallet's mark carries the
              identity; its NAME lives in the tooltip/aria, never as visible text. */}
          <span
            className="inline-flex"
            title={wallet.named ? wallet.name : undefined}
            aria-label={wallet.named ? `Connected via ${wallet.name}` : "Connected wallet"}
          >
            <WalletMark wallet={wallet} />
          </span>
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

      <HomeActions />

      {/* The standardized state banner (class 4): set by a failed scan, cleared by
          the next success — and the data already on screen stays below it (a failed
          background read never blanks the screen). Retry is the MANUAL refresh. */}
      {dataError && <Banner message={dataError} onRetry={() => void refresh(true)} />}
      {/* Calm strip, not the warn banner: the data below is real — pending kem
          delivery, or a locked wallet serving its last scan (the engine's scanNotice, @bongtu/client/selfscan). */}
      {!dataError && dataNotice && <p className="text-muted text-[0.85rem] px-0.5">{dataNotice}</p>}
      <ActivityList
        history={history.slice(0, RECENT_COUNT)}
        loading={loading}
        explorerBase={DEFAULTS.explorer}
        onViewAll={() => navigate("activity")}
      />
    </div>
  );
}
