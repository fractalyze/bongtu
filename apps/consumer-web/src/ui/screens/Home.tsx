// Home: the scan-driven balance hero, the connected-wallet card, the (stubbed)
// primary actions, and the recent activity head — sibling white cards in one
// vertical stack, byte-patterned on wallet-web's Home. All private data comes from
// the self-scan of the public feed; a dataError renders the calm retry banner
// instead of numbers, and the calm strip carries the scan's pending/locked notices.
//
// The 4 op screens land in S5-S6: until then the action buttons render DISABLED
// with the stub notice below them, so this slice ships a WORKING discovery wallet
// (login → balance → activity → receive-by-address) that promises nothing it
// cannot do yet.

import { useState } from "react";
import type { ReactNode } from "react";
import { encodeAddress } from "@bongtu/core/pubkey";
import { useWallet } from "../App.js";
import { navigate } from "../hooks.js";
import { DEFAULTS } from "../../config.js";
import { shortenPubkey } from "../format.js";
import { BalanceCard } from "../components/BalanceCard.js";
import { ActivityList } from "../components/ActivityList.js";
import { SelfScanSyncDot } from "../components/SyncDot.js";
import { LockChip } from "../components/LockChip.js";
import { ReceiveModal } from "../components/ReceiveModal.js";
import { MintModal } from "../components/MintModal.js";
import { WalletMark } from "../components/WalletMark.js";
import { IconButton, LinkButton, TestnetTag } from "../components/controls.js";
import { Banner } from "@bongtu/ui/Banner";
import {
  EnvelopeLogo,
  IconGear,
  IconLink,
  IconSend,
  IconWithdraw,
  IconDeposit,
} from "../components/icons.js";

// Home shows the head of the feed; the full flat list lives at #/activity.
const RECENT_COUNT = 4;

/** The one honest line under the disabled actions: what is coming, and what
 *  already works. One exported constant so the copy gate and the tooltip cannot
 *  drift from what renders. */
export const ACTIONS_STUB_NOTICE =
  "Sending, withdrawing and depositing arrive in the next update. You can already receive privately — share your address.";

const STUB_ACTIONS = [
  { label: "Send", Icon: IconSend },
  { label: "Withdraw", Icon: IconWithdraw },
  { label: "Deposit", Icon: IconDeposit },
] as const;

/** The action grid, stubbed: every button DISABLED (S5-S6 wire the real screens)
 *  with the notice as its tooltip and as the visible line below. Pure and
 *  prop-free so the copy gate renders it headlessly. */
export function ActionStubs(): ReactNode {
  return (
    <section className="flex flex-col gap-2" aria-label="Actions">
      <div className="grid grid-cols-3 gap-2">
        {STUB_ACTIONS.map(({ label, Icon }) => (
          <button
            key={label}
            className="bg-surface border border-border rounded-xl pt-3 px-1 pb-2.5 text-primary text-sm [font-weight:650] font-sans flex flex-col items-center gap-1.5 disabled:opacity-45 disabled:cursor-not-allowed"
            disabled
            title={ACTIONS_STUB_NOTICE}
          >
            <Icon />
            <span>{label}</span>
          </button>
        ))}
      </div>
      <p className="text-muted text-[0.8rem] px-0.5">{ACTIONS_STUB_NOTICE}</p>
    </section>
  );
}

export function Home(): ReactNode {
  const {
    session, connection, wallet, balance, history, loading, dataError, dataNotice,
    scannedNextLeafIndex, indexerUrl, refresh,
  } = useWallet();

  // Receive is a modal over Home — with the op screens still stubbed, sharing the
  // address IS the receive path, so it stays a first-class surface.
  const [receiveOpen, setReceiveOpen] = useState(false);
  // Testnet-only: self-mint public test kKRW (the deposit screen hosts this in
  // wallet-web; until S5 ships that screen, Home carries the affordance so a
  // tester can still fund an account from this app).
  const [mintOpen, setMintOpen] = useState(false);

  if (!session) return null;

  return (
    <div className="flex flex-col gap-3 px-4.5 pt-4.5 pb-6.5">
      <header className="flex items-center justify-between">
        <div className="inline-flex items-center gap-2 text-primary">
          <EnvelopeLogo size={26} />
          <span className="font-bold text-[1.1rem] tracking-[-0.01em]">bongtu</span>
          {DEFAULTS.testnet && <TestnetTag />}
        </div>
        {/* Icons only (the wallet-web U-W9 shape): sync state, lock state,
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
        onOpenReceive={() => setReceiveOpen(true)}
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

      <ActionStubs />

      {DEFAULTS.testnet && (
        <div className="flex justify-center">
          <LinkButton small subtle onClick={() => setMintOpen(true)}>
            Get test kKRW
          </LinkButton>
        </div>
      )}

      {/* The standardized state banner (class 4): set by a failed scan, cleared by
          the next success — and the data already on screen stays below it (a failed
          background read never blanks the screen). Retry is the MANUAL refresh. */}
      {dataError && <Banner message={dataError} onRetry={() => void refresh(true)} />}
      {/* Calm strip, not the warn banner: the data below is real — pending kem
          delivery, or a locked wallet serving its last scan (scanStore.scanNotice). */}
      {!dataError && dataNotice && <p className="text-muted text-[0.85rem] px-0.5">{dataNotice}</p>}
      <ActivityList
        history={history.slice(0, RECENT_COUNT)}
        loading={loading}
        explorerBase={DEFAULTS.explorer}
        onViewAll={() => navigate("activity")}
      />

      {receiveOpen && (
        <ReceiveModal pubkey={encodeAddress(session.compressedPubkey)} onClose={() => setReceiveOpen(false)} />
      )}
      {mintOpen && (
        <MintModal connection={connection} onClose={() => setMintOpen(false)} onMinted={() => {}} />
      )}
    </div>
  );
}
