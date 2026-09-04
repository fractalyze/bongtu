// The hero balance card on Home: the big private kKRW balance plus the wallet's
// bongtu receive ID directly under it. The ID is the receive surface — tapping it
// opens the receive modal, the copy icon copies the FULL id (shortened text alone
// would propagate truncated addresses), and a custom hover/focus tooltip reveals the
// full id in place. What the hero shows is the PURE balanceHero fold (homeView.ts,
// gated as a table): loading ellipsis or dash until the first completed pass —
// never a fabricated zero — and formatKkrw as the one number edge (never Number).

import type { ReactNode } from "react";
import { balanceHero } from "../homeView.js";
import { shortenPubkey } from "../format.js";
import { useCopyFeedback } from "../hooks.js";
import { IconButton } from "./controls.js";
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
  const hero = balanceHero(balance, loading);
  return (
    <section className="bg-surface border border-border rounded-xl pt-6.5 px-5 pb-5 text-center flex flex-col gap-1.5">
      <div className="text-[0.8rem] text-muted font-semibold">Private balance</div>
      <div className="flex items-baseline justify-center gap-1 flex-wrap">
        {hero.kind !== "amount" ? (
          <span className="text-[2.1rem] text-muted">{hero.kind === "loading" ? "…" : "—"}</span>
        ) : (
          <>
            <span className="text-[2.1rem] [font-weight:750] tracking-[-0.02em] tabular-nums">
              {hero.text}
            </span>
            <span className="text-muted font-semibold">kKRW</span>
          </>
        )}
      </div>
      <div className="flex items-center justify-center gap-0.5 mt-1.5">
        <span className="relative inline-flex group">
          <button
            className="font-mono text-xs text-muted bg-surface-2 border-0 rounded-full px-2.5 py-1 cursor-pointer transition-colors hover:bg-border hover:text-ink"
            onClick={onOpenReceive}
            aria-label="Your bongtu address. Open receive"
            aria-describedby="bongtu-id-tip"
          >
            {shortenPubkey(pubkey)}
          </button>
          <span
            className="absolute bottom-[calc(100%+8px)] left-1/2 -translate-x-1/2 bg-ink text-white font-mono text-[0.68rem] leading-[1.45] px-[9px] py-1.5 rounded-lg w-max max-w-[250px] [overflow-wrap:anywhere] text-center opacity-0 pointer-events-none transition-opacity z-30 group-hover:opacity-100 group-has-[:focus-visible]:opacity-100"
            role="tooltip"
            id="bongtu-id-tip"
          >
            {pubkey}
          </span>
        </span>
        <IconButton
          small
          ok={copied}
          onClick={copy}
          aria-label={copied ? "Copied" : "Copy bongtu address"}
        >
          {copied ? <IconCheck size={15} /> : <IconCopy size={15} />}
        </IconButton>
      </div>
    </section>
  );
}
