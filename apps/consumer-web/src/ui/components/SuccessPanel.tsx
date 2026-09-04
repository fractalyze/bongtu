// The done state shared by Deposit, Send and Withdraw: mark, headline, the amount that
// moved, the explorer link, and the way back home. The three screens differ only in
// their headline, so this is the one place their success copy is written.

import type { ReactNode } from "react";
import { navigate } from "../hooks.js";
import { Button } from "./controls.js";
import { ExplorerLink } from "./ExplorerLink.js";
import { ScreenHeader } from "./ScreenHeader.js";
import { SuccessMark } from "./SuccessMark.js";

export function SuccessPanel({
  title,
  headline,
  amount,
  explorerUrl,
}: {
  /** The screen header (Send / Withdraw / Deposit) — unchanged from the form. */
  title: string;
  headline: string;
  /** Already formatted kKRW. */
  amount: string;
  explorerUrl: string;
}): ReactNode {
  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title={title} />
      <div className="flex flex-col items-center gap-2.5 text-center pt-4.5">
        <SuccessMark />
        <h2 className="mt-1.5 text-xl font-bold">{headline}</h2>
        <p className="text-[1.8rem] [font-weight:750] my-0.5 tabular-nums">
          {amount} <span className="text-[0.62em] font-semibold text-muted ml-1">kKRW</span>
        </p>
        <ExplorerLink href={explorerUrl} />
        <Button variant="primary" block className="mt-2" onClick={() => navigate("home")}>
          Done
        </Button>
      </div>
    </div>
  );
}
