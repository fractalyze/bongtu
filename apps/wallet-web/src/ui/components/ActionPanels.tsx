// The three phases Send, Withdraw and Deposit render identically: the one-time asset
// download, the staged run, and the confirm sheet. Only the confirm ROWS differ per
// action (a recipient, a source, a note about the extra approve tx), so those come in
// as children; everything around them is written once here. The fourth phase, done,
// is SuccessPanel — the same idea, already shared.
//
// The machine that decides WHICH of these renders is src/ui/actionMachine.ts.

import type { ReactNode } from "react";
import { StagedProgress, type StagedStep } from "./StagedProgress.js";
import { DownloadProgress } from "./DownloadProgress.js";
import { ScreenHeader } from "./ScreenHeader.js";
import { Button } from "./controls.js";
import type { CircuitDownloadView } from "../hooks.js";

function Panel({ title, children }: { title: string; children: ReactNode }): ReactNode {
  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title={title} />
      <div className="flex flex-col gap-4">{children}</div>
    </div>
  );
}

/** The amount in play, in the size it deserves — the one thing the user checks on the
 *  confirm sheet and watches while the proof runs. Already formatted kKRW. */
export function AmountHero({ amount }: { amount: string }): ReactNode {
  return (
    <div className="text-center text-[1.9rem] [font-weight:750] py-2 tabular-nums">
      {amount} <span className="text-[0.62em] font-semibold text-muted ml-1">kKRW</span>
    </div>
  );
}

/** Cold cache: the one-time key download IS the screen. No inputs and no buttons —
 *  everything the user could press here needs these assets anyway. */
export function DownloadingPanel({
  title,
  download,
}: {
  title: string;
  download: CircuitDownloadView;
}): ReactNode {
  return (
    <Panel title={title}>
      <DownloadProgress view={download} />
    </Panel>
  );
}

/** The run in flight: the amount, then the staged progress with its honest clock. */
export function RunningPanel({
  title,
  amount,
  stage,
  elapsed,
  steps,
  walletName,
}: {
  title: string;
  amount: string;
  stage: string;
  elapsed: number;
  steps: StagedStep[];
  walletName: string;
}): ReactNode {
  return (
    <Panel title={title}>
      <AmountHero amount={amount} />
      <StagedProgress stage={stage} elapsed={elapsed} steps={steps} walletName={walletName} />
    </Panel>
  );
}

/** The confirm sheet: the amount, the action's own detail rows, an optional note about
 *  what confirming will cost, and the Cancel / Confirm pair. Confirm stays disabled
 *  while the proving assets are still streaming in. */
export function ConfirmPanel({
  title,
  amount,
  note,
  download,
  onCancel,
  onConfirm,
  children,
}: {
  /** the screen's own title — the header reads "Confirm <title>". */
  title: string;
  amount: string;
  note?: ReactNode;
  download: CircuitDownloadView;
  onCancel: () => void;
  onConfirm: () => void;
  /** the <dt>/<dd> rows of this action's detail list. */
  children: ReactNode;
}): ReactNode {
  return (
    <Panel title={`Confirm ${title}`}>
      <AmountHero amount={amount} />
      <dl className="grid grid-cols-[auto_1fr] gap-x-3.5 gap-y-2 p-3.5 bg-surface border border-border rounded-xl">
        {children}
      </dl>
      {note}
      <DownloadProgress view={download} />
      <div className="flex gap-2.5">
        <Button variant="ghost" className="flex-1" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="primary" className="flex-1" disabled={download.active} onClick={onConfirm}>
          {download.active ? "Preparing…" : "Confirm"}
        </Button>
      </div>
    </Panel>
  );
}
