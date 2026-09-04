// The three phases Send, Withdraw and Deposit render identically: the one-time asset
// download, the staged run, and the confirm sheet. Only the confirm ROWS differ per
// action (a recipient name, a payout address, a note about the extra approve tx), so
// those come in as children; everything around them is written once here. The fourth
// phase, done, is SuccessPanel — the same idea, already shared. Trimmed against
// wallet-web's panels only where this profile removed the feature (no sponsored-gas
// row: consumer v1 self-submits every leg).
//
// The machine that decides WHICH of these renders is src/ui/actionMachine.ts.

import type { ReactNode } from "react";
import { StagedProgress, type StagedStep } from "./StagedProgress.js";
import { DownloadProgress } from "./DownloadProgress.js";
import { ScreenHeader } from "./ScreenHeader.js";
import { Button } from "./controls.js";
import { IconShieldCheck, IconWallet } from "./icons.js";
import type { CircuitDownloadView } from "../hooks.js";

function Panel({
  title,
  backDisabled = false,
  children,
}: {
  title: string;
  backDisabled?: boolean;
  children: ReactNode;
}): ReactNode {
  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title={title} backDisabled={backDisabled} />
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
  describeKey,
  elapsed,
  steps,
  walletName,
}: {
  title: string;
  amount: string;
  stage: string;
  /** which stage writes the line under the active step — see StagedProgress. */
  describeKey?: string;
  elapsed: number;
  steps: StagedStep[];
  walletName: string;
}): ReactNode {
  return (
    // Back is disabled while the run is live: the flow keeps executing after an
    // unmount (wallet popups with no app context behind them), and a remounted
    // screen would show a fresh form over the hidden run — the OpGate refusal
    // would then be the only trace an op exists. The run IS the screen.
    <Panel title={title} backDisabled>
      <AmountHero amount={amount} />
      <StagedProgress
        stage={stage}
        describeKey={describeKey}
        elapsed={elapsed}
        steps={steps}
        walletName={walletName}
      />
    </Panel>
  );
}

/** The one-glance direction of a confirm, drawn rather than listed (the wallet-web
 *  grill decision, kept): two icon cards — wallet = Public kKRW, shield = Private
 *  kKRW, the private side tinted as the protected one — joined by a dashed arrow
 *  whose dashes flow in the direction of the money. Deposit shields, withdraw
 *  unshields; the cards swap sides accordingly. */
export function FlowHint({ direction }: { direction: "shield" | "unshield" }): ReactNode {
  const publicCard = (
    <span className="flex flex-col items-center gap-1.5 bg-surface border border-border rounded-xl px-4 py-3 min-w-[104px]">
      <IconWallet size={22} className="text-primary" />
      <span className="text-[0.8rem] font-semibold text-muted">Public kKRW</span>
    </span>
  );
  const privateCard = (
    <span className="flex flex-col items-center gap-1.5 bg-pos-bg border border-[#cfe5d6] rounded-xl px-4 py-3 min-w-[104px]">
      <IconShieldCheck size={22} className="text-pos" />
      <span className="text-[0.8rem] font-semibold text-pos">Private kKRW</span>
    </span>
  );
  const [from, to] =
    direction === "shield" ? [publicCard, privateCard] : [privateCard, publicCard];
  const label =
    direction === "shield" ? "Public kKRW to Private kKRW" : "Private kKRW to Public kKRW";
  return (
    <div className="flex items-center justify-center gap-3" aria-label={label}>
      {from}
      <svg viewBox="0 0 64 24" className="w-16 h-6 flex-none" aria-hidden="true">
        <line
          x1="2"
          y1="12"
          x2="50"
          y2="12"
          className="stroke-border-strong animate-flow-dash"
          strokeWidth="2"
          strokeDasharray="6 5"
        />
        <polygon points="50,6 62,12 50,18" className="fill-border-strong" />
      </svg>
      {to}
    </div>
  );
}

/** What a spend that takes several transactions tells the user before they start it:
 *  how many approvals, and what each one is for. Deliberately not a warning — nothing
 *  is wrong, this is simply what moving a balance held in many pieces costs. It is the
 *  same count the running screen then steps through. */
export function ApprovalPlan({
  pieces,
  legCount,
  terminal,
}: {
  pieces: number;
  legCount: number;
  /** "payment" / "withdrawal" — what the last approval does. */
  terminal: string;
}): ReactNode {
  return (
    <p className="text-muted text-[0.88rem]">
      Your balance is in {pieces} pieces, so this takes {legCount} approvals:{" "}
      {legCount - 1} to combine them, then the {terminal}.
    </p>
  );
}

/** The confirm sheet: the amount, the action's own detail rows, an optional note about
 *  what confirming will cost, and the Cancel / Confirm pair. Confirm stays disabled
 *  while the proving assets are still streaming in. */
export function ConfirmPanel({
  title,
  amount,
  hint,
  note,
  download,
  onCancel,
  onConfirm,
  children,
}: {
  /** the screen's own title — the header reads "Confirm <title>". */
  title: string;
  amount: string;
  /** optional direction line (FlowHint) rendered between the amount and the rows. */
  hint?: ReactNode;
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
      {hint}
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
