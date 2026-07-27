// The shared Send (transfer) / Withdraw screen. Both prove in the browser and submit
// through the connected wallet; the ONLY difference is transfer needs a recipient
// pubkey and withdraw does not. Keeping them one component means the validate →
// confirm → staged-prove → success flow lives in exactly one place.
//
// The phases themselves are not written here: useActionMachine owns form → confirm →
// running → done (and the asset prefetch that rides along), and ActionPanels renders
// the three phases every action screen shares. What stays below is what a SPEND is —
// its recipient field, its amount field, and its confirm rows.
//
// CIRCUIT AUTO-PICK. The user never chooses a circuit. previewSpend answers, from the
// amount typed so far, which one this payment needs — a send covered by ≤2 notes on
// the small transfer, 3–10 notes on transfer10 — and that answer drives the one-time
// key download, so the ~114 MB arity-10 key is fetched only for a payment that
// genuinely needs it. When even the widest circuit cannot reach the amount (>10 notes
// for a send, >2 for a withdraw, which has no arity-10 circuit), the form does NOT
// dead-end on an error: it offers the merge below, which folds up to ten notes into
// one through the same machine and hands the user back to what they were doing.
//
// Amounts: the form takes DECIMAL kKRW (parseKkrw, ≤6 fraction digits, 2^100 belt) and
// converts to raw wei at the UI edge — the flow/witness layer still receives raw wei
// strings, unchanged.

import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { decodeAddress, encodeAddress } from "@bongtu/core/pubkey";
import { DEFAULTS } from "../../config.js";
import { runSpend, type SpendOutcome } from "../../lib/spendFlow.js";
import { previewMerge, previewSpend } from "../../lib/spend.js";
import { useWallet } from "../App.js";
import { useActionMachine } from "../actionMachine.js";
import { formatKkrw, parseKkrw } from "../../lib/money.js";
import { amountError, recipientError } from "../format.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { SPEND_STEPS } from "../components/StagedProgress.js";
import { SuccessPanel } from "../components/SuccessPanel.js";
import { ConfirmPanel, DownloadingPanel, FlowHint, RunningPanel } from "../components/ActionPanels.js";
import { AmountInput, Button, ErrorBanner, Field, TextInput } from "../components/controls.js";

/** What the user is told when their balance is real but too scattered to spend at
 *  once, and the way out. Deliberately not an ErrorBanner: nothing is wrong with
 *  what they typed, there is just a step to take first. */
function MergePrompt({
  maxNotes,
  verb,
  mergeable,
  onMerge,
}: {
  maxNotes: number;
  /** "send" / "withdrawal" — what they were trying to do. */
  verb: string;
  /** what one merge would fold together, or null when there is nothing to fold. */
  mergeable: { count: number; total: string } | null;
  onMerge: () => void;
}): ReactNode {
  return (
    <div className="flex flex-col gap-2.5 p-3.5 bg-surface border border-border rounded-xl">
      <p className="text-[0.95rem] font-semibold">Your balance is split across too many notes</p>
      <p className="text-muted text-[0.88rem]">
        Your money arrives in separate pieces, and one {verb} can use at most {maxNotes} of
        them at a time. Merge your pieces into one, then try this amount again.
      </p>
      {mergeable && (
        <p className="text-muted text-[0.88rem]">
          This merges your {mergeable.count} largest pieces into a single{" "}
          {formatKkrw(BigInt(mergeable.total))} kKRW note.
        </p>
      )}
      <Button variant="primary" block disabled={!mergeable} onClick={onMerge}>
        Merge your notes
      </Button>
    </div>
  );
}

export function SpendScreen({ kind }: { kind: "transfer" | "withdraw" }): ReactNode {
  const { session, connection, wallet, indexerUrl, notes, balance, refreshAfterAction } =
    useWallet();
  const isTransfer = kind === "transfer";

  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  // The merge is a spend of its own, run through the SAME machine: entering merge
  // mode freezes what it will fold, so a background /notes refresh cannot change the
  // sheet under the user mid-confirm.
  const [merging, setMerging] = useState<{ count: number; total: string } | null>(null);

  // The raw-wei amount the protocol layer receives; 0n while the input is invalid.
  const amountWei = useMemo(() => {
    const p = parseKkrw(amount);
    return p.ok ? p.wei : 0n;
  }, [amount]);

  // Which circuit this amount needs, and whether it is out of reach at any arity.
  const plan = useMemo(
    () => previewSpend(kind, notes, amountWei.toString()),
    [kind, notes, amountWei],
  );
  const mergeable = useMemo(() => previewMerge(notes), [notes]);
  const action = useActionMachine<SpendOutcome>({
    circuit: merging ? "transfer10" : plan.circuit,
    steps: SPEND_STEPS,
  });

  const rcptErr = isTransfer ? recipientError(recipient) : null;
  const amtErr = amountError(amount, balance);
  const needsMerge = plan.blocker === "needs-merge";
  // Guard on a KNOWN balance: until /notes loads (balance===null) amountError can't
  // catch over-spend, so don't let the user start a proof that would revert on-chain.
  const formValid = balance !== null && !amtErr && !needsMerge && (!isTransfer || !rcptErr);

  const title = merging ? "Merge notes" : isTransfer ? "Send" : "Withdraw";
  // The amount in play: the payment, or — in merge mode — what the merge consolidates.
  const review = formatKkrw(merging ? BigInt(merging.total) : amountWei);

  // A failed run lands back on the form. Leave merge mode with it, so the user is
  // returned to the payment they were making — reading the failure over the Send
  // form, with the merge offer still there to retry — instead of a Send form wearing
  // a "Merge notes" title.
  useEffect(() => {
    if (merging && action.phase === "form" && action.error) setMerging(null);
  }, [merging, action.phase, action.error]);

  function startMerge(): void {
    if (!mergeable) return;
    setMerging(mergeable);
    action.review();
  }

  /** Back from a finished merge to the payment that sent the user here, with the
   *  refreshed balance behind it. */
  function leaveMerge(): void {
    setMerging(null);
    action.cancel();
  }

  function confirm(): void {
    if (!connection || !session) return;
    // The spending key comes from the wallet's lock INSIDE runSpend — this component
    // never holds it. The session pubkey rides along so the flow can refuse a key that
    // isn't this session's.
    void action.submit(
      (onStage) =>
        runSpend(
          merging ? "merge" : kind,
          { connection, indexerUrl, notes, sessionPubkey: session.compressedPubkey },
          // The flow/witness layer only ever sees the canonical hex form — base58
          // stops at this edge. A merge pays the wallet itself, so it takes neither.
          {
            to: isTransfer && !merging ? decodeAddress(recipient.trim()) : undefined,
            amount: amountWei.toString(),
          },
          onStage,
        ),
      refreshAfterAction,
    );
  }

  // --- success ---------------------------------------------------------------
  if (action.phase === "done" && action.outcome) {
    return (
      <SuccessPanel
        title={title}
        headline={merging ? "Notes merged" : isTransfer ? "Payment sent" : "Withdrawal sent"}
        amount={review}
        explorerUrl={action.outcome.explorerUrl}
        doneLabel={merging ? `Back to ${isTransfer ? "Send" : "Withdraw"}` : "Done"}
        onDone={merging ? leaveMerge : undefined}
      />
    );
  }

  // --- running ---------------------------------------------------------------
  if (action.phase === "running") {
    return (
      <RunningPanel
        title={title}
        amount={review}
        stage={action.stage}
        elapsed={action.elapsed}
        steps={action.steps}
        walletName={wallet.name}
      />
    );
  }

  // --- confirm ---------------------------------------------------------------
  if (action.phase === "confirm") {
    return (
      <ConfirmPanel
        title={title}
        amount={review}
        hint={
          !isTransfer && !merging ? (
            <FlowHint direction="unshield" />
          ) : undefined
        }
        note={
          merging ? (
            <p className="text-muted text-[0.88rem]">
              This sends your balance to yourself as one note. It takes one signature and
              one transaction, and your balance does not change.
            </p>
          ) : undefined
        }
        download={action.download}
        onCancel={merging ? leaveMerge : action.cancel}
        onConfirm={confirm}
      >
        {merging ? (
          <>
            <dt className="text-muted text-sm">Merging</dt>
            <dd className="text-right text-[0.9rem]">{merging.count} notes into 1</dd>
            <dt className="text-muted text-sm">To</dt>
            <dd className="text-right text-[0.9rem]">Your own wallet</dd>
          </>
        ) : (
          isTransfer && (
            <>
              <dt className="text-muted text-sm">To</dt>
              <dd className="font-mono text-right text-[0.9rem] [overflow-wrap:anywhere]">
                {/* canonical base58 regardless of which form was typed — what
                    the user confirms is the address, not their keystrokes */}
                {encodeAddress(decodeAddress(recipient.trim()))}
              </dd>
            </>
          )
        )}
        <dt className="text-muted text-sm">Network</dt>
        <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
          GIWA · chain {DEFAULTS.chainId}
        </dd>
      </ConfirmPanel>
    );
  }

  // --- form ------------------------------------------------------------------
  // The one-time key download takes over the screen only for the circuit the screen
  // OPENS on, where nothing is typed yet. The arity-10 key starts downloading while
  // the user is mid-amount, and replacing the form then would strand them with no
  // way to correct what they typed — the confirm sheet's own progress bar (and its
  // disabled Confirm) covers that one.
  if (action.download.active && plan.circuit === kind) {
    return <DownloadingPanel title={title} download={action.download} />;
  }

  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title={title} />
      <div className="flex flex-col gap-4">
        {isTransfer && (
          <Field label="Recipient address" error={recipient.trim() ? rcptErr : null}>
            <TextInput
              mono
              placeholder="bongtu address (3… or legacy 0x…)"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
          </Field>
        )}

        <Field
          label="Amount (kKRW)"
          hint={<>Balance: {balance === null ? "—" : formatKkrw(balance)} kKRW</>}
          error={amount.trim() ? amtErr : null}
        >
          <AmountInput value={amount} onValueChange={setAmount} />
        </Field>

        {action.error && <ErrorBanner message={action.error} />}

        {needsMerge ? (
          <MergePrompt
            maxNotes={isTransfer ? 10 : 2}
            verb={isTransfer ? "send" : "withdrawal"}
            mergeable={mergeable}
            onMerge={startMerge}
          />
        ) : (
          <Button variant="primary" block disabled={!formValid} onClick={action.review}>
            Continue
          </Button>
        )}
      </div>
    </div>
  );
}
