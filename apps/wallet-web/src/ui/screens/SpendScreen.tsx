// The shared Send (transfer) / Withdraw screen, on the consumer flow variants:
// both prove in-browser and self-submit to the op MODULES through the connected
// wallet (no relayer in v1); the only differences are what identifies the payee
// and which circuit the terminal leg lands on.
//
// SEND IS REGISTRY-NAME-ONLY (v1 product decision, locked): a consumer payment
// seals to the payee's registered v2 triple — spend pubkey + note-layer view
// pubkey + ML-KEM ek, ~1.2 KB — which is nothing a person could paste, so there
// is no address field and no address grammar here. The name resolves at
// Continue time through the ONE seam (lib/payName.ts): a v2 record pays, a
// v1-only record refuses with the exact cannot-receive copy, a network failure
// propagates instead of reading as "unregistered".
//
// WITHDRAW binds its payout target IN-PROOF: the L1 recipient is a public input
// of withdrawPriv, so once the proof exists nobody — not even this wallet — can
// swap where the money lands. The confirm sheet says so in plain words
// (WITHDRAW_PROOF_BOUND_NOTE).
//
// The phases are not written here: useActionMachine owns form → confirm →
// running → done (plus the one-op gate and asset prefetch), ActionPanels renders
// the shared phase shells, and previewSpend answers — from the amount typed so
// far — which circuit is needed and how many transactions the chain takes.

import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { getAddress } from "viem";
import { DEFAULTS } from "../../config.js";
import type { SpendOutcome } from "@bongtu/client/spend";
import { consumerCircuitOf, type ConsumerRecipient } from "@bongtu/client/consumer";
import { normalizeName } from "@bongtu/core/indexerApi";
import { resolveConsumerRecipient } from "../../lib/payName.js";
import { consumerErrorMessage } from "../../lib/errors.js";
import { useWallet } from "../App.js";
import { useActionMachine, stepsForRun } from "../actionMachine.js";
import { formatKkrw, parseKkrw } from "@bongtu/client/money";
import { amountError, evmAddressError, shortenPubkey } from "../format.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { activeStep, chainSteps, SPEND_STEPS } from "../components/StagedProgress.js";
import { SuccessPanel } from "../components/SuccessPanel.js";
import {
  ApprovalPlan,
  ConfirmPanel,
  DownloadingPanel,
  FlowHint,
  RunningPanel,
} from "../components/ActionPanels.js";
import { AmountInput, Button, ErrorBanner, Field, TextInput } from "../components/controls.js";

/** The proof-bound-recipient property, stated where the user confirms the
 *  target: the payout address is a public input of the withdraw proof. */
export const WITHDRAW_PROOF_BOUND_NOTE =
  "The payout address is locked into your proof. Once you confirm, it cannot be redirected by anyone.";

export function SpendScreen({ kind }: { kind: "transfer" | "withdraw" }): ReactNode {
  const { connection, wallet, indexerUrl, notes, balance, ops, refreshAfterAction } = useWallet();
  const isTransfer = kind === "transfer";

  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  // Withdraw-only: an optional L1 payout address. Empty pays the connected
  // account (today's default, and what the field's hint says).
  const [destination, setDestination] = useState("");
  // The payee resolved for the CURRENT input at Continue time, plus the resolve
  // step's own error — judgments no form-shape check can make.
  const [resolved, setResolved] = useState<{ name: string; recipient: ConsumerRecipient } | null>(null);
  const [nameError, setNameError] = useState<string | null>(null);

  // The raw-wei amount the protocol layer receives; 0n while the input is invalid.
  const amountWei = useMemo(() => {
    const p = parseKkrw(amount);
    return p.ok ? p.wei : 0n;
  }, [amount]);

  // Which circuit this amount needs (mapped onto the consumer twin — the merge
  // legs are transfer10x2Priv), how many transactions, and whether the wallet
  // simply cannot afford it. The circuit drives the one-time key download, so
  // the big arity-10 key is fetched only when the plan genuinely needs it.
  const plan = useMemo(
    () => (ops ? ops.preview(kind, amountWei.toString()) : { circuit: kind, blocker: null, legCount: 1, pieces: 0 }),
    // `notes` is the reactivity key: the facade's note source reads the scan
    // ref, and a landed scan updates `notes` in the same pass.
    [ops, kind, amountWei, notes],
  );
  const circuit = consumerCircuitOf(plan.circuit);
  const action = useActionMachine<SpendOutcome>({ circuit, steps: SPEND_STEPS });

  // Stale-resolve guard: the stored triple only counts while the field still
  // names the same canonical name — editing after a resolve can never pay the
  // previously resolved person.
  const typedName = isTransfer ? normalizeName(recipient) : null;
  const activeResolve =
    resolved !== null && typedName !== null && resolved.name === typedName ? resolved : null;
  const amtErr = amountError(amount, balance);
  const destErr = isTransfer ? null : evmAddressError(destination);
  // The destination becomes an address exactly once: checksummed here, so the
  // string the confirm sheet shows IS the string the flow's proof binds. Null
  // means "defaulted" — the flow then pays the connected account on its own.
  const withdrawDest =
    !isTransfer && destErr === null && destination.trim() !== ""
      ? getAddress(destination.trim())
      : null;
  // Guard on a KNOWN balance: until the first scan lands (balance===null)
  // amountError can't catch over-spend, so don't let the user start a proof
  // that would revert on-chain.
  const formValid =
    balance !== null && !amtErr && !plan.blocker && (!isTransfer || recipient.trim() !== "") && !destErr;

  const title = isTransfer ? "Send" : "Withdraw";
  const terminalWord = isTransfer ? "payment" : "withdrawal";
  const review = formatKkrw(amountWei);

  function confirm(): void {
    if (!ops) return;
    // The spending key comes from the wallet's lock INSIDE the flow — this
    // component never holds it. The notes are the self-scan result set, and the
    // between-legs re-read is a self-scan pass too — both live behind the
    // facade's note source (App constructs the ONE ConsumerOps per login).
    void action.submit(
      async (onStage) =>
        ops.spend(
          kind,
          {
            to: activeResolve?.recipient,
            amount: amountWei.toString(),
            withdrawTo: withdrawDest ?? undefined,
          },
          onStage,
        ),
      refreshAfterAction,
    );
  }

  // Continue resolves the name BEFORE the confirm sheet opens — the sheet must
  // show who gets paid, so the record has to exist first. Withdraw has no name
  // to resolve and reviews directly.
  async function handleContinue(): Promise<void> {
    if (!isTransfer) {
      action.review();
      return;
    }
    setNameError(null);
    try {
      const out = await resolveConsumerRecipient(indexerUrl, recipient);
      if (!out.ok) {
        setNameError(out.message);
        return;
      }
      setResolved(out);
      action.review();
    } catch (e) {
      // A network/server failure lands in the same slot in the classified
      // words (transport reads "could not reach", never a raw fetch line) —
      // and "the indexer is down" must not read as "that name doesn't exist".
      setNameError(consumerErrorMessage(e));
    }
  }

  // --- success ---------------------------------------------------------------
  if (action.phase === "done" && action.outcome) {
    return (
      <SuccessPanel
        title={title}
        headline={isTransfer ? "Payment sent" : "Withdrawal sent"}
        amount={review}
        explorerUrl={action.outcome.explorerUrl}
      />
    );
  }

  // --- running ---------------------------------------------------------------
  if (action.phase === "running") {
    // A chain shows its TRANSACTIONS as the steps, each described by the stage it
    // is in — the between-legs self-scan wait included ("waiting"); a plain spend
    // keeps the assemble/prove/submit rail.
    const chained = action.legCount > 1;
    const steps = chained
      ? stepsForRun(chainSteps(action.legCount, isTransfer ? "Sending" : "Withdrawing"), action.unlocking)
      : action.steps;
    const { stage, describeKey } = activeStep(action);
    return (
      <RunningPanel
        title={title}
        amount={review}
        stage={stage}
        describeKey={describeKey}
        elapsed={action.elapsed}
        steps={steps}
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
        hint={!isTransfer ? <FlowHint direction="unshield" /> : undefined}
        note={
          <>
            {plan.legCount > 1 && (
              <ApprovalPlan pieces={plan.pieces} legCount={plan.legCount} terminal={terminalWord} />
            )}
            {!isTransfer && <p className="text-sm text-muted">{WITHDRAW_PROOF_BOUND_NOTE}</p>}
          </>
        }
        download={action.download}
        onCancel={action.cancel}
        onConfirm={confirm}
      >
        {isTransfer && activeResolve && (
          <>
            <dt className="text-muted text-sm">To</dt>
            <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
              {/* both halves of the binding: the name being paid, and the key the
                  directory vouches for it — what is confirmed is "this name pays
                  this key", not the keystrokes. */}
              <span className="font-semibold">{activeResolve.name}</span>
              <br />
              <span className="font-mono text-muted text-[0.8rem]">
                {shortenPubkey(activeResolve.recipient.owner)}
              </span>
            </dd>
          </>
        )}
        {!isTransfer && (
          <>
            <dt className="text-muted text-sm">To</dt>
            <dd className="font-mono text-right text-[0.9rem] [overflow-wrap:anywhere]">
              {/* always the CHECKSUMMED L1 address — a defaulted field confirms
                  the connected account explicitly, not an implicit blank. */}
              {withdrawDest ?? (connection ? getAddress(connection.address) : "—")}
            </dd>
          </>
        )}
        <dt className="text-muted text-sm">Network</dt>
        <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
          {DEFAULTS.chainName} · chain {DEFAULTS.chainId}
        </dd>
      </ConfirmPanel>
    );
  }

  // --- form ------------------------------------------------------------------
  // The one-time key download takes over the screen only for the circuit the
  // screen OPENS on, where nothing is typed yet. The arity-10 key starts
  // downloading while the user is mid-amount, and replacing the form then would
  // strand them with no way to correct what they typed — the confirm sheet's own
  // progress bar (and its disabled Confirm) covers that one.
  if (action.download.active && plan.circuit === kind) {
    return <DownloadingPanel title={title} download={action.download} />;
  }

  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title={title} />
      <div className="flex flex-col gap-4">
        {!isTransfer && (
          <Field
            label="Destination address"
            hint={<>Optional — leave empty to withdraw to your connected account.</>}
            error={destination.trim() ? destErr : null}
          >
            <TextInput
              mono
              placeholder="0x… L1 address (defaults to your connected account)"
              value={destination}
              onChange={(e) => setDestination(e.target.value)}
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
            />
          </Field>
        )}
        {isTransfer && (
          <Field label="To (payment name)" error={recipient.trim() ? nameError : null}>
            <TextInput
              placeholder="Payment name, like alice"
              value={recipient}
              onChange={(e) => {
                setRecipient(e.target.value);
                // any edit invalidates the resolve result AND its error — the
                // activeResolve guard would re-judge anyway; clearing keeps the
                // field honest immediately
                setResolved(null);
                setNameError(null);
              }}
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

        <Button variant="primary" block disabled={!formValid} onClick={() => void handleContinue()}>
          Continue
        </Button>
      </div>
    </div>
  );
}
