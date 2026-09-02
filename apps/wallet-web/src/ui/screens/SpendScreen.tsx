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
// CIRCUIT AUTO-PICK, AND HOW MANY TRANSACTIONS. The user never chooses a circuit, and
// never has to go and tidy their notes first. previewSpend answers, from the amount
// typed so far, which circuit this payment needs — driving the one-time key download,
// so the ~114 MB arity-10 key is fetched only when it is genuinely needed — and how
// many transactions it takes. A balance spread across more notes than one circuit can
// spend does not block the form: the plan simply grows the merge legs that make it
// fit, the confirm sheet says how many approvals that is, and the running screen
// counts them off. Nothing about it is a separate screen the user has to visit.
//
// Amounts: the form takes DECIMAL kKRW (parseKkrw, ≤6 fraction digits, 2^100 belt) and
// converts to raw wei at the UI edge — the flow/witness layer still receives raw wei
// strings, unchanged.

import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { getAddress } from "viem";
import { decodeAddress, encodeAddress } from "@bongtu/core/pubkey";
import { DEFAULTS } from "../../config.js";
import { runSpendChain, type SpendOutcome } from "@bongtu/client/spendFlow";
import { resolveName, type NameRecord } from "@bongtu/client/indexerClient";
import { previewSpend } from "@bongtu/client/spend";
import { keyCache } from "../../lib/keyCache.js";
import { proveInBrowser } from "../../lib/prove.js";
import { useWallet } from "../App.js";
import { useActionMachine, stepsForRun } from "../actionMachine.js";
import { formatKkrw, parseKkrw } from "@bongtu/client/money";
import { amountError, evmAddressError, recipientError, recipientName } from "../format.js";
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

export function SpendScreen({ kind }: { kind: "transfer" | "withdraw" }): ReactNode {
  const { session, connection, wallet, indexerUrl, notes, balance, reloadNotes, refreshAfterAction } =
    useWallet();
  const isTransfer = kind === "transfer";

  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  // Withdraw-only: an optional L1 payout address. Empty pays the connected
  // account (today's default, and what the field's hint says); non-empty must
  // be a real L1 address (evmAddressError) — an EOA, not a bongtu address.
  const [destination, setDestination] = useState("");
  // Pay-by-name (transfer-only): the directory record resolved for the CURRENT
  // input at Continue time, plus the resolve step's own error (unregistered /
  // network) — a judgment the form-shape recipientError cannot make.
  const [resolved, setResolved] = useState<NameRecord | null>(null);
  const [nameError, setNameError] = useState<string | null>(null);

  // The raw-wei amount the protocol layer receives; 0n while the input is invalid.
  const amountWei = useMemo(() => {
    const p = parseKkrw(amount);
    return p.ok ? p.wei : 0n;
  }, [amount]);

  // Which circuit this amount needs, how many transactions, and whether the wallet
  // simply cannot afford it.
  const plan = useMemo(
    () => previewSpend(kind, notes, amountWei.toString()),
    [kind, notes, amountWei],
  );
  const action = useActionMachine<SpendOutcome>({ circuit: plan.circuit, steps: SPEND_STEPS });

  const rcptErr = isTransfer ? recipientError(recipient) : null;
  // Which reading the input gets is unambiguous BY LENGTH (recipientName): a name
  // normalizes to <=32 chars while both address encodings are longer (legacy hex
  // 0x+64 chars, base58check 51), so a non-null name IS the name path and every
  // other input stays on today's decodeAddress path untouched.
  const typedName = isTransfer ? recipientName(recipient) : null;
  // Stale-resolve guard: the stored record only counts while it still matches
  // what the field says NOW (the name is re-derived from the input), so editing
  // the field after a resolve can never pay the previously resolved name.
  const activeRecord =
    resolved !== null && typedName !== null && resolved.name === typedName ? resolved : null;
  const amtErr = amountError(amount, balance);
  // The destination is judged as an L1 address (never recipientError's bjj
  // grammar), and becomes an address exactly once: checksummed here, so the
  // string the confirm sheet shows IS the string the flow's proof binds. Null
  // means "defaulted" — the flow then pays the connected account on its own.
  const destErr = isTransfer ? null : evmAddressError(destination);
  const withdrawDest =
    !isTransfer && destErr === null && destination.trim() !== ""
      ? getAddress(destination.trim())
      : null;
  // Guard on a KNOWN balance: until /notes loads (balance===null) amountError can't
  // catch over-spend, so don't let the user start a proof that would revert on-chain.
  const formValid =
    balance !== null && !amtErr && !plan.blocker && (!isTransfer || !rcptErr) && !destErr;

  const title = isTransfer ? "Send" : "Withdraw";
  const terminalWord = isTransfer ? "payment" : "withdrawal";
  const review = formatKkrw(amountWei);

  function confirm(): void {
    if (!connection || !session) return;
    // The spending key comes from the wallet's lock INSIDE runSpendChain — this
    // component never holds it. The session pubkey rides along so the flow can refuse
    // a key that isn't this session's, and is the payee of every merge leg.
    void action.submit(
      async (onStage) =>
        runSpendChain(
          kind,
          {
            connection,
            indexerUrl,
            pool: DEFAULTS.pool,
            explorer: DEFAULTS.explorer,
            // Empty config means "no relayer" — the flow's undefined default
            // (wallet self-submit); the flow itself relays only withdraw legs.
            relayerUrl: DEFAULTS.relayerUrl || undefined,
            notes,
            sessionPubkey: session.compressedPubkey,
            reloadNotes,
          },
          // The flow/witness layer only ever sees the canonical hex form — a
          // resolved name contributes its owner key through the same decodeAddress
          // normalization a typed address gets; base58 and names stop at this edge.
          // The withdraw destination rides the flow's proof-bound recipient param
          // (withdrawTo); undefined is the flow's own connected-account default.
          {
            to: isTransfer
              ? decodeAddress(activeRecord ? activeRecord.owner : recipient.trim())
              : undefined,
            amount: amountWei.toString(),
            withdrawTo: withdrawDest ?? undefined,
          },
          onStage,
          // The engine takes the app's lock + prover through its deps seam: proving
          // is in-browser snarkjs over the same-origin circuit assets.
          { keyCache, prove: (request) => proveInBrowser(request, DEFAULTS.circuitBaseUrl) },
        ),
      refreshAfterAction,
    );
  }

  // Continue resolves a name BEFORE the confirm sheet opens — the sheet must show
  // the name→owner binding, so the record has to exist first. A plain address goes
  // straight to review as before. This small async wrapper stays OUTSIDE
  // useActionMachine: resolution is a form-time concern, not an action phase.
  async function handleContinue(): Promise<void> {
    if (typedName === null) {
      action.review();
      return;
    }
    setNameError(null);
    try {
      const record = await resolveName(indexerUrl, typedName);
      if (!record) {
        setNameError("That name isn't registered.");
        return;
      }
      setResolved(record);
      action.review();
    } catch (e) {
      // A network/server failure surfaces its thrown message in the same slot.
      setNameError(e instanceof Error ? e.message : String(e));
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
    // A chain shows its TRANSACTIONS as the steps, each described by the stage it is
    // in; a plain spend keeps the assemble/prove/submit rail it always had.
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
          plan.legCount > 1 ? (
            <ApprovalPlan pieces={plan.pieces} legCount={plan.legCount} terminal={terminalWord} />
          ) : undefined
        }
        download={action.download}
        onCancel={action.cancel}
        onConfirm={confirm}
      >
        {isTransfer && (
          <>
            <dt className="text-muted text-sm">To</dt>
            <dd className="font-mono text-right text-[0.9rem] [overflow-wrap:anywhere]">
              {/* canonical base58 regardless of which form was typed — what the
                  user confirms is the address, not their keystrokes. A resolved
                  name shows BOTH halves of the binding (name AND owner address):
                  what is confirmed is "this name pays this key". */}
              {activeRecord ? (
                <>
                  <span className="font-sans font-semibold">{activeRecord.name}</span>
                  <br />
                  {encodeAddress(decodeAddress(activeRecord.owner))}
                </>
              ) : (
                encodeAddress(decodeAddress(recipient.trim()))
              )}
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
        {!isTransfer && DEFAULTS.relayerUrl && (
          <>
            {/* the relayed path shows no wallet gas popup after Confirm — say
                why up front, or the missing popup reads as a hang. */}
            <dt className="text-muted text-sm">Gas</dt>
            <dd className="text-right text-[0.9rem]">Sponsored — submitted by the relayer</dd>
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
          <Field label="Recipient" error={recipient.trim() ? (rcptErr ?? nameError) : null}>
            <TextInput
              mono
              placeholder="bongtu address (3… or legacy 0x…) or name"
              value={recipient}
              onChange={(e) => {
                setRecipient(e.target.value);
                // any edit invalidates the resolve result AND its error — the
                // activeRecord guard would re-judge anyway; clearing keeps the
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
