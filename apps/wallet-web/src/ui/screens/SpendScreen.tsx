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
import { decodeAddress, encodeAddress } from "@bongtu/core/pubkey";
import { DEFAULTS } from "../../config.js";
import { runSpendChain, type SpendOutcome } from "@bongtu/client/spendFlow";
import { prepareStealthDestination } from "@bongtu/client/stealthKeys";
import { navigate } from "../hooks.js";
import { previewSpend } from "@bongtu/client/spend";
import { keyCache } from "../../lib/keyCache.js";
import { proveInBrowser } from "../../lib/prove.js";
import { useWallet } from "../App.js";
import { useActionMachine, stepsForRun } from "../actionMachine.js";
import { formatKkrw, parseKkrw } from "@bongtu/client/money";
import { amountError, recipientError } from "../format.js";
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
  // Withdraw-only: pay a freshly derived one-time (stealth) address instead of
  // the connected account. Costs one extra signature popup at submit.
  const [stealthMode, setStealthMode] = useState(false);

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
  const amtErr = amountError(amount, balance);
  // Guard on a KNOWN balance: until /notes loads (balance===null) amountError can't
  // catch over-spend, so don't let the user start a proof that would revert on-chain.
  const formValid = balance !== null && !amtErr && !plan.blocker && (!isTransfer || !rcptErr);

  const title = isTransfer ? "Send" : "Withdraw";
  const terminalWord = isTransfer ? "payment" : "withdrawal";
  const review = formatKkrw(amountWei);

  function confirm(): void {
    if (!connection || !session) return;
    // The spending key comes from the wallet's lock INSIDE runSpendChain — this
    // component never holds it. The session pubkey rides along so the flow can refuse
    // a key that isn't this session's, and is the payee of every merge leg.
    void action.submit(
      async (onStage) => {
        // The stealth destination is derived JUST before the run: meta keys from
        // the wallet's ONE lock (unlockStealth — the first stealth action pays a
        // popup, later ones ride the hold under the lock's idle/account rules),
        // then a fresh ephemeral — this screen stores nothing.
        // prepareStealthDestination owns the derivation whole (address +
        // announcement as one value); this screen only decides WHETHER.
        const stealth =
          !isTransfer && stealthMode
            ? await prepareStealthDestination(connection, {
                getKeys: () => keyCache.unlockStealth(connection, session.compressedPubkey),
              })
            : undefined;
        return runSpendChain(
          kind,
          {
            connection,
            indexerUrl,
            pool: DEFAULTS.pool,
            explorer: DEFAULTS.explorer,
            notes,
            sessionPubkey: session.compressedPubkey,
            reloadNotes,
          },
          // The flow/witness layer only ever sees the canonical hex form — base58
          // stops at this edge.
          {
            to: isTransfer ? decodeAddress(recipient.trim()) : undefined,
            amount: amountWei.toString(),
            stealth,
          },
          onStage,
          // The engine takes the app's lock + prover through its deps seam: proving
          // is in-browser snarkjs over the same-origin circuit assets.
          { keyCache, prove: (request) => proveInBrowser(request, DEFAULTS.circuitBaseUrl) },
        );
      },
      refreshAfterAction,
    );
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
              {/* canonical base58 regardless of which form was typed — what
                  the user confirms is the address, not their keystrokes */}
              {encodeAddress(decodeAddress(recipient.trim()))}
            </dd>
          </>
        )}
        {!isTransfer && stealthMode && (
          <>
            <dt className="text-muted text-sm">To</dt>
            <dd className="text-right text-[0.9rem]">new stealth address (derived at submit)</dd>
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
          <label className="flex items-start gap-2.5 bg-surface border border-border rounded-xl p-3 cursor-pointer">
            <input
              type="checkbox"
              className="mt-0.5"
              checked={stealthMode}
              onChange={(e) => setStealthMode(e.target.checked)}
            />
            <span className="flex flex-col gap-0.5">
              <span className="text-sm font-semibold">Anonymous withdrawal (stealth address)</span>
              <span className="text-[11.5px] text-muted">
                Pays a fresh one-time address only you can spend from — your wallet address never
                appears on-chain. Find the funds later under{" "}
                <button type="button" className="underline" onClick={() => navigate("stealth")}>
                  Stealth funds
                </button>
                . Your first stealth action asks for one extra signature; after that your
                unlocked wallet reuses it.
              </span>
            </span>
          </label>
        )}
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

        <Button variant="primary" block disabled={!formValid} onClick={action.review}>
          Continue
        </Button>
      </div>
    </div>
  );
}
