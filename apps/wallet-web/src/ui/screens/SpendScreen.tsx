// The shared Send (transfer) / Withdraw screen. Both are a 2-in spend that proves in
// the browser and submits through the connected wallet; the ONLY difference is
// transfer needs a recipient pubkey and withdraw does not. Keeping them one component
// means the validate → confirm → staged-prove → success flow lives in exactly one place.
//
// The phases themselves are not written here: useActionMachine owns form → confirm →
// running → done (and the asset prefetch that rides along), and ActionPanels renders
// the three phases every action screen shares. What stays below is what a SPEND is —
// its recipient field, its amount field, and its confirm rows.
//
// Amounts: the form takes DECIMAL kKRW (parseKkrw, ≤6 fraction digits, 2^100 belt) and
// converts to raw wei at the UI edge — the flow/witness layer still receives raw wei
// strings, unchanged.

import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { decodeAddress, encodeAddress } from "@bongtu/core/pubkey";
import { DEFAULTS } from "../../config.js";
import { runSpend, type SpendOutcome } from "../../lib/spendFlow.js";
import { useWallet } from "../App.js";
import { useActionMachine } from "../actionMachine.js";
import { formatKkrw, parseKkrw } from "../../lib/money.js";
import { amountError, recipientError } from "../format.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { SPEND_STEPS } from "../components/StagedProgress.js";
import { SuccessPanel } from "../components/SuccessPanel.js";
import { ConfirmPanel, DownloadingPanel, RunningPanel } from "../components/ActionPanels.js";
import { AmountInput, Button, ErrorBanner, Field, TextInput } from "../components/controls.js";

export function SpendScreen({ kind }: { kind: "transfer" | "withdraw" }): ReactNode {
  const { session, connection, wallet, indexerUrl, notes, balance, refreshAfterAction, syncing } =
    useWallet();
  const isTransfer = kind === "transfer";

  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const action = useActionMachine<SpendOutcome>({ circuit: kind, steps: SPEND_STEPS });

  const rcptErr = isTransfer ? recipientError(recipient) : null;
  const amtErr = amountError(amount, balance);
  // Guard on a KNOWN balance: until /notes loads (balance===null) amountError can't
  // catch over-spend, so don't let the user start a proof that would revert on-chain.
  const formValid = balance !== null && !amtErr && (!isTransfer || !rcptErr);

  const title = isTransfer ? "Send" : "Withdraw";

  // The raw-wei amount the protocol layer receives; 0n while the input is invalid.
  const amountWei = useMemo(() => {
    const p = parseKkrw(amount);
    return p.ok ? p.wei : 0n;
  }, [amount]);
  const review = formatKkrw(amountWei);

  function confirm(): void {
    if (!connection || !session) return;
    // The spending key comes from the wallet's lock INSIDE runSpend — this component
    // never holds it. The session pubkey rides along so the flow can refuse a key that
    // isn't this session's.
    void action.submit(
      (onStage) =>
        runSpend(
          kind,
          { connection, indexerUrl, notes, sessionPubkey: session.compressedPubkey },
          // The flow/witness layer only ever sees the canonical hex form — base58
          // stops at this edge.
          {
            to: isTransfer ? decodeAddress(recipient.trim()) : undefined,
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
        headline={isTransfer ? "Payment sent" : "Withdrawal sent"}
        amount={review}
        explorerUrl={action.outcome.explorerUrl}
        syncing={syncing}
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
        <dt className="text-muted text-sm">Network</dt>
        <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
          GIWA · chain {DEFAULTS.chainId}
        </dd>
      </ConfirmPanel>
    );
  }

  // --- form ------------------------------------------------------------------
  if (action.download.active) {
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

        <Button variant="primary" block disabled={!formValid} onClick={action.review}>
          Continue
        </Button>
      </div>
    </div>
  );
}
