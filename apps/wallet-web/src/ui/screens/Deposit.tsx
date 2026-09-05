// The consumer Deposit screen: mint public kKRW into a private note(V) through the
// deposit MODULE (consumerRunDeposit — the approve still targets the POOL escrow).
// Byte-patterned on treasury-web's Deposit with ONE consumer-only addition: an
// optional third-party recipient by REGISTRY NAME. A resolved v2 name mints the
// note straight to that person's registered triple — they discover it by
// self-scan — and a v1-only record refuses with the exact cannot-receive copy
// (lib/payName.ts): sealing to a missing key would land funds nobody could find.
//
// Amounts: the form takes DECIMAL kKRW (parseKkrw, ≤6 fraction digits, 2^100 belt)
// and converts to raw wei at the UI edge; the flow still receives a raw-wei string.

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../../config.js";
import type { ConsumerDepositOutcome } from "@bongtu/client/consumer";
import { readTokenState } from "@bongtu/client-evm/connection";
import { normalizeName } from "@bongtu/core/indexerApi";
import type { ConsumerRecipient } from "@bongtu/client/consumer";
import { resolveConsumerRecipient } from "../../lib/payName.js";
import { consumerErrorMessage } from "../../lib/errors.js";
import { useWallet } from "../App.js";
import { useActionMachine } from "../actionMachine.js";
import { formatKkrw, parseKkrw } from "@bongtu/client/money";
import { amountError, shortenPubkey } from "../format.js";
import { ScreenHeader } from "../components/ScreenHeader.js";
import { SuccessPanel } from "../components/SuccessPanel.js";
import { DEPOSIT_STEPS } from "../components/StagedProgress.js";
import { ConfirmPanel, DownloadingPanel, FlowHint, RunningPanel } from "../components/ActionPanels.js";
import { AmountInput, Button, ErrorBanner, Field, LinkButton, TestnetTag, TextInput } from "../components/controls.js";
import { MintModal } from "../components/MintModal.js";

/** What the optional recipient field is FOR, in the field's own hint slot. */
export const DEPOSIT_RECIPIENT_HINT =
  "Optional. Enter a payment name to deposit straight to someone else, privately.";

export function Deposit(): ReactNode {
  const { connection, wallet, indexerUrl, ops, refreshAfterAction } = useWallet();

  const [amount, setAmount] = useState("");
  const [recipientInput, setRecipientInput] = useState("");
  // The name resolved for the CURRENT input at Continue time, plus the resolve
  // step's own error (unregistered / v1-only / network) — judgments the form's
  // shape checks cannot make.
  const [resolved, setResolved] = useState<{ name: string; recipient: ConsumerRecipient } | null>(null);
  const [nameError, setNameError] = useState<string | null>(null);
  const [tokenBalance, setTokenBalance] = useState<bigint | null>(null);
  const [allowance, setAllowance] = useState<bigint | null>(null);
  const [mintOpen, setMintOpen] = useState(false);
  const action = useActionMachine<ConsumerDepositOutcome>({ circuit: "depositPriv", steps: DEPOSIT_STEPS });

  // Re-read balance + allowance on demand (after the faucet mint confirms).
  // Best-effort: an RPC hiccup shows "—".
  const refreshTokenState = useCallback(async (): Promise<void> => {
    if (!connection) return;
    try {
      const s = await readTokenState(connection, DEFAULTS.token, connection.address, DEFAULTS.pool);
      setTokenBalance(s.balance);
      setAllowance(s.allowance);
    } catch {
      setTokenBalance(null);
      setAllowance(null);
    }
  }, [connection]);

  useEffect(() => {
    void refreshTokenState();
  }, [refreshTokenState]);

  const amtErr = amountError(amount, tokenBalance, "Amount exceeds your kKRW balance.");
  // Guard on a KNOWN balance: until the token state loads the over-spend check
  // can't fire, so don't let the user start a proof that would revert.
  const formValid = tokenBalance !== null && !amtErr;

  // The raw-wei amount the flow receives; 0n while the input is invalid.
  const amountWei = useMemo(() => {
    const p = parseKkrw(amount);
    return p.ok ? p.wei : 0n;
  }, [amount]);
  const review = formatKkrw(amountWei);

  // Stale-resolve guard: the stored triple only counts while the field still
  // names the same canonical name — editing after a resolve can never mint to
  // the previously resolved person.
  const typedName = normalizeName(recipientInput);
  const activeResolve =
    resolved !== null && typedName !== null && resolved.name === typedName ? resolved : null;

  // Whether the confirm step will need an approve tx (allowance covers V => skip).
  const willApprove = allowance === null || amountWei <= 0n || allowance < amountWei;

  function confirm(): void {
    if (!ops) return;
    // The spending key comes from the wallet's lock INSIDE the flow — this
    // component never holds it; the facade carries the session pubkey so the
    // flow can refuse a key that isn't this session's.
    void action.submit(
      (onStage) =>
        ops.deposit({ amount: amountWei.toString(), recipient: activeResolve?.recipient }, onStage),
      refreshAfterAction,
    );
  }

  // Continue resolves a typed name BEFORE the confirm sheet opens — the sheet
  // must show the name it will mint to, so the record has to exist first. An
  // empty field goes straight to review: the deposit is the wallet's own.
  async function handleContinue(): Promise<void> {
    if (recipientInput.trim() === "") {
      setResolved(null);
      action.review();
      return;
    }
    setNameError(null);
    try {
      const out = await resolveConsumerRecipient(indexerUrl, recipientInput);
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
        title="Deposit"
        headline={activeResolve ? `Deposited to ${activeResolve.name}` : "Deposit completed"}
        amount={review}
        explorerUrl={action.outcome.explorerUrl}
      />
    );
  }

  // --- running ---------------------------------------------------------------
  if (action.phase === "running") {
    return (
      <RunningPanel
        title="Deposit"
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
        title="Deposit"
        amount={review}
        hint={<FlowHint direction="shield" />}
        note={
          willApprove ? (
            <p className="text-sm text-muted">
              This needs two transactions: first approve the pool to pull this amount, then
              shield it.
            </p>
          ) : undefined
        }
        download={action.download}
        onCancel={action.cancel}
        onConfirm={confirm}
      >
        <dt className="text-muted text-sm">To</dt>
        <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
          {activeResolve ? (
            <>
              {/* both halves of the binding, Send-confirm parity: a deposit to
                  a name is as irreversible as a send to it, so it confirms the
                  key the directory vouches for, not just the keystrokes. */}
              <span className="font-semibold">{activeResolve.name}</span>
              <br />
              <span className="font-mono text-muted text-[0.8rem]">
                {shortenPubkey(activeResolve.recipient.owner)}
              </span>
            </>
          ) : (
            "Your private balance"
          )}
        </dd>
        <dt className="text-muted text-sm">Network</dt>
        <dd className="text-right text-[0.9rem] [overflow-wrap:anywhere]">
          {DEFAULTS.chainName} · chain {DEFAULTS.chainId}
        </dd>
      </ConfirmPanel>
    );
  }

  // --- form ------------------------------------------------------------------
  if (action.download.active) {
    return <DownloadingPanel title="Deposit" download={action.download} />;
  }

  // Two states by what the user actually has: no kKRW => the mint guide IS the
  // screen (nothing to deposit yet); some kKRW => the depositable amount leads
  // and the faucet collapses to a side offer. Allowance is deliberately not
  // shown — the flow approves exactly V when needed; it's plumbing, not a
  // decision the user makes here.
  const noTokens = tokenBalance !== null && tokenBalance === 0n;

  return (
    <div className="flex flex-col gap-4.5 px-4.5 pt-4.5 pb-6.5">
      <ScreenHeader title="Deposit" />
      <div className="flex flex-col gap-4">
        <p className="text-sm text-muted">
          kKRW in, <strong>private kKRW</strong> out. Then send and withdraw with nothing
          revealed.
        </p>

        <div
          className="flex flex-col gap-0.5 bg-surface border border-border rounded-xl p-3.5"
          aria-live="polite"
        >
          <span className="text-[0.8rem] text-muted">You can deposit</span>
          <span className="text-2xl font-bold tabular-nums">
            {tokenBalance === null ? "—" : formatKkrw(tokenBalance)}{" "}
            <span className="text-[0.9rem] font-semibold text-muted ml-1">kKRW</span>
          </span>
        </div>

        {noTokens ? (
          DEFAULTS.testnet ? (
            <div className="flex flex-col gap-2 bg-surface border border-border-strong rounded-xl p-3.5">
              <div className="flex items-center gap-2">
                <TestnetTag />
                <span className="text-[0.9rem] font-semibold">First, get test kKRW</span>
              </div>
              {/* No amount here: the mint dialog's amount is freeform, and the
                  prefill is a starting point, not an offer. */}
              <p className="text-sm text-muted">
                Mint free test kKRW (you pay only gas), then deposit it here.
              </p>
              <Button variant="primary" block disabled={!connection} onClick={() => setMintOpen(true)}>
                Get Test kKRW
              </Button>
            </div>
          ) : (
            // Non-testnet: no mint to offer — just say what's missing.
            <div className="flex flex-col gap-2 bg-surface border border-border-strong rounded-xl p-3.5">
              <p className="text-sm text-muted">
                Depositing needs kKRW in this account. Fund it first, then come back.
              </p>
            </div>
          )
        ) : (
          <>
            <Field
              label="Amount (kKRW)"
              right={
                DEFAULTS.testnet ? (
                  <LinkButton small subtle onClick={() => setMintOpen(true)}>
                    Need more test kKRW?
                  </LinkButton>
                ) : undefined
              }
              error={amount.trim() ? amtErr : null}
            >
              <AmountInput value={amount} onValueChange={setAmount} />
            </Field>
            <Field
              label="Deposit to (payment name)"
              hint={DEPOSIT_RECIPIENT_HINT}
              error={recipientInput.trim() ? nameError : null}
            >
              <TextInput
                placeholder="Leave empty to deposit to yourself"
                value={recipientInput}
                onChange={(e) => {
                  setRecipientInput(e.target.value);
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
          </>
        )}

        {action.error && <ErrorBanner message={action.error} />}

        {!noTokens && (
          <Button variant="primary" block disabled={!formValid} onClick={() => void handleContinue()}>
            Continue
          </Button>
        )}
      </div>

      {DEFAULTS.testnet && mintOpen && (
        <MintModal
          connection={connection}
          onClose={() => setMintOpen(false)}
          onMinted={refreshTokenState}
        />
      )}
    </div>
  );
}
