// TESTNET-ONLY mint dialog (render behind DEFAULTS.testnet): self-mint test kKRW from
// the connected wallet. The deployed kKRW is MockERC20 whose `mint` is permissionless
// (no backend faucet service or operator key) — the user pays their own GIWA gas, so a
// zero-gas account is pre-checked and told plainly (with the GIWA faucet link) instead
// of failing inside the wallet with an opaque object. The amount is prefilled with the
// standard faucet amount and freely editable; on a confirmed mint the caller refreshes
// its token state and the dialog switches to its completion view (MintSuccess), so the
// Mint button cannot be pressed twice for one visit.

import { useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../../config.js";
import { FAUCET_AMOUNT } from "../../lib/faucet.js";
import {
  mintTestToken,
  readGasBalance,
  walletErrorMessage,
  type Connection,
} from "../../lib/metamask.js";
import { groupAmountInput, parseKkrw } from "../../lib/money.js";
import { ExplorerLink } from "./ExplorerLink.js";
import { Modal } from "./Modal.js";
import { AmountInput, Button, ErrorBanner, Field, TestnetTag } from "./controls.js";

/** The dialog after a confirmed mint: what happened, where to look, and the way out —
 *  no second Mint button. Its own component so the completed state renders (and
 *  gates) without a live transaction. */
export function MintSuccess({
  explorerUrl,
  onClose,
}: {
  explorerUrl: string;
  onClose: () => void;
}): ReactNode {
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm">Test kKRW added to your account.</p>
      <ExplorerLink href={explorerUrl} />
      <Button variant="primary" block onClick={onClose}>
        Close
      </Button>
    </div>
  );
}

export function MintModal({
  connection,
  onClose,
  onMinted,
}: {
  connection: Connection | null;
  onClose: () => void;
  /** Called after a confirmed mint so the opener re-reads balance/allowance. */
  onMinted: () => Promise<void> | void;
}): ReactNode {
  // Editable prefill: whole-kKRW form ("1,000,000"), not the display formatter's
  // six-fraction-digit output.
  const [amount, setAmount] = useState(groupAmountInput((FAUCET_AMOUNT / 10n ** 18n).toString()));
  const [pending, setPending] = useState(false);
  const [txUrl, setTxUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const parsed = parseKkrw(amount);
  const amtErr = !parsed.ok
    ? parsed.error
    : parsed.wei <= 0n
      ? "Amount must be greater than zero."
      : null;

  async function mint(): Promise<void> {
    if (!connection || !parsed.ok) return;
    setPending(true);
    setError(null);
    setTxUrl(null);
    try {
      // The mint is permissionless but still a tx: an account with ZERO gas ETH
      // fails inside the wallet with an opaque object — say it plainly instead.
      if ((await readGasBalance(connection)) === 0n) {
        throw new Error(
          "This account has no GIWA Sepolia ETH to pay gas — get a little ETH onto GIWA Sepolia first, then mint.",
        );
      }
      const res = await mintTestToken(connection, DEFAULTS.token, connection.address, parsed.wei);
      setTxUrl(res.explorerUrl);
      await onMinted();
    } catch (e) {
      setError(walletErrorMessage(e));
    } finally {
      setPending(false);
    }
  }

  return (
    <Modal
      title={
        <span className="inline-flex items-center gap-2">
          Get Test kKRW <TestnetTag />
        </span>
      }
      ariaLabel="Get Test kKRW"
      onClose={onClose}
    >
      {txUrl ? (
        <MintSuccess explorerUrl={txUrl} onClose={onClose} />
      ) : (
        <div className="flex flex-col gap-3">
          <Field label="Amount (kKRW)" error={amount.trim() ? amtErr : null}>
            <AmountInput value={amount} onValueChange={setAmount} disabled={pending} />
          </Field>
          {error && <ErrorBanner message={error} />}
          <Button
            variant="primary"
            block
            disabled={pending || !connection || !!amtErr}
            onClick={() => void mint()}
          >
            {pending ? "Minting…" : "Mint"}
          </Button>
        </div>
      )}
    </Modal>
  );
}
