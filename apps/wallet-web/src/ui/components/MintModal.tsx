// TESTNET-ONLY mint dialog (render behind DEFAULTS.testnet): self-mint test kKRW from
// the connected wallet. The deployed kKRW is MockERC20 whose `mint` is permissionless
// (no backend faucet service or operator key) — the user pays their own GIWA gas, so a
// zero-gas account is pre-checked and told plainly (with the GIWA faucet link) instead
// of failing inside MetaMask with an opaque object. Prefilled with the standard faucet
// amount but editable; on a confirmed mint the caller refreshes its token state.

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
import { Modal } from "./Modal.js";
import { AmountInput, Button, ErrorBanner, Field, TestnetTag } from "./controls.js";

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
      // fails inside MetaMask with an opaque object — say it plainly instead.
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
      <div className="flex flex-col gap-3">
        <p className="text-sm text-muted">
          Mint free test kKRW to this account (you pay only gas), then deposit it here.
        </p>
        <Field label="Amount (kKRW)" error={amount.trim() ? amtErr : null}>
          <AmountInput value={amount} onValueChange={setAmount} disabled={pending} />
        </Field>
        {error && <ErrorBanner message={error} />}
        {txUrl && (
          <a
            className="text-primary no-underline text-[0.9rem] font-semibold"
            href={txUrl}
            target="_blank"
            rel="noreferrer"
          >
            Minted — view on explorer
          </a>
        )}
        <Button
          variant="primary"
          block
          disabled={pending || !connection || !!amtErr}
          onClick={() => void mint()}
        >
          {pending ? "Minting…" : "Mint"}
        </Button>
      </div>
    </Modal>
  );
}
