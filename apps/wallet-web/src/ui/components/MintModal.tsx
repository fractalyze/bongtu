// TESTNET-ONLY mint dialog (render behind DEFAULTS.testnet): self-mint test kKRW from
// the connected wallet. The deployed kKRW is MockERC20 whose `mint` is permissionless
// (no backend faucet service or operator key) — the user pays their own gas, so a
// zero-gas account is pre-checked and told plainly (with the faucet link) instead
// of failing inside the wallet with an opaque object. The amount starts EMPTY (U-W9: a
// prefilled million read as a fixed faucet ration rather than a field to fill in); on a
// confirmed mint the caller refreshes its token state and the dialog switches to its
// completion view (MintSuccess), so the Mint button cannot be pressed twice for one
// visit.

import { useState } from "react";
import type { ReactNode } from "react";
import { DEFAULTS } from "../../config.js";
import { GAS_TOKEN_PHRASE, NATIVE_CURRENCY } from "@bongtu/core/network";
import {
  mintTestToken,
  readGasBalance,
  walletErrorMessage,
  type Connection,
} from "@bongtu/client-evm/connection";
import { parseKkrw } from "@bongtu/client/money";
import { shortenPubkey } from "../format.js";
import { ExplorerLink } from "./ExplorerLink.js";
import { Modal } from "./Modal.js";
import { AmountInput, Button, ErrorBanner, Field, TestnetTag } from "./controls.js";

/** The dialog after a confirmed mint: what happened, WHICH transaction it was, where
 *  to look, and the way out — no second Mint button. Its own component so the
 *  completed state renders (and gates) without a live transaction. */
export function MintSuccess({
  txHash,
  explorerUrl,
  onClose,
}: {
  txHash: string;
  explorerUrl: string;
  onClose: () => void;
}): ReactNode {
  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm">Test kKRW added to your account.</p>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        {/* shortenPubkey is the app's one middle-shortener (addresses, keys, and
            here a tx hash) — the full hash is one tap away behind the link. */}
        <span className="font-mono text-xs text-muted">{shortenPubkey(txHash)}</span>
        <ExplorerLink href={explorerUrl} />
      </div>
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
  // Starts empty: the user says how much test kKRW they want.
  const [amount, setAmount] = useState("");
  const [pending, setPending] = useState(false);
  const [tx, setTx] = useState<{ hash: string; explorerUrl: string } | null>(null);
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
    setTx(null);
    try {
      // The mint is permissionless but still a tx: an account with ZERO gas ETH
      // fails inside the wallet with an opaque object — say it plainly instead.
      if ((await readGasBalance(connection)) === 0n) {
        // The phrase carries GAS_TOKEN_PHRASE so ErrorBanner recognises this as a
        // gas-shortfall message and offers the faucet link.
        throw new Error(
          `This account has no ${GAS_TOKEN_PHRASE} to pay gas. ` +
            `Get a little ${NATIVE_CURRENCY.symbol} onto ${DEFAULTS.chainName} first, then mint.`,
        );
      }
      const res = await mintTestToken(connection, DEFAULTS.token, connection.address, parsed.wei);
      setTx({ hash: res.txHash, explorerUrl: res.explorerUrl });
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
      {tx ? (
        <MintSuccess txHash={tx.hash} explorerUrl={tx.explorerUrl} onClose={onClose} />
      ) : (
        <div className="flex flex-col gap-3">
          <p className="text-sm text-muted">
            Mints test kKRW to your connected account — you only pay gas.
          </p>
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
