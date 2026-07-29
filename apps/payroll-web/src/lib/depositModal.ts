// The deposit dialog's PURE decisions and its two account reads. The console's
// deposit stopped being an inline panel (it competed with the worksheet for the
// operator's attention and had nowhere to put the mint affordance): it is now a
// modal, and everything it decides — what the buttons may do, what it says when
// the account cannot pay gas, what the amount field starts at — lives here so it
// gates headlessly (test/depositModal.test.ts). The view only renders it.
//
// The mint follows the WALLET's grammar (wallet-web MintModal): the deployed kKRW
// is MockERC20 whose `mint` is permissionless, so the operator self-mints and pays
// their own GIWA gas — no faucet service, no operator key. A zero-gas account is
// pre-checked and told plainly (with the faucet link) instead of failing inside
// the wallet with an opaque provider object.

import type { Connection } from "@bongtu/client/connection";
import { mintTestToken, readGasBalance, readTokenState } from "@bongtu/client/connection";
import type { DepositStage } from "@bongtu/client/depositFlow";
import { formatKkrw } from "@bongtu/client/money";
import { parseDepositAmount } from "./errors.js";

/**
 * The FIXED ration one [Mint] tap adds: 1,000,000 kKRW at the token's 18 decimals.
 * Fixed, not a second amount field, because this dialog already has one and the
 * mint is a means to it, not a decision of its own — and one tap has to cover a
 * whole test pay run (255 random recipients) without sending the operator back for
 * more. Payroll owns the constant rather than importing the wallet's FAUCET_AMOUNT:
 * the two apps mint for different reasons and may diverge.
 */
export const MINT_AMOUNT = 1_000_000n * 10n ** 18n;

/** What the dialog says when the connected account cannot pay for either tx. The
 *  faucet link is rendered next to it (config gasFaucet), so the next step is one
 *  click away rather than a search. */
export const NO_GAS_MESSAGE =
  "This account has no GIWA Sepolia ETH to pay gas. Get a little ETH first, then continue.";

/** The gas verdict. `unknown` is a read that has not landed (or failed) — it never
 *  blocks: guessing "none" would lock a funded operator out of their own deposit. */
export type GasState = "unknown" | "none" | "funded";

/** Everything the open dialog holds. `null` in the console's state is "closed" —
 *  there is no separate open flag, so a stale amount cannot outlive a close. */
export interface DepositModalState {
  /** the typed kKRW amount (grouped as typed — groupAmountInput at the edge). */
  amount: string;
  /** the running deposit's stage, null when no deposit is in flight. */
  stage: DepositStage | null;
  /** true while the self-mint tx is in flight. */
  minting: boolean;
  /** the account's PUBLIC kKRW (ERC-20 balanceOf) — not the shielded pool balance.
   *  null until the first read lands, or after one fails: never a false zero. */
  tokenBalance: bigint | null;
  gas: GasState;
  error: string | null;
}

/** The stage line the Deposit button shows while a deposit runs — the same
 *  narration the pay run's rail uses, in one place. */
export const DEPOSIT_STAGE_LABEL: Record<DepositStage, string> = {
  unlock: "Waiting for wallet signature",
  approve: "Approving kKRW",
  prove: "Generating the zero-knowledge proof (GPU server)",
  submit: "Waiting for the wallet to send",
};

/**
 * The amount the field starts at: the sheet's shortfall when there is one (the
 * operator opened this dialog to cover it), otherwise empty.
 *
 * The shortfall is rounded UP to the 6-decimal display grid the money layer
 * accepts. formatKkrw TRUNCATES beyond 6 digits, so the raw shortfall would
 * prefill an amount fractionally SMALLER than the gap — depositing it would leave
 * the sheet still insufficient, by dust, with no visible reason.
 */
export function prefillAmount(shortfallWei: bigint | null): string {
  if (shortfallWei === null || shortfallWei <= 0n) return "";
  const grid = 10n ** 12n; // 1e18 wei per kKRW / 1e6 display digits
  return formatKkrw(((shortfallWei + grid - 1n) / grid) * grid);
}

/** A freshly opened dialog: prefilled amount, nothing read yet, nothing running. */
export function openDepositModal(shortfallWei: bigint | null): DepositModalState {
  return {
    amount: prefillAmount(shortfallWei),
    stage: null,
    minting: false,
    tokenBalance: null,
    gas: "unknown",
    error: null,
  };
}

/** What the dialog may do right now, and what it says about it. */
export interface DepositModalView {
  /** the parsed amount, or null when the field is empty/unparseable. */
  amountWei: bigint | null;
  /** the field's message — null while the field is untouched, so an empty form
   *  does not open shouting. */
  amountError: string | null;
  canDeposit: boolean;
  canMint: boolean;
  /** a deposit or a mint is in flight: the dialog cannot be closed out from under
   *  the wallet popups it is driving. */
  busy: boolean;
  /** the in-dialog plain notice (zero gas), or null. */
  notice: string | null;
  depositLabel: string;
  mintLabel: string;
}

export function depositModalView(state: DepositModalState): DepositModalView {
  const typed = state.amount.trim() !== "";
  const parsed = parseDepositAmount(state.amount);
  const amountWei = parsed.ok && parsed.wei > 0n ? parsed.wei : null;
  const amountError = !typed
    ? null
    : !parsed.ok
      ? parsed.error
      : parsed.wei <= 0n
        ? "Enter an amount above zero."
        : null;
  const busy = state.stage !== null || state.minting;
  // `unknown` gas stays actionable — only a READ ZERO disables. A wallet that
  // fails anyway still surfaces its own message through payrollErrorMessage.
  const gasless = state.gas === "none";
  return {
    amountWei,
    amountError,
    canDeposit: !busy && !gasless && amountWei !== null,
    canMint: !busy && !gasless,
    busy,
    notice: gasless ? NO_GAS_MESSAGE : null,
    depositLabel: state.stage !== null ? DEPOSIT_STAGE_LABEL[state.stage] : "Deposit",
    mintLabel: state.minting ? "Minting…" : `Mint ${formatKkrw(MINT_AMOUNT)} test kKRW`,
  };
}

// --- the dialog's chain reads -------------------------------------------------------

/** The chain edges, injectable so the decisions above and the mint's arguments gate
 *  with no wallet and no RPC (the same deps seam runDeposit uses). */
export interface DepositModalDeps {
  readGasBalance: typeof readGasBalance;
  readTokenState: typeof readTokenState;
  mintTestToken: typeof mintTestToken;
}

export const DEPOSIT_MODAL_DEPS: DepositModalDeps = { readGasBalance, readTokenState, mintTestToken };

/** The gas pre-check both actions run before touching the wallet. Best-effort: a
 *  read that throws is `unknown`, which lets the action proceed. */
export async function readGas(connection: Connection, deps: DepositModalDeps): Promise<GasState> {
  try {
    return (await deps.readGasBalance(connection)) === 0n ? "none" : "funded";
  } catch {
    return "unknown";
  }
}

/** The dialog's account readout: the account's PUBLIC kKRW and its gas verdict.
 *  Independent and best-effort — a token read that fails must not also erase the
 *  gas verdict (they are separate RPC calls and fail separately). */
export async function readDepositAccount(
  connection: Connection,
  token: string,
  pool: string,
  deps: DepositModalDeps,
): Promise<{ tokenBalance: bigint | null; gas: GasState }> {
  const [balance, gas] = await Promise.all([
    deps
      .readTokenState(connection, token, connection.address, pool)
      .then((s) => s.balance)
      .catch(() => null),
    readGas(connection, deps),
  ]);
  return { tokenBalance: balance, gas };
}

/** Mint the fixed ration to the connected account itself — the permissionless
 *  MockERC20 path. To ANYONE else would be a transfer the operator did not ask for. */
export async function mintTestKkrw(
  connection: Connection,
  token: string,
  deps: DepositModalDeps,
): Promise<void> {
  await deps.mintTestToken(connection, token, connection.address, MINT_AMOUNT);
}
