// The deposit dialog's PURE decisions and its two account reads. The console's
// deposit stopped being an inline panel (it competed with the worksheet for the
// operator's attention and had nowhere to put the mint affordance): it is now a
// modal, and everything it decides — what the buttons may do, what it says when
// the account cannot pay gas, what the amount field starts at — lives here so it
// gates headlessly (test/depositModal.test.ts). The view only renders it.
//
// The mint follows the WALLET's grammar (treasury-web MintModal): the deployed kKRW
// is MockERC20 whose `mint` is permissionless, so the operator self-mints and pays
// their own gas — no faucet service, no operator key. A zero-gas account is
// pre-checked and told plainly (with the faucet link) instead of failing inside
// the wallet with an opaque provider object. The mint is its OWN popup over the
// deposit dialog — an empty amount the operator fills, a Mint press, a completion
// view with the transaction — not a one-tap fixed ration off the label row: a
// stray click must not send a transaction.

import type { Connection, SubmitResult } from "@bongtu/client/connection";
import { mintTestToken, readGasBalance, readTokenState } from "@bongtu/client/connection";
import type { DepositStage } from "@bongtu/client/deposit";
import { formatKkrw } from "@bongtu/client/money";
import { GAS_TOKEN_PHRASE, NATIVE_CURRENCY } from "@bongtu/core/network";
import { parseDepositAmount } from "./errors.js";

/** What the dialog says when the connected account cannot pay for either tx. The
 *  faucet link is rendered next to it (config gasFaucet), so the next step is one
 *  click away rather than a search. */
export const NO_GAS_MESSAGE =
  `This account has no ${GAS_TOKEN_PHRASE} to pay gas. Get a little ${NATIVE_CURRENCY.symbol} first, then continue.`;

/** The gas verdict. `unknown` is a read that has not landed (or failed) — it never
 *  blocks: guessing "none" would lock a funded operator out of their own deposit. */
export type GasState = "unknown" | "none" | "funded";

/** The mint popup over the deposit dialog. `null` on the deposit state is
 *  "closed" — the same no-open-flag rule the deposit itself follows. */
export interface MintState {
  /** the typed kKRW amount to mint — starts EMPTY (a prefilled number reads as a
   *  fixed ration rather than a field to fill in; wallet U-W9 lesson). */
  amount: string;
  /** true while the mint tx is in flight — the popup cannot be closed under it. */
  pending: boolean;
  /** the confirmed mint — flips the popup to its completion view, so the Mint
   *  button cannot be pressed twice for one visit. */
  tx: SubmitResult | null;
  error: string | null;
}

/** Everything the open dialog holds. `null` in the console's state is "closed" —
 *  there is no separate open flag, so a stale amount cannot outlive a close. */
export interface DepositModalState {
  /** the typed kKRW amount (grouped as typed — groupAmountInput at the edge). */
  amount: string;
  /** the running deposit's stage, null when no deposit is in flight. */
  stage: DepositStage | null;
  /** the mint popup, null when closed. */
  mint: MintState | null;
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
    mint: null,
    tokenBalance: null,
    gas: "unknown",
    error: null,
  };
}

export function openMint(): MintState {
  return { amount: "", pending: false, tx: null, error: null };
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
  // An OPEN mint popup does not make the deposit busy — only its in-flight tx
  // does: the popup overlays the dialog anyway, and a finished mint must leave
  // the deposit's own buttons live the moment the popup closes.
  const busy = state.stage !== null || state.mint?.pending === true;
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
    mintLabel: "No kKRW?",
  };
}

/** What the mint POPUP may do right now. Same field grammar as the deposit's own
 *  amount (parseDepositAmount): the two fields sit one popup apart and must not
 *  word the same mistake differently. */
export interface MintView {
  amountWei: bigint | null;
  /** null while the field is untouched — an empty popup does not open shouting. */
  amountError: string | null;
  canMint: boolean;
  /** the tx is in flight: no second Mint press, no close out from under it. */
  busy: boolean;
}

export function mintView(mint: MintState): MintView {
  const typed = mint.amount.trim() !== "";
  const parsed = parseDepositAmount(mint.amount);
  const amountWei = parsed.ok && parsed.wei > 0n ? parsed.wei : null;
  const amountError = !typed
    ? null
    : !parsed.ok
      ? parsed.error
      : parsed.wei <= 0n
        ? "Enter an amount above zero."
        : null;
  return {
    amountWei,
    amountError,
    canMint: !mint.pending && mint.tx === null && amountWei !== null,
    busy: mint.pending,
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

/** Mint the typed amount to the connected account itself — the permissionless
 *  MockERC20 path. To ANYONE else would be a transfer the operator did not ask for. */
export async function mintTestKkrw(
  connection: Connection,
  token: string,
  amountWei: bigint,
  deps: DepositModalDeps,
): Promise<SubmitResult> {
  return deps.mintTestToken(connection, token, connection.address, amountWei);
}
