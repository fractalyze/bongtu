// txbuild/size.ts — the pre-send Transaction v1 size assertion (SOLR §3.1.3
// gate 4, client side). TWO wire models live here on purpose:
//
//   v0TxSize   a byte-faithful port of the harness gate-4 calculator
//              (chains/solana/harness/src/lib.rs v0_tx_size) — the COMMITTED
//              oracle the per-op worst-case table was computed with (a v0
//              message wrapping the op plus a ComputeBudget instruction
//              pair); test/txsize.test.ts pins this mirror to those numbers
//              so the two calculators cannot drift.
//   v1TxSize   the SIMD-0385 v1 MESSAGE FORMAT the client actually sends —
//              the only format whose 4,096 B budget fits these payloads:
//              version(1) + header(3) + configMask u32(4) + lifetime
//              token(32) + numInstructions u8 + numStaticAccounts u8 + 32 B
//              per static account + a 4 B per-instruction header (program
//              index u8, account count u8, data length u16) + raw payloads —
//              no shortvecs inside the message, no ComputeBudget
//              instructions (the budget rides the header config: u32 CU
//              limit + u32 loaded-accounts limit, + u64 priority fee when
//              set — budget.ts owns the WHY).
//
// For every op shape here the v1 wire lands BELOW the committed v0-model
// worst case (the dropped ComputeBudget pair and its program key outweigh the
// new header fields); the pre-send assertion compares the BUILT transaction
// against the v1 worst case, and the committed gate-4 table stays anchored
// through the pinned v0-model equality.

import { SOLANA_OPS, wireLenOf } from "@bongtu/core/solanaOps";
import {
  DEPOSIT_PRIV_ACCOUNTS,
  SPEND_BASE_ACCOUNTS,
  WITHDRAW_PRIV_BASE_ACCOUNTS,
} from "./accounts.js";
import type { ConsumerOpName } from "./data.js";

/** The Transaction v1 wire ceiling (SIMD-0296). */
export const TX_V1_LIMIT = 4096;

/** shortvec (compact-u16) encoded length. */
const shortvecLen = (n: number): number => {
  if (n >= 16384) throw new Error(`shortvec: ${n} out of range`);
  return n < 128 ? 1 : 2;
};

/** ComputeBudget instruction data lengths in the v0-era model
 *  (SetComputeUnitLimit u8+u32, SetComputeUnitPrice u8+u64). */
const CB_LIMIT_DATA = 5;
const CB_PRICE_DATA = 9;

/**
 * The harness gate-4 model: exact serialized size of the v0-FORMAT
 * transaction wrapping one op instruction plus the two ComputeBudget
 * instructions, one fee-payer signature, no address lookup tables. Account
 * keys = the op's metas + the ComputeBudget program id.
 */
export function v0TxSize(opAccounts: number, opDataLen: number): number {
  const keys = opAccounts + 1;
  const cbLimitIx = 1 + shortvecLen(0) + shortvecLen(CB_LIMIT_DATA) + CB_LIMIT_DATA;
  const cbPriceIx = 1 + shortvecLen(0) + shortvecLen(CB_PRICE_DATA) + CB_PRICE_DATA;
  const opIx = 1 + shortvecLen(opAccounts) + opAccounts + shortvecLen(opDataLen) + opDataLen;
  const legacy =
    (shortvecLen(1) + 64) +
    3 +
    (shortvecLen(keys) + 32 * keys) +
    32 +
    shortvecLen(3) +
    cbLimitIx +
    cbPriceIx +
    opIx;
  return legacy + 1 + shortvecLen(0); // version byte + empty ALT vec
}

/**
 * The SIMD-0385 v1 format the client sends (module doc): one fee-payer
 * signature over version + header + configMask + lifetime + counts + static
 * accounts (the op's metas only — no ComputeBudget program) + one 4 B
 * instruction header + the raw payload + the header-config values (CU limit
 * u32 + loaded-accounts u32, + priority fee u64 when prioritized).
 */
export function v1TxSize(opAccounts: number, opDataLen: number, prioritized = false): number {
  const fixed = (shortvecLen(1) + 64) + 1 + 3 + 4 + 32 + 1 + 1;
  const configValues = 4 + 4 + (prioritized ? 8 : 0);
  return fixed + 32 * opAccounts + configValues + 4 + opAccounts + opDataLen;
}

/** Worst-case account-meta count per op: the fixed prefix from the program's
 *  account layout + the maximum nullifier-PDA run (the layout table's spend
 *  arity; a deposit has none). */
export function worstCaseAccounts(op: ConsumerOpName): number {
  const arity = SOLANA_OPS[op].enabled?.arity ?? 0;
  if (op === "depositPriv") return DEPOSIT_PRIV_ACCOUNTS;
  if (op === "withdrawPriv") return WITHDRAW_PRIV_BASE_ACCOUNTS + arity;
  return SPEND_BASE_ACCOUNTS + arity;
}

/** The op's worst-case v1 transaction size, priced with the priority fee set
 *  (the larger of the two config shapes) — the pre-send ceiling. */
export function worstCaseTxSize(op: ConsumerOpName): number {
  return v1TxSize(worstCaseAccounts(op), wireLenOf(SOLANA_OPS[op]), true);
}

/**
 * The pre-send assertion: the BUILT transaction must fit Transaction v1 and
 * must not exceed its op's worst-case shape (more metas or a different data
 * length than the worst case means the builder drifted from the program's
 * account layout — fail before the wire, not on it).
 */
export function assertTransactionSize(
  op: ConsumerOpName,
  built: { accountCount: number; dataLen: number; serializedLen: number },
): void {
  const layout = SOLANA_OPS[op];
  if (built.dataLen !== wireLenOf(layout)) {
    throw new Error(`${op}: instruction data is ${built.dataLen} B, the wire is fixed at ${wireLenOf(layout)} B`);
  }
  if (built.accountCount > worstCaseAccounts(op)) {
    throw new Error(`${op}: ${built.accountCount} account metas exceed the worst-case ${worstCaseAccounts(op)}`);
  }
  if (built.serializedLen > TX_V1_LIMIT) {
    throw new Error(`${op}: serialized transaction is ${built.serializedLen} B, over the ${TX_V1_LIMIT} B v1 limit`);
  }
  if (built.serializedLen > worstCaseTxSize(op)) {
    throw new Error(
      `${op}: serialized transaction is ${built.serializedLen} B, over the op's worst case ` +
        `${worstCaseTxSize(op)} B — the wire shape drifted`,
    );
  }
}
