// Transaction-size regression, client side. Two pinned mirrors (size.ts):
// v0TxSize must EQUAL the committed gate-4 worst cases (chains/solana/README /
// gate4_tx_size.rs — the harness model those numbers were computed with,
// v0 envelope + ComputeBudget instruction pair), and v1TxSize — the SIMD-0385
// format the client actually sends, budget in the header config instead of
// instructions — must land at the algebraically derived offset below it. A
// divergence in either says which wire model drifted from the consensus
// format.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  TX_V1_LIMIT,
  assertTransactionSize,
  v0TxSize,
  v1TxSize,
  worstCaseAccounts,
  worstCaseTxSize,
  type ConsumerOpName,
} from "@bongtu/client-solana/txbuild";
import { SOLANA_OPS, wireLenOf } from "@bongtu/core/solanaOps";

/** The gate-4 committed worst-case transaction sizes (chains/solana/README
 *  "Tx size" table — harness v0_tx_size over the same shapes). */
const GATE4_WORST: Record<ConsumerOpName, { accounts: number; txSize: number }> = {
  depositPriv: { accounts: 10, txSize: 3435 },
  transferPriv: { accounts: 10, txSize: 3499 },
  transfer10x2Priv: { accounts: 18, txSize: 4019 },
  withdrawPriv: { accounts: 14, txSize: 2416 },
};

/** v1-versus-v0-model delta for these shapes (<128 accounts, >127 B data):
 *  the v1 wire DROPS the ComputeBudget pair (20 B of instructions + the 32 B
 *  program key + 2 B of the v0 per-ix shortvec overhead vs the flat 4 B v1
 *  headers) and ADDS configMask(4) + config values (4+4, +8 prioritized) +
 *  the counts/version framing — net -41 B unprioritized, -33 B prioritized. */
const V1_DELTA_PRIORITIZED = -33;

for (const [op, want] of Object.entries(GATE4_WORST) as [ConsumerOpName, { accounts: number; txSize: number }][]) {
  test(`${op}: worst-case shapes pin to gate 4 (v0 model) and its v1 offset`, () => {
    assert.equal(worstCaseAccounts(op), want.accounts, "worst-case account count");
    const dataLen = wireLenOf(SOLANA_OPS[op]);
    assert.equal(v0TxSize(want.accounts, dataLen), want.txSize, "harness gate-4 model mirror");
    assert.equal(v1TxSize(want.accounts, dataLen, true), want.txSize + V1_DELTA_PRIORITIZED, "v1 wire offset");
    assert.equal(v1TxSize(want.accounts, dataLen, false), want.txSize + V1_DELTA_PRIORITIZED - 8);
    assert.equal(worstCaseTxSize(op), want.txSize + V1_DELTA_PRIORITIZED);
    assert.ok(worstCaseTxSize(op) <= TX_V1_LIMIT);
  });
}

test("transfer10x2Priv stays the tightest wire on the rail (the §3.1.2 margin)", () => {
  const headroom = TX_V1_LIMIT - worstCaseTxSize("transfer10x2Priv");
  assert.equal(headroom, 77 - V1_DELTA_PRIORITIZED, "the gate-4 77 B margin minus the v1 offset");
});

test("assertTransactionSize: accepts the worst case, rejects every drift class", () => {
  const op: ConsumerOpName = "transferPriv";
  const dataLen = wireLenOf(SOLANA_OPS[op]);
  const fits = { accountCount: worstCaseAccounts(op), dataLen, serializedLen: worstCaseTxSize(op) };
  assertTransactionSize(op, fits);
  assert.throws(() => assertTransactionSize(op, { ...fits, dataLen: dataLen + 1 }), /wire is fixed/);
  assert.throws(
    () => assertTransactionSize(op, { ...fits, accountCount: worstCaseAccounts(op) + 1 }),
    /exceed the worst-case/,
  );
  assert.throws(
    () => assertTransactionSize(op, { ...fits, serializedLen: worstCaseTxSize(op) + 1 }),
    /worst case/,
  );
  assert.throws(() => assertTransactionSize(op, { ...fits, serializedLen: TX_V1_LIMIT + 1 }), /v1 limit/);
});

test("v0TxSize matches the consensus-format arithmetic on a hand-checked point", () => {
  // 1 account, 0-byte data: sigs (1+64) + header 3 + keys (1 + 32*2) +
  // blockhash 32 + ix-count shortvec 1 + cb ixs (8 + 12) + op ix (1+1+1+1+0)
  // + version 1 + empty ALT vec 1 = 192.
  assert.equal(v0TxSize(1, 0), 192);
});

test("v1TxSize matches the SIMD-0385 layout on a hand-checked point", () => {
  // 1 account, 0-byte data, unprioritized: sigs (1+64) + version 1 + header 3
  // + configMask 4 + lifetime 32 + numIx 1 + numAccounts 1 + keys 32 + config
  // values (4+4) + ix header 4 + payload (1+0) = 152; +8 prioritized.
  assert.equal(v1TxSize(1, 0), 152);
  assert.equal(v1TxSize(1, 0, true), 160);
});
