// The CU-limit mirror pin (the network.ts mirror-plus-pin pattern): the
// browser-safe limits table in txbuild/budget.ts must track the committed
// per-op budgets (chains/solana/cu_budget.json) exactly — limit == budget +
// the mandated client headroom — and must cover every consumer op the file
// budgets. Moving a budget without moving the mirror fails here in
// milliseconds; the budgets themselves move only by explicit commit. Also
// pins the SIMD-0385 v1 budget shape: BOTH mandatory header-config fields
// present on every op (an unset field budgets ZERO on v1 — budget.ts doc).

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  COMPUTE_UNIT_LIMITS,
  CU_LIMIT_HEADROOM,
  LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
  transactionBudgetOf,
  type ConsumerOpName,
} from "@bongtu/client-solana/txbuild";

const BUDGET_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  "..",
  "..",
  "..",
  "chains",
  "solana",
  "cu_budget.json",
);
const budgets = JSON.parse(readFileSync(BUDGET_PATH, "utf8")) as Record<string, number | string>;

/** camelCase op -> the budget file's snake_case key. */
const SNAKE: Record<ConsumerOpName, string> = {
  depositPriv: "deposit_priv",
  transferPriv: "transfer_priv",
  transfer10x2Priv: "transfer10x2_priv",
  withdrawPriv: "withdraw_priv",
};

test("every consumer limit is its committed budget plus the mandated headroom, under the CU cap", () => {
  for (const [op, key] of Object.entries(SNAKE) as [ConsumerOpName, string][]) {
    const budget = budgets[key];
    assert.equal(typeof budget, "number", `cu_budget.json has no ${key}`);
    assert.equal(
      COMPUTE_UNIT_LIMITS[op],
      (budget as number) + CU_LIMIT_HEADROOM,
      `${op}: limit must be budget + ${CU_LIMIT_HEADROOM} (mirror drifted from cu_budget.json)`,
    );
    assert.ok(COMPUTE_UNIT_LIMITS[op] > (budget as number), "limits sit ABOVE the budget (the file's comment)");
    assert.ok(COMPUTE_UNIT_LIMITS[op] <= 1_400_000, "under the per-tx CU cap");
  }
});

test("every *_priv budget in the file has a mirror row (coverage, both directions)", () => {
  const consumerKeys = Object.keys(budgets).filter((k) => k.endsWith("_priv"));
  assert.deepEqual(consumerKeys.sort(), Object.values(SNAKE).sort());
});

test("transactionBudgetOf carries BOTH mandatory v1 fields, priority fee only when asked", () => {
  const plain = transactionBudgetOf("transferPriv");
  assert.equal(plain.computeUnitLimit, COMPUTE_UNIT_LIMITS.transferPriv);
  assert.equal(plain.loadedAccountsDataSizeLimit, LOADED_ACCOUNTS_DATA_SIZE_LIMIT);
  assert.ok(!("priorityFeeLamports" in plain), "no priority fee unless prioritized");

  const prioritized = transactionBudgetOf("withdrawPriv", 5_000n);
  assert.equal(prioritized.priorityFeeLamports, 5_000n);
  // Sanity on the loaded-accounts ceiling: generous vs the ~130 KB program
  // ELF + the SPL token program, tiny vs the network's 64 MiB cap.
  assert.ok(LOADED_ACCOUNTS_DATA_SIZE_LIMIT >= 1024 * 1024);
  assert.ok(LOADED_ACCOUNTS_DATA_SIZE_LIMIT <= 64 * 1024 * 1024);
});
