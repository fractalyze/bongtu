// txbuild/budget.ts — the per-transaction resource budget every op carries
// (SOLR §3.1: the default budget must always be raised explicitly — a client
// obligation). SOLR was written against the v0-era mechanism (a ComputeBudget
// instruction pair); the shipped SIMD-0385 v1 format moved the budget into
// the TRANSACTION HEADER (configMask + configValues), and made it MANDATORY:
// a v1 transaction with `computeUnitLimit` or `loadedAccountsDataSizeLimit`
// unset is budgeted ZERO (not the old 200k/64MiB defaults) and fails at
// execution — so the "both ixs" obligation becomes "both config fields", plus
// the priority fee (now total lamports per transaction, not per-CU).
//
// The CU limits MIRROR chains/solana/cu_budget.json — the committed per-op
// regression budgets — plus the headroom its comment mandates: "clients
// should keep the ~10k headroom (or set compute limits above the budget), not
// set limits at the measured value" (the pre-funded-PDA hardening path costs
// a few k CU per griefed PDA over the measured numbers). This module is a
// browser-safe mirror, not the owner: test/budget.test.ts holds every row to
// the JSON file (limit == budget + CU_LIMIT_HEADROOM, and every consumer op
// in the file has a row here) — the network.ts mirror-plus-pin pattern.

import type { ConsumerOpName } from "./data.js";

/** The client headroom over the committed budget (cu_budget.json comment). */
export const CU_LIMIT_HEADROOM = 10_000;

/** Per-op compute-unit limits: the committed budget + headroom, mirrored from
 *  chains/solana/cu_budget.json BY FIELD NAME (pin-tested; never re-measure
 *  here, never set at the measured value). */
export const COMPUTE_UNIT_LIMITS: Record<ConsumerOpName, number> = {
  depositPriv: 232_000 + CU_LIMIT_HEADROOM,
  transferPriv: 260_000 + CU_LIMIT_HEADROOM,
  transfer10x2Priv: 347_000 + CU_LIMIT_HEADROOM,
  withdrawPriv: 219_000 + CU_LIMIT_HEADROOM,
};

/** Loaded-accounts data budget, one generous ceiling for every consumer op:
 *  the real load is the pool program ELF (~130 KB) + the SPL token program +
 *  the pool accounts (~3 KB) — comfortably under 1 MiB; 2 MiB keeps room for
 *  program growth without approaching the network's 64 MiB cap. Mandatory on
 *  v1 (unset budgets ZERO bytes — the module doc). */
export const LOADED_ACCOUNTS_DATA_SIZE_LIMIT = 2 * 1024 * 1024;

/** The SIMD-0385 v1 header config slice the submits set (the kit
 *  V1TransactionConfig shape, declared structurally so this module stays a
 *  plain-data mirror). */
export interface SolanaTxBudget {
  computeUnitLimit: number;
  loadedAccountsDataSizeLimit: number;
  priorityFeeLamports?: bigint;
}

/**
 * The transaction budget for one op: the op's mirrored CU limit, the
 * loaded-accounts ceiling, and — when the caller prioritizes — the TOTAL
 * priority fee in lamports (the v1 semantic; 0n/absent = none).
 */
export function transactionBudgetOf(op: ConsumerOpName, priorityFeeLamports: bigint = 0n): SolanaTxBudget {
  return {
    computeUnitLimit: COMPUTE_UNIT_LIMITS[op],
    loadedAccountsDataSizeLimit: LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
    ...(priorityFeeLamports > 0n ? { priorityFeeLamports } : {}),
  };
}
