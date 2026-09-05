// The EVM io bundles for the engine's flows (issue #40). The rail-agnostic
// flows in @bongtu/client used to default their network edges to the real viem
// implementations; after the rail split the engine may not import a rail
// package, so those defaults live HERE and each app spreads the bundle for its
// family into the flow/facade deps once at wiring time. Members are exactly the
// engine's per-flow rail seams (ops/deposit.ts RunDepositDeps, ops/spend/run.ts
// RunSpendDeps, ops/consumer/run.ts RunConsumer*Deps, session/login.ts
// RunLoginDeps) — structural typing keeps a drift between a bundle and its seam
// a tsc error at the spread site.

import {
  approveToken,
  assertPoolKemEpoch,
  ensureChain,
  readTokenState,
  submitDeposit,
  submitTransfer,
  submitTransfer10x2,
  submitWithdraw,
} from "./connection/index.js";
import { submitWithdrawRelayed } from "./relayer.js";
import {
  submitDepositPriv,
  submitTransferPriv,
  submitTransfer10x2Priv,
  submitWithdrawPriv,
} from "./consumer.js";

/** The enterprise-family rail io: everything runDeposit / runSpendChain /
 *  runMergeChain (and the SpendOps facade) take beyond the app's own lock +
 *  prover. Spread it into the deps seam at wiring time. */
export const EVM_ENTERPRISE_IO = {
  ensureChain,
  assertPoolKemEpoch,
  readTokenState,
  approveToken,
  submitDeposit,
  submitTransfer,
  submitTransfer10x2,
  submitWithdraw,
  submitWithdrawRelayed,
};

/** The consumer-family rail io: everything consumerRunDeposit /
 *  consumerRunSpendChain (and the ConsumerOps facade) take beyond the app's own
 *  lock + prover. No KEM-epoch guard and no relayed submit — those seams do not
 *  exist in this family (ops/consumer/run.ts owns the WHY). */
export const EVM_CONSUMER_IO = {
  ensureChain,
  readTokenState,
  approveToken,
  submitDepositPriv,
  submitTransferPriv,
  submitTransfer10x2Priv,
  submitWithdrawPriv,
};
