// The consumer-family FLOW variants: consumerRunDeposit + consumerRunSpendChain,
// the prove+submit orchestrations the consumer wallet app wires exactly like the
// enterprise pair (ops/deposit.ts runDeposit / ops/spend/run.ts runSpendChain) —
// same stage grammar, same ctx/deps seam shape, same failure-reassurance rule,
// because all four now RUN the same drivers (ops/driver.ts runLegChain /
// runGuardedDeposit). What used to be a prose list of "the deltas, exactly" is
// now literally this file's family configs; the deltas themselves are unchanged:
//
//   - NO guardPool — there is no arbiter KEM epoch to guard: consumer
//     outputs seal to each RECIPIENT's registered triple (requests.ts),
//     not to a chain-vouched authority key, so the guard has no subject.
//   - membership is the AUTH-FREE path read (getPath / GET /path) — consumer
//     batches serve /path openly (OPMOD §4.4 public batch fill), so no read
//     needs the signed variant; the fake-IO suite pins that no signed fetch
//     ever fires.
//   - builders come from requests.ts: per-output sealing, no authority
//     envelope, kem cts surfaced in meta as `bytes[]` calldata.
//   - submits go to the MODULE addresses via the client-evm consumer submit
//     edge (@bongtu/client-evm/consumer); token approve still targets the
//     POOL (the escrow holder — docs/consumer.md).
//   - refresh-between-legs is a SELF-SCAN pass: consumer notes have no /notes
//     oracle, so ctx.reloadNotes is typed against the selfscan surface
//     (ScanNote) and the app supplies a runSelfScan-backed closure — the
//     indexer never appears here directly. (The driver reads only the
//     commitment/spent/leafIndex fields ScanNote and OwnerNote share.)
//   - merge legs are transfer10x2Priv-to-self: chain planning is the SAME pure
//     planSpendChain (arity-driven, family-blind), each picked circuit mapped
//     through consumerCircuitOf.

import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import type { Connection, SubmitResult, TokenState } from "@bongtu/client/rail";
import type { KeyCacheLike } from "@bongtu/client/keyCache";
import { getHead, getPath } from "@bongtu/core/indexerApi";
import type { PollForActionOptions } from "@bongtu/client/refresh";
import {
  planSpendChain,
  randField,
  type MembershipWitness,
  type SpendKind,
  type SpendLeg,
  type WalletInputNote,
} from "@bongtu/client/spend";
import {
  buildConsumerDepositRequest,
  buildConsumerTransferRequest,
  buildConsumerTransfer10x2Request,
  buildConsumerWithdrawRequest,
} from "./requests.js";
import {
  assertConsumerRecipient,
  consumerCircuitOf,
  freshConsumerDepositCrypto,
  freshConsumerSpendCrypto,
  selfConsumerRecipient,
  type ConsumerRecipient,
  type ConsumerSpendCircuit,
  type ConsumerSpendMeta,
} from "./plan.js";
import { isConsumerIdentity, type ScanNote } from "@bongtu/client/selfscan";
import type { ConsumerWalletIdentity } from "@bongtu/client/derive";
import type { DepositStage } from "@bongtu/client/deposit";
import type { OnSpendStage, SpendOutcome } from "@bongtu/client/spend";
import {
  runGuardedDeposit,
  runLegChain,
  type BuiltLeg,
  type DepositFamily,
  type LegChainFamily,
} from "../driver.js";

/** The unlock produces a full identity for every signature-derived key; only a
 *  synthetic enterprise-only identity (e.g. the sweeper's portal identity)
 *  lacks the view/KEM half — and such a session cannot seal or self-scan, so
 *  failing loudly here beats minting notes nobody could ever discover. */
function asConsumerIdentity(identity: Parameters<typeof isConsumerIdentity>[0]): ConsumerWalletIdentity {
  if (!isConsumerIdentity(identity)) {
    throw new Error("this session's key has no consumer view/KEM identity — log in again to derive it");
  }
  return identity;
}

// ============================ consumerRunDeposit =============================

export interface ConsumerDepositContext {
  connection: Connection;
  /** the POOL address — the escrow the ERC-20 approve targets and the puller of
   *  V (docs/consumer.md: modules verify, the pool holds the funds). */
  pool: string;
  /** the wrapped kKRW ERC-20 the pool escrows (app config). */
  token: string;
  /** the explorer base URL the success link is built on (app config). */
  explorer: string;
  /** the logged-in session's compressed bjj pubkey — what the just-in-time
   *  derivation must reproduce before any kKRW moves. */
  sessionPubkey: string;
}

export interface ConsumerDepositOutcome {
  txHash: string;
  explorerUrl: string;
  /** the minted value V (raw kKRW units). */
  amount: string;
  /** whether an ERC-20 approve tx was sent (false when the allowance covered V). */
  approved: boolean;
}

/** The network/proving I/O consumerRunDeposit performs, injectable exactly as
 *  ops/deposit.ts RunDepositDeps — minus assertPoolKemEpoch, which does not
 *  EXIST in this family's seam (a member nothing may call would only invite a
 *  fake to prove the wrong thing). The rail members are METHOD-style over the
 *  structural rail seam (@bongtu/client/rail) — apps spread
 *  @bongtu/client-evm/ops EVM_CONSUMER_IO. */
export interface RunConsumerDepositDeps {
  /** put the wallet on the live chain (silent when already there). */
  ensureChain(connection: Connection): Promise<void>;
  /** the wallet's lock — holds the spending key between actions (keyCache.ts). */
  keyCache: KeyCacheLike;
  /** the rail's token-state read: balance + allowance to the pool (view, no gas). */
  readTokenState(connection: Connection, tokenAddr: string, owner: string, spender: string): Promise<TokenState>;
  /** the rail's exact-amount ERC-20 approve; resolves after the receipt. */
  approveToken(connection: Connection, tokenAddr: string, spender: string, amount: bigint): Promise<string>;
  /** Turn a ProvingRequest into Groth16 calldata (the APP supplies this —
   *  treasury-web's in-browser snarkjs with its asset base applied). */
  prove: (request: ProvingRequest) => Promise<Calldata>;
  /** the rail's proven-depositPriv submit (to the deposit MODULE address). */
  submitDepositPriv(connection: Connection, calldata: Calldata, kemCiphertexts: string[], explorerBase: string, moduleAddress?: string): Promise<SubmitResult>;
}

/** What every consumer deposit must be handed: the app's lock, its prover, and
 *  the rail io (the engine has no rail defaults since the split — spread
 *  @bongtu/client-evm/ops EVM_CONSUMER_IO at the wiring site). */
export type ConsumerDepositIo = RunConsumerDepositDeps;

/**
 * Approve (if needed) → assemble the depositPriv witness → prove → submit to
 * the deposit module — the ONE guard sequence (ops/driver.ts runGuardedDeposit)
 * runDeposit also runs, with this family's deltas: no pool guard, the recipient
 * triple probed BEFORE any token motion (a doomed deposit must not waste an
 * approve tx — sealing would only catch a corrupt triple at the prove stage,
 * after the approve landed), and the depositPriv builder + module submit. The
 * one consumer-only knob: `args.recipient` mints note(V) to a THIRD PARTY's
 * registered triple (the consumer deposit's whole point — they discover it by
 * self-scan); omitted, the wallet mints to itself, the note(0) companion always
 * seals back to self.
 */
export async function consumerRunDeposit(
  ctx: ConsumerDepositContext,
  args: { amount: string; recipient?: ConsumerRecipient },
  onStage: (stage: DepositStage) => void,
  deps: ConsumerDepositIo,
): Promise<ConsumerDepositOutcome> {
  const io: RunConsumerDepositDeps = deps;
  const family: DepositFamily<ConsumerWalletIdentity> = {
    connection: ctx.connection,
    sessionPubkey: ctx.sessionPubkey,
    keyCache: io.keyCache,
    ensureChain: () => io.ensureChain(ctx.connection),
    precheck: () => {
      if (args.recipient) assertConsumerRecipient(args.recipient);
    },
    refineIdentity: asConsumerIdentity,
    // The approve targets the POOL — the escrow that pulls V on a module's
    // accepted proof; approving the module would fund nothing (modules hold no
    // funds, docs/consumer.md).
    readTokenState: () =>
      io.readTokenState(ctx.connection, ctx.token, ctx.connection.address, ctx.pool),
    approveToken: (V) => io.approveToken(ctx.connection, ctx.token, ctx.pool, V),
    buildDeposit: (identity, amount) => {
      const crypto = freshConsumerDepositCrypto(randField);
      const self = selfConsumerRecipient(identity);
      const built = buildConsumerDepositRequest(
        [
          { recipient: args.recipient ?? self, value: amount },
          { recipient: self, value: "0" },
        ],
        crypto,
      );
      return {
        request: built.request,
        submit: (calldata) =>
          io.submitDepositPriv(ctx.connection, calldata, built.meta.kemCiphertexts, ctx.explorer),
      };
    },
    prove: io.prove,
  };
  return runGuardedDeposit(args.amount, family, onStage);
}

// =========================== consumerRunSpendChain ===========================

export interface ConsumerSpendContext {
  connection: Connection;
  indexerUrl: string;
  /** the explorer base URL the success link is built on (app config). */
  explorer: string;
  /** the wallet's discovered notes — the SELF-SCAN result set (selfscan.ts),
   *  because consumer notes have no /notes oracle to load from. */
  notes: ScanNote[];
  /** the logged-in session's compressed bjj pubkey — what the just-in-time
   *  derivation must reproduce before any of these notes may be spent. */
  sessionPubkey: string;
  /** Re-discover the wallet's notes: a SELF-SCAN pass (the app wraps
   *  runSelfScan + its state store into this closure). A chain cannot plan its
   *  next leg from `notes` alone — the note a merge just created only exists
   *  once a scan of the public feed has found it and its leafIndex. */
  reloadNotes: () => Promise<ScanNote[]>;
}

/** The network/proving I/O a consumer spend performs — RunSpendDeps minus the
 *  seams this family removes (assertPoolKemEpoch: nothing to guard;
 *  getSignedPath: membership is auth-free; relayed submit: v1 self-submits).
 *  The rail members are METHOD-style over the structural rail seam
 *  (@bongtu/client/rail) — apps spread @bongtu/client-evm/ops EVM_CONSUMER_IO. */
export interface RunConsumerSpendDeps {
  /** put the wallet on the live chain (silent when already there). */
  ensureChain(connection: Connection): Promise<void>;
  /** the wallet's lock — holds the spending key between actions (keyCache.ts). */
  keyCache: KeyCacheLike;
  getHead: typeof getHead;
  /** the AUTH-FREE membership read — consumer batches serve /path openly. */
  getPath: typeof getPath;
  /** Turn a ProvingRequest into Groth16 calldata (the APP supplies this). */
  prove: (request: ProvingRequest) => Promise<Calldata>;
  /** the rail's proven-transferPriv submit (to the op's MODULE address). */
  submitTransferPriv(connection: Connection, calldata: Calldata, kemCiphertexts: string[], explorerBase: string, moduleAddress?: string): Promise<SubmitResult>;
  /** the rail's proven-transfer10x2Priv submit (every consumer merge leg). */
  submitTransfer10x2Priv(connection: Connection, calldata: Calldata, kemCiphertexts: string[], explorerBase: string, moduleAddress?: string): Promise<SubmitResult>;
  /** the rail's proven-withdrawPriv submit (proof-bound payout). */
  submitWithdrawPriv(connection: Connection, calldata: Calldata, kemCiphertexts: string[], explorerBase: string, moduleAddress?: string): Promise<SubmitResult>;
  /** interval/cap/sleep for the between-legs wait (refresh.ts), so tests can
   *  run a chain without real seconds. */
  poll: PollForActionOptions;
}

/** What every consumer spend must be handed: the app's lock instance, its
 *  prover, and the rail io (spread @bongtu/client-evm/ops EVM_CONSUMER_IO at
 *  the wiring site). The engine-side edges default to the real ones. */
export type ConsumerSpendIo = Pick<
  RunConsumerSpendDeps,
  | "keyCache"
  | "prove"
  | "ensureChain"
  | "submitTransferPriv"
  | "submitTransfer10x2Priv"
  | "submitWithdrawPriv"
> &
  Partial<RunConsumerSpendDeps>;

const SPEND_DEFAULT_DEPS: Pick<RunConsumerSpendDeps, "getHead" | "getPath" | "poll"> = {
  getHead,
  getPath,
  poll: {},
};

/** One planned leg resolved into what its builder takes. A merge is a
 *  transfer10x2Priv paying the wallet's OWN triple the whole fold; a terminal
 *  leg carries the user's ask. */
interface ConsumerAction {
  circuit: ConsumerSpendCircuit;
  inputs: WalletInputNote[];
  /** the recipient triple — self for merges, the payee for a transfer; unused
   *  by withdraw (its payout target is the L1 recipient below). */
  to: ConsumerRecipient;
  amount: string;
}

function consumerLegAction(
  step: SpendLeg,
  inputs: WalletInputNote[],
  identity: ConsumerWalletIdentity,
  args: { to?: ConsumerRecipient; amount: string },
): ConsumerAction {
  const self = selfConsumerRecipient(identity);
  if (step.leg === "merge") {
    return { circuit: "transfer10x2Priv", inputs, to: self, amount: step.mergedValue };
  }
  return {
    circuit: consumerCircuitOf(step.leg),
    inputs,
    to: args.to ?? self,
    amount: args.amount,
  };
}

function buildConsumerLeg(
  action: ConsumerAction,
  identity: ConsumerWalletIdentity,
  memberships: MembershipWitness[],
  crypto: ReturnType<typeof freshConsumerSpendCrypto>,
  withdrawRecipient: string,
): { request: ProvingRequest; meta: ConsumerSpendMeta } {
  const { circuit, inputs, to, amount } = action;
  if (circuit === "withdrawPriv") {
    return buildConsumerWithdrawRequest(identity, inputs, memberships, amount, crypto, withdrawRecipient);
  }
  if (circuit === "transfer10x2Priv") {
    return buildConsumerTransfer10x2Request(identity, inputs, memberships, to, amount, crypto);
  }
  return buildConsumerTransferRequest(identity, inputs, memberships, to, amount, crypto);
}

/** The consumer deltas, as the driver's family config: no pool guard, the
 *  view/KEM-refined identity, the OPEN membership read, the requests.ts builders
 *  per picked circuit, the module submits carrying the per-output kem cts, and
 *  the self-scan reload. */
function consumerFamily(
  io: RunConsumerSpendDeps,
  ctx: ConsumerSpendContext,
  args: { to?: ConsumerRecipient; amount: string; withdrawTo?: string },
): LegChainFamily<ConsumerWalletIdentity, ScanNote> {
  // A withdraw pays the connected account unless withdrawTo substitutes another
  // L1 address — either way proof-bound.
  const withdrawRecipient = args.withdrawTo ?? ctx.connection.address;
  return {
    connection: ctx.connection,
    sessionPubkey: ctx.sessionPubkey,
    keyCache: io.keyCache,
    ensureChain: () => io.ensureChain(ctx.connection),
    // no guardPool: there is no arbiter KEM epoch in this family (delta list).
    refineIdentity: asConsumerIdentity,
    getHead: () => io.getHead(ctx.indexerUrl),
    readPath: (_identity, leafIndex) => io.getPath(ctx.indexerUrl, leafIndex),
    buildLeg: (step, inputs, identity, memberships): BuiltLeg => {
      const action = consumerLegAction(step, inputs, identity, args);
      const crypto = freshConsumerSpendCrypto(randField);
      const built = buildConsumerLeg(action, identity, memberships, crypto, withdrawRecipient);
      // The tx carries the per-output kem cts the builder sealed — one
      // 1088-byte entry per output, in output order; a substituted ct simply
      // never decapsulates for its recipient (self-sabotage class, never theft:
      // the commitment binds the SPEND key in-proof).
      const submitFor =
        action.circuit === "withdrawPriv"
          ? io.submitWithdrawPriv
          : action.circuit === "transfer10x2Priv"
            ? io.submitTransfer10x2Priv
            : io.submitTransferPriv;
      return {
        request: built.request,
        membershipOk: built.meta.membershipOk,
        payeeSalt: crypto.payeeSalt ?? "",
        submit: (calldata) =>
          submitFor(ctx.connection, calldata, built.meta.kemCiphertexts, ctx.explorer),
      };
    },
    prove: io.prove,
    reloadNotes: ctx.reloadNotes,
    poll: io.poll,
  };
}

/**
 * Plan the consumer spend as a chain and run it through the one driver
 * (ops/driver.ts runLegChain): per leg, auth-free membership → requests.ts
 * witness build → proof → module submit; after a merge leg, the "waiting" pause
 * until a self-scan pass has found the note it created. Stage grammar
 * (unlock → assemble → prove → submit → waiting), leg numbering, and the
 * partial-failure reassurance are the driver's — the same run runSpendChain
 * gets — so the app renders both families through one progress rail.
 *
 * `args.to` is the payee's registered consumer triple (consumerRecipientOf) —
 * required for a transfer, ignored by a withdraw, never consumed by a merge
 * (merges pay the wallet itself). A withdraw pays the connected account unless
 * `args.withdrawTo` substitutes another L1 address — either way proof-bound.
 */
export async function consumerRunSpendChain(
  kind: SpendKind,
  ctx: ConsumerSpendContext,
  args: { to?: ConsumerRecipient; amount: string; withdrawTo?: string },
  onStage: OnSpendStage,
  deps: ConsumerSpendIo,
): Promise<SpendOutcome> {
  const io: RunConsumerSpendDeps = { ...SPEND_DEFAULT_DEPS, ...deps };
  if (kind === "transfer" && args.to === undefined) {
    throw new Error("a consumer transfer needs the payee's registered consumer triple");
  }
  // Planning is pure and touches nothing, so it happens FIRST — and it is the
  // SAME planner as the enterprise chain (selection is arity-driven and
  // family-blind); only the circuit each leg lands on maps to the consumer twin.
  const plan = planSpendChain(kind, ctx.notes, args.amount);
  const { outcomes } = await runLegChain(plan, plan.length, consumerFamily(io, ctx, args), onStage);
  return outcomes[outcomes.length - 1] as SpendOutcome;
}
