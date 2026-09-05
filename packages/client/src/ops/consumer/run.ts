// The consumer-family FLOW variants: consumerRunDeposit + consumerRunSpendChain,
// the prove+submit orchestrations the consumer wallet app wires exactly like the
// enterprise pair (ops/deposit.ts runDeposit / ops/spend/run.ts runSpendChain) —
// same stage grammar, same ctx/deps seam shape, same failure-reassurance rule.
//
// ONE file for both flows, where the enterprise pair is two: the enterprise
// flows share nothing (a deposit has no membership machinery), so each owns a
// file; the consumer variants are each a SHORT list of deltas from their twin,
// and the deltas are family-wide — keeping both beside the one list below is
// what stops them drifting apart. The deltas, exactly:
//
//   - NO assertPoolKemEpoch — there is no arbiter KEM epoch to guard: consumer
//     outputs seal to each RECIPIENT's registered triple (requests.ts),
//     not to a chain-vouched authority key, so the guard has no subject.
//   - membership is the AUTH-FREE path read (getPath / GET /path) — consumer
//     batches serve /path openly (OPMOD §4.4 public batch fill), so no read
//     needs the signed variant; the fake-IO suite pins that no signed fetch
//     ever fires.
//   - builders come from requests.ts (S2): per-output sealing, no
//     authority envelope, kem cts surfaced in meta as `bytes[]` calldata.
//   - submits go to the MODULE addresses via submit.ts; token approve
//     still targets the POOL (the escrow holder — docs/consumer.md).
//   - refresh-between-legs is a SELF-SCAN pass: consumer notes have no /notes
//     oracle, so ctx.reloadNotes is typed against the selfscan surface
//     (ScanNote) and the app supplies a runSelfScan-backed closure — the
//     indexer never appears here directly.
//   - merge legs are transfer10x2Priv-to-self: chain planning is the SAME pure
//     planSpendChain (arity-driven, family-blind), each picked circuit mapped
//     through consumerCircuitOf.

import { commitment } from "@bongtu/core/note";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import {
  walletErrorMessage,
  type Connection,
  type SubmitResult,
  type TokenState,
} from "@bongtu/client/rail";
import type { KeyCacheLike } from "@bongtu/client/keyCache";
import { getHead, getPath } from "@bongtu/core/indexerApi";
import { pollUntil, type PollForActionOptions } from "@bongtu/client/refresh";
import {
  pendingLegOf,
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
import { assertDepositAffordable } from "@bongtu/client/deposit";
import { isConsumerIdentity, type ScanNote } from "@bongtu/client/selfscan";
import type { ConsumerWalletIdentity } from "@bongtu/client/derive";
import { DEPOSIT_FAILURE_REASSURANCE, type DepositStage } from "@bongtu/client/deposit";
import {
  CHAIN_FAILURE_REASSURANCE,
  MERGE_NOT_INDEXED_MESSAGE,
  type LegProgress,
  type OnSpendStage,
  type SpendOutcome,
} from "@bongtu/client/spend";

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
 * the deposit module. Stage grammar and guard order are runDeposit's
 * (unlock → approve → prove → submit; affordability checked before the approve
 * tx; the unlock's session-account check before any token motion). The one
 * consumer-only knob: `args.recipient` mints note(V) to a THIRD PARTY's
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
  const amount = args.amount.trim();
  const V = BigInt(amount);
  if (V <= 0n) throw new Error(`deposit amount must be positive, got ${V}`);
  // Probe the triple BEFORE any token motion: a doomed deposit must not waste
  // an approve tx (ops/deposit.ts family rule) — sealing would only catch a
  // corrupt triple at the prove stage, after the approve landed.
  if (args.recipient) assertConsumerRecipient(args.recipient);

  const locked = !io.keyCache.isUnlocked();
  onStage(locked ? "unlock" : "approve");
  await io.ensureChain(ctx.connection);
  const { balance, allowance } = await io.readTokenState(
    ctx.connection,
    ctx.token,
    ctx.connection.address,
    ctx.pool,
  );
  assertDepositAffordable(V, balance);
  const identity = asConsumerIdentity(await io.keyCache.unlock(ctx.connection, ctx.sessionPubkey));
  if (locked) onStage("approve");
  const approved = allowance < V;
  if (approved) {
    // The approve targets the POOL — the escrow that pulls V on a module's
    // accepted proof; approving the module would fund nothing (modules hold no
    // funds, docs/consumer.md).
    await io.approveToken(ctx.connection, ctx.token, ctx.pool, V);
  }

  try {
    onStage("prove");
    const crypto = freshConsumerDepositCrypto(randField);
    const self = selfConsumerRecipient(identity);
    const built = buildConsumerDepositRequest(
      [
        { recipient: args.recipient ?? self, value: amount },
        { recipient: self, value: "0" },
      ],
      crypto,
    );
    const calldata = await io.prove(built.request);

    onStage("submit");
    const res = await io.submitDepositPriv(
      ctx.connection,
      calldata,
      built.meta.kemCiphertexts,
      ctx.explorer,
    );
    return { txHash: res.txHash, explorerUrl: res.explorerUrl, amount, approved };
  } catch (e) {
    // runDeposit's money-state rule verbatim (ops/deposit.ts): once the approve landed, a later
    // failure must say where the money stands.
    if (!approved) throw e;
    throw new Error(`${walletErrorMessage(e)} ${DEPOSIT_FAILURE_REASSURANCE}`);
  }
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

// Fresh per leg, because each leg moves the root — ops/spend/run.ts fetchMemberships
// with the signed read swapped for the open one (no owner key leaves the leg).
async function fetchMemberships(
  io: RunConsumerSpendDeps,
  indexerUrl: string,
  inputs: WalletInputNote[],
): Promise<MembershipWitness[]> {
  const head = await io.getHead(indexerUrl);
  const memberships: MembershipWitness[] = [];
  for (const n of inputs) {
    const p = await io.getPath(indexerUrl, n.leafIndex);
    memberships.push({ root: head.root, pathElements: p.siblings, leafIndex: n.leafIndex });
  }
  return memberships;
}

/** ops/spend/run.ts openSpendSession minus the KEM-epoch guard: align the chain,
 *  then take the spending key from the lock (session-account-checked per LEG,
 *  so a mid-chain account switch blocks the remaining transactions). */
async function openConsumerSession(
  io: RunConsumerSpendDeps,
  ctx: ConsumerSpendContext,
  onStage: OnSpendStage,
  leg: LegProgress,
): Promise<ConsumerWalletIdentity> {
  const locked = !io.keyCache.isUnlocked();
  onStage(locked ? "unlock" : "assemble", leg);
  await io.ensureChain(ctx.connection);
  const identity = asConsumerIdentity(await io.keyCache.unlock(ctx.connection, ctx.sessionPubkey));
  if (locked) onStage("assemble", leg);
  return identity;
}

/** One planned leg resolved into what its builder takes. A merge is a
 *  transfer10x2Priv paying the wallet's OWN triple the whole fold; a terminal
 *  leg carries the user's ask. Inputs the plan left pending are the notes
 *  earlier merges have since created (same pendingLegOf protocol as the spend run). */
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
  identity: ConsumerWalletIdentity,
  args: { to?: ConsumerRecipient; amount: string },
  merged: (WalletInputNote | undefined)[],
): ConsumerAction {
  const inputs = step.inputs.map((n) => {
    const from = pendingLegOf(n.leafIndex);
    if (from === null) return n;
    const real = merged[from];
    if (!real) throw new Error(`merge leg ${from + 1} has not produced its note yet`);
    return real;
  });
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

/** One transaction: auth-free membership → witness → proof → module submit. The
 *  payee salt comes back with it — a merge leg's output note is identified by
 *  the salt this run drew (spendFlow's rule unchanged). */
async function runConsumerLeg(
  io: RunConsumerSpendDeps,
  ctx: ConsumerSpendContext,
  identity: ConsumerWalletIdentity,
  action: ConsumerAction,
  onStage: OnSpendStage,
  leg: LegProgress,
  withdrawRecipient: string,
): Promise<{ outcome: SpendOutcome; payeeSalt: string }> {
  const memberships = await fetchMemberships(io, ctx.indexerUrl, action.inputs);
  const crypto = freshConsumerSpendCrypto(randField);
  const built = buildConsumerLeg(action, identity, memberships, crypto, withdrawRecipient);
  if (!built.meta.membershipOk) {
    throw new Error("Your balance just changed. Go back and try again.");
  }

  onStage("prove", leg);
  const calldata = await io.prove(built.request);

  onStage("submit", leg);
  // The tx carries the per-output kem cts the builder sealed — one 1088-byte
  // entry per output, in output order; a substituted ct simply never
  // decapsulates for its recipient (self-sabotage class, never theft: the
  // commitment binds the SPEND key in-proof).
  const res =
    action.circuit === "withdrawPriv"
      ? await io.submitWithdrawPriv(ctx.connection, calldata, built.meta.kemCiphertexts, ctx.explorer)
      : action.circuit === "transfer10x2Priv"
        ? await io.submitTransfer10x2Priv(ctx.connection, calldata, built.meta.kemCiphertexts, ctx.explorer)
        : await io.submitTransferPriv(ctx.connection, calldata, built.meta.kemCiphertexts, ctx.explorer);
  return {
    outcome: { txHash: res.txHash, explorerUrl: res.explorerUrl },
    payeeSalt: crypto.payeeSalt ?? "",
  };
}

/** Wait for a self-scan pass to discover the note a merge leg created — its
 *  leafIndex is what the next leg proves membership against. The identity
 *  (mergedValue, payeeSalt, own spend key) → commitment rule is spendFlow's
 *  awaitMergedNote unchanged; only the note SOURCE differs (a scan of the
 *  public feed instead of the arbiter's /notes). */
async function awaitMergedNote(
  io: RunConsumerSpendDeps,
  ctx: ConsumerSpendContext,
  identity: ConsumerWalletIdentity,
  mergedValue: string,
  payeeSalt: string,
): Promise<WalletInputNote> {
  const wanted = commitment(BigInt(mergedValue), BigInt(payeeSalt), identity.keypair.publicKey).toString();
  const seen = (notes: ScanNote[]): ScanNote | undefined =>
    notes.find((n) => n.commitment === wanted && !n.spent);
  const { last } = await pollUntil(ctx.reloadNotes, (ns) => seen(ns) !== undefined, io.poll);
  const note = last ? seen(last) : undefined;
  if (!note) throw new Error(MERGE_NOT_INDEXED_MESSAGE);
  return { value: mergedValue, salt: payeeSalt, leafIndex: note.leafIndex };
}

/**
 * Plan the consumer spend as a chain and run it: per leg, auth-free membership →
 * requests.ts witness build → proof → module submit; after a merge leg, the
 * "waiting" pause until a self-scan pass has found the note it created. Stage
 * grammar (unlock → assemble → prove → submit → waiting), leg numbering, and
 * the partial-failure reassurance are runSpendChain's, so the app renders both
 * families through one progress rail.
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
  const count = plan.length;
  const merged: (WalletInputNote | undefined)[] = [];
  const outcomes: SpendOutcome[] = [];
  const withdrawRecipient = args.withdrawTo ?? ctx.connection.address;

  for (const index of Array(count).keys()) {
    const leg: LegProgress = { index, count };
    const step = plan[index];
    try {
      const identity = await openConsumerSession(io, ctx, onStage, leg);
      const action = consumerLegAction(step, identity, args, merged);
      const run = await runConsumerLeg(io, ctx, identity, action, onStage, leg, withdrawRecipient);
      outcomes.push(run.outcome);
      if (step.leg === "merge") {
        onStage("waiting", leg);
        merged[index] = await awaitMergedNote(io, ctx, identity, step.mergedValue, run.payeeSalt);
      }
    } catch (e) {
      // spendFlow's rule: a one-transaction spend fails exactly as it always
      // did; only a chain that already landed legs earns the reassurance.
      if (count === 1) throw e;
      throw new Error(`${walletErrorMessage(e)} ${CHAIN_FAILURE_REASSURANCE}`);
    }
  }
  return outcomes[outcomes.length - 1] as SpendOutcome;
}
