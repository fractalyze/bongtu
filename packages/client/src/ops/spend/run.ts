// The enterprise family's chain runners (SPEC §7): runSpendChain for the public
// wallet's two spend actions, runMergeChain for payroll's pre-disburse fold. The
// witness assembly, membership fold, in-browser proof and wallet submit stay in
// the same tested pure libs (plan.ts / builders.ts / the injected prover +
// connection edges); the LOOP itself — leg order, stage grammar, per-leg session
// guard, merge wait, partial-failure reassurance — is the family-invariant
// driver (../driver.ts runLegChain), and this file supplies only the enterprise
// deltas as its family config: the arbiter KEM-epoch guard, the SIGNED
// membership read, the enterprise builders per picked circuit, the pool submits
// (withdraw optionally relayed), and the arbiter /notes reload.
//
// A SPEND IS A CHAIN, not a transaction. A spending circuit takes a fixed number of
// input notes, so a balance spread across more notes than that cannot be paid in one
// go. The wallet does not stop and send the user off to merge first: planSpendChain
// (plan.ts) plans the whole way through — however many transfer10x2 self-sends it
// takes to fold the balance down, then the payment itself — and runSpendChain below
// runs the legs back to back, one wallet approval each. A plain send is simply a chain
// of one, and runs byte-identically to what it always did. (transfer10 is deprecated,
// 2026-07-28: no leg of any chain proves or submits it anymore.)
//
// Between legs the chain WAITS. A merge leg's output note does not exist for the next
// leg until the indexer has seen the transaction: only then does the note have a leaf
// index and a membership path to prove against. That wait is a reported stage of its
// own ("waiting"), so the screen can say what it is waiting for.

import type { StealthDerivation } from "@bongtu/core/stealth";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import type { Connection, SubmitResult } from "@bongtu/client/rail";
import type { KeyCacheLike } from "@bongtu/client/keyCache";
import { getHead, getSignedPath, type OwnerNote } from "@bongtu/core/indexerApi";
import type { PollForActionOptions } from "@bongtu/client/refresh";
import {
  buildTransferRequest,
  buildTransfer10x2Request,
  buildWithdrawRequest,
} from "./builders.js";
import {
  planDisburseChain,
  planSpendChain,
  pendingLegOf,
  type SpendAction,
  type SpendCrypto,
  type SpendKind,
  type SpendLeg,
  type WalletInputNote,
  type MembershipWitness,
} from "./plan.js";
import { freshSpendCrypto, randField } from "./crypto.js";
import type { WalletIdentity } from "@bongtu/client/derive";
import { mergeNotePendingError, runLegChain, type BuiltLeg, type LegChainFamily, type LegProgress, type OnSpendStage, type SpendOutcome, type SpendStage } from "../driver.js";

// The stage grammar, progress shape, and money-state wording are the DRIVER's
// (one loop, one rule set); re-exported here so this subpath stays the one
// stable public surface the apps and suites import them from.
export { CHAIN_FAILURE_REASSURANCE, MERGE_NOT_INDEXED_MESSAGE } from "../driver.js";
export type { LegProgress, OnSpendStage, SpendOutcome, SpendStage };

export interface SpendContext {
  connection: Connection;
  indexerUrl: string;
  /** the pool address every leg proves against and submits to (app config). */
  pool: string;
  /** the explorer base URL the success link is built on (app config). */
  explorer: string;
  /** the gas-sponsoring relayer base URL (app config; apps/relayer). Set => the
   *  terminal WITHDRAW leg is submitted through it — no wallet popup, the
   *  relayer pays gas, and it cannot redirect the payout because the recipient
   *  is proof-bound (pub[26]). Absent/empty => wallet self-submit, the
   *  pre-relayer behavior. Transfer and merge legs NEVER relay: they carry no
   *  proof-bound recipient, so there is nothing a relayer could safely offer. */
  relayerUrl?: string;
  notes: OwnerNote[];
  /** the logged-in session's compressed bjj pubkey — what the just-in-time
   *  derivation must reproduce before any of these notes may be spent, and the payee
   *  of every merge leg. */
  sessionPubkey: string;
  /** Re-read the owner's notes from the indexer. A chain cannot plan its next leg
   *  from `notes` alone: the note a merge just created is not in there, and only the
   *  indexer can say which leaf it landed on. */
  reloadNotes: () => Promise<OwnerNote[]>;
}

/** The network/proving I/O a spend performs, injectable so the pure orchestration
 *  (guard order, stage order, leg order) is unit-testable with fakes — the same seam
 *  ops/deposit.ts uses (RunDepositDeps). The rail members are METHOD-style over
 *  the structural rail seam (@bongtu/client/rail), so the rail client's real
 *  edges (typed over its own wider Connection) are assignable — apps spread
 *  @bongtu/client-evm/ops EVM_ENTERPRISE_IO. */
export interface RunSpendDeps {
  /** put the wallet on the live chain (silent when already there). */
  ensureChain(connection: Connection): Promise<void>;
  /** refuse a pool whose arbiter KEM key the chain does not vouch for. */
  assertPoolKemEpoch(connection: Connection, poolAddr: string): Promise<void>;
  /** the wallet's lock — holds the spending key between actions (keyCache.ts). */
  keyCache: KeyCacheLike;
  getHead: typeof getHead;
  getSignedPath: typeof getSignedPath;
  /** Turn a ProvingRequest into Groth16 calldata. The APP supplies this: treasury-web
   *  injects in-browser snarkjs (prove.ts proveInBrowser with its circuit asset
   *  base URL applied); payroll-web will inject its prover-service adapter. */
  prove: (request: ProvingRequest) => Promise<Calldata>;
  /** the rail's proven-transfer submit (2-in / 2-out). */
  submitTransfer(connection: Connection, poolAddr: string, calldata: Calldata, kemCiphertext: string, explorerBase: string): Promise<SubmitResult>;
  /** the rail's proven-transfer10x2 submit (10-in / 2-out — every merge leg). */
  submitTransfer10x2(connection: Connection, poolAddr: string, calldata: Calldata, kemCiphertext: string, explorerBase: string): Promise<SubmitResult>;
  /** the rail's proven-withdraw submit; a stealth payout hands the WHOLE core
   *  derivation and the rail maps its announcement half to calldata. */
  submitWithdraw(connection: Connection, poolAddr: string, calldata: Calldata, kemCiphertext: string, explorerBase: string, stealth?: StealthDerivation): Promise<SubmitResult>;
  /** reached only when ctx carries a relayerUrl, and only by the terminal
   *  withdraw leg (@bongtu/client-evm/relayer). */
  submitWithdrawRelayed(relayerUrl: string, calldata: Calldata, kemCiphertext: string, explorerBase: string, stealth?: StealthDerivation): Promise<SubmitResult>;
  /** interval/cap/sleep for the between-legs wait — the wallet's one bounded-poll
   *  policy (refresh.ts), so tests can run a chain without real seconds. */
  poll: PollForActionOptions;
}

/** What every spend must be handed: the app's lock instance, its prover, and the
 *  rail io (the engine has no rail defaults since the split — spread
 *  @bongtu/client-evm/ops EVM_ENTERPRISE_IO at the wiring site). The engine-side
 *  edges (indexer reads, poll policy) default to the real ones. */
export type SpendIo = Pick<
  RunSpendDeps,
  | "keyCache"
  | "prove"
  | "ensureChain"
  | "assertPoolKemEpoch"
  | "submitTransfer"
  | "submitTransfer10x2"
  | "submitWithdraw"
  | "submitWithdrawRelayed"
> &
  Partial<RunSpendDeps>;

const DEFAULT_DEPS: Pick<RunSpendDeps, "getHead" | "getSignedPath" | "poll"> = {
  getHead,
  getSignedPath,
  poll: {},
};

// Each circuit's builder gets exactly the witness its `main` takes; withdraw's
// payee is an L1 address (the proof-bound payout target), and transfer10x2
// serves both the 3–10-note payment and the merge legs.
function buildRequest(
  action: SpendAction,
  identity: WalletIdentity,
  memberships: MembershipWitness[],
  crypto: SpendCrypto,
  withdrawRecipient: string,
) {
  // (withdrawRecipient is ignored by the transfer builders.)
  const { circuit, inputs, to, amount } = action;
  if (circuit === "withdraw") return buildWithdrawRequest(identity, inputs, memberships, amount, crypto, withdrawRecipient);
  if (circuit === "transfer10x2") {
    return buildTransfer10x2Request(identity, inputs, memberships, to, amount, crypto);
  }
  return buildTransferRequest(identity, inputs, memberships, to, amount, crypto);
}

/** Resolve one planned leg (inputs already de-pended by the driver) into the action
 *  that proves it. A merge pays the wallet itself the whole fold; a terminal leg
 *  pays whoever the user typed. */
function legAction(
  step: SpendLeg,
  inputs: WalletInputNote[],
  ctx: SpendContext,
  args: { to?: string; amount: string },
): SpendAction {
  if (step.leg === "merge") {
    return { circuit: "transfer10x2", inputs, to: ctx.sessionPubkey, amount: step.mergedValue };
  }
  return { circuit: step.leg, inputs, to: args.to ?? "", amount: args.amount };
}

/** The enterprise deltas, as the driver's family config: the arbiter KEM-epoch
 *  guard, the SIGNED membership read (a disbursed note lives inside a batch, and
 *  the arbiter indexer only opens a batch slot to the owner who proves it —
 *  routes/path.ts; for single-append leaves the auth is ignored), the enterprise
 *  builders, the pool submits (withdraw optionally relayed), and the arbiter
 *  /notes reload. */
function enterpriseFamily(
  io: RunSpendDeps,
  ctx: SpendContext,
  args: { to?: string; amount: string; stealth?: StealthDerivation; withdrawTo?: string },
): LegChainFamily<WalletIdentity, OwnerNote> {
  return {
    connection: ctx.connection,
    sessionPubkey: ctx.sessionPubkey,
    keyCache: io.keyCache,
    ensureChain: () => io.ensureChain(ctx.connection),
    guardPool: () => io.assertPoolKemEpoch(ctx.connection, ctx.pool),
    refineIdentity: (identity) => identity,
    getHead: () => io.getHead(ctx.indexerUrl),
    readPath: (identity, leafIndex) =>
      io.getSignedPath(ctx.indexerUrl, leafIndex, identity.compressedPubkey, identity.keypair.formattedPrivateKey),
    buildLeg: (step, inputs, identity, memberships): BuiltLeg => {
      // Only the terminal leg is the withdraw the stealth destination (and the
      // user-typed withdrawTo) is for; a merge pays the wallet itself and must
      // never consume either.
      const stealth = step.leg === "merge" ? undefined : args.stealth;
      const withdrawTo = step.leg === "merge" ? undefined : args.withdrawTo;
      const action = legAction(step, inputs, ctx, args);
      const crypto = freshSpendCrypto(randField);
      // Withdraw pays the CONNECTED account by default — byte-for-byte the old
      // money movement, now proof-bound instead of msg.sender-implied. A user-typed
      // destination (withdrawTo) substitutes theirs through the SAME proof-bound
      // param; a stealth run substitutes its freshly derived one-time address.
      const built = buildRequest(
        action, identity, memberships, crypto,
        stealth?.address ?? withdrawTo ?? ctx.connection.address,
      );
      return {
        request: built.request,
        membershipOk: built.meta.membershipOk,
        payeeSalt: crypto.payeeSalt ?? "",
        // The tx carries the SAME encapsulation the proof's kemBinding committed
        // to (crypto.kemCiphertext) — a different ct would decapsulate to
        // mismatching limbs at the arbiter and burn the envelope into an alarm.
        // Withdraw alone may go through the gas-sponsoring relayer
        // (ctx.relayerUrl): its payout target is proof-bound (pub[26]), so a
        // third-party submitter can pay the gas without being able to redirect
        // it. A configured-but-failing relayer THROWS here rather than falling
        // back to the wallet — silently paying gas from the user's own account
        // is the promise the relayer breaks (io/relayer.ts owns that WHY).
        // Merge legs are transfer10x2 and take the non-withdraw branch, so they
        // can never relay by construction.
        submit: (calldata) =>
          action.circuit === "withdraw"
            ? ctx.relayerUrl
              ? io.submitWithdrawRelayed(
                  ctx.relayerUrl, calldata, crypto.kemCiphertext, ctx.explorer, stealth,
                )
              : io.submitWithdraw(
                  // The derivation travels WHOLE: connection.ts maps its
                  // announcement half to calldata, and splitting it here is
                  // exactly the seam where the pays-what-it-announces invariant
                  // could silently break.
                  ctx.connection, ctx.pool, calldata, crypto.kemCiphertext, ctx.explorer, stealth,
                )
            : (action.circuit === "transfer" ? io.submitTransfer : io.submitTransfer10x2)(
                ctx.connection, ctx.pool, calldata, crypto.kemCiphertext, ctx.explorer,
              ),
      };
    },
    prove: io.prove,
    reloadNotes: ctx.reloadNotes,
    poll: io.poll,
  };
}

/**
 * Plan the spend as a chain of transactions and run it through the one driver:
 * for each leg, fetch fresh membership → assemble the witness → prove → submit
 * through the connected wallet, and after a merge leg, wait for the indexer to
 * record the note it created. `onStage` fires as each stage of each leg begins,
 * carrying which leg it is, so the screen can show "Combining (1 of 2)" and then
 * the payment.
 *
 * Throws the same distinct errors the pure libs raise (insufficient balance,
 * membership-stale, the wallet's own rejection) for the UI to show. A chain that
 * fails partway also carries CHAIN_FAILURE_REASSURANCE (the driver's rule),
 * because "your send failed" reads very differently when two transactions already
 * went through.
 */
export async function runSpendChain(
  kind: SpendKind,
  ctx: SpendContext,
  // `stealth` is the core derivation from prepareStealthDestination
  // (stealthKeys.ts), consumed only by the terminal withdraw leg. `withdrawTo`
  // is a user-specified L1 payout address for a plain withdraw (undefined pays
  // the connected account): it rides the same proof-bound recipient param, and
  // because no derivation reaches submitWithdraw, the announcement fields stay
  // the plain-withdraw sentinel (core ZERO_EPHEMERAL) exactly as the default.
  args: { to?: string; amount: string; stealth?: StealthDerivation; withdrawTo?: string },
  onStage: OnSpendStage,
  deps: SpendIo,
): Promise<SpendOutcome> {
  const io: RunSpendDeps = { ...DEFAULT_DEPS, ...deps };
  // Planning is pure and touches nothing, so it happens FIRST: a wallet that cannot
  // afford the amount learns that before it is asked for a signature.
  const plan = planSpendChain(kind, ctx.notes, args.amount);
  const { outcomes } = await runLegChain(plan, plan.length, enterpriseFamily(io, ctx, args), onStage);
  // The terminal leg is the transaction the user asked for: it is what the success
  // screen links and what the post-action refresh polls for.
  return outcomes[outcomes.length - 1] as SpendOutcome;
}

/** What runMergeChain hands back: the single note that now covers the amount —
 *  ready to be the terminal transaction's one input — and the merge transactions
 *  that made it (empty when the balance already held such a note). */
export interface MergeChainResult {
  funding: WalletInputNote;
  mergeTxs: SpendOutcome[];
}

/**
 * Run the merges that put a 1-input terminal transaction within reach: plan with
 * planDisburseChain (plan.ts), then run THE SAME driver runSpendChain runs —
 * stopped one leg short. The terminal leg (payroll's 1-in/256-out disburse) is
 * the CALLER's transaction: this package owns "merge until one note covers the
 * total", the app owns what that note then pays for.
 *
 * `onStage` legs are numbered over merges + 1 — the +1 being the terminal
 * transaction the caller runs next — so one progress rail can show the whole run
 * ("combining 1 of 3 … paying 3 of 3") without the caller re-deriving the count.
 *
 * Throws `insufficient` (planning, before anything is signed) and, once any merge
 * has landed, wraps a later failure with CHAIN_FAILURE_REASSURANCE — the merges
 * that went through are real notes, and a retry plans a shorter chain over them.
 * (With the count including the caller's terminal transaction, every leg the
 * driver actually runs sits in a chain of ≥ 2, so the driver's single-transaction
 * exemption can never strip the reassurance from a landed merge.)
 */
export async function runMergeChain(
  ctx: SpendContext,
  amount: string,
  onStage: OnSpendStage,
  deps: SpendIo,
): Promise<MergeChainResult> {
  const io: RunSpendDeps = { ...DEFAULT_DEPS, ...deps };
  const plan = planDisburseChain(ctx.notes, amount);
  const { outcomes, merged } = await runLegChain(
    plan.merges,
    plan.merges.length + 1, // + the caller's terminal transaction
    enterpriseFamily(io, ctx, { amount }),
    onStage,
  );

  const from = pendingLegOf(plan.funding.leafIndex);
  if (from === null) return { funding: plan.funding, mergeTxs: outcomes };
  const real = merged[from];
  if (!real) throw mergeNotePendingError(from);
  return { funding: real, mergeTxs: outcomes };
}
