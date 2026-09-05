// The ONE leg-chain driver behind the three chain runners — runSpendChain and
// runMergeChain (./spend/run.ts) and consumerRunSpendChain (./consumer/run.ts) —
// and the ONE guard sequence behind the two deposits (./deposit.ts runDeposit,
// ./consumer/run.ts consumerRunDeposit). Before this file, the loop was written
// three times and the deposit guards twice, held in sync by a comment listing
// "the deltas, exactly"; that list is now the FAMILY CONFIG each runner supplies,
// and everything family-INVARIANT lives here exactly once:
//
//   - the leg loop and its stage grammar (unlock → assemble → prove → submit,
//     and the "waiting" pause after a merge leg);
//   - the per-leg session guard ORDER: align the chain, run the family's pool
//     guard if it has one, then take the spending key from the lock — nothing
//     is read, proven or submitted before the unlock's session-account check
//     resolves, and it re-runs per LEG so an account switched midway blocks the
//     remaining transactions rather than signing them with someone else's key
//     (test/accountBinding.test.ts);
//   - the pending-note protocol: a plan marks a merge's future note with a
//     negative leafIndex (pendingLegOf), and the driver substitutes the real
//     note the earlier leg created;
//   - the merge wait (awaitMergedNote): the value+salt+owner → commitment rule
//     that identifies the note a merge created, polled through the family's
//     note reload until it has a real leaf to prove membership against;
//   - the partial-failure reassurance rule: a one-transaction run fails exactly
//     as it always did (count === 1 passes the cause through raw, code and all),
//     while a chain that already landed legs wraps the wallet's classified
//     words with CHAIN_FAILURE_REASSURANCE;
//   - the deposit guard sequence: amount parse → family precheck → chain align →
//     pool guard → token-state read → affordability → unlock → exact-V approve
//     (skipped when the allowance covers V) → prove → submit, with the
//     approve-landed reassurance rule (DEPOSIT_FAILURE_REASSURANCE).
//
// What a family supplies (the old delta list, as code): the pool guard's
// PRESENCE (enterprise: the arbiter KEM-epoch check; consumer: none — there is
// no chain-vouched authority key to guard), the membership read (signed
// getSignedPath vs open getPath), the builder mapping per picked circuit, the
// submit per circuit (with its crypto and routing closed over), and the note
// reload (arbiter /notes vs a self-scan pass).
//
// The reload seam is deliberately NARROW (issue #27's enabler): the driver
// touches only commitment / spent / leafIndex of a reloaded note
// (MergedNoteView below), which OwnerNote and ScanNote both satisfy
// structurally — the two note shapes stay distinct, and neither is restructured
// to share a loop.

import { commitment } from "@bongtu/core/note";
import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import {
  walletErrorMessage,
  type Connection,
  type SubmitResult,
  type TokenState,
} from "@bongtu/client/rail";
import type { KeyCacheLike } from "@bongtu/client/keyCache";
import type { WalletIdentity } from "@bongtu/client/derive";
import { pollUntil, type PollForActionOptions } from "@bongtu/client/refresh";
import {
  pendingLegOf,
  type MembershipWitness,
  type SpendLeg,
  type WalletInputNote,
} from "./spend/plan.js";

// ------------------------------ stage grammar --------------------------------

/** The coarse stages a spend leg passes through (no witness sub-stage — witness is
 *  ~150 ms and invisible; the multi-second cost is the proof). "unlock" is the
 *  signature that hands over the spending key, and fires ONLY when the wallet is
 *  locked — an unlocked wallet starts at "assemble". "waiting" is the pause after a
 *  merge leg, while the note source catches up enough for the next leg to be built. */
export type SpendStage = "unlock" | "assemble" | "prove" | "submit" | "waiting";

/** Which transaction of the chain is reporting, and how many there are in total. */
export interface LegProgress {
  index: number;
  count: number;
}

/** How a run reports itself: a stage, and the leg it belongs to. */
export type OnSpendStage = (stage: SpendStage, leg: LegProgress) => void;

export interface SpendOutcome {
  txHash: string;
  explorerUrl: string;
}

/** The coarse stages a deposit passes through. "unlock" is the signature that hands
 *  over the spending key and fires ONLY when the wallet is locked; "approve" is
 *  SKIPPED (no tx) when the pool allowance already covers V; "prove" is the
 *  multi-second in-browser proof. */
export type DepositStage = "unlock" | "approve" | "prove" | "submit";

// --------------------------- money-state wording -----------------------------

/** What a chain says when a leg fails partway through. The money is the point: no
 *  payment left the wallet, and the merges that DID land are not undone — retrying
 *  simply plans a shorter chain over the notes that are now fewer. */
export const CHAIN_FAILURE_REASSURANCE =
  "Nothing was sent. Your balance is unchanged, and already-combined pieces stay combined.";

export const MERGE_NOT_INDEXED_MESSAGE =
  "The network has not recorded your combined note yet. Try again in a moment.";

/** What a deposit says when it fails AFTER its approve tx landed. Same money-state
 *  rule as CHAIN_FAILURE_REASSURANCE: name what stands (the approval) and what
 *  didn't move (every token). */
export const DEPOSIT_FAILURE_REASSURANCE =
  "No kKRW left your account. The approval stays in place and is reused when you retry.";

// ---------------------------- the leg-chain driver ---------------------------

/** The three fields of a reloaded note the merge wait reads — the issue #27 seam:
 *  OwnerNote (arbiter /notes) and ScanNote (self-scan) both satisfy this
 *  structurally, so the driver is note-shape-blind by construction. */
export interface MergedNoteView {
  commitment: string;
  leafIndex: number;
  spent: boolean;
}

/** What a family's builder hands back for one leg: the request to prove, the
 *  staleness verdict, the salt that will identify a merge leg's output note, and
 *  the circuit-matched submit with its per-tx crypto and routing closed over. */
export interface BuiltLeg {
  request: ProvingRequest;
  /** false => the selected notes went stale between plan and build. */
  membershipOk: boolean;
  /** the payment output's salt ("" when the circuit has none, e.g. withdraw). */
  payeeSalt: string;
  submit(calldata: Calldata): Promise<SubmitResult>;
}

/** One family's deltas, exactly — everything runLegChain does not own. */
export interface LegChainFamily<Id extends WalletIdentity, Note extends MergedNoteView> {
  connection: Connection;
  /** the logged-in session's compressed bjj pubkey the unlock must reproduce. */
  sessionPubkey: string;
  /** the wallet's lock — holds the spending key between actions (keyCache.ts). */
  keyCache: KeyCacheLike;
  /** put the wallet on the live chain (silent when already there). */
  ensureChain(): Promise<void>;
  /** the family's pool guard, run after the chain align and BEFORE the unlock.
   *  Enterprise: refuse a pool whose arbiter KEM key the chain does not vouch
   *  for. Consumer: ABSENT — outputs seal to each recipient's registered
   *  triple, not to a chain-vouched authority key, so the guard has no subject. */
  guardPool?: () => Promise<void>;
  /** narrow the unlocked identity to what the family's builders need (consumer:
   *  require the view/KEM half; enterprise: the identity as-is). */
  refineIdentity(identity: WalletIdentity): Id;
  getHead(): Promise<{ root: string }>;
  /** the membership read: signed getSignedPath (enterprise — the arbiter indexer
   *  only opens a batch slot to the proven owner) vs open getPath (consumer —
   *  /path is served openly, no owner key leaves the leg). */
  readPath(identity: Id, leafIndex: number): Promise<{ siblings: string[] }>;
  /** map the planned leg to its family circuit, build the ProvingRequest, and
   *  bind the matching submit. `inputs` are the step's inputs with every
   *  pending note already resolved to the real one an earlier merge created. */
  buildLeg(
    step: SpendLeg,
    inputs: WalletInputNote[],
    identity: Id,
    memberships: MembershipWitness[],
  ): BuiltLeg;
  /** Turn a ProvingRequest into Groth16 calldata (the APP supplies this). */
  prove(request: ProvingRequest): Promise<Calldata>;
  /** the between-legs note reload: arbiter /notes (enterprise) vs a self-scan
   *  pass (consumer) — only MergedNoteView's three fields are read. */
  reloadNotes(): Promise<Note[]>;
  /** interval/cap/sleep for the between-legs wait (refresh.ts), so tests can
   *  run a chain without real seconds. */
  poll: PollForActionOptions;
}

/**
 * The guards that must pass before ANY read, proof or submit, in this order: align
 * the chain, run the family's pool guard, then take the spending key from the
 * wallet's lock — one signature the first time, reused after that, and refused
 * outright when the account selected in the connected wallet is no longer this
 * session's (keyCache.ts). Re-run per LEG, so an account switched midway through a
 * chain blocks the remaining transactions rather than signing them with someone
 * else's key.
 *
 * The "unlock" stage is announced up front when the wallet is locked, so the
 * progress list never has to step backwards into a popup it didn't predict.
 */
async function openSession<Id extends WalletIdentity, Note extends MergedNoteView>(
  family: LegChainFamily<Id, Note>,
  onStage: OnSpendStage,
  leg: LegProgress,
): Promise<Id> {
  const locked = !family.keyCache.isUnlocked();
  onStage(locked ? "unlock" : "assemble", leg);
  await family.ensureChain();
  await family.guardPool?.();
  // Nothing is read, proven or submitted before this resolves; the key leaves via
  // the built request only as witness input to the injected prover.
  const identity = family.refineIdentity(
    await family.keyCache.unlock(family.connection, family.sessionPubkey),
  );
  if (locked) onStage("assemble", leg);
  return identity;
}

/** Resolve a plan's inputs: notes the plan left pending are the real notes earlier
 *  merge legs have since created (the pendingLegOf protocol, spend/plan.ts). */
/** The one wording for "a planned input references a merge leg that has not
 *  landed yet" — the driver resolves chain-internal inputs with it, and
 *  runMergeChain's funding-note resolution (its caller-side seam) reuses it
 *  so the protocol string cannot drift. */
export const mergeNotePendingError = (fromLeg: number): Error =>
  new Error(`merge leg ${fromLeg + 1} has not produced its note yet`);

function resolveInputs(
  planned: WalletInputNote[],
  merged: readonly (WalletInputNote | undefined)[],
): WalletInputNote[] {
  return planned.map((n) => {
    const from = pendingLegOf(n.leafIndex);
    if (from === null) return n;
    const real = merged[from];
    if (!real) throw mergeNotePendingError(from);
    return real;
  });
}

// Membership witnesses are fetched freshly per leg, because each leg moves the
// root; only the read itself (signed vs open) is the family's.
async function fetchMemberships<Id extends WalletIdentity, Note extends MergedNoteView>(
  family: LegChainFamily<Id, Note>,
  identity: Id,
  inputs: WalletInputNote[],
): Promise<MembershipWitness[]> {
  const head = await family.getHead();
  const memberships: MembershipWitness[] = [];
  for (const n of inputs) {
    const p = await family.readPath(identity, n.leafIndex);
    memberships.push({ root: head.root, pathElements: p.siblings, leafIndex: n.leafIndex });
  }
  return memberships;
}

/** Wait for the family's note source to record the note a merge leg created, and
 *  answer with it — its leaf index is what the next leg proves membership against.
 *  The wanted note is output 0 of the merge, worth the whole fold, owned by the
 *  wallet, on the salt this run drew for it. */
async function awaitMergedNote<Id extends WalletIdentity, Note extends MergedNoteView>(
  family: LegChainFamily<Id, Note>,
  identity: Id,
  mergedValue: string,
  payeeSalt: string,
): Promise<WalletInputNote> {
  const wanted = commitment(
    BigInt(mergedValue),
    BigInt(payeeSalt),
    identity.keypair.publicKey,
  ).toString();
  const seen = (notes: Note[]): Note | undefined =>
    notes.find((n) => n.commitment === wanted && !n.spent);
  const { last } = await pollUntil(family.reloadNotes, (ns) => seen(ns) !== undefined, family.poll);
  const note = last ? seen(last) : undefined;
  if (!note) throw new Error(MERGE_NOT_INDEXED_MESSAGE);
  return { value: mergedValue, salt: payeeSalt, leafIndex: note.leafIndex };
}

/** What one driver run hands back: every landed transaction in leg order, and the
 *  real notes the merge legs created (indexed by leg, the pendingLegOf protocol) —
 *  runMergeChain resolves its funding note from the latter. */
export interface LegChainRun {
  outcomes: SpendOutcome[];
  merged: (WalletInputNote | undefined)[];
}

/**
 * Run a planned chain of legs: for each, open the session (guards re-run per leg),
 * fetch fresh membership, build through the family, prove, submit, and after a
 * merge leg wait for the note it created. `count` is the total the progress rail
 * shows — legs.length for a whole chain, merges + 1 when the terminal transaction
 * is the CALLER's (runMergeChain: the driver stopped one leg short).
 *
 * Failure keeps the money-state rule in one place: when count === 1 the cause
 * passes through raw (a raw provider rejection keeps its code for the app's own
 * walletErrorMessage); any longer chain wraps the wallet's classified words with
 * CHAIN_FAILURE_REASSURANCE, because "your send failed" reads very differently
 * when transactions already went through.
 */
export async function runLegChain<Id extends WalletIdentity, Note extends MergedNoteView>(
  legs: SpendLeg[],
  /** total transactions the RUN reports (drives leg numbering AND gates the
   *  count===1 reassurance exemption). INVARIANT: count >= legs.length —
   *  understating it would silently strip CHAIN_FAILURE_REASSURANCE from a
   *  multi-leg chain, so the driver refuses (runMergeChain passes merges+1,
   *  runSpendChain passes the full leg count). */
  count: number,
  family: LegChainFamily<Id, Note>,
  onStage: OnSpendStage,
): Promise<LegChainRun> {
  if (count < legs.length) {
    throw new Error(`runLegChain: count ${count} understates the chain's ${legs.length} legs`);
  }
  const merged: (WalletInputNote | undefined)[] = [];
  const outcomes: SpendOutcome[] = [];

  for (const index of Array(legs.length).keys()) {
    const leg: LegProgress = { index, count };
    const step = legs[index];
    try {
      const identity = await openSession(family, onStage, leg);
      const inputs = resolveInputs(step.inputs, merged);
      const memberships = await fetchMemberships(family, identity, inputs);
      const built = family.buildLeg(step, inputs, identity, memberships);
      if (!built.membershipOk) {
        throw new Error("Your balance just changed. Go back and try again.");
      }
      onStage("prove", leg);
      const calldata = await family.prove(built.request);
      onStage("submit", leg);
      const res = await built.submit(calldata);
      outcomes.push({ txHash: res.txHash, explorerUrl: res.explorerUrl });
      if (step.leg === "merge") {
        onStage("waiting", leg);
        merged[index] = await awaitMergedNote(family, identity, step.mergedValue, built.payeeSalt);
      }
    } catch (e) {
      // A one-transaction run fails exactly as it always did — the reassurance is
      // about the legs a chain may already have landed, and would only confuse here.
      if (count === 1) throw e;
      throw new Error(`${walletErrorMessage(e)} ${CHAIN_FAILURE_REASSURANCE}`);
    }
  }
  return { outcomes, merged };
}

// -------------------------- the deposit guard driver -------------------------

/**
 * Cheap PURE precheck the deposit guard sequence runs right after reading token
 * state: a deposit of `V` raw units cannot succeed if it exceeds the depositor's
 * public kKRW `balance` (the pool pulls exactly V via safeTransferFrom, which
 * would revert). Throwing here — BEFORE the approve tx and the multi-second
 * proof — mirrors selectInputNotes (ops/spend/plan.ts) rejecting an over-spend.
 */
export function assertDepositAffordable(V: bigint, balance: bigint): void {
  if (V > balance) {
    throw new Error(`insufficient kKRW balance: deposit ${V} exceeds balance ${balance}`);
  }
}

/** What a family's deposit builder hands back: the request to prove and the
 *  submit with its per-tx crypto (the envelope/seal material) closed over. */
export interface BuiltDeposit {
  request: ProvingRequest;
  submit(calldata: Calldata): Promise<SubmitResult>;
}

/** One deposit family's deltas — everything runGuardedDeposit does not own. */
export interface DepositFamily<Id extends WalletIdentity> {
  connection: Connection;
  sessionPubkey: string;
  keyCache: KeyCacheLike;
  ensureChain(): Promise<void>;
  /** the family's pool guard (enterprise: KEM epoch; consumer: absent) — run
   *  FIRST among the network guards: a pool that can never accept this build's
   *  proof is not worth an approve tx, a popup, or a proof. */
  guardPool?: () => Promise<void>;
  /** family precheck before ANY token motion (consumer: probe the recipient
   *  triple — a doomed deposit must not waste an approve tx). */
  precheck?: () => void;
  refineIdentity(identity: WalletIdentity): Id;
  /** the rail's token-state read: balance + allowance to the escrow (view). */
  readTokenState(): Promise<TokenState>;
  /** the rail's exact-amount ERC-20 approve to the POOL escrow; resolves after
   *  the receipt. */
  approveToken(amount: bigint): Promise<unknown>;
  /** build the family's deposit ProvingRequest and bind its submit. */
  buildDeposit(identity: Id, amount: string): BuiltDeposit;
  /** Turn a ProvingRequest into Groth16 calldata (the APP supplies this). */
  prove(request: ProvingRequest): Promise<Calldata>;
}

export interface GuardedDepositOutcome {
  txHash: string;
  explorerUrl: string;
  /** the minted value V (raw kKRW units). */
  amount: string;
  /** whether an ERC-20 approve tx was sent (false when the allowance covered V). */
  approved: boolean;
}

/**
 * The ONE deposit guard sequence, cheapest-first and all of it before the approve
 * tx: parse the amount, run the family precheck, align the chain, run the family's
 * pool guard, read token state, refuse an unaffordable V, then the unlock — whose
 * session-account check resolves BEFORE the approve tx so a mid-session account
 * switch costs the user nothing (minting into a stranger's key must never be
 * preceded by an approve the user paid gas for). The approve submits exactly V,
 * ONLY when the current allowance is below it; the stage still fires either way so
 * the UI shows it advancing.
 *
 * Failure keeps the money-state rule in one place: once the approve tx has landed,
 * a later failure wraps the wallet's classified words with
 * DEPOSIT_FAILURE_REASSURANCE (an approval went through but nothing moved, and it
 * is reused on retry); with no approve landed the cause passes through raw.
 */
export async function runGuardedDeposit<Id extends WalletIdentity>(
  amountRaw: string,
  family: DepositFamily<Id>,
  onStage: (stage: DepositStage) => void,
): Promise<GuardedDepositOutcome> {
  const amount = amountRaw.trim();
  const V = BigInt(amount);
  if (V <= 0n) throw new Error(`deposit amount must be positive, got ${V}`);
  family.precheck?.();

  // Announce the signature stage up front when the wallet is locked, so the
  // progress list never has to step backwards into a popup it didn't predict.
  const locked = !family.keyCache.isUnlocked();
  onStage(locked ? "unlock" : "approve");
  await family.ensureChain();
  await family.guardPool?.();
  const { balance, allowance } = await family.readTokenState();
  assertDepositAffordable(V, balance);
  const identity = family.refineIdentity(
    await family.keyCache.unlock(family.connection, family.sessionPubkey),
  );
  if (locked) onStage("approve");
  const approved = allowance < V;
  if (approved) {
    await family.approveToken(V);
  }

  try {
    onStage("prove");
    const built = family.buildDeposit(identity, amount);
    const calldata = await family.prove(built.request);
    onStage("submit");
    const res = await built.submit(calldata);
    return { txHash: res.txHash, explorerUrl: res.explorerUrl, amount, approved };
  } catch (e) {
    if (!approved) throw e;
    throw new Error(`${walletErrorMessage(e)} ${DEPOSIT_FAILURE_REASSURANCE}`);
  }
}
