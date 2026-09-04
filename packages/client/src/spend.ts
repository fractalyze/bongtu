// PURE wallet-side witness assembly for the CPU circuits the public app proves in
// the browser: transfer (2-in / 2-out), transfer10x2 (10-in / 2-out) and withdraw
// (2-in / 1-out), SPEC §4 / §7. Framework- and network-free so the exact code runs
// in the browser view AND the headless spend-witness gate. It imports the sdk crypto
// DIRECTLY, so every commitment / nullifier is byte-identical to what snarkjs proves
// and the contract verifies — the witness objects produced here are EXACTLY the
// circom `main` inputs deploy/gates/e2e_orchestrator.ts assembles by hand, in
// ProvingRequest form (@bongtu/core/proving).
//
// What it does NOT do (SPEC §6 boundary): it does not prove (browser snarkjs, see
// prove.ts) and does not send the tx (the wallet, see connection.ts). It stops at "a
// valid transfer/transfer10x2/withdraw ProvingRequest", ready to prove and submit.
//
// ARITY, and who picks it. Every circuit here takes a FIXED number of inputs — 2 for
// transfer/withdraw, 10 for transfer10x2 — so a spend that needs fewer pads the rest
// with {nullifier:0, value:0, enabled:0, path:zeros}: the contract-derived enabled=0
// disables that slot's membership and the §5.2 value-belt forces its value to 0 (no
// mint). The wallet PICKS the circuit from how many notes the payment needs
// (planSpendAction): ≤2 notes stay on the cheap 2×2 transfer, 3–10 go to transfer10x2,
// and a withdraw — which has no arity-10 circuit — stays at 2. All of them emit their
// ciphertext as circuit outputs (public signals), so — unlike disburse — the wallet
// assembles NO separate ciphertext blob; the tx is just (a, b, c, pub, kemCiphertext).
//
// WHEN THE ARITY IS NOT ENOUGH, the wallet does not stop and ask the user to go merge
// their notes first. planSpendChain plans the WHOLE way through: however many
// transfer10x2 self-sends it takes to fold the balance down to something the terminal
// circuit can spend, then the payment or withdrawal itself. One plan, run as one
// flow — see spendFlow.runSpendChain.
//
// TRANSFER10 IS DEPRECATED (user decision 2026-07-28): the 10-in/10-OUT circuit
// stays deployed on chain, but the wallet never routes to it — every >2-input spend
// AND every merge leg proves transfer10x2 (10-in / 2-OUT), because an output is a
// depth-32 IMT append and transfer10 paid for eight zero-value pads every time.
// buildTransfer10Request below survives only for the committed transfer10 e2e
// driver; nothing reachable from the wallet UI produces a "transfer10" request.

import {
  deriveKeypair,
  commitment,
  nullifier,
} from "@bongtu/core/note";
import { ml_kem768, kemSsToLimbs, kemHexToBytes, kemBytesToHex } from "@bongtu/core/kem";
import { ARBITER_KEM_PK, ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y, H } from "@bongtu/core/network";
import { unpackPubkey } from "@bongtu/core/pubkey";
import { foldToRoot } from "@bongtu/core/imt";
import { TRANSFER10_ARITY } from "@bongtu/core/envelope";
import type { Point } from "@bongtu/core/babyjub";
import { toWire } from "@bongtu/core/proving";
import type {
  TransferInput,
  Transfer10Input,
  Transfer10x2Input,
  WithdrawInput,
  ProvingRequest,
} from "@bongtu/core/proving";
import type { WalletIdentity } from "@bongtu/client/derive";

// --- app-facing input shapes (all field elements as decimal strings) ------------

/** An unspent note the wallet owns, as surfaced by the balance view. The wallet is
 *  the owner, so the spending key is the derived identity — not carried per note. */
export interface WalletInputNote {
  value: string;
  salt: string;
  leafIndex: number;
}

/** What note selection picks from: the balance view's notes (a structural subset
 *  of the indexer's OwnerNote, so `/notes` results feed in directly). */
export interface SelectableNote {
  value: string;
  salt: string;
  leafIndex: number;
  spent: boolean;
}

/** Membership of one input note against the live root (from GET /path/{leafIndex}). */
export interface MembershipWitness {
  root: string;
  /** length-H (32) merkle siblings of the note against `root`. */
  pathElements: string[];
  leafIndex: number;
}

/** Fresh per-tx crypto material. `ecdhPrivateKey`/`encryptionNonce` must never be
 *  reused across txs (a shared ephemeral key + nonce is a two-time pad). */
export interface SpendCrypto {
  ecdhPrivateKey: string;
  encryptionNonce: string;
  /** the pool's stored arbiter PUBLIC key — the authority envelope target (§6b v2). */
  authorityPubKey: [string, string];
  /** ML-KEM-768 shared-secret limbs (decimal) — the PQ half of the hybrid
   *  envelope key, a fresh encapsulation per tx (pq-envelope-design.md §5). */
  kemSs: [string, string];
  /** the matching 1088-byte encapsulation ciphertext, 0x-hex — the tx's
   *  `bytes kemCiphertext` calldata arg. */
  kemCiphertext: string;
  /** salt for the change note back to the wallet. */
  changeSalt: string;
  /** salts for the padded (value-0) input slots — one per slot the spend does not
   *  fill, so no two pads land on the same commitment. A 2-arity spend of one note
   *  uses the first; transfer10x2 can use all nine. */
  padSalts: string[];
  /** transfer/transfer10x2: salt for the payment output to the recipient (a merge's
   *  merged note is this output, paid to the wallet itself). */
  payeeSalt?: string;
  /** DEPRECATED transfer10 only: salts for its 8 zero-value output slots after
   *  payment + change. transfer10x2 has no output pads (its 2 outputs are the 2 a
   *  spend needs); still drawn so the retained transfer10 builder keeps working. */
  outputPadSalts: string[];
}

/** Pad slots a spend can have to fill: 9 unused inputs (arity 10, one real note)
 *  and — for the deprecated transfer10 builder only — 8 unused outputs. Drawn on
 *  every spend so one SpendCrypto bundle serves whichever builder runs. */
const MAX_INPUT_PADS = TRANSFER10_ARITY - 1;
const MAX_OUTPUT_PADS = TRANSFER10_ARITY - 2;

export interface SpendMeta {
  /** recomputed input commitments (real inputs then, if padded, the value-0 note). */
  inputCommitments: string[];
  /** nullifiers per input (0 for the padded input). */
  nullifiers: string[];
  enabled: string[];
  realInputCount: number;
  inputTotal: string;
  /** transfer: amount paid to the recipient. withdraw: ERC20 amount out. */
  amount: string;
  changeValue: string;
  /** every real input's path folds to the shared root. */
  membershipOk: boolean;
  outputCommitments: string[];
  outputValues: string[];
}

/** The circuits a spend can land on. transfer10x2 is picked only when the payment
 *  genuinely needs 3–10 notes — its zkey is ~3x the 2×2 one to download. The
 *  deprecated "transfer10" is deliberately NOT a member: the type is the routing
 *  pin that keeps the wallet off the 10-output circuit for good. */
export type SpendCircuit = "transfer" | "transfer10x2" | "withdraw";

export interface SpendResult<C extends ProvingRequest["circuit"]> {
  request: Extract<ProvingRequest, { circuit: C }>;
  meta: SpendMeta;
}

// --- note selection + per-tx crypto ---------------------------------------------

/** Why a selection cannot go ahead, in the two shapes that get answered differently:
 *  `insufficient` — the wallet simply does not hold enough, which only a smaller
 *  amount fixes; `needs-merge` — it does hold enough, but across more notes than
 *  ONE transaction can spend. Only the first reaches the user: `needs-merge` is
 *  planSpendChain's signal to itself that another merge leg is needed. */
export type SpendBlocker = "insufficient" | "needs-merge";

/** A selection failure carrying WHICH of the two it is, so the caller can tell a
 *  wallet that cannot afford the amount from one that just needs another leg. */
export class SpendSelectionError extends Error {
  constructor(
    readonly blocker: SpendBlocker,
    message: string,
  ) {
    super(message);
    this.name = "SpendSelectionError";
  }
}

/** Unspent notes, largest value first (leafIndex breaks ties for determinism). */
function unspentLargestFirst(notes: readonly SelectableNote[]): SelectableNote[] {
  return [...notes]
    .filter((n) => !n.spent)
    .sort((a, b) => {
      const d = BigInt(b.value) - BigInt(a.value); // value descending…
      return d > 0n ? 1 : d < 0n ? -1 : a.leafIndex - b.leafIndex; // …then leafIndex for determinism
    });
}

const pickNote = (n: SelectableNote): WalletInputNote => ({
  value: n.value,
  salt: n.salt,
  leafIndex: n.leafIndex,
});

/**
 * Pick which unspent notes fund a payment of `amount` — the wallet's coin
 * selection, PURE. Amount-aware largest-first cover with at most `maxArity` notes
 * (the circuit's fixed input count; unused slots are padded): take notes in
 * descending value until they cover the amount. Largest-first is optimal here —
 * if ANY k notes cover the amount, the largest k do — so a selection that
 * overruns `maxArity` proves no k-note cover exists at all.
 *
 * Distinct failures so the UI can say the right thing:
 *   - no spendable notes at all (balance not loaded / everything spent);
 *   - `insufficient`: the whole unspent total is below the amount;
 *   - `needs-merge`: the balance suffices but is spread over more than
 *     `maxArity` notes — the user must consolidate first.
 */
export function selectInputNotes(
  notes: readonly SelectableNote[],
  amount: string,
  maxArity = 2,
): WalletInputNote[] {
  const amt = ((): bigint => {
    try {
      return BigInt(amount);
    } catch {
      throw new Error(`amount must be a positive integer, got ${JSON.stringify(amount)}`);
    }
  })();
  if (amt <= 0n) throw new Error(`amount must be a positive integer, got ${amt}`);

  const unspent = unspentLargestFirst(notes);
  if (unspent.length === 0) {
    throw new SpendSelectionError("insufficient", "no spendable notes. Load your balance first");
  }

  const chosen: WalletInputNote[] = [];
  const covered = unspent.reduce<bigint>((sum, n) => {
    if (sum >= amt) return sum;
    chosen.push(pickNote(n));
    return sum + BigInt(n.value);
  }, 0n);
  if (covered >= amt && chosen.length <= maxArity) return chosen;

  const total = unspent.reduce((s, n) => s + BigInt(n.value), 0n);
  if (total < amt) {
    throw new SpendSelectionError(
      "insufficient",
      `insufficient balance: amount ${amt} exceeds unspent total ${total}`,
    );
  }
  const bestCover = unspent.slice(0, maxArity).reduce((s, n) => s + BigInt(n.value), 0n);
  throw new SpendSelectionError(
    "needs-merge",
    `amount ${amt} needs more than ${maxArity} notes (the largest ${maxArity} cover ${bestCover}); ` +
      `this spend takes at most ${maxArity} input notes — merge your notes or split the payment first`,
  );
}

// --- circuit choice (the wallet's auto-pick) -------------------------------------

/** The kinds of value-moving spend the wallet runs. A merge is not one of them: it is
 *  never something the user asks for, only a leg inside a chain (planSpendChain). */
export type SpendKind = "transfer" | "withdraw";

/** A resolved spend: which circuit proves it, which notes it consumes, who is paid
 *  and how much — everything the flow needs before it touches the network. */
export interface SpendAction {
  circuit: SpendCircuit;
  inputs: WalletInputNote[];
  /** compressed bjj pubkey of the payee; the wallet's own for a merge, unused by
   *  withdraw (whose only output is the change note). */
  to: string;
  amount: string;
}

/** How many input notes each terminal circuit can spend at once. */
export const terminalArity = (kind: SpendKind): number =>
  kind === "withdraw" ? 2 : TRANSFER10_ARITY;

/**
 * Resolve ONE transaction to its circuit and its input notes — the wallet's circuit
 * AUTO-PICK, PURE and the single place the rule lives:
 *
 *   transfer  ≤2 notes  -> transfer     (the cheap 2×2 zkey, ~29 MB)
 *   transfer  3–10 notes-> transfer10x2 (~95 MB, fetched only when needed)
 *   withdraw  ≤2 notes  -> withdraw     (there is no withdraw10 circuit)
 *
 * Throws SpendSelectionError when the amount does not fit that arity — which is not
 * a dead end for the user: planSpendChain below answers it by planning the merges
 * that make it fit.
 */
export function planSpendAction(
  kind: SpendKind,
  notes: readonly SelectableNote[],
  args: { to?: string; amount: string },
): SpendAction {
  const { amount } = args;
  if (kind === "withdraw") {
    return { circuit: "withdraw", inputs: selectInputNotes(notes, amount, 2), to: "", amount };
  }
  const inputs = selectInputNotes(notes, amount, TRANSFER10_ARITY);
  return { circuit: inputs.length > 2 ? "transfer10x2" : "transfer", inputs, to: args.to ?? "", amount };
}

/** Sum of a selection's note values, as a decimal string. */
function totalValue(inputs: readonly WalletInputNote[]): string {
  return inputs.reduce((s, n) => s + BigInt(n.value), 0n).toString();
}

// --- the spend CHAIN (merges, then the payment) ----------------------------------

/**
 * One transaction of a spend. A `merge` leg is a transfer10x2 self-send that folds
 * its inputs into a single note worth `mergedValue` (zero change); the last leg is
 * the payment or withdrawal the user actually asked for, and names its own circuit.
 */
export type SpendLeg =
  | { leg: "merge"; inputs: WalletInputNote[]; mergedValue: string }
  | { leg: SpendCircuit; inputs: WalletInputNote[] };

/** Which circuit proves a leg (a merge is always the 10-in/2-out transfer10x2 —
 *  never the deprecated 10-out transfer10). */
export const legCircuit = (leg: SpendLeg): SpendCircuit =>
  leg.leg === "merge" ? "transfer10x2" : leg.leg;

/**
 * The leafIndex a PLAN gives the note a merge leg will create. That note does not
 * exist yet — it gets a real leaf only once its transaction lands — so the plan
 * marks it with a negative index naming the leg that produces it, and the runner
 * substitutes the real note before building the leg that spends it.
 */
export const pendingLeaf = (legIndex: number): number => -(legIndex + 1);

/** The merge leg a pending input is waiting on, or null for a real note. */
export const pendingLegOf = (leafIndex: number): number | null =>
  leafIndex < 0 ? -leafIndex - 1 : null;

/**
 * Plan the WHOLE way from the balance the wallet holds to the payment the user asked
 * for: zero or more merge legs, then the terminal spend. PURE and deterministic — the
 * same notes and amount always give the same legs, which is what lets the confirm
 * sheet promise a number of approvals before anything is signed.
 *
 * The rule is "merge only as far as you must". Each merge folds the ten largest notes
 * of the working set into one, and planning STOPS the moment the amount is coverable
 * within the terminal circuit's arity — so a 20-note wallet spending an amount its
 * top 19 notes cover takes one merge, and only a near-full-balance spend takes two.
 * In general a wallet of N notes needs ⌈(N - arity) / 9⌉ merges at worst (each merge
 * turns 10 notes into 1, a net loss of 9).
 *
 * Throws the `insufficient` SpendSelectionError — before planning a single leg —
 * when the wallet simply does not hold the amount. It never throws `needs-merge`:
 * that blocker is exactly what this function exists to answer.
 */
export function planSpendChain(
  kind: SpendKind,
  notes: readonly SelectableNote[],
  amount: string,
): SpendLeg[] {
  const arity = terminalArity(kind);
  const legs: SpendLeg[] = [];

  // Bounded by construction: every pass either returns or replaces ≥2 notes with 1,
  // so the working set strictly shrinks until one note holds the whole balance.
  const plan = (working: SelectableNote[]): SpendLeg[] => {
    try {
      // selectInputNotes owns the amount validation and the `insufficient` verdict,
      // and it runs BEFORE any merge is planned — a wallet that cannot afford the
      // amount is told so, not offered a chain that would not help.
      const inputs = selectInputNotes(working, amount, arity);
      const circuit: SpendCircuit =
        kind === "withdraw" ? "withdraw" : inputs.length > 2 ? "transfer10x2" : "transfer";
      legs.push({ leg: circuit, inputs });
      return legs;
    } catch (e) {
      if (!(e instanceof SpendSelectionError) || e.blocker !== "needs-merge") throw e;
    }

    const fold = working.slice(0, TRANSFER10_ARITY);
    const mergedValue = totalValue(fold);
    legs.push({ leg: "merge", inputs: fold.map(pickNote), mergedValue });
    // The folded notes leave the working set and the note they will become takes
    // their place, so the next pass plans against what the wallet will actually hold.
    return plan(unspentLargestFirst([
      { value: mergedValue, salt: "", leafIndex: pendingLeaf(legs.length - 1), spent: false },
      ...working.slice(TRANSFER10_ARITY),
    ]));
  };
  return plan(unspentLargestFirst(notes));
}

/** A merge leg on its own — what planDisburseChain emits, since a disburse chain's
 *  terminal transaction (the 1-in/256-out disburse) is the APP's leg, not this
 *  package's. */
export type MergeLeg = Extract<SpendLeg, { leg: "merge" }>;

/** The way from the balance a payroll wallet holds to the ONE note a disburse can
 *  spend: the merge legs to run first (possibly none), then which note funds the
 *  terminal 1-input transaction — a real note, or (leafIndex < 0, see pendingLeaf)
 *  the note the LAST merge leg will create. */
export interface DisburseChainPlan {
  merges: MergeLeg[];
  funding: WalletInputNote;
}

/**
 * Plan the merges that put a payroll disburse within reach. The terminal disburse
 * circuit spends exactly ONE input note (SPEC §4, 1-in / B-out), so the plan folds
 * — ten largest notes at a time, each fold a transfer10x2 self-send exactly like a
 * wallet merge — until a single note covers `amount`. PURE and deterministic, same
 * ground as planSpendChain; the difference is the terminal leg: a disburse is the
 * app's own transaction (payroll's builder + submit), so the plan hands back the
 * funding note instead of a terminal SpendLeg.
 *
 * "Merge only as far as you must" holds here too: a wallet whose largest note
 * already covers the amount plans ZERO merges, and planning stops the moment a
 * fold's total does. Throws the `insufficient` SpendSelectionError — before any
 * leg is planned — when the whole balance is below the amount; never `needs-merge`
 * (that verdict is exactly what the merges answer).
 */
export function planDisburseChain(
  notes: readonly SelectableNote[],
  amount: string,
): DisburseChainPlan {
  const merges: MergeLeg[] = [];

  // Bounded by construction: every pass either returns or replaces ≥2 notes with
  // 1, so the working set strictly shrinks until one note holds the whole balance.
  const plan = (working: SelectableNote[]): DisburseChainPlan => {
    try {
      // selectInputNotes at arity 1 owns the amount validation and the
      // `insufficient` verdict — a wallet that cannot afford the payroll is told
      // so before any merge is planned.
      const [funding] = selectInputNotes(working, amount, 1);
      return { merges, funding };
    } catch (e) {
      if (!(e instanceof SpendSelectionError) || e.blocker !== "needs-merge") throw e;
    }

    const fold = working.slice(0, TRANSFER10_ARITY);
    const mergedValue = totalValue(fold);
    merges.push({ leg: "merge", inputs: fold.map(pickNote), mergedValue });
    return plan(unspentLargestFirst([
      { value: mergedValue, salt: "", leafIndex: pendingLeaf(merges.length - 1), spent: false },
      ...working.slice(TRANSFER10_ARITY),
    ]));
  };
  return plan(unspentLargestFirst(notes));
}

/** What the Send/Withdraw form shows while the user types. */
export interface SpendPreview {
  /** Which circuit's one-time key the screen should be fetching: the FIRST leg's,
   *  because that is the proof the user waits on next (every merge is transfer10x2). */
  circuit: SpendCircuit;
  /** The only thing that can still block a spend outright: not holding enough. */
  blocker: SpendBlocker | null;
  /** Transactions this spend takes — one wallet approval each. 1 is the plain case. */
  legCount: number;
  /** How many unspent notes the balance is currently spread across. */
  pieces: number;
}

/**
 * What the Send/Withdraw form needs on every keystroke: which circuit this amount
 * would use (so the screen can start the right one-time zkey download) and how many
 * transactions it would take (so the confirm sheet can say so). Never throws — an
 * amount that is empty or unparseable is simply "not decided yet": the default
 * circuit and no blocker, since the form's own amountError already says what is
 * wrong with it.
 */
export function previewSpend(
  kind: SpendKind,
  notes: readonly SelectableNote[],
  amount: string,
): SpendPreview {
  const pieces = unspentLargestFirst(notes).length;
  const fallback: SpendCircuit = kind === "withdraw" ? "withdraw" : "transfer";
  try {
    const legs = planSpendChain(kind, notes, amount);
    return { circuit: legCircuit(legs[0]), blocker: null, legCount: legs.length, pieces };
  } catch (e) {
    const blocker = e instanceof SpendSelectionError ? e.blocker : null;
    return { circuit: fallback, blocker, legCount: 1, pieces };
  }
}

/** A fresh field element (decimal string) per call — the injectable randomness
 *  behind `freshSpendCrypto` (the platform CSPRNG via `randField` below; a
 *  deterministic double in tests). */
export type RandField = () => string;

// Fresh per-tx field randomness, from the platform CSPRNG. A shared ephemeral ECDH key
// + nonce across outputs of ONE tx is fine; reuse ACROSS txs is a two-time pad, so both
// spend and deposit draw fresh values every action.
export function randField(): string {
  const b = new Uint8Array(31); // < 2^248, safely under the field prime
  crypto.getRandomValues(b);
  const x = b.reduce<bigint>((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
  return (x === 0n ? 1n : x).toString();
}

/** One ML-KEM encapsulation result in wire form: witness limbs + tx ct. */
export interface KemMaterial {
  kemSs: [string, string];
  kemCiphertext: string;
}

/** The injectable KEM draw behind fresh{Spend,Deposit}Crypto — real
 *  encapsulation in the browser, a deterministic double in tests. */
export type KemDrawFn = () => KemMaterial;

/**
 * Fresh ML-KEM-768 encapsulation against the institutional arbiter key
 * (ARBITER_KEM_PK — the pool stores its keccak256 per epoch). One encapsulation
 * PER TX: reusing a ct across ops collapses the PQ compartment
 * (pq-envelope-design.md §6), so this is drawn alongside the ECDH ephemeral in
 * every fresh crypto bundle. noble's encapsulate uses the platform CSPRNG.
 */
export function freshKemMaterial(): KemMaterial {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(kemHexToBytes(ARBITER_KEM_PK));
  const [l0, l1] = kemSsToLimbs(sharedSecret);
  return { kemSs: [l0.toString(), l1.toString()], kemCiphertext: kemBytesToHex(cipherText) };
}

/**
 * Clamp a fresh field draw to a valid Poseidon-encryption nonce. Every circuit's
 * `SymmetricEncrypt` constrains `nonce < 2^128` (zeto encrypt.circom — the nonce
 * shares a Poseidon state slot with `messageLength * 2^128`), so a full-width
 * field draw fails witness generation with "Assert Failed … SymmetricEncrypt".
 * Masking to the low 128 bits keeps the draw uniform.
 */
export function toEncryptionNonce(fieldDraw: string): string {
  return (BigInt(fieldDraw) & ((1n << 128n) - 1n)).toString();
}

/**
 * Draw the fresh per-tx crypto material for one spend. Every draw is a NEW field
 * element from `rand`: sharing the ephemeral ECDH key + nonce across outputs of
 * ONE tx is fine, but reuse ACROSS txs is a two-time pad — so callers draw a
 * whole fresh SpendCrypto per spend. The authority target is the pool's stored
 * arbiter PUBLIC key (§6b v2): the contract injects the same key from storage
 * before verifying, so a different target fails the proof. `drawKem` adds the
 * fresh per-tx ML-KEM encapsulation (hybrid envelope, injectable for tests).
 *
 * The pad salts are drawn for the WIDEST arity (transfer10x2) on every spend, so one
 * bundle serves whichever circuit the auto-pick lands on — a 2×2 spend simply uses
 * the first of them. Drawing 21 field elements is microseconds next to the proof.
 */
export function freshSpendCrypto(rand: RandField, drawKem: KemDrawFn = freshKemMaterial): SpendCrypto {
  const kem = drawKem();
  return {
    ecdhPrivateKey: rand(),
    encryptionNonce: toEncryptionNonce(rand()),
    authorityPubKey: [ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y],
    kemSs: kem.kemSs,
    kemCiphertext: kem.kemCiphertext,
    changeSalt: rand(),
    padSalts: Array.from({ length: MAX_INPUT_PADS }, () => rand()),
    payeeSalt: rand(),
    outputPadSalts: Array.from({ length: MAX_OUTPUT_PADS }, () => rand()),
  };
}

// --- helpers -------------------------------------------------------------------

// The membership witness shared by every spending circuit: recompute each real
// input's commitment + nullifier from the wallet key, pad the remaining slots up to
// the circuit's arity with value-0 notes, and fold every real input to the shared
// root. Exported (not just used here) because the consumer builders
// (consumerBuild.ts) spend the SAME untyped notes — the input-side algebra is
// family-shared by construction, so reusing this function keeps it that way.
export interface AssembledInputs {
  nullifiers: bigint[];
  inputCommitments: bigint[];
  inputValues: bigint[];
  inputSalts: bigint[];
  enabled: bigint[];
  pathElements: bigint[][];
  leafIndices: bigint[];
  root: bigint;
  inputTotal: bigint;
  membershipOk: boolean;
}

export function assembleInputs(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  padSalts: string[],
  arity: number,
): AssembledInputs {
  if (inputs.length < 1 || inputs.length > arity) {
    throw new Error(`this spend takes 1 to ${arity} input notes, got ${inputs.length}`);
  }
  if (memberships.length !== inputs.length) {
    throw new Error(`need one membership witness per input: ${memberships.length} != ${inputs.length}`);
  }
  const padCount = arity - inputs.length;
  if (padSalts.length < padCount) {
    throw new Error(`need ${padCount} pad salts for a ${inputs.length}-of-${arity} spend, got ${padSalts.length}`);
  }
  const self = identity.keypair;
  const zeros: bigint[] = new Array(H).fill(0n);

  // All real inputs must be proven against ONE root (the live root). Take it from the
  // first membership and require the rest agree.
  const root = BigInt(memberships[0].root);
  for (const m of memberships) {
    if (BigInt(m.root) !== root) throw new Error("all input memberships must share one root");
    if (m.pathElements.length !== H) {
      throw new Error(`pathElements must have length ${H}, got ${m.pathElements.length}`);
    }
  }

  const nullifiers: bigint[] = [];
  const inputCommitments: bigint[] = [];
  const inputValues: bigint[] = [];
  const inputSalts: bigint[] = [];
  const enabled: bigint[] = [];
  const pathElements: bigint[][] = [];
  const leafIndices: bigint[] = [];
  const { inputTotal, membershipOk } = inputs.reduce(
    (acc, note, i) => {
      const v = BigInt(note.value);
      const s = BigInt(note.salt);
      if (v < 0n) throw new Error(`input #${i + 1} value must be non-negative, got ${v}`);
      const c = commitment(v, s, self.publicKey);
      const nf = nullifier(v, s, self.formattedPrivateKey);
      const path = memberships[i].pathElements.map((x) => BigInt(x));
      const pathOk = foldToRoot(c, path, memberships[i].leafIndex) === root;
      nullifiers.push(nf);
      inputCommitments.push(c);
      inputValues.push(v);
      inputSalts.push(s);
      enabled.push(1n);
      pathElements.push(path);
      leafIndices.push(BigInt(memberships[i].leafIndex));
      return { inputTotal: acc.inputTotal + v, membershipOk: acc.membershipOk && pathOk };
    },
    { inputTotal: 0n, membershipOk: true },
  );

  // Pad the unused slots with value-0 notes owned by the wallet: nullifier 0,
  // enabled 0, zeros path (membership disabled; the value belt forces value 0 -> no
  // mint), each on its OWN salt so no two pads share a commitment. This is the
  // convention the committed circuits/fixtures/inputs/transfer10x2_merge.json (and
  // transfer10.json) fixtures carry.
  for (const i of Array(padCount).keys()) {
    const s = BigInt(padSalts[i]);
    nullifiers.push(0n);
    inputCommitments.push(commitment(0n, s, self.publicKey));
    inputValues.push(0n);
    inputSalts.push(s);
    enabled.push(0n);
    pathElements.push([...zeros]);
    leafIndices.push(0n);
  }

  return {
    nullifiers,
    inputCommitments,
    inputValues,
    inputSalts,
    enabled,
    pathElements,
    leafIndices,
    root,
    inputTotal,
    membershipOk,
  };
}

// --- transfer (2-in / 2-out) ----------------------------------------------------

/**
 * Assemble a transfer ProvingRequest: spend 1–2 of the wallet's notes, pay
 * `recipientCompressed` `amount`, send the change back to the wallet. Value is
 * conserved (sum(real inputs) == amount + change). The two output owners MAY
 * coincide (a self-send): the transfer circuit encrypts receiver ciphertext i
 * under encryptionNonce + i (§11-8 v1.1, U-X3), so duplicate owners no longer
 * share a keystream — the old two-time-pad rejection applies only to the
 * shared-nonce disburse path.
 *
 * Throws on: a bad input count, a malformed recipient pubkey, amount <= 0,
 * amount exceeding the input total, or a wrong-length path.
 */
export function buildTransferRequest(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipientCompressed: string,
  amount: string,
  crypto: SpendCrypto,
): SpendResult<"transfer"> {
  if (crypto.payeeSalt === undefined) throw new Error("transfer needs crypto.payeeSalt for the payment output");
  const self = identity.keypair;
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, 2);

  const payee = parsePayee(recipientCompressed);
  const payVal = BigInt(amount);
  if (payVal <= 0n) throw new Error(`transfer amount must be positive, got ${payVal}`);
  if (payVal > ins.inputTotal) {
    throw new Error(`amount ${payVal} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - payVal;

  // Fixed output order, mirrored by the circuit's per-output nonces: output 0 =
  // payment (recipient), output 1 = change (wallet). recipient == self is legal.
  const outputOwnerPublicKeys: Point[] = [payee, self.publicKey];
  const payeeSalt = BigInt(crypto.payeeSalt);
  const changeSalt = BigInt(crypto.changeSalt);
  const outputValues = [payVal, changeVal];
  const outputSalts = [payeeSalt, changeSalt];
  const outputCommitments = [
    commitment(payVal, payeeSalt, payee),
    commitment(changeVal, changeSalt, self.publicKey),
  ];

  const inputBig: TransferInput = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: self.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  const request = { circuit: "transfer", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: spendMeta(ins, payVal.toString(), changeVal.toString(), outputCommitments, outputValues),
  };
}

// --- transfer10x2 (10-in / 2-out) -------------------------------------------------

/** The recipient's point from its compressed form, with a message that names the
 *  field the user typed rather than the crypto that rejected it. */
function parsePayee(recipientCompressed: string): Point {
  try {
    return unpackPubkey(recipientCompressed.trim());
  } catch (e) {
    throw new Error(`recipient pubkey invalid: ${(e as Error).message}`);
  }
}

/**
 * Assemble a transfer10x2 ProvingRequest: spend 1–10 of the wallet's notes, pay
 * `recipientCompressed` `amount`, send the change back to the wallet. The input
 * side is buildTransfer10Request's exactly — extra slots padded (nullifier 0,
 * value 0, enabled 0, zeros path, a value-0 self-owned commitment) — but there
 * are only TWO outputs, the two a spend needs: output 0 the payment, output 1
 * the change. That is the whole point of the circuit: an output is a depth-32
 * IMT append, and transfer10's eight zero-value output pads were pure gas.
 *
 * The two uses, both through this one builder (the shape the committed
 * circuits/fixtures/inputs/transfer10x2_merge.json fixture carries):
 *   - a payment needing 3–10 notes (recipient = the payee, change back home);
 *   - a self-merge (recipient = the wallet's own address, amount = the full
 *     input total), which lands everything in ONE note with a ZERO-value change
 *     note — zero change is legal, the commitment is still nonzero.
 * Duplicate output owners are safe: receiver ciphertext i is encrypted under
 * encryptionNonce + i (§11-8 v1.1), so the shared-keystream ban that applies to
 * disburse does not apply here.
 */
export function buildTransfer10x2Request(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipientCompressed: string,
  amount: string,
  crypto: SpendCrypto,
): SpendResult<"transfer10x2"> {
  if (crypto.payeeSalt === undefined) throw new Error("transfer10x2 needs crypto.payeeSalt for the payment output");
  const self = identity.keypair;
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, TRANSFER10_ARITY);

  const payee = parsePayee(recipientCompressed);
  const payVal = BigInt(amount);
  if (payVal <= 0n) throw new Error(`transfer amount must be positive, got ${payVal}`);
  if (payVal > ins.inputTotal) {
    throw new Error(`amount ${payVal} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - payVal;

  // Fixed output order, mirrored by the circuit's per-output nonces: output 0 =
  // payment (or the merged note), output 1 = change (value 0 for a full-total
  // merge — still a real note on its own salt).
  const outputOwnerPublicKeys: Point[] = [payee, self.publicKey];
  const payeeSalt = BigInt(crypto.payeeSalt);
  const changeSalt = BigInt(crypto.changeSalt);
  const outputValues = [payVal, changeVal];
  const outputSalts = [payeeSalt, changeSalt];
  const outputCommitments = [
    commitment(payVal, payeeSalt, payee),
    commitment(changeVal, changeSalt, self.publicKey),
  ];

  const inputBig: Transfer10x2Input = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: self.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  const request = { circuit: "transfer10x2", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: spendMeta(ins, payVal.toString(), changeVal.toString(), outputCommitments, outputValues),
  };
}

// --- transfer10 (10-in / 10-out) — DEPRECATED -------------------------------------

/**
 * @deprecated The wallet routes NOTHING here anymore (user decision 2026-07-28):
 * transfer10 stays deployed on chain, but every >2-input spend and every merge
 * leg proves transfer10x2 above. Kept only for the committed
 * live driver of the (now deprecated) V4 entrypoint used.
 *
 * Assemble a transfer10 ProvingRequest: spend 1–10 of the wallet's notes, pay
 * `recipientCompressed` `amount`, send the change back to the wallet. Same shape as
 * buildTransferRequest at arity 10 — the extra input slots are padded (nullifier 0,
 * value 0, enabled 0, zeros path, a value-0 self-owned commitment) and the extra
 * OUTPUT slots are real value-0 notes back to the wallet, which is exactly what the
 * committed circuits/fixtures/inputs/transfer10.json fixture carries.
 *
 * The two uses, both through this one builder:
 *   - a payment needing 3–10 notes (recipient = the payee);
 *   - a self-merge (recipient = the wallet's own address, amount = the full input
 *     total), which lands everything in ONE note and leaves 9 value-0 notes behind.
 * Duplicate output owners are safe: receiver ciphertext i is encrypted under
 * encryptionNonce + i (§11-8 v1.1), so the shared-keystream ban that applies to
 * disburse does not apply here.
 */
export function buildTransfer10Request(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipientCompressed: string,
  amount: string,
  crypto: SpendCrypto,
): SpendResult<"transfer10"> {
  if (crypto.payeeSalt === undefined) throw new Error("transfer10 needs crypto.payeeSalt for the payment output");
  const self = identity.keypair;
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, TRANSFER10_ARITY);

  const payee = parsePayee(recipientCompressed);
  const payVal = BigInt(amount);
  if (payVal <= 0n) throw new Error(`transfer amount must be positive, got ${payVal}`);
  if (payVal > ins.inputTotal) {
    throw new Error(`amount ${payVal} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - payVal;

  const padCount = TRANSFER10_ARITY - 2;
  if (crypto.outputPadSalts.length < padCount) {
    throw new Error(`transfer10 needs ${padCount} outputPadSalts, got ${crypto.outputPadSalts.length}`);
  }
  // Fixed output order, mirrored by the circuit's per-output nonces: output 0 =
  // payment, output 1 = change, outputs 2..9 = value-0 notes back to the wallet.
  const outputOwnerPublicKeys: Point[] = [
    payee,
    ...Array.from({ length: padCount + 1 }, () => self.publicKey),
  ];
  const outputValues = [payVal, changeVal, ...Array.from({ length: padCount }, () => 0n)];
  const outputSalts = [
    BigInt(crypto.payeeSalt),
    BigInt(crypto.changeSalt),
    ...crypto.outputPadSalts.slice(0, padCount).map((s) => BigInt(s)),
  ];
  const outputCommitments = outputValues.map((v, i) => commitment(v, outputSalts[i], outputOwnerPublicKeys[i]));

  const inputBig: Transfer10Input = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: self.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  const request = { circuit: "transfer10", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: spendMeta(ins, payVal.toString(), changeVal.toString(), outputCommitments, outputValues),
  };
}

// --- withdraw (2-in / 1-out) ----------------------------------------------------

/**
 * Assemble a withdraw ProvingRequest: spend 1–2 of the wallet's notes, push `amount`
 * of the underlying ERC-20 to the caller, keep the remainder as a change note. The
 * circuit's `out` public = sum(inputs) - sum(outputs) = amount, so change = total -
 * amount. A full withdrawal leaves a value-0 change note (its commitment is still
 * non-zero, so the contract accepts the append).
 *
 * Throws on: a bad input count, amount <= 0, amount exceeding the input total, or a
 * wrong-length path.
 */
export function buildWithdrawRequest(
  identity: WalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  amount: string,
  crypto: SpendCrypto,
  recipient: string,
): SpendResult<"withdraw"> {
  const recipientBig = BigInt(recipient);
  if (recipientBig === 0n || recipientBig > (1n << 160n) - 1n) {
    throw new Error(`withdraw recipient must be a nonzero L1 address, got ${recipient}`);
  }
  const self = identity.keypair;
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, 2);

  const out = BigInt(amount);
  if (out <= 0n) throw new Error(`withdraw amount must be positive, got ${out}`);
  if (out > ins.inputTotal) throw new Error(`amount ${out} exceeds spendable input total ${ins.inputTotal}`);
  const changeVal = ins.inputTotal - out;

  const changeSalt = BigInt(crypto.changeSalt);
  const outputValues = [changeVal];
  const outputSalts = [changeSalt];
  const outputCommitments = [commitment(changeVal, changeSalt, self.publicKey)];
  const outputOwnerPublicKeys: Point[] = [self.publicKey];

  const inputBig: WithdrawInput = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: self.formattedPrivateKey,
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
    recipient: recipientBig,
  };

  const request = { circuit: "withdraw", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: spendMeta(ins, out.toString(), changeVal.toString(), outputCommitments, outputValues),
  };
}

// --- shared meta ----------------------------------------------------------------
// (wire decimalisation is sdk toWire — byte-equality with the old per-field
// serializers pinned on the committed fixtures before the swap)

function spendMeta(
  ins: AssembledInputs,
  amount: string,
  changeValue: string,
  outputCommitments: bigint[],
  outputValues: bigint[],
): SpendMeta {
  return {
    inputCommitments: ins.inputCommitments.map((x) => x.toString()),
    nullifiers: ins.nullifiers.map((x) => x.toString()),
    enabled: ins.enabled.map((x) => x.toString()),
    realInputCount: ins.enabled.filter((e) => e === 1n).length,
    inputTotal: ins.inputTotal.toString(),
    amount,
    changeValue,
    membershipOk: ins.membershipOk,
    outputCommitments: outputCommitments.map((x) => x.toString()),
    outputValues: outputValues.map((x) => x.toString()),
  };
}
