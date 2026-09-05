// ops/spend/plan.ts — input shapes, note selection, circuit choice, chain
// planning and the form preview (split from spend.ts; the subpath
// @bongtu/client/spend re-exports everything via index.ts).

import { TRANSFER10_ARITY } from "@bongtu/core/envelope";
import type { ProvingRequest } from "@bongtu/core/proving";

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
export const MAX_INPUT_PADS = TRANSFER10_ARITY - 1;
export const MAX_OUTPUT_PADS = TRANSFER10_ARITY - 2;

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
