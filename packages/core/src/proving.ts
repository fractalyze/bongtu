// ProvingRequest / Calldata — the shared proving wire types (TS source of truth).
//
// A ProvingRequest is a COMPLETE, already-resolved circom witness input plus a
// circuit tag. A prover is a PURE PROVER (SPEC §6): it turns this witness input
// into a proof. It does NOT parse CSV, resolve ETH addresses to bjj pubkeys, build
// merkle witnesses from chain state, or submit txs — the apps (payroll-web,
// wallet-web) do all of that and hand the prover a finished input. So every
// membership witness (root/pathElements/leafIndices/enabled) and every ciphertext
// key (ecdhPrivateKey/encryptionNonce/authorityPublicKey) is already present in
// the request.
//
// Two provers consume these types today:
//   - prover/ (top-level, Python FastAPI over rabbitsnark GPU): serves disburse
//     (1×256) over HTTP; prover/prover_service/schema.py MIRRORS this file and
//     must be kept in sync with it.
//   - apps/wallet-web browser snarkjs: proves transfer/withdraw in-page (a
//     self-custody wallet never sends spending-key witnesses to a server).
//
// The `input` field of each variant is EXACTLY the object the corresponding circom
// `main` consumes — the same shape deploy/gates/e2e_orchestrator.ts and the
// deploy/live/ drivers assemble. Field elements are FieldInput
// (bigint | number | string): provers stringify them to decimal for the witness
// calculator, so a request deserialized from JSON (field elements as decimal
// strings) is accepted as-is. Points are [x, y] pairs (PointInput).

import type { FieldInput, PointInput } from "./babyjub.js";

/** Proving backend. deposit/transfer/transfer10/transfer10x2/withdraw prove on
 *  CPU (snarkjs); disburse (1×256, ~2.79M constraints) proves on GPU
 *  (rabbitsnark, via the prover/ service). */
export type Backend = "cpu" | "gpu";

/** The v1 circuits (SPEC §4) plus the two 10-input instantiations of the transfer
 *  base, `transfer10` (10-out) and `transfer10x2` (2-out). */
export type Circuit =
  | "deposit"
  | "transfer"
  | "transfer10"
  | "transfer10x2"
  | "withdraw"
  | "disburse";

// ---------------------------------------------------------------------------
// Per-circuit witness inputs (the exact circom `main` input objects).
// ---------------------------------------------------------------------------

/** deposit (0-in / 2-out): mint. No membership — an authority (auditor) envelope
 *  over both outputs is the only encryption (deposit publishes no per-recipient
 *  ciphertext, so duplicate output owners are harmless here). */
export interface DepositInput {
  outputCommitments: FieldInput[]; // length 2
  outputValues: FieldInput[]; // length 2
  outputSalts: FieldInput[]; // length 2
  outputOwnerPublicKeys: PointInput[]; // length 2
  ecdhPrivateKey: FieldInput; // ephemeral key for the authority envelope
  kemSs: FieldInput[]; // [2] LE-uint128 limbs of the ML-KEM-768 shared secret (hybrid envelope key, @bongtu/core/kem)
  encryptionNonce: FieldInput;
  authorityPublicKey: PointInput; // the pool's stored arbiter key
}

/** transfer (2-in / 2-out): IMT membership + nullifiers; ciphertext rides as public
 *  signals (small base, no subtree gadget / disclosureHash). Receiver ciphertext i is
 *  encrypted under encryptionNonce + i (§11-8 v1.1), so duplicate output owners are
 *  fine — self-send is allowed. A padded input carries nullifier=0, value=0,
 *  enabled=0, pathElements=zeros. */
export interface TransferInput {
  nullifiers: FieldInput[]; // length 2 (0 for a padded input)
  inputCommitments: FieldInput[]; // length 2
  inputValues: FieldInput[]; // length 2
  inputSalts: FieldInput[]; // length 2
  inputOwnerPrivateKey: FieldInput; // one owner spends both real inputs
  ecdhPrivateKey: FieldInput;
  root: FieldInput; // membership root (a live pool root)
  pathElements: FieldInput[][]; // [2][H] merkle siblings
  leafIndices: FieldInput[]; // [2]
  enabled: FieldInput[]; // [2] 0/1 (contract re-derives, but the witness needs it)
  outputCommitments: FieldInput[]; // length 2
  outputValues: FieldInput[]; // length 2
  outputSalts: FieldInput[]; // length 2
  outputOwnerPublicKeys: PointInput[]; // length 2 (duplicates allowed: per-output nonce)
  kemSs: FieldInput[]; // [2] LE-uint128 limbs of the ML-KEM-768 shared secret (hybrid envelope key, @bongtu/core/kem)
  encryptionNonce: FieldInput;
  authorityPublicKey: PointInput;
}

/** transfer10 (10-in / 10-out): the SAME base as transfer (`ZetoTransferSmall`) at
 *  arity 10 — 261,683 constraints, 141 public signals. It exists so one tx can
 *  consolidate up to ten notes instead of chaining 2-in self-sends, and can fan
 *  out to ten payees. Every field is the transfer field at length 10: unused
 *  input slots are padded (nullifier=0, value=0, enabled=0, zeros path, a
 *  nonzero value-0 commitment) and unused output slots carry value 0. Receiver
 *  ciphertext i is encrypted under encryptionNonce + i (§11-8 v1.1), so
 *  duplicate output owners are fine — a self-merge, where every output is the
 *  sender's own key, is the headline use. */
export interface Transfer10Input {
  nullifiers: FieldInput[]; // length 10 (0 for a padded input)
  inputCommitments: FieldInput[]; // length 10
  inputValues: FieldInput[]; // length 10
  inputSalts: FieldInput[]; // length 10
  inputOwnerPrivateKey: FieldInput; // one owner spends every real input
  ecdhPrivateKey: FieldInput;
  root: FieldInput; // membership root (a live pool root)
  pathElements: FieldInput[][]; // [10][H] merkle siblings
  leafIndices: FieldInput[]; // [10]
  enabled: FieldInput[]; // [10] 0/1 (contract re-derives, but the witness needs it)
  outputCommitments: FieldInput[]; // length 10
  outputValues: FieldInput[]; // length 10
  outputSalts: FieldInput[]; // length 10
  outputOwnerPublicKeys: PointInput[]; // length 10 (duplicates allowed: per-output nonce)
  kemSs: FieldInput[]; // [2] LE-uint128 limbs of the ML-KEM-768 shared secret (hybrid envelope key, @bongtu/core/kem)
  encryptionNonce: FieldInput;
  authorityPublicKey: PointInput;
}

/** transfer10x2 (10-in / 2-out): the SAME base as transfer at 10 inputs but only
 *  TWO outputs — 212,386 constraints, 68 public signals. Output arity is what a
 *  spend pays for on chain (every output is a depth-32 IMT leaf append), and
 *  transfer10's eight surplus outputs are zero-value padding on a real spend:
 *  the two here are the two a spend needs, output 0 the payment (or, for a pure
 *  merge, the merged note) and output 1 the change (zero when nothing is left
 *  over). The input side is identical to Transfer10Input — unused slots padded
 *  (nullifier=0, value=0, enabled=0, zeros path, a nonzero value-0 commitment).
 *  Both outputs may share an owner (§11-8 v1.1 per-output nonce), which is what
 *  makes the merge shape legal. */
export interface Transfer10x2Input {
  nullifiers: FieldInput[]; // length 10 (0 for a padded input)
  inputCommitments: FieldInput[]; // length 10
  inputValues: FieldInput[]; // length 10
  inputSalts: FieldInput[]; // length 10
  inputOwnerPrivateKey: FieldInput; // one owner spends every real input
  ecdhPrivateKey: FieldInput;
  root: FieldInput; // membership root (a live pool root)
  pathElements: FieldInput[][]; // [10][H] merkle siblings
  leafIndices: FieldInput[]; // [10]
  enabled: FieldInput[]; // [10] 0/1 (contract re-derives, but the witness needs it)
  outputCommitments: FieldInput[]; // length 2
  outputValues: FieldInput[]; // length 2 — [payment, change]
  outputSalts: FieldInput[]; // length 2
  outputOwnerPublicKeys: PointInput[]; // length 2 (duplicates allowed: per-output nonce)
  kemSs: FieldInput[]; // [2] LE-uint128 limbs of the ML-KEM-768 shared secret (hybrid envelope key, @bongtu/core/kem)
  encryptionNonce: FieldInput;
  authorityPublicKey: PointInput;
}

/** withdraw (2-in / 1-out): IMT membership + nullifiers; ERC-20 out. One change
 *  output (value may be 0 for a full withdrawal). Authority envelope over the spend. */
export interface WithdrawInput {
  nullifiers: FieldInput[]; // length 2 (0 for a padded input)
  inputCommitments: FieldInput[]; // length 2
  inputValues: FieldInput[]; // length 2
  inputSalts: FieldInput[]; // length 2
  inputOwnerPrivateKey: FieldInput;
  root: FieldInput;
  pathElements: FieldInput[][]; // [2][H]
  leafIndices: FieldInput[]; // [2]
  enabled: FieldInput[]; // [2] 0/1
  outputCommitments: FieldInput[]; // length 1 (the change note)
  outputValues: FieldInput[]; // length 1
  outputSalts: FieldInput[]; // length 1
  outputOwnerPublicKeys: PointInput[]; // length 1
  ecdhPrivateKey: FieldInput;
  kemSs: FieldInput[]; // [2] LE-uint128 limbs of the ML-KEM-768 shared secret (hybrid envelope key, @bongtu/core/kem)
  encryptionNonce: FieldInput;
  authorityPublicKey: PointInput;
  /** L1 address the pool pays (public input, uint160 range) — bound in-proof
   *  so a relayer cannot redirect a stealth withdraw. */
  recipient: FieldInput;
}

/** disburse (1-in / 256-out): IMT membership + one nullifier; subtree gadget +
 *  disclosureHash. All 256 outputs share one ephemeral key + nonce, so their owner
 *  pubkeys must be distinct (§11-8 — the prover MUST reject duplicates). The single
 *  input is always real (enabled=[1]). */
export interface DisburseInput {
  nullifiers: FieldInput[]; // length 1
  inputCommitments: FieldInput[]; // length 1
  inputValues: FieldInput[]; // length 1
  inputSalts: FieldInput[]; // length 1
  inputOwnerPrivateKey: FieldInput;
  ecdhPrivateKey: FieldInput;
  root: FieldInput;
  pathElements: FieldInput[][]; // [1][H]
  leafIndices: FieldInput[]; // [1]
  enabled: FieldInput[]; // [1] == [1]
  outputCommitments: FieldInput[]; // length 256
  outputValues: FieldInput[]; // length 256
  outputSalts: FieldInput[]; // length 256
  outputOwnerPublicKeys: PointInput[]; // length 256 (must be distinct)
  kemSs: FieldInput[]; // [2] LE-uint128 limbs of the ML-KEM-768 shared secret (hybrid envelope key, @bongtu/core/kem)
  encryptionNonce: FieldInput;
  authorityPublicKey: PointInput;
}

// ---------------------------------------------------------------------------
// The tagged request union + the calldata result.
// ---------------------------------------------------------------------------

/** A complete, resolved proving request: circuit tag + its exact witness input,
 *  plus an optional backend override. */
export type ProvingRequest =
  | { circuit: "deposit"; input: DepositInput; backend?: Backend }
  | { circuit: "transfer"; input: TransferInput; backend?: Backend }
  | { circuit: "transfer10"; input: Transfer10Input; backend?: Backend }
  | { circuit: "transfer10x2"; input: Transfer10x2Input; backend?: Backend }
  | { circuit: "withdraw"; input: WithdrawInput; backend?: Backend }
  | { circuit: "disburse"; input: DisburseInput; backend?: Backend };

/** The map from a circuit tag to the shape of its `input`. */
export interface CircuitInputs {
  deposit: DepositInput;
  transfer: TransferInput;
  transfer10: Transfer10Input;
  transfer10x2: Transfer10x2Input;
  withdraw: WithdrawInput;
  disburse: DisburseInput;
}

/** Groth16 proof in snarkjs `exportSolidityCallData` form (the G2 inner-swap on `b`
 *  is already applied), plus the public signals. Every value is a `"0x…"` 32-byte
 *  hex string, ready to splat into a BongtuPool verifier call `(a, b, c, pub)`. */
export interface Calldata {
  a: [string, string];
  b: [[string, string], [string, string]];
  c: [string, string];
  pub: string[];
}

// ---------------------------------------------------------------------------
// The wire encoding.
// ---------------------------------------------------------------------------

/**
 * THE producer-side wire encoding: recursively replace every bigint leaf with its
 * decimal-string form, so the value survives JSON.stringify (JSON has no bigints)
 * and every consumer — snarkjs' witness calculator, the prover service
 * (schema.py), a written inputs/*.json fixture — accepts it as-is. FieldInput
 * admits `string`, so the result still satisfies the same declared shape: apply
 * it to a ProvingRequest (or a bare circuit input object) right before
 * stringifying. Non-bigint leaves (numbers, strings, null) pass through
 * untouched; wire bytes are pinned in proving.test.ts.
 */
// Leaves are expected to be bigint: only bigint converts to a decimal string;
// number/string leaves pass through untouched (producers build all-bigint
// inputs — a non-canonical string here would reach the wire as-is).
export function toWire<T>(v: T): T {
  if (typeof v === "bigint") return v.toString() as unknown as T;
  if (Array.isArray(v)) return v.map(toWire) as unknown as T;
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v)) o[k] = toWire((v as Record<string, unknown>)[k]);
    return o as unknown as T;
  }
  return v;
}
