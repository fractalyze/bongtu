// prover-cli request/response types.
//
// A ProvingRequest is a COMPLETE, already-resolved circom witness input plus a
// circuit tag. prover-cli is a PURE PROVER (SPEC §6): it turns this witness input
// into a proof. It does NOT parse CSV, resolve ETH addresses to bjj pubkeys, build
// merkle witnesses from chain state, or submit txs — the admin app (apps/, U4) does
// all of that and hands prover-cli a finished input. So every membership witness
// (root/pathElements/leafIndices/enabled) and every ciphertext key (ecdhPrivateKey/
// encryptionNonce/authorityPublicKey) is already present in the request.
//
// The `input` field of each variant is EXACTLY the object the corresponding circom
// `main` consumes — the same shape deploy/e2e_orchestrator.ts and
// deploy/giwa_disburse256.ts assemble by hand today. Field elements are FieldInput
// (bigint | number | string): the prover strifies them to decimal for snarkjs, so a
// request deserialized from JSON (field elements as decimal strings) is accepted
// as-is. Points are [x, y] pairs (PointInput).

import type { FieldInput, PointInput } from "../../sdk/src/babyjub.js";

/** Proving backend. deposit/transfer/withdraw prove on CPU (snarkjs); disburse (1×256,
 *  ~1.66M constraints) proves on GPU (rabbitsnark). `backend` on a request overrides
 *  the per-circuit default in prove.ts. */
export type Backend = "cpu" | "gpu";

/** The four v1 circuits (SPEC §4). */
export type Circuit = "deposit" | "transfer" | "withdraw" | "disburse";

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
  encryptionNonce: FieldInput;
  authorityPublicKey: PointInput; // the pool's stored arbiter key
}

/** transfer (2-in / 2-out): IMT membership + nullifiers; ciphertext rides as public
 *  signals (small base, no subtree gadget / disclosureHash). All outputs share one
 *  ephemeral key + nonce, so output owner pubkeys must be distinct (§11-8 two-time-pad
 *  guard, enforced in prove.ts). A padded input carries nullifier=0, value=0,
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
  outputOwnerPublicKeys: PointInput[]; // length 2 (must be distinct)
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
  encryptionNonce: FieldInput;
  authorityPublicKey: PointInput;
}

/** disburse (1-in / 256-out): IMT membership + one nullifier; subtree gadget +
 *  disclosureHash. All 256 outputs share one ephemeral key + nonce, so their owner
 *  pubkeys must be distinct (§11-8). The single input is always real (enabled=[1]). */
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
  | { circuit: "withdraw"; input: WithdrawInput; backend?: Backend }
  | { circuit: "disburse"; input: DisburseInput; backend?: Backend };

/** The map from a circuit tag to the shape of its `input`. */
export interface CircuitInputs {
  deposit: DepositInput;
  transfer: TransferInput;
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
