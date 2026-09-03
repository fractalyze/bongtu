// Shared consumer-family fixture material — the Stage C companion of
// fixture_lib.ts for the five consumer (no-auditor) circuits (OPMOD §2/§3/§4,
// .dev/op-module-design.md).
//
// The consumer generators (gen_consumer_inputs, gen_consumer_zero_leaf,
// gen_consumer_attack_inputs) and the three consumer gates
// (consumer_receiver_decrypt_check, consumer_disclosure_binding_check,
// consumer_viewtag_canonicality_check) all need the SAME per-recipient
// identities and the SAME deterministic per-output encapsulations: the
// generators write only (viewPub, kemSs limbs) into the witness JSON, while
// the gates additionally need each recipient's view identity (viewPriv +
// kemDk) and the 1088-byte kem ct to run the OPMOD §3.6 discovery pipeline
// against the circuit's real artifacts. Deriving both sides from one shared,
// PRNG-free plan makes that agreement structural, exactly as fixture_lib.ts
// does for the enterprise generators.
//
// Identities here follow the OPMOD §3.1 shape without the wallet's EIP-712
// seed: a consumer identity is (bjj SPEND keypair, bjj note-layer VIEW
// keypair, ML-KEM-768 keypair), every scalar/seed index-derived. Spend keys
// REUSE fixture_lib's receiver(i)/SENDER material where a twin exists — notes
// are untyped, and keeping the spend keys aligned keeps commitments/
// nullifiers comparable across the two families' fixtures.

import { createHash } from "node:crypto";

import type { FieldInput, PointInput } from "@bongtu/core/babyjub";
import { sealConsumerOutput } from "@bongtu/core/consumer";
import type { SealedConsumerOutput } from "@bongtu/core/consumer";
import { ml_kem768 } from "@bongtu/core/kem";
import { deriveKeypair, commitment } from "@bongtu/core/note";
import type { Keypair } from "@bongtu/core/note";

import { ECDH_SK, ENCRYPTION_NONCE, SENDER, receiver, salt } from "./fixture_lib.js";

const sha256 = (label: string): Uint8Array =>
  new Uint8Array(createHash("sha256").update(label).digest());

// --- consumer identities ----------------------------------------------------

/** One consumer party: spend (commitments/nullifiers), note-layer view (ECDH
 *  receiver-ct target) and ML-KEM-768 (the hybrid PQ half). viewPriv/kemDk
 *  together form the OPMOD §3.1 view identity — the gates decrypt with them. */
export interface ConsumerIdentity {
  spend: Keypair;
  view: Keypair;
  kem: { publicKey: Uint8Array; secretKey: Uint8Array };
}

function kemKeygen(tag: string): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return ml_kem768.keygen(
    new Uint8Array([
      ...sha256(`bongtu/consumer-fixture/kem/${tag}/d`),
      ...sha256(`bongtu/consumer-fixture/kem/${tag}/z`),
    ]),
  );
}

function identity(tag: string, spend: Keypair, viewScalar: bigint): ConsumerIdentity {
  return { spend, view: deriveKeypair(viewScalar), kem: kemKeygen(tag) };
}

/** Consumer twin of fixture_lib's receiver(i): same SPEND key, plus an
 *  index-derived view keypair and KEM keypair. */
export function consumerReceiver(i: number): ConsumerIdentity {
  return identity(`receiver/${i}`, receiver(i), 7000000007n + BigInt(i) * 1000033n);
}

/** The consumer SENDER (the spender of every consumer fixture input): the
 *  enterprise SENDER spend key with its own view identity — change notes
 *  encrypt to this (the sender recovers change from chain scan alone). */
export const CONSUMER_SENDER: ConsumerIdentity = identity("sender", SENDER, 8100000011n);

/** A disburse pad identity (OPMOD §4.5): a full, well-formed throwaway —
 *  distinct spend key per slot (never reused across batches), fresh view
 *  identity, fresh KEM keypair. Nothing about a pad is structurally special. */
export function padIdentity(i: number): ConsumerIdentity {
  return identity(
    `pad/${i}`,
    deriveKeypair(6100000019n + BigInt(i) * 1000003n),
    9200000033n + BigInt(i) * 1000039n,
  );
}

// --- deterministic per-output seals ----------------------------------------

/** One planned output note of a consumer fixture. */
export interface OutputPlan {
  value: bigint;
  salt: bigint;
  id: ConsumerIdentity;
}

/** A sealed plan: everything the generator needs (viewPub, kemSs) plus
 *  everything the gates need (kem ct bytes, expected ct/viewTag, receiver key,
 *  commitment) — one deterministic object both sides derive identically. */
export interface SealedPlanOutput {
  plan: OutputPlan;
  seal: SealedConsumerOutput;
  commitment: bigint;
}

/** Deterministic ML-KEM encapsulation randomness for output `i` of fixture
 *  `label` — the consumer analogue of fixture_lib's kemDraw, keyed per output
 *  because the hybrid fold is per-output in this family (OPMOD §3.3). */
export function encapSeed(label: string, i: number): Uint8Array {
  return sha256(`bongtu/consumer-fixture/encap/${label}/${i}`);
}

/** Seal every output of a fixture plan with the shared ephemeral key and the
 *  OPMOD §3.5 nonce rule (encryptionNonce + i, i = the output position). */
export function sealPlan(
  label: string,
  plan: OutputPlan[],
  encryptionNonce: bigint = ENCRYPTION_NONCE,
  ephemeralPriv: bigint = BigInt(ECDH_SK),
): SealedPlanOutput[] {
  return plan.map((p, i) => ({
    plan: p,
    seal: sealConsumerOutput({
      value: p.value,
      salt: p.salt,
      ephemeralPriv,
      viewPub: p.id.view.publicKey,
      kemEk: p.id.kem.publicKey,
      encryptionNonce,
      index: i,
      encapSeed: encapSeed(label, i),
    }),
    commitment: commitment(p.value, p.salt, p.id.spend.publicKey),
  }));
}

// --- fixture output plans (shared: generators write them, gates decrypt them)

/** depositPriv (0-in / 2-out): mint 1000 + 2000 directly to two third-party
 *  recipients — the consumer deposit's whole point (OPMOD §2). */
export function depositPrivPlan(): OutputPlan[] {
  return [
    { value: 1000n, salt: salt(0), id: consumerReceiver(0) },
    { value: 2000n, salt: salt(1), id: consumerReceiver(1) },
  ];
}

/** transferPriv (2-in / 2-out): output 0 = payment, output 1 = change to the
 *  sender's own identity (the pinned output order, consumer transfer base). */
export function transferPrivPlan(): OutputPlan[] {
  return [
    { value: 600n, salt: salt(0), id: consumerReceiver(0) },
    { value: 400n, salt: salt(1), id: CONSUMER_SENDER },
  ];
}

/** transfer10x2Priv (10-in / 2-out): the 4-real-inputs consolidation paying
 *  one payee with change — the enterprise transfer10x2 fixture's twin. */
export function transfer10x2PrivPlan(): OutputPlan[] {
  return [
    { value: 700n, salt: salt(110), id: consumerReceiver(0) },
    { value: 300n, salt: salt(111), id: CONSUMER_SENDER },
  ];
}

/** withdrawPriv (2-in / 1-out): the single output is the CHANGE note, back to
 *  the sender (OPMOD §2: the consumer sender recovers change by scan). */
export function withdrawPrivPlan(): OutputPlan[] {
  return [{ value: 100n, salt: salt(0), id: CONSUMER_SENDER }];
}

/** disbursePriv (1-in / 16-out): 12 funded outputs to distinct recipients plus
 *  4 value-0 PAD slots with distinct throwaway identities (OPMOD §4.5) — the
 *  funded-AND-pad mix the receiver-decrypt parity gate must round-trip. */
export const DISBURSE_PRIV_B = 16;
export const DISBURSE_PRIV_FUNDED = 12;
export function disbursePrivPlan(): OutputPlan[] {
  const funded = Array.from({ length: DISBURSE_PRIV_FUNDED }, (_, i) => ({
    value: 100n + BigInt(i),
    salt: salt(200 + i),
    id: consumerReceiver(i),
  }));
  const pads = Array.from({ length: DISBURSE_PRIV_B - DISBURSE_PRIV_FUNDED }, (_, i) => ({
    value: 0n,
    salt: salt(200 + DISBURSE_PRIV_FUNDED + i),
    id: padIdentity(i),
  }));
  return [...funded, ...pads];
}

// --- witness-input interfaces (local: @bongtu/core/proving grows the module
// --- wire types in a later unit; the circuits are the contract here) --------

export interface ConsumerDepositInput {
  outputCommitments: FieldInput[]; // [2]
  outputValues: FieldInput[];
  outputSalts: FieldInput[];
  outputOwnerPublicKeys: PointInput[]; // SPEND keys (commitment binding)
  outputViewPublicKeys: PointInput[]; // note-layer VIEW keys (receiver cts)
  ecdhPrivateKey: FieldInput;
  kemSs: FieldInput[][]; // [nOutputs][2] per-output LE-uint128 limbs
  encryptionNonce: FieldInput;
}

export interface ConsumerSpendInput {
  nullifiers: FieldInput[];
  inputCommitments: FieldInput[];
  inputValues: FieldInput[];
  inputSalts: FieldInput[];
  inputOwnerPrivateKey: FieldInput;
  ecdhPrivateKey: FieldInput;
  kemSs: FieldInput[][]; // [nOutputs][2]
  root: FieldInput;
  pathElements: FieldInput[][];
  leafIndices: FieldInput[];
  enabled: FieldInput[];
  outputCommitments: FieldInput[];
  outputValues: FieldInput[];
  outputSalts: FieldInput[];
  outputOwnerPublicKeys: PointInput[];
  outputViewPublicKeys: PointInput[];
  encryptionNonce: FieldInput;
}

export interface ConsumerWithdrawInput extends ConsumerSpendInput {
  recipient: FieldInput; // L1 payout address, proof-bound (OPMOD §2)
}

/** The output-side witness fields a sealed plan materializes (spread into the
 *  circuit input object; identical field order across all five circuits). */
export function outputSide(sealed: SealedPlanOutput[]): {
  outputCommitments: bigint[];
  outputValues: bigint[];
  outputSalts: bigint[];
  outputOwnerPublicKeys: PointInput[];
  outputViewPublicKeys: PointInput[];
  kemSs: bigint[][];
} {
  return {
    outputCommitments: sealed.map((s) => s.commitment),
    outputValues: sealed.map((s) => s.plan.value),
    outputSalts: sealed.map((s) => s.plan.salt),
    outputOwnerPublicKeys: sealed.map((s) => s.plan.id.spend.publicKey),
    outputViewPublicKeys: sealed.map((s) => s.plan.id.view.publicKey),
    kemSs: sealed.map((s) => [s.seal.kemSs[0], s.seal.kemSs[1]]),
  };
}
