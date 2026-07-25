// PURE employer-mode assembly (SPEC §7 employer-mode, §6 prover contract).
//
// This module owns the whole "recipients + input note + membership -> a complete
// disburse ProvingRequest + the on-chain ciphertext blob" job. It is
// FRAMEWORK-FREE and side-effect-free so the exact same code runs in the browser
// view and in test/assemble.test.ts. It imports the sdk crypto DIRECTLY (not a
// copy), so every commitment / nullifier / Poseidon-sponge ciphertext is
// byte-identical to what the prover service proves and the contract verifies.
//
// What it does NOT do (SPEC §6 boundary): it does not prove (that is the local
// prover service) and does not send the tx (that is MetaMask in chain.ts). It stops
// exactly at "a valid ProvingRequest + the 2054-element ciphertext, ready to
// prove and submit".

import {
  deriveKeypair,
  commitment,
  nullifier,
  poseidonEncrypt,
  ecdhSharedSecret,
  assertDistinctOwnerPubkeys,
} from "@bongtu/sdk/note";
import { unpackPubkey } from "@bongtu/sdk/pubkey";
import { ImtTree } from "@bongtu/sdk/imt";
import { poseidon2 } from "@bongtu/sdk/poseidon";
import type { Point } from "@bongtu/sdk/babyjub";
import type { DisburseInput, ProvingRequest } from "@bongtu/sdk/proving";
import { H, B } from "../config.js";

// --- app-facing input shapes (all field elements as decimal strings) ------------

export interface RecipientRow {
  /** The recipient's compressed bjj pubkey — a 32-byte hex string (sdk/pubkey.ts). */
  pubkey: string;
  /** The amount to pay this recipient, decimal. */
  amount: string;
}

export interface InputNote {
  value: string;
  salt: string;
  /** The employer's formatted bjj private scalar (the spending key of the input note).
   *  In this PoC it is pasted directly; full ETH->bjj onboarding is out of scope. */
  ownerPrivateKey: string;
}

export interface Membership {
  root: string;
  /** length-H (32) merkle siblings of the input note against `root`. */
  pathElements: string[];
  leafIndex: number;
}

export interface CryptoParams {
  /** ephemeral ECDH private scalar shared across every output envelope of this batch. */
  ecdhPrivateKey: string;
  encryptionNonce: string;
  /** the pool's stored arbiter PUBLIC key (safe in employer-mode). */
  authorityPubKey: [string, string];
  /** base for deriving fresh, deterministic output salts. */
  saltSeed: string;
  /** base scalar for deriving distinct dummy owner keys for zero-value padding. */
  padSeed: string;
}

export interface AssembleMeta {
  inputCommitment: string;
  nullifier: string;
  subtreeRoot: string;
  disclosureHash: string;
  inputValue: string;
  disbursed: string;
  changeValue: string;
  realCount: number;
  changeCount: number;
  padCount: number;
  membershipOk: boolean;
  ciphertextLen: number;
}

export interface LedgerRow {
  pubkey: string;
  amount: string;
  kind: "recipient" | "change";
}

export interface AssembleResult {
  /** The exact request POSTed to the prover service (all field elements decimal). */
  request: ProvingRequest;
  /** The 2054-element receiver++authority ciphertext for disburseWithCiphertexts. */
  ciphertext: string[];
  meta: AssembleMeta;
  /** The employer's OWN ledger (no arbiter key) — its authored recipients + change. */
  ledger: LedgerRow[];
}

// --- helpers -------------------------------------------------------------------

// Fold a leaf up an IMT auth path, taking left/right from the bits of leafIndex —
// bit j == 1 means the sibling is the LEFT child at level j. Mirrors ImtTree.
function foldToRoot(leaf: bigint, siblings: bigint[], leafIndex: number): bigint {
  let cur = leaf;
  let idx = leafIndex;
  for (let j = 0; j < siblings.length; j++) {
    cur = idx % 2 === 1 ? poseidon2(siblings[j], cur) : poseidon2(cur, siblings[j]);
    idx = Math.floor(idx / 2);
  }
  return cur;
}

// disclosureHash: Poseidon(2) chain over the receiver ciphertext then the authority
// ciphertext, seeded at 0 — byte-identical to the in-circuit gadget and to
// deploy/giwa_disburse256.ts. Equals the proof's pub[2] once proven.
function computeDisclosureHash(receiverFlat: bigint[], authorityCt: bigint[]): bigint {
  let dh = 0n;
  for (const x of receiverFlat) dh = poseidon2(dh, x);
  for (const x of authorityCt) dh = poseidon2(dh, x);
  return dh;
}

// Convert a bigint-typed DisburseInput into the decimal-string form that survives
// JSON.stringify (a ProvingRequest POSTed to the service has no bigints). The prover
// accepts decimal strings as FieldInput as-is.
function toDecimalInput(input: DisburseInput): DisburseInput {
  const s = (x: bigint | number | string): string => BigInt(x).toString();
  const point = (p: readonly [bigint | number | string, bigint | number | string]): [string, string] => [
    s(p[0]),
    s(p[1]),
  ];
  return {
    nullifiers: input.nullifiers.map(s),
    inputCommitments: input.inputCommitments.map(s),
    inputValues: input.inputValues.map(s),
    inputSalts: input.inputSalts.map(s),
    inputOwnerPrivateKey: s(input.inputOwnerPrivateKey),
    ecdhPrivateKey: s(input.ecdhPrivateKey),
    root: s(input.root),
    pathElements: (input.pathElements as (bigint | number | string)[][]).map((row) => row.map(s)),
    leafIndices: input.leafIndices.map(s),
    enabled: input.enabled.map(s),
    outputCommitments: input.outputCommitments.map(s),
    outputValues: input.outputValues.map(s),
    outputSalts: input.outputSalts.map(s),
    outputOwnerPublicKeys: input.outputOwnerPublicKeys.map(point),
    encryptionNonce: s(input.encryptionNonce),
    authorityPublicKey: point(input.authorityPublicKey),
  };
}

// --- the assembly --------------------------------------------------------------

/**
 * Assemble a complete disburse ProvingRequest + the on-chain ciphertext from the
 * employer's input note, a membership witness, and up to B recipient rows.
 *
 * Outputs are laid out as: the N real recipients, then a single change note back to
 * the employer for (inputValue - disbursed) when positive, then zero-value padding
 * to exactly B outputs — so CheckSum (sum(outputs) == inputValue) holds and every
 * output owner pubkey is distinct (§11-8 two-time-pad guard, enforced here).
 *
 * Throws on: no/too-many recipients, a non-positive amount, disbursed > inputValue,
 * a malformed recipient pubkey, a duplicate/colliding output owner, or a wrong-length
 * path. A thrown error means the batch is not provable and must be fixed first.
 */
export function buildDisburseRequest(
  inputNote: InputNote,
  membership: Membership,
  recipients: RecipientRow[],
  crypto: CryptoParams,
): AssembleResult {
  if (recipients.length === 0) throw new Error("at least one recipient is required");
  if (recipients.length > B) throw new Error(`too many recipients: ${recipients.length} > ${B}`);

  const V = BigInt(inputNote.value);
  const inSalt = BigInt(inputNote.salt);
  const employer = deriveKeypair(BigInt(inputNote.ownerPrivateKey));
  const inputCommitment = commitment(V, inSalt, employer.publicKey);
  const nf = nullifier(V, inSalt, employer.formattedPrivateKey);

  // Resolve recipient rows -> outputs, summing the disbursement.
  interface Out {
    owner: Point;
    value: bigint;
    kind: "recipient" | "change" | "pad";
  }
  const outs: Out[] = [];
  let disbursed = 0n;
  const ledger: LedgerRow[] = [];
  recipients.forEach((r, i) => {
    let owner: Point;
    try {
      owner = unpackPubkey(r.pubkey.trim());
    } catch (e) {
      throw new Error(`recipient #${i + 1} pubkey invalid: ${(e as Error).message}`);
    }
    const amt = BigInt(r.amount);
    if (amt <= 0n) throw new Error(`recipient #${i + 1} amount must be positive, got ${amt}`);
    disbursed += amt;
    outs.push({ owner, value: amt, kind: "recipient" });
    ledger.push({ pubkey: r.pubkey.trim(), amount: amt.toString(), kind: "recipient" });
  });
  if (disbursed > V) {
    throw new Error(`recipients sum ${disbursed} exceeds input note value ${V} (nothing to over-spend)`);
  }

  // Change back to the employer for the remainder keeps sum(outputs) == inputValue.
  const changeValue = V - disbursed;
  let changeCount = 0;
  if (changeValue > 0n) {
    outs.push({ owner: employer.publicKey, value: changeValue, kind: "change" });
    ledger.push({ pubkey: "(employer change)", amount: changeValue.toString(), kind: "change" });
    changeCount = 1;
  }

  // Pad to exactly B with zero-value notes to DISTINCT dummy owner keys. Distinct
  // keys are required by the two-time-pad guard even though the value is 0.
  const padSeed = BigInt(crypto.padSeed);
  const realCount = recipients.length;
  let padCount = 0;
  for (let i = outs.length; i < B; i++) {
    const dummy = deriveKeypair(padSeed + BigInt(i) * 1000003n + 1n).publicKey;
    outs.push({ owner: dummy, value: 0n, kind: "pad" });
    padCount++;
  }

  // Fresh deterministic salts, then the distinctness guard over ALL B owners.
  const saltSeed = BigInt(crypto.saltSeed);
  const outputSalts = outs.map((_, i) => saltSeed + BigInt(i));
  const outputValues = outs.map((o) => o.value);
  const outputOwnerPublicKeys: Point[] = outs.map((o) => o.owner);
  assertDistinctOwnerPubkeys(outputOwnerPublicKeys);

  const outputCommitments = outs.map((o, i) => commitment(o.value, outputSalts[i], o.owner));
  const subtreeRoot = new ImtTree(H, B).computeSubtreeRoot(outputCommitments);

  const root = BigInt(membership.root);
  const pathElements = membership.pathElements.map((x) => BigInt(x));
  if (pathElements.length !== H) {
    throw new Error(`pathElements must have length ${H}, got ${pathElements.length}`);
  }
  const membershipOk = foldToRoot(inputCommitment, pathElements, membership.leafIndex) === root;

  const inputBig: DisburseInput = {
    nullifiers: [nf],
    inputCommitments: [inputCommitment],
    inputValues: [V],
    inputSalts: [inSalt],
    inputOwnerPrivateKey: employer.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root,
    pathElements: [pathElements],
    leafIndices: [BigInt(membership.leafIndex)],
    enabled: [1n],
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    encryptionNonce: BigInt(crypto.encryptionNonce),
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  // Ciphertext: per-output receiver envelope [value, salt] (256 * 4 = 1024) ++ the
  // single authority envelope over [inOwn, inValue, inSalt, all output owners, all
  // output (value,salt)] (1030). Total 2054 = disburseCiphertextLen(B=256). Same
  // construction as deploy/giwa_disburse256.ts.
  const ecdh = BigInt(crypto.ecdhPrivateKey);
  const nonce = BigInt(crypto.encryptionNonce);
  const authorityPub: Point = [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])];
  const receiverFlat: bigint[] = outs.flatMap((o, i) =>
    poseidonEncrypt([o.value, outputSalts[i]], ecdhSharedSecret(ecdh, o.owner), nonce),
  );
  const authPlain: bigint[] = [
    employer.publicKey[0],
    employer.publicKey[1],
    V,
    inSalt,
    ...outs.flatMap((o) => [o.owner[0], o.owner[1]]),
    ...outs.flatMap((o, i) => [o.value, outputSalts[i]]),
  ];
  const authorityCt = poseidonEncrypt(authPlain, ecdhSharedSecret(ecdh, authorityPub), nonce);
  const ciphertext = [...receiverFlat, ...authorityCt];
  const disclosureHash = computeDisclosureHash(receiverFlat, authorityCt);
  if (ciphertext.length !== 2054) {
    throw new Error(`ciphertext length ${ciphertext.length} != 2054 (disburseCiphertextLen for B=${B})`);
  }

  const request: ProvingRequest = { circuit: "disburse", input: toDecimalInput(inputBig), backend: "gpu" };

  return {
    request,
    ciphertext: ciphertext.map((x) => x.toString()),
    meta: {
      inputCommitment: inputCommitment.toString(),
      nullifier: nf.toString(),
      subtreeRoot: subtreeRoot.toString(),
      disclosureHash: disclosureHash.toString(),
      inputValue: V.toString(),
      disbursed: disbursed.toString(),
      changeValue: changeValue.toString(),
      realCount,
      changeCount,
      padCount,
      membershipOk,
      ciphertextLen: ciphertext.length,
    },
    ledger,
  };
}
