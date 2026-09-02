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
} from "@bongtu/core/note";
import { unpackPubkey, decodeAddress } from "@bongtu/core/pubkey";
import { ImtTree, foldToRoot } from "@bongtu/core/imt";
import { buildAuthorityPlaintext, disclosureChain } from "@bongtu/core/envelope";
import {
  ml_kem768,
  kemSsToLimbs,
  kemHexToBytes,
  kemBytesToHex,
  hybridEnvelopeKey,
  KEM_CIPHERTEXT_BYTES,
} from "@bongtu/core/kem";
import { ARBITER_KEM_PK } from "@bongtu/core/network";
import { toEncryptionNonce } from "@bongtu/client/spend";
import { SUBGROUP_ORDER, type Point } from "@bongtu/core/babyjub";
import { toWire } from "@bongtu/core/proving";
import type { DisburseInput, ProvingRequest } from "@bongtu/core/proving";
import { H, B } from "../config.js";

// --- app-facing input shapes (all field elements as decimal strings) ------------

export interface RecipientRow {
  /** The recipient's bongtu address — base58check or legacy 32-byte hex (both normalized via decodeAddress). */
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
  /** the pool's stored arbiter PUBLIC key (safe in employer-mode). */
  authorityPubKey: [string, string];
  /** ML-KEM-768 shared-secret limbs (decimal) — the PQ half of the hybrid
   *  authority-envelope key (pq-envelope-design.md §2/§5); the circuit folds
   *  them into hybridKey and outputs their kemBinding. */
  kemSs: [string, string];
  /** the matching 1088-byte encapsulation ciphertext, 0x-hex — the tx's
   *  `bytes kemCiphertext` arg (never sent to the prover). */
  kemCiphertext: string;
}

/**
 * Per-batch secret entropy — every recipient-count-hiding value is drawn FRESH
 * from the platform CSPRNG here, never from a hardcoded/deterministic seed.
 * A prior design let an observer who knew the (default) ecdh/nonce/salt/pad
 * seeds recompute every pad key, trial-decrypt the on-chain `Disbursed`
 * ciphertext, and recover the REAL recipient count (the whole point of padding
 * to B is to hide it). Drawing all of it fresh per batch closes that leak.
 * Injectable so tests can substitute a deterministic double.
 */
export interface DisburseEntropy {
  /** a fresh field element (decimal string, < field prime) — the ephemeral ECDH
   *  private scalar, the encryption nonce, each output salt, and the shuffle. */
  randField: () => string;
  /** a fresh NONZERO babyjub scalar (< SUBGROUP_ORDER) — a dummy pad owner's
   *  spending key. Random (not seed+index) so pad keys are not recomputable. */
  randScalar: () => bigint;
}

function randBytes(n: number): bigint {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b.reduce<bigint>((x, byte) => (x << 8n) | BigInt(byte), 0n);
}

/** The platform-CSPRNG entropy used in the browser (wallet spend.ts:randField
 *  pattern). The default 5th arg of buildDisburseRequest. */
export const cryptoEntropy: DisburseEntropy = {
  randField() {
    const x = randBytes(31); // < 2^248, safely under the field prime
    return (x === 0n ? 1n : x).toString();
  },
  randScalar() {
    const x = randBytes(48) % SUBGROUP_ORDER; // wide draw -> negligible modulo bias
    return x === 0n ? 1n : x;
  },
};

/**
 * Fresh ML-KEM-768 encapsulation against the institutional arbiter key
 * (ARBITER_KEM_PK) — drawn once PER BATCH alongside the ephemeral ECDH scalar
 * (ct reuse across txs collapses the PQ compartment, design doc §6). The view
 * calls this at assemble time; tests inject fixed material into CryptoParams.
 */
export function freshDisburseKem(): { kemSs: [string, string]; kemCiphertext: string } {
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(kemHexToBytes(ARBITER_KEM_PK));
  const [l0, l1] = kemSsToLimbs(sharedSecret);
  return { kemSs: [l0.toString(), l1.toString()], kemCiphertext: kemBytesToHex(cipherText) };
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
  /** The batch's 1088-byte ML-KEM ct (0x-hex) — the tx's `bytes kemCiphertext`
   *  arg; passed through from CryptoParams so submit uses the SAME encapsulation
   *  the proof's kemBinding committed to. */
  kemCiphertext: string;
  meta: AssembleMeta;
  /** The employer's OWN ledger (no arbiter key) — its authored recipients + change. */
  ledger: LedgerRow[];
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
  entropy: DisburseEntropy = cryptoEntropy,
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
  const ledger: LedgerRow[] = [];
  const disbursed = recipients.reduce<bigint>((sum, r, i) => {
    // Rows may arrive as base58check (pasted address) or legacy hex; decodeAddress
    // is the one normalization point, so the witness AND the ledger both see
    // canonical hex (the admin console is an operator tool — it displays hex).
    const { owner, canonical } = (() => {
      try {
        const hex = decodeAddress(r.pubkey);
        return { owner: unpackPubkey(hex), canonical: hex };
      } catch (e) {
        throw new Error(`recipient #${i + 1} pubkey invalid: ${(e as Error).message}`);
      }
    })();
    const amt = BigInt(r.amount);
    if (amt <= 0n) throw new Error(`recipient #${i + 1} amount must be positive, got ${amt}`);
    outs.push({ owner, value: amt, kind: "recipient" });
    ledger.push({ pubkey: canonical, amount: amt.toString(), kind: "recipient" });
    return sum + amt;
  }, 0n);
  if (disbursed > V) {
    throw new Error(`recipients sum ${disbursed} exceeds input note value ${V} (nothing to over-spend)`);
  }

  // Change back to the employer for the remainder keeps sum(outputs) == inputValue.
  const changeValue = V - disbursed;
  const changeCount = changeValue > 0n ? 1 : 0;
  if (changeValue > 0n) {
    outs.push({ owner: employer.publicKey, value: changeValue, kind: "change" });
    ledger.push({ pubkey: "(employer change)", amount: changeValue.toString(), kind: "change" });
  }

  // Pad to exactly B with zero-value notes to DISTINCT dummy owner keys. Each pad
  // owner is a FRESH RANDOM babyjub scalar (not `seed + i*step`): an observer who
  // knew the old pad seed could recompute every dummy key, trial-decrypt the
  // on-chain ciphertext, and count the reals. Distinct keys are still required by
  // the two-time-pad guard even though the value is 0 (random collision negligible).
  const realCount = recipients.length;
  const padCount = Math.max(0, B - outs.length);
  for (const _ of Array(padCount).keys()) {
    const dummy = deriveKeypair(entropy.randScalar()).publicKey;
    outs.push({ owner: dummy, value: 0n, kind: "pad" });
  }

  // A FRESH CSPRNG salt per output — sequential `saltSeed + i` would let any one
  // recipient (who learns their own slot's salt) derive every other slot's salt.
  const salts = outs.map(() => BigInt(entropy.randField()));

  // Fisher-Yates shuffle the slots over the CSPRNG so POSITION encodes nothing: the
  // natural real->change->pad layout leaks a lower bound N >= i+1 at each real slot.
  // Every per-output array (owners, values, salts, and thus commitments, receiver
  // ciphertexts, and the authority-plaintext outputs) is permuted the SAME way, or
  // the proof breaks.
  const order = outs.map((_, i) => i);
  for (const i of Array.from({ length: order.length - 1 }, (_, k) => order.length - 1 - k)) {
    const j = Number(BigInt(entropy.randField()) % BigInt(i + 1));
    const t = order[i];
    order[i] = order[j];
    order[j] = t;
  }
  const shuffledOuts = order.map((k) => outs[k]);
  const outputSalts = order.map((k) => salts[k]);
  const outputValues = shuffledOuts.map((o) => o.value);
  const outputOwnerPublicKeys: Point[] = shuffledOuts.map((o) => o.owner);
  assertDistinctOwnerPubkeys(outputOwnerPublicKeys);

  const outputCommitments = shuffledOuts.map((o, i) => commitment(o.value, outputSalts[i], o.owner));
  const subtreeRoot = new ImtTree(H, B).computeSubtreeRoot(outputCommitments);

  // The ephemeral ECDH key + encryption nonce are drawn FRESH per batch too: as
  // constants the whole receiver-envelope keystream was predictable, so an observer
  // could decrypt [value, salt] for every slot and read off the real count directly.
  const ecdh = BigInt(entropy.randField());
  // Clamped to 128 bits: SymmetricEncrypt constrains nonce < 2^128 (the nonce shares
  // a Poseidon state slot with messageLength * 2^128), so a full-width field draw
  // fails witness generation. The wallet's freshSpendCrypto clamps the same way.
  const nonce = BigInt(toEncryptionNonce(entropy.randField()));

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
    ecdhPrivateKey: ecdh,
    root,
    pathElements: [pathElements],
    leafIndices: [BigInt(membership.leafIndex)],
    enabled: [1n],
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    kemSs: [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])],
    encryptionNonce: nonce,
    authorityPublicKey: [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])],
  };

  // The tx's KEM ct is length-checked here (not just on-chain) so a truncated
  // paste fails at assemble time, before the multi-second GPU proof.
  if (kemHexToBytes(crypto.kemCiphertext).length !== KEM_CIPHERTEXT_BYTES) {
    throw new Error(`kemCiphertext must be ${KEM_CIPHERTEXT_BYTES} bytes (draw it with freshDisburseKem)`);
  }

  // Ciphertext: per-output receiver envelope [value, salt] (256 * 4 = 1024) ++ the
  // single authority envelope (1030), laid out by the owning codec
  // (@bongtu/core/envelope). Total 2054 = disburseCiphertextLen(B=256). Uses the
  // SHUFFLED outs + salts + the fresh ecdh/nonce drawn above so the on-chain wire
  // matches the proven witness.
  const authorityPub: Point = [BigInt(crypto.authorityPubKey[0]), BigInt(crypto.authorityPubKey[1])];
  const receiverFlat: bigint[] = shuffledOuts.flatMap((o, i) =>
    poseidonEncrypt([o.value, outputSalts[i]], ecdhSharedSecret(ecdh, o.owner), nonce),
  );
  const authPlain = buildAuthorityPlaintext("disburse", {
    inputs: [{ owner: employer.publicKey, value: V, salt: inSalt }],
    outputs: shuffledOuts.map((o, i) => ({ owner: o.owner, value: o.value, salt: outputSalts[i] })),
  });
  // Hybrid envelope key (design doc §2): the SAME tagged Poseidon fold the
  // circuit derives in-witness — a raw-ECDH key here would emit a ciphertext
  // that mismatches the proof's disclosureHash.
  const authorityCt = poseidonEncrypt(
    authPlain,
    hybridEnvelopeKey(ecdhSharedSecret(ecdh, authorityPub), [BigInt(crypto.kemSs[0]), BigInt(crypto.kemSs[1])]),
    nonce,
  );
  const ciphertext = [...receiverFlat, ...authorityCt];
  // Poseidon(2) fold over receiver ++ authority — equals the proof's pub[2] once proven.
  const disclosureHash = disclosureChain(ciphertext);
  if (ciphertext.length !== 2054) {
    throw new Error(`ciphertext length ${ciphertext.length} != 2054 (disburseCiphertextLen for B=${B})`);
  }

  const request: ProvingRequest = { circuit: "disburse", input: toWire(inputBig), backend: "gpu" };

  return {
    request,
    ciphertext: ciphertext.map((x) => x.toString()),
    kemCiphertext: crypto.kemCiphertext,
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
