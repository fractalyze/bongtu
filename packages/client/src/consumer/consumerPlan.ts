// consumer/consumerPlan.ts — the recipient triple, per-tx crypto, circuit
// mapping and output planning/sealing (split from consumerBuild.ts; the subpath
// @bongtu/client/consumerBuild re-exports everything).
import type { Point } from "@bongtu/core/babyjub";
import { sealConsumerOutput, type SealedConsumerOutput } from "@bongtu/core/consumer";
import { KEM_EK_ZERO, NOTE_VIEW_PUB_ZERO } from "@bongtu/core/eddsa";
import { TRANSFER10_ARITY } from "@bongtu/core/envelope";
import type { NameRecord } from "@bongtu/core/indexerApi";
import { kemBytesToHex, kemHexToBytes } from "@bongtu/core/kem";
import { commitment } from "@bongtu/core/note";
import type { ProvingRequest } from "@bongtu/core/proving";
import { unpackPubkey } from "@bongtu/core/pubkey";

import type { DepositMeta } from "@bongtu/client/deposit";
import type { ConsumerWalletIdentity } from "@bongtu/client/derive";
import {
  toEncryptionNonce,
  type RandField,
  type SpendCircuit,
  type SpendMeta,
} from "@bongtu/client/spend";
// --- the recipient triple --------------------------------------------------------

/** The consumer triple a payment needs (docs/consumer.md § The registry triple):
 *  the bjj SPEND pubkey (`owner`, the note's commitment binding), the note-layer
 *  bjj VIEW pubkey (the receiver-ct ECDH target) and the ML-KEM-768
 *  encapsulation key. Derived from the registry's NameRecord v2 fields rather
 *  than re-declared, so a registry wire-shape change breaks this type at compile
 *  time instead of silently diverging. */
export type ConsumerRecipient = Pick<NameRecord, "owner"> &
  Required<Pick<NameRecord, "noteViewPub" | "kemEk">>;

/** Narrow a resolved v2 NameRecord to a payable consumer recipient. Throws on a
 *  legacy record (no consumer pair) and on the signed zero-sentinel clear — both
 *  mean "this name cannot receive consumer notes", and failing HERE beats
 *  sealing to a key nobody holds (the funds would land, but the recipient could
 *  never discover the note by scan). */
export function consumerRecipientOf(record: NameRecord): ConsumerRecipient {
  const { noteViewPub, kemEk } = record;
  if (
    noteViewPub === undefined ||
    kemEk === undefined ||
    noteViewPub === NOTE_VIEW_PUB_ZERO ||
    kemEk === KEM_EK_ZERO
  ) {
    throw new Error(
      `name "${record.name}" has no consumer identity registered — it cannot receive consumer notes`,
    );
  }
  return { owner: record.owner, noteViewPub, kemEk };
}

/** The wallet's own triple — the target of every change note, because the
 *  sender recovers change by SELF-SCAN (there is no /notes oracle for consumer
 *  notes, docs/consumer.md § Discovery is self-scan). */
export function selfConsumerRecipient(identity: ConsumerWalletIdentity): ConsumerRecipient {
  return {
    owner: identity.compressedPubkey,
    noteViewPub: identity.compressedViewPubkey,
    kemEk: kemBytesToHex(identity.kemKeypair.ek),
  };
}

// --- per-tx crypto ---------------------------------------------------------------

/** Fresh per-tx crypto for one consumer deposit. Unlike the enterprise
 *  DepositCrypto there is no arbiter target and no per-tx KEM draw: each
 *  output's ML-KEM encapsulation happens inside sealing, against that
 *  RECIPIENT's kemEk (per-output, OPMOD §3.3). `encapSeeds` exists only so
 *  deterministic tests can pin seals; production leaves it unset and the
 *  encapsulation draws from the platform CSPRNG. */
export interface ConsumerDepositCrypto {
  ecdhPrivateKey: string;
  encryptionNonce: string;
  /** salt for output 0. */
  salt0: string;
  /** salt for output 1. */
  salt1: string;
  /** per-output ML-KEM encapsulation randomness — deterministic tests ONLY. */
  encapSeeds?: Uint8Array[];
}

/** Exactly FOUR draws — ecdhPrivateKey, encryptionNonce, salt0, salt1 — since
 *  reusing an ephemeral ECDH key + nonce across txs is a two-time pad (the
 *  per-output KEM freshness needs no draw here: it is CSPRNG-internal to
 *  sealing). */
export function freshConsumerDepositCrypto(rand: RandField): ConsumerDepositCrypto {
  return {
    ecdhPrivateKey: rand(),
    // clamped to <2^128 (SymmetricEncrypt slot). The per-output offset nonce+i
    // can still exceed the slot in the residual [2^128-255, 2^128) range —
    // core/consumer offsetNonce then throws LOUDLY (retryable, ~2^-121), the
    // clamp does not exclude it
    encryptionNonce: toEncryptionNonce(rand()),
    salt0: rand(),
    salt1: rand(),
  };
}

/** Fresh per-tx crypto for one consumer spend (transferPriv / transfer10x2Priv /
 *  withdrawPriv): the enterprise SpendCrypto minus the authority material and
 *  the per-tx arbiter KEM draw (per-output encapsulation lives in sealing). */
export interface ConsumerSpendCrypto {
  ecdhPrivateKey: string;
  encryptionNonce: string;
  /** transferPriv/transfer10x2Priv: salt for the payment output. */
  payeeSalt?: string;
  /** salt for the change note back to the wallet. */
  changeSalt: string;
  /** salts for the padded (value-0) input slots, one per unfilled slot so no
   *  two pads land on the same commitment. */
  padSalts: string[];
  /** per-output ML-KEM encapsulation randomness — deterministic tests ONLY. */
  encapSeeds?: Uint8Array[];
}

/** Thirteen draws: ecdh key, nonce, payee salt, change salt, nine pad salts —
 *  pad salts sized for the widest arity (transfer10x2Priv) so ONE bundle serves
 *  whichever circuit the auto-pick lands on, exactly as freshSpendCrypto does
 *  for the enterprise family. */
export function freshConsumerSpendCrypto(rand: RandField): ConsumerSpendCrypto {
  return {
    ecdhPrivateKey: rand(),
    encryptionNonce: toEncryptionNonce(rand()),
    payeeSalt: rand(),
    changeSalt: rand(),
    padSalts: Array.from({ length: TRANSFER10_ARITY - 1 }, () => rand()),
  };
}

// --- circuit routing -------------------------------------------------------------

/** The consumer circuits a spend can land on (a deposit is not a spend). */
export type ConsumerSpendCircuit = "transferPriv" | "transfer10x2Priv" | "withdrawPriv";

/** Map the enterprise auto-pick (planSpendAction / planSpendChain — reused
 *  as-is: selection is arity-driven and family-blind) onto the consumer twin.
 *  A Record keyed by the FULL union is what makes totality compile-time real:
 *  a new SpendCircuit member is a missing-property error here, never a silent
 *  route of a consumer spend onto the wrong circuit (a ternary else would
 *  absorb it). */
const CONSUMER_CIRCUIT: Record<SpendCircuit, ConsumerSpendCircuit> = {
  transfer: "transferPriv",
  transfer10x2: "transfer10x2Priv",
  withdraw: "withdrawPriv",
};
export const consumerCircuitOf = (circuit: SpendCircuit): ConsumerSpendCircuit =>
  CONSUMER_CIRCUIT[circuit];

// --- output planning + sealing ---------------------------------------------------

export interface ConsumerOutputSpec {
  recipient: ConsumerRecipient;
  value: bigint;
  salt: bigint;
}

export interface PlannedConsumerOutput {
  value: bigint;
  salt: bigint;
  spendPub: Point;
  viewPub: Point;
  seal: SealedConsumerOutput;
  commitment: bigint;
}

/** unpack with a message naming the field the caller supplied, not the curve
 *  math that rejected it (mirrors spend.ts parsePayee). */
/** Cheap validity probe for a recipient triple — the SAME parses sealing will
 *  do, run BEFORE any token motion so a corrupt hand-built triple cannot cost
 *  an approve tx (the family rule depositFlow.ts states). Registry-resolved
 *  triples already passed consumerRecipientOf; this guards the manual path. */
export function assertConsumerRecipient(recipient: ConsumerRecipient): void {
  parsePoint(recipient.owner, "recipient owner pubkey");
  parsePoint(recipient.noteViewPub, "recipient noteViewPub");
  kemHexToBytes(recipient.kemEk);
}

function parsePoint(hex: string, field: string): Point {
  try {
    return unpackPubkey(hex.trim());
  } catch (e) {
    throw new Error(`${field} invalid: ${(e as Error).message}`);
  }
}

/** Seal every output of one tx: per-output ECDH against the recipient's VIEW
 *  key, a fresh per-output ML-KEM encapsulation against their kemEk, ciphertext
 *  at `encryptionNonce + i` with i = the output position — the OPMOD §3.5 rule
 *  that makes duplicate output owners safe. The commitment binds the SPEND key,
 *  so a wrong view/kem key can never misdirect funds — only the sender's own
 *  ciphertext delivery (the S3.3 self-sabotage class). */
export function planConsumerOutputs(
  specs: ConsumerOutputSpec[],
  crypto: { ecdhPrivateKey: string; encryptionNonce: string; encapSeeds?: Uint8Array[] },
): PlannedConsumerOutput[] {
  return specs.map((spec, i) => {
    const spendPub = parsePoint(spec.recipient.owner, `output ${i} recipient owner pubkey`);
    const viewPub = parsePoint(spec.recipient.noteViewPub, `output ${i} recipient noteViewPub`);
    return {
      value: spec.value,
      salt: spec.salt,
      spendPub,
      viewPub,
      seal: sealConsumerOutput({
        value: spec.value,
        salt: spec.salt,
        ephemeralPriv: BigInt(crypto.ecdhPrivateKey),
        viewPub,
        kemEk: kemHexToBytes(spec.recipient.kemEk),
        encryptionNonce: BigInt(crypto.encryptionNonce),
        index: i,
        encapSeed: crypto.encapSeeds?.[i],
      }),
      commitment: commitment(spec.value, spec.salt, spendPub),
    };
  });
}

/** The output-side witness fields — the ONE field grammar all the consumer
 *  circuits share (circuits/fixtures/consumer_lib.ts outputSide and its
 *  deploy/gates/consumer_leg.ts twin). */
export function outputSide(outs: PlannedConsumerOutput[]): {
  outputCommitments: bigint[];
  outputValues: bigint[];
  outputSalts: bigint[];
  outputOwnerPublicKeys: Point[];
  outputViewPublicKeys: Point[];
  kemSs: bigint[][];
} {
  return {
    outputCommitments: outs.map((o) => o.commitment),
    outputValues: outs.map((o) => o.value),
    outputSalts: outs.map((o) => o.salt),
    outputOwnerPublicKeys: outs.map((o) => o.spendPub),
    outputViewPublicKeys: outs.map((o) => o.viewPub),
    kemSs: outs.map((o) => [o.seal.kemSs[0], o.seal.kemSs[1]]),
  };
}

/** What the tx submit needs beyond the proof: the per-output kem ciphertexts
 *  (`bytes[] kemCiphertexts` calldata) and the viewTags (public signals the
 *  circuit itself emits — surfaced for display/debugging, never re-supplied). */
export interface ConsumerSealMeta {
  /** one 1088-byte 0x-hex ML-KEM ct per output, in output order (OPMOD §3.4). */
  kemCiphertexts: string[];
  viewTags: string[];
}

export function sealMeta(outs: PlannedConsumerOutput[]): ConsumerSealMeta {
  return {
    kemCiphertexts: outs.map((o) => kemBytesToHex(o.seal.kemCiphertext)),
    viewTags: outs.map((o) => o.seal.viewTag.toString()),
  };
}

// --- results ---------------------------------------------------------------------

export interface ConsumerDepositMeta extends DepositMeta, ConsumerSealMeta {}
export interface ConsumerSpendMeta extends SpendMeta, ConsumerSealMeta {}

export interface ConsumerDepositResult {
  request: Extract<ProvingRequest, { circuit: "depositPriv" }>;
  meta: ConsumerDepositMeta;
}

export interface ConsumerSpendResult<C extends ConsumerSpendCircuit> {
  request: Extract<ProvingRequest, { circuit: C }>;
  meta: ConsumerSpendMeta;
}
