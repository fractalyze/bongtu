// PURE wallet-side witness assembly for the four CPU consumer (no-auditor)
// circuits: depositPriv (0-in / 2-out mint), transferPriv (2-in / 2-out),
// transfer10x2Priv (10-in / 2-out) and withdrawPriv (2-in / 1-out + proof-bound
// recipient) — OPMOD §2, docs/consumer.md. The enterprise builders (deposit.ts /
// spend.ts) stop at "a valid ProvingRequest" and so does this file; what changes
// is the OUTPUT side: no authority envelope exists, so every output note is
// SEALED to its recipient's consumer triple instead — a receiver ciphertext
// under the hybrid per-output key (ECDH against the note-layer VIEW key + a
// fresh per-output ML-KEM-768 encapsulation against the registered kemEk), a
// viewTag, and the 1088-byte kem ct the tx carries as calldata (OPMOD §3.3–§3.5).
//
// Reused, not reimplemented: the input side (membership, nullifiers, padding) is
// spend.ts assembleInputs verbatim — notes are UNTYPED, so the commitment/
// nullifier algebra is family-shared by construction and reusing the one
// function keeps it that way; note selection and chain planning
// (selectInputNotes / planSpendAction / planSpendChain) are arity-driven and
// family-blind, so consumer flows call them unchanged and map the picked circuit
// through consumerCircuitOf. Per-output sealing is @bongtu/core/consumer
// sealConsumerOutput — the same function the fixture generators
// (circuits/fixtures/consumer_lib.ts) and the consumer e2e leg
// (deploy/gates/consumer_leg.ts) call, which is what makes the witness objects
// built here byte-identical to the committed circuits/fixtures/inputs/
// {depositPriv,transferPriv,transfer10x2Priv,withdrawPriv}.json — pinned in
// test/consumerBuild.test.ts.
//
// What the client supplies vs what the chain injects (mirrors consumer_leg.ts):
// `enabled` and the withdraw `recipient` ARE witness inputs — the circuit needs
// them to build a witness — but on-chain the module re-derives/range-checks and
// injects them into the public vector before verify (OPMOD §2), so a witness
// that lies about either simply fails verification. The kem ciphertexts are NOT
// witness material: they ride the tx as `bytes[] kemCiphertexts` calldata, one
// entry per output, surfaced here in each result's meta.

import type { Point } from "@bongtu/core/babyjub";
import { sealConsumerOutput } from "@bongtu/core/consumer";
import type { SealedConsumerOutput } from "@bongtu/core/consumer";
import { KEM_EK_ZERO, NOTE_VIEW_PUB_ZERO } from "@bongtu/core/eddsa";
import { TRANSFER10_ARITY } from "@bongtu/core/envelope";
import type { NameRecord } from "@bongtu/core/indexerApi";
import { kemBytesToHex, kemHexToBytes } from "@bongtu/core/kem";
import { commitment } from "@bongtu/core/note";
import { toWire } from "@bongtu/core/proving";
import type {
  ConsumerDepositInput,
  ConsumerSpendInput,
  ConsumerWithdrawInput,
  ProvingRequest,
} from "@bongtu/core/proving";
import { unpackPubkey } from "@bongtu/core/pubkey";

import type { DepositMeta } from "@bongtu/client/deposit";
import type { ConsumerWalletIdentity } from "@bongtu/client/derive";
import { assembleInputs, toEncryptionNonce } from "@bongtu/client/spend";
import type {
  AssembledInputs,
  MembershipWitness,
  RandField,
  SpendCircuit,
  SpendMeta,
  WalletInputNote,
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

interface ConsumerOutputSpec {
  recipient: ConsumerRecipient;
  value: bigint;
  salt: bigint;
}

interface PlannedConsumerOutput {
  value: bigint;
  salt: bigint;
  spendPub: Point;
  viewPub: Point;
  seal: SealedConsumerOutput;
  commitment: bigint;
}

/** unpack with a message naming the field the caller supplied, not the curve
 *  math that rejected it (mirrors spend.ts parsePayee). */
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
function planConsumerOutputs(
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
function outputSide(outs: PlannedConsumerOutput[]): {
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

function sealMeta(outs: PlannedConsumerOutput[]): ConsumerSealMeta {
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

function consumerSpendMeta(
  ins: AssembledInputs,
  amount: string,
  changeValue: string,
  outs: PlannedConsumerOutput[],
): ConsumerSpendMeta {
  return {
    inputCommitments: ins.inputCommitments.map((x) => x.toString()),
    nullifiers: ins.nullifiers.map((x) => x.toString()),
    enabled: ins.enabled.map((x) => x.toString()),
    realInputCount: ins.enabled.filter((e) => e === 1n).length,
    inputTotal: ins.inputTotal.toString(),
    amount,
    changeValue,
    membershipOk: ins.membershipOk,
    outputCommitments: outs.map((o) => o.commitment.toString()),
    outputValues: outs.map((o) => o.value.toString()),
    ...sealMeta(outs),
  };
}

// --- depositPriv (0-in / 2-out) --------------------------------------------------

/** One requested deposit output: who receives, how much. Value 0 is legal (the
 *  "note(V) + note(0)" mint shape uses it) as long as the TOTAL is positive —
 *  a value-0 note is still a real, non-zero commitment. */
export interface ConsumerDepositOutput {
  recipient: ConsumerRecipient;
  value: string;
}

/**
 * Assemble a depositPriv ProvingRequest: mint TWO output notes, each to ANY
 * consumer recipient — third parties included, which is the consumer deposit's
 * whole point (the enterprise deposit can only mint to the depositor because it
 * publishes no per-recipient ciphertext; this one seals per output, so the
 * recipient discovers the mint by scan). The on-chain `out` public (pub[0])
 * equals the value total the pool pulls.
 *
 * Throws on an output count != 2 (the circuit arity), a negative value, or a
 * non-positive total.
 */
export function buildConsumerDepositRequest(
  outputs: ConsumerDepositOutput[],
  crypto: ConsumerDepositCrypto,
): ConsumerDepositResult {
  if (outputs.length !== 2) {
    throw new Error(`depositPriv mints exactly 2 outputs, got ${outputs.length}`);
  }
  const values = outputs.map((o) => BigInt(o.value));
  for (const [i, v] of values.entries()) {
    if (v < 0n) throw new Error(`deposit output ${i} value must be non-negative, got ${v}`);
  }
  const total = values[0] + values[1];
  if (total <= 0n) throw new Error(`deposit total must be positive, got ${total}`);

  const salts = [BigInt(crypto.salt0), BigInt(crypto.salt1)];
  const outs = planConsumerOutputs(
    outputs.map((o, i) => ({ recipient: o.recipient, value: values[i], salt: salts[i] })),
    crypto,
  );

  const inputBig: ConsumerDepositInput = {
    ...outputSide(outs),
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    encryptionNonce: BigInt(crypto.encryptionNonce),
  };

  const request = { circuit: "depositPriv", input: toWire(inputBig), backend: "cpu" } as const;
  return {
    request,
    meta: {
      outputCommitments: outs.map((o) => o.commitment.toString()),
      outputValues: outs.map((o) => o.value.toString()),
      amount: total.toString(),
      ...sealMeta(outs),
    },
  };
}

// --- transferPriv / transfer10x2Priv (n-in / 2-out) ------------------------------

/** The shared 2-output spend core: input side via spend.ts assembleInputs (the
 *  untyped-note algebra), output 0 = payment sealed to the recipient triple,
 *  output 1 = change sealed to the wallet's own triple — the pinned output
 *  order every consumer transfer fixture carries. */
function consumerTransferParts(
  identity: ConsumerWalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipient: ConsumerRecipient,
  amount: string,
  crypto: ConsumerSpendCrypto,
  arity: number,
): { input: ConsumerSpendInput; meta: ConsumerSpendMeta } {
  if (crypto.payeeSalt === undefined) {
    throw new Error("a consumer transfer needs crypto.payeeSalt for the payment output");
  }
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, arity);

  const payVal = BigInt(amount);
  if (payVal <= 0n) throw new Error(`transfer amount must be positive, got ${payVal}`);
  if (payVal > ins.inputTotal) {
    throw new Error(`amount ${payVal} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - payVal;

  const outs = planConsumerOutputs(
    [
      { recipient, value: payVal, salt: BigInt(crypto.payeeSalt) },
      {
        recipient: selfConsumerRecipient(identity),
        value: changeVal,
        salt: BigInt(crypto.changeSalt),
      },
    ],
    crypto,
  );

  const input: ConsumerSpendInput = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: identity.keypair.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    ...outputSide(outs),
    encryptionNonce: BigInt(crypto.encryptionNonce),
  };
  return { input, meta: consumerSpendMeta(ins, payVal.toString(), changeVal.toString(), outs) };
}

/**
 * Assemble a transferPriv ProvingRequest: spend 1–2 of the wallet's notes, pay
 * the recipient triple `amount`, seal the change back to the wallet. Value is
 * conserved (sum(real inputs) == amount + change); recipient == self is legal
 * (per-output nonce, OPMOD §3.5).
 */
export function buildConsumerTransferRequest(
  identity: ConsumerWalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipient: ConsumerRecipient,
  amount: string,
  crypto: ConsumerSpendCrypto,
): ConsumerSpendResult<"transferPriv"> {
  const { input, meta } = consumerTransferParts(
    identity,
    inputs,
    memberships,
    recipient,
    amount,
    crypto,
    2,
  );
  return { request: { circuit: "transferPriv", input: toWire(input), backend: "cpu" }, meta };
}

/**
 * Assemble a transfer10x2Priv ProvingRequest: the 3–10-note consolidation/spend
 * (and the merge leg of a consumer chain — a self-send where the recipient is
 * the wallet's own triple). Input side identical to the enterprise
 * transfer10x2: unused slots padded {nullifier 0, value 0, enabled 0, zeros
 * path, a value-0 self-owned commitment on its own salt}.
 */
export function buildConsumerTransfer10x2Request(
  identity: ConsumerWalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  recipient: ConsumerRecipient,
  amount: string,
  crypto: ConsumerSpendCrypto,
): ConsumerSpendResult<"transfer10x2Priv"> {
  const { input, meta } = consumerTransferParts(
    identity,
    inputs,
    memberships,
    recipient,
    amount,
    crypto,
    TRANSFER10_ARITY,
  );
  return { request: { circuit: "transfer10x2Priv", input: toWire(input), backend: "cpu" }, meta };
}

// --- withdrawPriv (2-in / 1-out + recipient) -------------------------------------

/**
 * Assemble a withdrawPriv ProvingRequest: spend 1–2 notes, push `amount` of the
 * ERC-20 to the proof-bound L1 `recipient`, seal the change note back to the
 * wallet (a full withdrawal leaves a value-0 change note — still a non-zero
 * commitment). The recipient is bound IN-PROOF so a relayer cannot redirect the
 * payout; the module range-checks the same slot on-chain (OPMOD §2).
 */
export function buildConsumerWithdrawRequest(
  identity: ConsumerWalletIdentity,
  inputs: WalletInputNote[],
  memberships: MembershipWitness[],
  amount: string,
  crypto: ConsumerSpendCrypto,
  recipient: string,
): ConsumerSpendResult<"withdrawPriv"> {
  const recipientBig = BigInt(recipient);
  if (recipientBig === 0n || recipientBig > (1n << 160n) - 1n) {
    throw new Error(`withdraw recipient must be a nonzero L1 address, got ${recipient}`);
  }
  const ins = assembleInputs(identity, inputs, memberships, crypto.padSalts, 2);

  const out = BigInt(amount);
  if (out <= 0n) throw new Error(`withdraw amount must be positive, got ${out}`);
  if (out > ins.inputTotal) {
    throw new Error(`amount ${out} exceeds spendable input total ${ins.inputTotal}`);
  }
  const changeVal = ins.inputTotal - out;

  const outs = planConsumerOutputs(
    [
      {
        recipient: selfConsumerRecipient(identity),
        value: changeVal,
        salt: BigInt(crypto.changeSalt),
      },
    ],
    crypto,
  );

  const inputBig: ConsumerWithdrawInput = {
    nullifiers: ins.nullifiers,
    inputCommitments: ins.inputCommitments,
    inputValues: ins.inputValues,
    inputSalts: ins.inputSalts,
    inputOwnerPrivateKey: identity.keypair.formattedPrivateKey,
    ecdhPrivateKey: BigInt(crypto.ecdhPrivateKey),
    root: ins.root,
    pathElements: ins.pathElements,
    leafIndices: ins.leafIndices,
    enabled: ins.enabled,
    ...outputSide(outs),
    encryptionNonce: BigInt(crypto.encryptionNonce),
    recipient: recipientBig,
  };

  const request = { circuit: "withdrawPriv", input: toWire(inputBig), backend: "cpu" } as const;
  return { request, meta: consumerSpendMeta(ins, out.toString(), changeVal.toString(), outs) };
}
