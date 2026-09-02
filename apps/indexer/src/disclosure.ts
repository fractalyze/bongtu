// disclosureHash verification (SPEC §6b indexer duty, §4/§11-6).
//
// A `disburse` proof commits to a Poseidon(2) chain over its emitted ciphertext:
// the receiver ciphertexts (B notes x 4 field elements = [value, salt] under
// SymmetricEncrypt) FOLLOWED by the authority (non-repudiation) envelope. The
// on-chain `disclosureHash` public signal is that chain's final value. The chain
// itself never re-hashes the emitted bytes (2,054 Poseidons ~ 61M gas, §4), so
// checking that the published ciphertext actually hashes to the committed
// `disclosureHash` is delegated to the indexer. This is what makes
// non-repudiation more than contract-detect-only for the authority envelope
// (§11-6): a sender who publishes junk (or tampered) ciphertext produces a
// mismatch the indexer flags as a first-class alarm.
//
// The chain itself (fold every receiver element then every authority element,
// starting from 0) is owned by @bongtu/core/envelope::disclosureChain — one
// implementation shared with every producer, pinned byte-identical to the
// in-circuit gadget by the sdk pin suite (packages/core/test/envelope.test.ts p2).

import { disclosureChain } from "@bongtu/core/envelope";

export type DisclosureStatus =
  | "verified" // published ciphertext (receiver ++ authority) hashes to disclosureHash
  | "mismatch" // published ciphertext does NOT hash to disclosureHash (junk/tamper)
  | "unverifiable" // only receiver-length ciphertext on-chain; the chain cannot complete (§11-6)
  | "withheld"; // plain disburse(): no ciphertext published at all
// Only a full-chain match stays off the alarm channel (store.addEvent):
// "mismatch" is a proven tamper; "unverifiable"/"withheld" mean the auditor
// cannot check the chain from public data and must judge the publication gap —
// a receiver-only emission of exactly B*4 elements is indistinguishable from
// tampered receiver-only bytes, so silence here would make the §6b alarm duty
// bypassable by simply truncating what is published.

export interface DisclosureResult {
  status: DisclosureStatus;
  txHash: string;
  startLeafIndex: number;
  emittedCount: number; // # ciphertext elements published in the event
  receiverCount: number; // B * 4 (the receiver-only portion)
  recomputed: string; // decimal; Poseidon-chain over the emitted ciphertext
  expected: string; // decimal; the on-chain disclosureHash public signal
}

// Classify a disburse's published ciphertext against its committed disclosureHash.
// `emitted` is the DisburseCiphertexts array (empty for a plain disburse(), which
// publishes nothing). On-chain conventions:
//   - receiver ++ authority (length > B*4): the whole chain recomputes, so an
//     exact match passes and any other value is a proven tamper;
//   - receiver only (length == B*4): disburseWithCiphertexts withheld the
//     authority tail, so the chain cannot be completed and NO verdict is
//     reachable — "unverifiable", never "mismatch" (absence is not tamper);
//   - nothing at all: plain disburse() emits no ciphertext event — "withheld".
// A nonzero length below the receiver run is a structurally broken feed → tamper.
export function verifyDisclosure(
  emitted: bigint[],
  onchainDH: bigint,
  batchSize: number,
  txHash: string,
  startLeafIndex: number,
): DisclosureResult {
  const receiverCount = batchSize * 4;
  const recomputed = disclosureChain(emitted);
  const status: DisclosureStatus =
    emitted.length === 0 ? "withheld"
    : recomputed === onchainDH ? "verified"
    : emitted.length === receiverCount ? "unverifiable"
    : "mismatch";
  return {
    status,
    txHash,
    startLeafIndex,
    emittedCount: emitted.length,
    receiverCount,
    recomputed: recomputed.toString(),
    expected: onchainDH.toString(),
  };
}
