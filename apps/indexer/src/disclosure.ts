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
import { poseidon2, FIELD_PRIME } from "@bongtu/core/poseidon";

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

// The served-blob verifier (SOLR §3.3.2): on the Solana rail the enterprise
// disburse bytes are INSTITUTION-served, not on-chain, and any party checks
// them by refolding against the chain-committed DisburseBatch.disclosureHash.
// Inherits the gate-6 (chains/solana/harness gate6_disburse_refold.rs)
// verifier behavior: a non-canonical alias (element + r) is rejected BEFORE
// folding — byte equality, not mod-p equivalence (OPMOD §4.4): poseidon folds
// reduce mod p silently, so an aliased element WOULD reproduce the committed
// hash for bytes the wire must refuse. `recomputed: "0"` marks the pre-fold
// reject (no fold ran); everything else delegates to the enterprise
// classifier, so the alarm classes map unchanged (mismatch / unverifiable /
// withheld).
export function verifyServedDisclosure(
  elements: bigint[],
  onchainDH: bigint,
  batchSize: number,
  txHash: string,
  startLeafIndex: number,
): DisclosureResult {
  if (elements.length > 0 && elements.some((x) => x < 0n || x >= FIELD_PRIME)) {
    return {
      status: "mismatch",
      txHash,
      startLeafIndex,
      emittedCount: elements.length,
      receiverCount: batchSize * 4,
      recomputed: "0",
      expected: onchainDH.toString(),
    };
  }
  return verifyDisclosure(elements, onchainDH, batchSize, txHash, startLeafIndex);
}

/** verifyConsumerDisclosure's answer: the alarm-classified result, plus the
 *  batch's commitment run when every check passed (the public-fill material —
 *  a null keeps a bad publish an alarm instead of a wrong fill). */
export interface ConsumerDisclosureVerdict {
  result: DisclosureResult;
  /** the B output commitments — safe to hand to
   *  MirrorTree.fillBatch(…, "public"); null on any failing check. */
  leaves: bigint[] | null;
}

// The OPMOD §4.4 consumer-disburse checks — the PUBLIC-mode duty behind the
// public batch fill. In order:
//   1. canonical form: every published element < p. The chain already rejects
//      >= p (NonCanonicalDisclosureElement), so a violation here is feed
//      corruption — classified into the existing "mismatch" alarm class rather
//      than throwing, because poseidon folds reduce mod p silently and a
//      mod-p-aliased element WOULD pass the fold while its raw bytes disagree
//      with the proven ones (§4.4 canonical-form binding).
//   2. the §4.2 extended fold over the 6B elements == the proof's
//      disclosureHash ("mismatch" otherwise). The module enforces the exact
//      length on-chain, so a wrong-length publish is a broken feed —
//      "unverifiable" for a truncation, "withheld" for an absent publish,
//      mapping the enterprise classes unchanged.
//   3. the commitment run (elements 5B..6B-1) folded pairwise up LOG_B levels
//      == the SubtreeAppended subtreeRoot. Implied by 2 + circuit soundness,
//      but kept independent because it is what makes the FILL safe: a bad
//      publish becomes an alarm instead of a 500 out of MirrorTree.path's
//      internal fold-to-root backstop. A check-3 failure reuses "mismatch"
//      with (recomputed, expected) = (fold, subtreeRoot).
export function verifyConsumerDisclosure(
  disclosure: bigint[],
  onchainDH: bigint,
  subtreeRoot: bigint,
  batchSize: number,
  txHash: string,
  startLeafIndex: number,
): ConsumerDisclosureVerdict {
  const B = batchSize;
  const expectedLen = 6 * B;
  const base: Omit<DisclosureResult, "status" | "recomputed" | "expected"> = {
    txHash,
    startLeafIndex,
    emittedCount: disclosure.length,
    receiverCount: 4 * B,
  };
  const fail = (status: DisclosureStatus, recomputed: bigint, expected: bigint = onchainDH): ConsumerDisclosureVerdict => ({
    result: { status, ...base, recomputed: recomputed.toString(), expected: expected.toString() },
    leaves: null,
  });

  if (disclosure.length === 0) return fail("withheld", 0n);
  if (disclosure.length !== expectedLen) return fail("unverifiable", 0n);
  if (disclosure.some((x) => x < 0n || x >= FIELD_PRIME)) return fail("mismatch", 0n);

  const recomputed = disclosureChain(disclosure);
  if (recomputed !== onchainDH) return fail("mismatch", recomputed);

  // Check 3 — a plain pairwise Merkle fold, no zeros involved: all B slots of a
  // consumer batch are real nonzero-commitment notes (§4.5 pads included).
  const leaves = disclosure.slice(5 * B, 6 * B);
  const fold = ((): bigint => {
    const up = (level: bigint[]): bigint[] =>
      level.length === 1 ? level : up(Array.from({ length: level.length / 2 }, (_, m) => poseidon2(level[2 * m], level[2 * m + 1])));
    return up(leaves)[0];
  })();
  if (fold !== subtreeRoot) return fail("mismatch", fold, subtreeRoot);

  return {
    result: { status: "verified", ...base, recomputed: recomputed.toString(), expected: onchainDH.toString() },
    leaves,
  };
}
