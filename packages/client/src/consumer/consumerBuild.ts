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
// This file stitches the split module back into the ONE stable public subpath
// (@bongtu/client/consumerBuild); the implementation lives in the sibling parts.
export * from "./consumerPlan.js";
export * from "./consumerRequests.js";

