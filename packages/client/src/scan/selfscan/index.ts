// The consumer self-scan discovery engine (OPMOD §3.6, .dev/op-module-design.md):
// balance and activity from the PUBLIC /events feed with only the wallet's own
// keys — no arbiter indexer, no /notes, no read-auth. The normative pipeline,
// implemented exactly:
//
//   per event, per output slice:
//     viewTag prefilter    viewTag_i == Poseidon(3)([TAG_VIEWTAG, viewPriv·ecdhPublicKey]) & 0xff
//                          — a tag miss skips ALL expensive work (~256× filter, OPMOD §3.2);
//     Decaps + open        openConsumerOutput(ct_i, kemCiphertexts[i]) at nonce + i (§3.5);
//     leaf-match           accept iff commitment(value, salt, spendPub) equals the
//                          on-chain leaf — the MAC substitute, the same rule as
//                          balance.ts trialDecryptEvents;
//     spent check          nullifier(value, salt, spendPriv) ∈ GET /nullifiers.
//
// Where the on-chain leaf comes from splits by op shape. A consumer DISBURSE
// publishes its whole commitment run in the feed entry (`outputCommitments`,
// which the indexer refuses to serve unless it folds to the SubtreeAppended
// subtreeRoot — OPMOD §4.4), so a batch note leaf-matches inline and its
// leafIndex is `batchId + outputIndex`.
// A single-append op's feed entry carries the leafIndex but NOT the leaf value,
// so the pure pass emits those decrypts as CANDIDATES and the shell confirms
// each against the indexer's auth-free `GET /path/{leafIndex}`: folding the
// candidate commitment up the served siblings must reproduce the served root
// (collision resistance makes that fold equality exactly leaf equality). A
// wrong-key or junk-KEM decrypt yields garbage whose fold cannot match — the
// S3.3 self-sabotage class surfaces as a dropped candidate, never a throw.
//
// KEM transport states (OPMOD §5): a consumer disburse whose kem cts are not
// yet assembled ("pending"/"withheld"/"accepted-unassembled") or whose
// disclosure run is not full CANNOT be scanned yet — it surfaces as a
// PendingDiscovery ("discovery pending"), never as silently empty, and the
// shell re-reads exactly those seqs on every later scan until they resolve.
//
// Enterprise coexistence: the same wallet may also hold enterprise-envelope-era
// notes (receiver cts ECDH-encrypted to the SPEND key, no viewTags). Events
// without consumer view material go through the deferred-acceptance twin of
// balance.ts trialDecryptEvents — same slice grammar, same two-nonce rule
// (event nonce + the §11-8 v1.1 per-output offset), same leaf-match, only the
// acceptance is deferred to the shared path-fold confirm. trialDecryptEvents
// itself is untouched (its Map-fed acceptance is the recovery-tooling shape).
//
// Pure core + thin fetch shell, mirroring the balance.ts pattern: everything
// above the SelfScanIo seam is synchronous and PRNG-free, so the headless suite
// (test/selfscan.test.ts) drives recorded feeds through the whole engine.
// This file stitches the split module back into the ONE stable public subpath
// (@bongtu/client/selfscan); the implementation lives in the sibling scan* parts.
export * from "./engine.js";
export * from "./run.js";

