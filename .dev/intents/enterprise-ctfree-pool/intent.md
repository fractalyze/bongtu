# Ct-free enterprise circuits and the dedicated-pool deploy profile

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

Enterprise receiver ciphertexts (transfer / transfer10 / transfer10x2 / disburse) are
classical-ECDH-only and permanently published: a future ECDLP break retro-decrypts every
recipient's [value, salt] and linkage (HNDL — recorded as the U8 exposure in
docs/security-model.md). Issue #10 resolved the fork on 2026-09-04: enterprise becomes N
dedicated pools (one per institution, own arbiter key/epochs) running **ct-free** enterprise
circuits — receiver-cts removed, the hybrid authority envelope kept — with discovery served
by the institution's own indexer. None of that shape exists yet: there are no ct-free
circuit variants and no deploy profile that stands up a dedicated enterprise pool.

This is the foundation slice of the #10 campaign; indexer internal mode and the receipt
convention are separate intents (`enterprise-indexer-internal`, `enterprise-receipts`).

## Proposed outcome

- Ct-free variants of the four enterprise bases exist: EncryptOutputs stripped from the
  three spending bases and the deposit base, authority envelope untouched; verifiers,
  zkeys (including the disburse256 GPU zkey and its witness .so/w2s pair), and committed
  fixtures regenerated.
- A deploy profile stands up an enterprise-dedicated pool: audited-only registration,
  ct-free verifiers, named record files `addresses.<chainid>.<name>.json` (the
  consumer.31337 precedent).
- A gate on a fresh local chain proves deposit → disburse settles on a pool the profile
  just created.
- A committed testnet (84532) deployment record exists for an enterprise pool.
- The live Maroo pool (450815), its records, and all existing circuits are byte-for-byte
  unchanged.

## Affected users and systems

Employer, recipient, arbiter. Components: circuits, contracts (EVM deploy scripts and
registration path), prover fixtures, deploy/. Indexer and wallets are out of scope here.

## Constraints

- Live pool untouched; existing circuits and verifiers untouched (variants are additive).
- disburse256 zkey regen is GPU-box-only (~2.5 min setup, 1.24 GB zkey); the witness .so +
  w2s must be rebuilt in the same change or the prover service fails at boot.
- Committed fixtures bind to one arbiter key; new ct-free fixtures must be proven against
  whatever key the profile deploys with, or the smoke deposit reverts InvalidProof.
- Sequencing with the `deploy-per-chain` intent: whichever lands second rebases; if the
  split lands first, the new records go under deploy/evm/.

## Open questions

- Variant naming scheme for circuit files and verifier contracts.
- Exact public-signal index deltas and their ABI/event impact on the pool contract.
- Whether BongtuPool is reused with zero code change (the decided model assumes the pool
  contract is reused via deploy profile) or needs a registration-mode switch.
- Testnet arbiter key handling: Deploy.s.sol default vs a fresh institution key.
