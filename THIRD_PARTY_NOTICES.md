# Third-party notices

bongtu is licensed under Apache-2.0 (see `LICENSE`, `NOTICE`). It builds on and
depends on the following third-party software.

## Derived source (redistributed, in this repo)

- **Zeto** — https://github.com/hyperledger-labs/zeto — Apache-2.0, © 2024 Kaleido, Inc.
  Portions of the circom circuits and the on-chain/SDK design are derived from Zeto.
  Derived files under `circuits/` retain the Apache-2.0 SPDX header and Kaleido
  copyright, and carry a per-file note describing the modification (e.g.
  `circuits/lib/check-nullifiers-value-imt-base.circom` rebases the value-keyed
  SMT membership onto an append-only IMT;
  `circuits/lib/anon_enc_nullifier_non_repudiation_imt_small_base.circom` is a
  reduced-arity non-repudiation base). The `BongtuPool` Solidity and the SDK are
  newly written but follow Zeto's design (UTXO commitments, nullifiers,
  ECDH + Poseidon-sponge encryption, non-repudiation envelope).
- **forge-std** — https://github.com/foundry-rs/forge-std — MIT OR Apache-2.0.
  Vendored under `contracts/lib/forge-std/` with its `LICENSE-MIT` / `LICENSE-APACHE`.

## Runtime / SDK dependencies (npm, MIT — not vendored)

- **poseidon-lite** (MIT) — Poseidon-v1 hashing in the SDK.
- **ethers** v5 (MIT) — deploy/e2e scripts.
- **@zk-kit / @noble** family (MIT) — as pulled transitively.

## Build / proving tools (GPL — NOT redistributed, external only)

These are used at build/prove time and are **not** committed or bundled into any
distributed artifact (they live in `node_modules/` or an external checkout,
gitignored):

- **circomlib** (GPL-3.0) — circuit `include`s, resolved via `-l` at compile time.
- **snarkjs**, **ffjavascript** (GPL-3.0) — witness/proof generation, loaded
  out-of-process / as an external module.
- **circom** (GPL-3.0) — the compiler.

**Copyleft isolation:** no GPL source is committed to this repo and no GPL code
is bundled into a distributed binary. Groth16 verifier `.sol` files under
`circuits/verifiers/` and `contracts/src/verifiers/` are **tool output** produced
by snarkjs (like a compiler's output), not derivative of the snarkjs source.
When the SDK/wallet is later distributed to end users, snarkjs MUST stay
server-side or an unbundled peer dependency so the copyleft is not triggered on
the distributed bundle (see SPEC §6).

## Proving system parameters

The committed proving keys / verifiers derive from a **single-party** trusted
setup (testnet PoC). A production deployment requires a fresh phase-2 MPC
ceremony (see SPEC §11/§13).
