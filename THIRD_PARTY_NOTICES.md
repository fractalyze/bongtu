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
- **OpenZeppelin Contracts** (v5.0, MIT) — https://github.com/OpenZeppelin/openzeppelin-contracts.
  The UUPS proxy machinery under `contracts/src/utils/proxy/` (Initializable, ERC1967Utils,
  UUPSUpgradeable, ERC1967Proxy, Proxy, StorageSlot, Address, IERC1822Proxiable) is vendored
  byte-faithfully from OZ v5.0 (repo avoids git submodules; see `contracts/src/utils/proxy/README.md`),
  each file retaining the MIT SPDX header. `Ownable2StepUpgradeable` is an initializer twin of the repo's
  own `Ownable2Step`, modeled on OZ's.

## Runtime / SDK dependencies (npm, MIT — not vendored)

- **poseidon-lite** (MIT) — Poseidon-v1 hashing in the SDK.
- **ethers** v5 (MIT) — deploy/e2e scripts.
- **@zk-kit / @noble** family (MIT) — as pulled transitively.

## Build / proving tools (GPL — external, with one deliberate wallet exception)

These are used at build/prove time and are **not committed** to this repo (they
live in `node_modules/` or an external checkout, gitignored):

- **circomlib** (GPL-3.0) — circuit `include`s, resolved via `-l` at compile time.
- **snarkjs**, **ffjavascript** (GPL-3.0) — witness/proof generation. Tooling and
  server-side uses load out-of-process / as an external module; the wallet app is
  the deliberate exception below.
- **circom** (GPL-3.0) — the compiler.

**Copyleft isolation:** no GPL source is committed to this repo. Groth16 verifier
`.sol` files under `circuits/verifiers/` and `contracts/src/verifiers/` are
**tool output** produced by snarkjs (like a compiler's output), not derivative of
the snarkjs source. The build/compile tools (circom, circomlib) and every
tooling/server-side use of snarkjs stay external and un-bundled (out-of-process
subprocess or `createRequire` from an external `node_modules`).

**Deliberate exception — the public wallet ships snarkjs.** Per the recorded
SPEC §6 decision (a), `apps/wallet-web` distributes snarkjs (GPL-3.0) to the
browser for in-browser proving — a self-custody wallet must not send its
spending-key witnesses to a server, so server-side isolation cannot apply there.
snarkjs is dynamically imported into its own build chunk, and distribution of the
built wallet bundle must comply with GPL-3.0 for that code. The decision and its
alternatives are recorded in
[`apps/wallet-web/README.md`](apps/wallet-web/README.md) ("GPL decision"). The
sdk contains no snarkjs code — only the node-only runtime loader
(`packages/core/src/extern.ts`), which the web bundles never import. No other
distributed artifact bundles GPL code.

## Proving system parameters

The committed proving keys / verifiers derive from a **single-party** trusted
setup (testnet PoC). A production deployment requires a fresh phase-2 MPC
ceremony (see SPEC §11/§13).
