# bongtu contracts

The Foundry half of bongtu: `BongtuPool` — one UUPS-upgradeable contract owning the
unified single-frontier IMT, the nullifier set, arbiter epochs, ERC-20 custody, and
the five Groth16 verifier calls (with `enabled` derived on-contract from the
nullifiers) — plus the generated verifiers and the Poseidon-v1 parity plumbing. Why
the pool is shaped this way (IMT design, enabled/nullifier soundness, disclosure
enforcement) is owned by [`.dev/spec-decisions.md`](../.dev/spec-decisions.md) §5; this README covers the
folder's layout, tests, and fixtures.

## Layout

```
src/
  BongtuPool.sol       the pool (Initializable + Ownable2StepUpgradeable + UUPSUpgradeable)
  verifiers/           snarkjs-generated Groth16 verifiers, contract-renamed only:
                       Deposit, Transfer, Transfer10, Withdraw, Disburse (1x16 dev), Disburse256 (prod)
                       (byte-identical otherwise to the committed circuits/verifiers/*.sol —
                        test/VerifierDrift.t.sol gates that)
  interfaces/          IPoseidon2, IVerifiers
  utils/               vendored IERC20 / SafeERC20 / Ownable2Step(Upgradeable) / proxy (ERC-1967, UUPS —
                       provenance + faithfulness notes in src/utils/proxy/README.md)
test/
  Base.sol             shared harness (Poseidon deploy from fixture bytecode, pool wiring)
  Poseidon.t.sol       Poseidon-v1 parity gate (circomlibjs bytecode == reference hash)
  Differential.t.sol   THE differential gate: contract root == SDK ImtTree oracle at every insert
  RealProof.t.sol      committed real Groth16 proofs vs the real verifiers: accepts + soundness reverts
  Transfer10.t.sol     the 10-in/10-out entry point: both real proofs, in-tx double spend, initializeV4
  VerifierDrift.t.sol  src/verifiers/*.sol == circuits/verifiers/*.sol modulo the contract rename
  Arbiter.t.sol        arbiter epoch lifecycle (initialize, rotateArbiter)
  Enforcement.t.sol    disclosure enforcement (ciphertext-length rule, self-burn defense)
  Disburse256.t.sol    the real GPU 1x256 disburse proof on-chain at production arity
  Upgrade.t.sol        UUPS upgrade gate (state survives an implementation swap)
  GasReport.t.sol      per-operation gas via gasleft() deltas
  mocks/               MockERC20, StubVerifiers, BongtuPoolV2 (upgrade target)
  fixtures/            committed test fixtures + their generators (below)
```

## Test

```sh
forge test    # 87 tests, all committed-fixture-driven — no network, no GPU
```

`foundry.toml`: solc 0.8.24, `ffi = true`, and `fs_permissions` granting read on
`./test` (fixtures), `./src` + `../circuits/verifiers` (the verifier drift gate reads both
copies as text), and read-write on `../deploy` (the deploy scripts write
`addresses.<chainid>.json` there). The same suite runs as the `forge` CI job,
followed by `deploy/deploy_local.sh` (see [`deploy/README.md`](../deploy/README.md)).

## Fixtures

Everything the tests consume is committed under `test/fixtures/`; the `gen_*` tsx
scripts regenerate them (they read `circuits/out/` proving artifacts — build those
first, see [`circuits/README.md`](../circuits/README.md)):

| generator | produces |
|---|---|
| `gen_poseidon.ts` | `poseidon2.hex` (circomlibjs Poseidon(2) creation bytecode) + `poseidon_ref.txt` (the parity reference hash) |
| `gen_differential.ts` | `differential.json` — the interleaved deposit → transfer → disburse → withdraw insert sequence with the SDK-oracle root after every insert |
| `gen_realproofs.ts` | `realproofs.json` — Solidity-ready calldata for the real deposit/transfer/transfer10/transfer10x2/withdraw/disburse proofs + the precomputed input commitments, plus the shared `arbiterKey`. `groth16 prove` is randomized, so a re-run rewrites every entry's proof points (publics and roots are stable); regenerate deliberately, not as a side effect |
| `gen_disburse256_oracle.ts` | `disburse256.oracle.json` — the B=256 insert-sequence oracle for the real GPU proof (`disburse256.{proof,public,calldata,input,vkey}.json` are committed outputs of the GPU proving run itself) |

## Deploy

Deploy scripts live in [`deploy/`](../deploy/README.md) (local anvil gate + the live
GIWA stack); the live addresses are in `deploy/addresses.91342.json` and the root
[`README.md`](../README.md) Status table.

## License

Apache-2.0 — see the root [`LICENSE`](../LICENSE). The licensing status of the
generated verifiers under `src/verifiers/` (snarkjs tool output) is covered in
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
