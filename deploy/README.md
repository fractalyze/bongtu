# bongtu deploy — B=256 production stack

Reusable Foundry deploy of the full production BongtuPool stack (M1 U6 / Done#2).
One script, one node, env-driven — the same two scripts run on a local anvil and
on GIWA Sepolia (only RPC + key + `--verify` differ).

## What it deploys

`forge/Deploy.s.sol` broadcasts, from a single deployer:

1. **Poseidon-v1** — from the circomlibjs creation bytecode (`contracts/test/fixtures/poseidon2.hex`),
   the byte-identical hash the circuits / SDK / tests use (inline `create`).
2. the **4 real Groth16 verifiers** — `DepositVerifier`, `WithdrawVerifier`,
   **`Disburse256Verifier`** (production 256-arity), `TransferVerifier`.
3. a **mock kKRW** ERC-20 (`MockERC20`, 18-dec, non-fee-on-transfer — the only
   shape the pool supports). On a real network, swap this for the real token
   address (the pool takes the token as a **constructor** arg — there is no
   `setERC20`; it is immutable).
4. **`BongtuPool(B=256)` behind a UUPS (ERC-1967) proxy**: the implementation is
   deployed first, then a proxy whose constructor runs
   `initialize(arbiterKey, ...)` atomically — seeding arbiter epoch 0 and wiring
   Poseidon + the 4 verifiers + the token. The **proxy** is the canonical,
   upgrade-stable pool address; the addresses file records both `pool` (proxy)
   and `poolImpl`. Owner = the deployer.

Addresses are written to `deploy/addresses.<chainid>.json` (forge also writes
`contracts/broadcast/Deploy.s.sol/<chainid>/run-latest.json`).

### Config (env, with defaults)

| env | default | meaning |
|-----|---------|---------|
| `DEPLOYER_KEY` | anvil account 0 | deployer privkey; also the owner |
| `BATCH_SIZE` | `256` | disburse batch size (production) |
| `ARBITER_KEY_X` / `ARBITER_KEY_Y` | disburse256 fixture `pub[8..9]` | arbiter authority pubkey |

The default arbiter key is read straight from the committed
`contracts/test/fixtures/disburse256.public.json` public signals `[8..9]`, i.e.
the `authorityPublicKey` the real GPU 256-disburse proof was made against — so a
real 256 disburse verifies against the deployed pool's stored key out of the box.
Override the two env vars for a production key.

## Run locally (the U6 gate)

```sh
cd bongtu && bash deploy/gates/deploy_local.sh    # exits 0 iff deploy + smoke pass
```

It starts a background anvil (chainId 31337, trap-killed on exit — no leak),
runs `forge script Deploy --broadcast`, records the addresses, reads the getters
back via `cast` (asserts `B()==256`), then runs `forge script Smoke --broadcast`:
a **real deposit** against the DEPLOYED pool using the committed real deposit
proof (`realproofs.json .deposit`) — mint mock kKRW → approve → `deposit(...)` —
and asserts the deployed instance advanced (`nextLeafIndex` 0 → 2) and custodied
the tokens. Proves the full stack is live and correctly wired.

Overridable: `DEPLOY_PORT` (default 8550), `RPC`, `CHAINID`, `FORGE`/`ANVIL`/`CAST`.

## Deploy to GIWA Sepolia (done — the live stack)

The live B=256 stack is already deployed with this pipeline: addresses in the
committed `deploy/addresses.91342.json` (proxy + impl also in the root
[`README.md`](../README.md) Status table). **The live pool is canonical — do not
redeploy for new work**; a circuit change ships as a UUPS upgrade (repo
[`CLAUDE.md`](../CLAUDE.md)). The runbook below is the recipe that produced it,
kept for a from-scratch redeploy.

GIWA Sepolia is the SAME `forge/Deploy.s.sol` with different env. Facts (verified
2026-07-23): chain **91342**, RPC **https://sepolia-rpc.giwa.io**, Blockscout
explorer https://sepolia-explorer.giwa.io, coinless (gas = ETH), Karst hardfork
(EIP-7825 per-tx gas cap 16,777,216 — the disburse gas is well under it), BN254
precompiles present (native Groth16 verify).

```sh
cd bongtu/contracts
export DEPLOYER_KEY=0x<funded-giwa-sepolia-key>   # fund via faucet.giwa.io; lives in .env (gitignored, template .env.example)
# optional: real arbiter key / real token (else a mock kKRW is deployed)
# export ARBITER_KEY_X=... ARBITER_KEY_Y=...
# export TOKEN_ADDRESS=0x<existing-erc20>

forge script ../deploy/forge/Deploy.s.sol:Deploy \
  --rpc-url https://sepolia-rpc.giwa.io \
  --broadcast --skip-simulation \
  --verify --verifier blockscout \
  --verifier-url https://sepolia-explorer.giwa.io/api
```

`--skip-simulation` is required (and is exactly what the validated `gates/deploy_local.sh`
uses): `Deploy.s.sol` deploys Poseidon via inline-assembly `create`, which forge's
on-chain simulation cannot model.

Addresses land in `deploy/addresses.91342.json`. Then the same smoke, pointed at
GIWA (needs the deployer funded; with the default `MockERC20`, mint is open):

```sh
forge script ../deploy/forge/Smoke.s.sol:Smoke --rpc-url https://sepolia-rpc.giwa.io --broadcast --skip-simulation
```

Notes for the live run:
- For a real token, set `TOKEN_ADDRESS=0x<erc20>` (no source edit needed); the
  smoke deposit then needs the deployer to actually hold + approve the deposit's
  `out` amount. With the default `MockERC20` the script mints it.
- GIWA is an OP-stack L2 → an L1 data fee applies on top of L2 gas; the RPC is
  rate-limited (Flashblocks RPC `sepolia-rpc-flashblocks.giwa.io` for ~200ms
  preconfs).
- solc pinned to 0.8.24 here; GIWA EVM is Osaka/Karst — deployment is
  permissionless and BN254 verify is native.

## Layout

Canonical data stays at the top; everything else is grouped by what runs it.

- `addresses.31337.json` / `addresses.91342.json` — recorded deployments (local anvil / live GIWA).
- `arbiter-kem-pk.91342.hex` — the live arbiter's ML-KEM-768 public key.

`forge/` — the Solidity scripts, run through `forge script` from `contracts/`:

- `Deploy.s.sol` — the whole stack in one broadcast (Poseidon + the six verifiers + impl + ERC-1967
  proxy running `initialize`) + the `addresses.<chainid>.json` writer.
- `Smoke.s.sol` — real-deposit smoke tx against the deployed pool.
- `AddressBook.sol` — the one declaration of the addresses-file field list, plus its read + merge-write.

`live/` — TypeScript drivers against the canonical LIVE GIWA pool. Each needs
`DEPLOYER_KEY` and pins `gasPrice` from `GIWA_GAS_FLOOR_GWEI`:

- `giwa_payroll_e2e.ts` — the payroll console's whole pay run, driving the console's own modules,
  every proof through the [`prover/`](../prover/README.md) service.
- `giwa_transfer10x2_e2e.ts` — the 10-in / 2-out spend gate (`--dry` for a network-free check).
- `giwa_gas_survey.ts` — per-action gas measurement feeding [`docs/performance.md`](../docs/performance.md).
- `lib/` — the viem rig + proof toolbox the drivers and the anvil gates share.

`gates/` — the pass/fail scripts (CI and pre-release):

- `deploy_local.sh` — anvil + Deploy + getter reads + Smoke, the U6 gate (also the CI `forge` job's deploy gate).
- `e2e_m0.sh` / `e2e_orchestrator.ts` — the M0 full spend-cycle e2e on a fresh anvil.
- `test_one_shot_deploy.sh` — scratch-anvil drill of the deploy: B=256, all six verifier getters
  wired and matching the record, Initializable version 1, `currentEpoch() == 0`.
- `upload_circuits.sh` — publishes the wallet's proving assets to the Vercel Blob store.

## License

Apache-2.0 — see the root [`LICENSE`](../LICENSE).
