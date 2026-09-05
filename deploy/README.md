# bongtu deploy — B=256 production stack

Reusable Foundry deploy of the full production BongtuPool stack. One script, one
node, env-driven — the same two scripts run on a local anvil and on the live
testnet, given the RPC, a funded key, and the two arbiter KEM variables that anvil
defaults but a live chain requires (see [Config](#config-env-with-defaults)).

## What it deploys

`forge/Deploy.s.sol` broadcasts, from a single deployer:

1. **Poseidon-v1** — from the circomlibjs creation bytecode (`chains/evm/test/fixtures/poseidon2.hex`),
   the byte-identical hash the circuits / SDK / tests use (inline `create`).
2. the **6 real Groth16 verifiers** — `DepositVerifier`, `WithdrawVerifier`,
   **`Disburse256Verifier`** (production 256-arity), `TransferVerifier`,
   `Transfer10Verifier`, `Transfer10x2Verifier`.
3. a **mock kKRW** ERC-20 (`MockERC20`, 18-dec, non-fee-on-transfer — the only
   shape the pool supports). On a real network, swap this for the real token
   address (the pool takes the token as an `initialize` arg and there is no
   `setERC20`, so it is fixed for the life of the deployment).
4. **`BongtuPool(B=256)` behind a UUPS (ERC-1967) proxy**: the implementation is
   deployed first, then a proxy whose constructor runs
   `initialize(arbiterKey, ...)` atomically — seeding arbiter epoch 0 and wiring
   Poseidon + all six verifiers + the token. That single call produces the full
   production shape; there is no follow-up initializer. The **proxy** is the canonical,
   upgrade-stable pool address; the addresses file records both `pool` (proxy)
   and `poolImpl`. Owner = the deployer.

Addresses are written to `deploy/addresses.<chainid>.json` (forge also writes
`chains/evm/broadcast/Deploy.s.sol/<chainid>/run-latest.json`).

### Config (env, with defaults)

| env | default | meaning |
|-----|---------|---------|
| `DEPLOYER_KEY` | anvil account 0 | deployer privkey; also the owner |
| `BATCH_SIZE` | `256` | disburse batch size (production) |
| `ARBITER_KEY_X` / `ARBITER_KEY_Y` | disburse256 fixture `pub[8..9]` | arbiter authority pubkey |
| `ARBITER_KEM_PK_HASH` | fixture hash — **chain 31337 only** | `keccak256` of the arbiter's ML-KEM-768 encapsulation key. Off anvil there is no default: `Deploy.s.sol` reads it with `vm.envBytes32`, which reverts when unset, and refuses the fixture value outright |
| `ARBITER_KEM_PK` | fixture key — **chain 31337 only** | the full encapsulation key recorded next to the hash; must hash to `ARBITER_KEM_PK_HASH`. Off anvil the deploy self-check fails without it (`no ARBITER_KEM_PK recorded`) |
| `LIVE_RPC` | the sdk `RPC_URL` | the chain the live invocation below and the `live/` drivers talk to (`.env.example` carries it) |
| `MODULE_PROFILE` | `none` (Deploy) / `consumer` (UpgradeV3) | which consumer module set the deployment registers — see [Deploy profiles](#deploy-profiles) |
| `MODULE_CHUNK_ARITY` | 86 at B=256, else 6 (min B) | outputs per disburse kem-ct chunk tx (OPMOD §5) |

### Deploy profiles

Which op families a deployment serves is the module registration list (OPMOD §7/§9 —
registration is `onlyOwner` + event-logged, upgrade-equivalent power):

| profile | how | arbiter key | what is registered |
|---|---|---|---|
| audited-only / enterprise | `Deploy.s.sol` with `MODULE_PROFILE=none` (the default — byte-identical to the pre-profile deploy), or `UpgradeV3.s.sol` with `MODULE_PROFILE=none` | required (epoch 0) | no consumer modules — the pool-level audit guarantee holds |
| consumer (shared pool) | `Deploy.s.sol MODULE_PROFILE=consumer` (fresh — how the live 450815 pool got them at genesis), or `UpgradeV3.s.sol` (the migration an existing pool would take — drilled on anvil only, never run on the retired 84532 pool, which stayed audited-only) | required (enterprise family live) | the 5 consumer modules via `ConsumerModuleKit` (`deploy/modules.<chainid>.json`). The shipped Maroo pool subsequently deregistered the disburse module (mass payout is enterprise-path only); a leaner p2p profile knob is follow-up work |
| consumer-only | `DeployConsumerOnly.s.sol` | **none exists** — `initializeConsumerOnly` mints no arbiter epoch, wires no enterprise verifier; every enterprise entrypoint reverts | the 5 consumer modules (records `addresses.consumer.<chainid>.json` + `modules.consumer.<chainid>.json`) |

`UpgradeV3.s.sol` is the OPMOD §7.3 migration for an EXISTING pool: consumer verifiers +
modules deployed first (inert until registered), then ONE
`upgradeToAndCall(reinitializeV3(modules))` — drilled by `gates/test_upgrade_v3.sh`
(v1 proxy → v3, modules registered, enterprise Smoke still accepted, rerun refused).

The two KEM knobs are **required off anvil, and deliberately have no live default** — a silent
fixture fallback would make every auditor envelope world-readable with nothing in the deploy saying
so ([`Deploy.s.sol` `_resolveKemPkHash`](forge/Deploy.s.sol)).

The default arbiter key is read straight from the committed
`chains/evm/test/fixtures/disburse256.public.json` public signals `[8..9]`, i.e.
the `authorityPublicKey` the real GPU 256-disburse proof was made against — so a
real 256 disburse verifies against the deployed pool's stored key out of the box.
Override the two env vars for a production key.

## Run locally

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

## Deploy to the live testnet

The live B=256 stack is already deployed with this pipeline; its addresses are in
the committed `deploy/addresses.450815.json` (the retired Base Sepolia stack stays
recorded in `addresses.84532.json`). **The live pool is canonical — do not
redeploy for new work**; a circuit change ships as a UUPS upgrade (repo
[`CLAUDE.md`](../CLAUDE.md)). The runbook below is the recipe that produced it,
kept for a from-scratch redeploy.

The live chain is the SAME `forge/Deploy.s.sol` with different env. Its facts —
chain id, RPC, explorer, faucet, gas-price pin — have one home,
`packages/core/src/chain/network.ts`, and are tabulated in
[`docs/deployment.md`](../docs/deployment.md#chain-facts). It is a sovereign EVM
L1 (Cosmos-SDK x/feemarket EIP-1559 fees, gas token tOKRW) with the BN254
precompiles present — the smoke deposit's Groth16 proof verified natively on-chain.

```sh
cd bongtu/chains/evm
export DEPLOYER_KEY=0x<funded-key>   # from the chain's faucet; lives in .env (gitignored, template .env.example)
export LIVE_RPC=<the chain's RPC>    # docs/deployment.md#chain-facts; .env.example carries the current one

# REQUIRED off anvil — no default, and the fixture value is refused:
export ARBITER_KEM_PK_HASH=0x<keccak256 of the institutional encapsulation key>
export ARBITER_KEM_PK=0x<the full 1184-byte encapsulation key>

# optional: real arbiter bjj key / real token (else a mock kKRW is deployed)
# export ARBITER_KEY_X=... ARBITER_KEY_Y=...
# export TOKEN_ADDRESS=0x<existing-erc20>

forge script ../deploy/forge/Deploy.s.sol:Deploy \
  --rpc-url "$LIVE_RPC" \
  --broadcast --skip-simulation
```

`--skip-simulation` is required (and is exactly what the validated `gates/deploy_local.sh`
uses): `Deploy.s.sol` deploys Poseidon via inline-assembly `create`, which forge's
on-chain simulation cannot model.

Addresses land in `deploy/addresses.<chainid>.json`. Then the same smoke, pointed
at the live chain (needs the deployer funded; with the default `MockERC20`, mint
is open):

```sh
forge script ../deploy/forge/Smoke.s.sol:Smoke --rpc-url "$LIVE_RPC" --broadcast --skip-simulation
```

Notes for the live run:
- For a real token, set `TOKEN_ADDRESS=0x<erc20>` (no source edit needed); the
  smoke deposit then needs the deployer to actually hold + approve the deposit's
  `out` amount. With the default `MockERC20` the script mints it.
- The chain is an L1, so a receipt's `gasUsed` × effective gas price is the whole
  cost (no OP-Stack L1 data fee). The x/feemarket base fee floor is high (8000
  gwei measured 2026-09-04) — budget deploys in whole tOKRW, not fractions.
- solc is pinned to 0.8.24 here; deployment is permissionless and BN254 verify is
  native.
- Source verification on the live chain's Blockscout works per contract:
  `forge verify-contract <addr> <path>:<Name> --chain-id 450815 --verifier blockscout
  --verifier-url https://explorer-testnet.maroo.io/blockscout/api` (constructor
  args for the proxy). The pool implementation, proxy and DepositVerifier are
  verified; Poseidon cannot be (no Solidity source).

## Layout

Canonical data stays at the top; everything else is grouped by what runs it.

- `addresses.31337.json` / `addresses.450815.json` — recorded deployments (local anvil / the live
  testnet); `addresses.84532.json` is the retired Base Sepolia stack, kept as a historical record.
  Take an address from these **by field name**: the deployer replays the same CREATE
  nonces on every chain, so several addresses recur across deployments while
  naming different contracts.
- `modules.<chainid>.json` — the consumer module set registered on the pool of
  `addresses.<chainid>.json` (written by `Deploy.s.sol MODULE_PROFILE=consumer` and
  `UpgradeV3.s.sol`; the canonical on-chain source is the `ModuleRegistered` event stream, this
  file is the deploy-time mirror). The 31337 file is tracked scratch, same as `addresses.31337.json`.
- `addresses.consumer.<chainid>.json` / `modules.consumer.<chainid>.json` — the consumer-only
  profile's record pair (`DeployConsumerOnly.s.sol`; tracked scratch at 31337).
  The **by field name** rule above covers the module records too: never take an address from any
  of these files by pattern-matching a remembered value.
- `arbiter-kem-pk.450815.hex` — the live arbiter's ML-KEM-768 public key (byte-identical to the
  historical `arbiter-kem-pk.84532.hex`: the arbiter did not rotate on the chain move).

`forge/` — the Solidity scripts, run through `forge script` from `chains/evm/`:

- `Deploy.s.sol` — the whole stack in one broadcast (Poseidon + the six verifiers + impl + ERC-1967
  proxy running `initialize`) + the `addresses.<chainid>.json` writer; `MODULE_PROFILE=consumer`
  additionally deploys + registers the consumer module set.
- `UpgradeV2.s.sol` — the shipped stealth-withdraw upgrade (verifier + impl + `reinitializeV2`).
- `UpgradeV3.s.sol` — the op-module upgrade for an EXISTING pool: consumer verifiers + modules +
  ONE `upgradeToAndCall(reinitializeV3(modules))` (OPMOD §7.3); merge-writes `poolImpl`, writes
  `modules.<chainid>.json`.
- `DeployConsumerOnly.s.sol` — the consumer-only profile (`initializeConsumerOnly`: no arbiter key
  exists; consumer modules are the whole op surface).
- `ConsumerModuleKit.sol` — the one declaration of the consumer module-set deploy + its record writer.
- `Smoke.s.sol` — real-deposit smoke tx against the deployed pool.
- `AddressBook.sol` — the one declaration of the addresses-file field list, plus its read + merge-write.

`live/` — TypeScript drivers against the canonical LIVE pool (`addresses.<chainid>.json`). Each needs
`DEPLOYER_KEY` and pins `gasPrice` from `GAS_PRICE_PIN_GWEI`:

- `payroll_e2e.ts` — the payroll console's whole pay run, driving the console's own modules,
  every proof through the [`prover/`](../prover/README.md) service.
- `transfer10x2_e2e.ts` — the 10-in / 2-out spend gate (`--dry` for a network-free check).
- `gas_survey.ts` — per-action gas measurement feeding [`docs/performance.md`](../docs/performance.md).
- `lib/` — the viem rig + proof toolbox the drivers and the anvil gates share.

`gates/` — the pass/fail scripts (CI and pre-release):

- `deploy_local.sh` — anvil + Deploy + getter reads + Smoke (also the CI `forge` job's deploy gate).
- `test_upgrade_v3.sh` — the op-module upgrade drill (v1 proxy → UpgradeV3 → modules registered,
  enterprise Smoke still accepted, rerun refused).
- `e2e_m0.sh` / `e2e_orchestrator.ts` — the M0 full spend-cycle e2e on a fresh anvil, including the
  portal leg (`portal_leg.ts`) and the arbiter-free consumer leg (`consumer_leg.ts`: profile deploy +
  V3 upgrade, CPU-proved consumer ops + disburse chunk txs, PUBLIC indexer, self-scan discovery +
  batch-interior spend via the auth-free `/path`, and the committed disbursePriv256 calldata replay).
- `test_one_shot_deploy.sh` — scratch-anvil drill of the deploy: B=256, all six verifier getters
  wired and matching the record, Initializable version 1, `currentEpoch() == 0`.
- `upload_circuits.sh` — publishes the wallet's proving assets to the Vercel Blob store.

## License

Apache-2.0 — see the root [`LICENSE`](../LICENSE).
