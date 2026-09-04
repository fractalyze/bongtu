# Deployment

The live bongtu stack runs on **Maroo Testnet, chain 450815** — deployed fresh on 2026-09-04,
dual-mode from genesis: `Deploy.s.sol MODULE_PROFILE=consumer` registered the five consumer
modules inside the deploy broadcast, so there is no V3 upgrade on this chain. Source of truth for
every address is `deploy/addresses.450815.json`, written by the deploy script and mirrored (with
an equality test) into `packages/core/src/network.ts` so both web apps read one set of constants.
The retired Base Sepolia stack (chain 84532) stays recorded in `deploy/addresses.84532.json` as a
historical record; it is no longer a live target.

## Live addresses

`deploy/addresses.450815.json` is canonical. Read an address out of it **by field name** and do not
transcribe one from anywhere else — the deployer replayed the same CREATE nonce sequence it had used
on the previous chains, so several addresses are byte-identical across deployments while naming
**different contracts** (Base Sepolia's *poseidon* address is this deployment's *depositPrivModule*;
its *depositVerifier* is now *transferPrivModule*). An address that merely looks familiar is the
failure mode this warning exists for. The consumer module set registered at genesis is recorded in
`deploy/modules.450815.json`. The pool registered five consumer modules at genesis, then
deregistered the consumer disburse module on 2026-09-04 (`removeModule`, tx
`0x41dc6e9b85ad4dd6d98f353db27d7cf36acb82c0e4101e31d8bc6df9e1dd0db2`) by product decision — mass
payout is an institution-managed-pool feature, enterprise-path only. The live family is the four
consumer P2P modules plus the full enterprise surface.

| role | field in `addresses.450815.json` |
|---|---|
| BongtuPool — ERC-1967 proxy, the canonical pool | `pool` |
| BongtuPool implementation | `poolImpl` |
| Poseidon-v1 hasher | `poseidon` |
| DepositVerifier | `depositVerifier` |
| WithdrawVerifier | `withdrawVerifier` |
| Disburse256Verifier | `disburseVerifier` |
| TransferVerifier | `transferVerifier` |
| Transfer10Verifier | `transfer10Verifier` |
| Transfer10x2Verifier | `transfer10x2Verifier` |
| mock kKRW (ERC-20) | `token` |
| owner / deployer | `owner` |

`packages/core/test/network.test.ts` holds the module constants to that file field-for-field, so a
stale copy in `network.ts` fails in milliseconds instead of at on-chain proof rejection. When the
two disagree, the JSON is right.

The pool implementation, the proxy and `DepositVerifier` are source-verified on the Blockscout
explorer (`forge verify-contract --verifier blockscout`, 2026-09-04); the other verifiers and the
mock token are bytecode-only — verify them the same way if needed. Poseidon has no Solidity source
at all — it is deployed from circomlibjs *creation bytecode*
(`contracts/test/fixtures/poseidon2.hex`). Audit everything against this repo at the commit that
deployed it.

Externally, call the proxy address simply "the pool contract"; "proxy" is plumbing vocabulary.

`batchSize` is 256. The **proxy** is the address to integrate against: the implementation and the
verifier addresses change on a circuit edit, the proxy address does not. The live pool is canonical
and is not redeployed for new work — a circuit change ships as a UUPS `upgradeToAndCall`
([contracts.md](contracts.md#proxy-and-wiring)).

`deploy/addresses.31337.json` is the equivalent record for the local anvil stack.

## Deploying

One script, one transaction sequence, one shape. `deploy/forge/Deploy.s.sol` deploys Poseidon-v1, the
six Groth16 verifiers, optionally a mock kKRW, the pool implementation, and an `ERC1967Proxy` whose
constructor runs `initialize` — which wires all six verifiers, derives the tree parameters and mints
arbiter epoch 0 carrying both halves of the authority key. There is no second step: the pool serves
every entry point from its first block, and `currentEpoch()` is 0 on a chain that has never rotated.

`deploy/gates/test_one_shot_deploy.sh` drills exactly that against a scratch anvil and cast-verifies
the result — `B() == 256`, all six verifier getters non-zero and matching the recorded addresses,
the Initializable version slot reading 1, `currentEpoch() == 0`.

Config is env-driven so the same script targets anvil or a testnet — with one asymmetry: the two KEM
variables have **no live default and are required off anvil**.

| variable | default |
|---|---|
| `DEPLOYER_KEY` | anvil account 0 |
| `BATCH_SIZE` | 256 |
| `ARBITER_KEY_X` / `ARBITER_KEY_Y` | the fixture arbiter bjj key (see the coupling section below) |
| `ARBITER_KEM_PK_HASH` | `keccak256` of the fixture ML-KEM-768 encapsulation key — **on chain 31337 only**; **REQUIRED** on any other chain |
| `ARBITER_KEM_PK` | the fixture encapsulation key — **on chain 31337 only**; **REQUIRED** on any other chain, and must hash to `ARBITER_KEM_PK_HASH` |
| `TOKEN_ADDRESS` | unset — deploys a mock kKRW; set it to an existing non-fee-on-transfer ERC-20 |

Off chain 31337 the script reads the hash with `vm.envBytes32` (which reverts when unset) and then
rejects the fixture value outright, and its self-check fails without a recorded `ARBITER_KEM_PK`.
The fixture keypair is public on both halves, so a silent fallback would leave every auditor
envelope readable with no symptom in the deploy output.

## Upgrading

The proxy address is permanent; the implementation behind it is not. A circuit or verifier change
ships as an owner-only `upgradeToAndCall` that carries the new implementation and its regenerated
verifiers **in one transaction**. Atomicity is load-bearing whenever the public-signal count moves:
old proofs fail new verifiers and vice versa, so a two-step swap would leave a window in which every
affected op reverts.

Whatever storage the change needs is moved by a fresh `reinitializer(2)` payload written against
that change — the pool ships with the version slot at 1 and nothing reserved in advance. Two rules
the payload must respect, both pinned by `contracts/test/Upgrade.t.sol`:

| rule | why |
|---|---|
| new state is APPENDED at the tail, off `uint256[47] __gap` | inserting a slot beside a logically-related one re-strides everything below it; a mis-declared layout does not announce itself, it moves the IMT root |
| a new verifier slot is filled in the SAME transaction as the implementation swap | the slot is zero until the payload runs, and the entry point calls it directly, so a bare `upgradeTo` would leave a pool that advertises the op and reverts on every call to it |

An upgrade should re-read the live proxy afterwards and require that everything it did not intend to
touch — the other verifiers, the arbiter key material, the epoch, and the IMT root plus
`nextLeafIndex` — is unchanged from the values pinned before broadcasting. The tree pair is the
check that catches a layout mistake.

The first live upgrade shipped this way on **2026-09-01**: the stealth-exit withdraw
(`recipient` at pub[26], uint[27]) via `deploy/forge/UpgradeV2.s.sol` — new
`WithdrawVerifier` + implementation + `reinitializeV2` in one broadcast, with two
pre-broadcast guards (the key must be the recorded owner; the version slot must
still read 1) so a misconfigured live run cannot strand orphan contracts after
paying their gas. `deploy/gates/test_upgrade_v2.sh` is the drill: it proves the
v1→v2 transition on a fresh anvil deploy, storage intact, second run refused.
The addresses live in `deploy/addresses.84532.json` (one owner; this file does
not restate them). One operational observation worth keeping: the public
`sepolia.base.org` RPC is load-balanced, and the first read after the broadcast
returned a MIXED view (new initializer slot, old verifier) from a lagging
replica — post-upgrade verification must re-read until consecutive reads agree.

## Deploy profiles and the consumer module family

Which op families a pool serves is its module registration list (`.dev/op-module-design.md`
§1/§7 — registration is `onlyOwner`, event-logged, and upgrade-equivalent power). Three
profiles exist; the env knob and script per profile live in
[`deploy/README.md`](../deploy/README.md#deploy-profiles):

- **audited-only / enterprise** — `Deploy.s.sol` with `MODULE_PROFILE=none` (the default;
  byte-identical to the pre-profile deploy). No consumer module is registered, so the
  pool-level audit guarantee holds: every op that exists is arbiter-disclosable.
- **consumer on the shared pool** — the live 450815 pool took the fresh-deploy form of this
  profile (`Deploy.s.sol MODULE_PROFILE=consumer` at genesis); the migration form below is the
  path an existing pool would take — drilled on anvil by `deploy/gates/test_upgrade_v3.sh`, never
  run on the retired 84532 pool, which stayed audited-only. Order per OPMOD §7.3:
  1. deploy the five consumer verifiers + five module contracts
     (`deploy/forge/ConsumerModuleKit.sol`; modules are inert until registered, so this
     carries no sequencing risk);
  2. deploy the new `BongtuPool` implementation (`applyOp*` + module registry +
     `reinitializeV3`; the six enterprise entrypoints byte-identical);
  3. ONE `upgradeToAndCall(impl, reinitializeV3(modules))` (`deploy/forge/UpgradeV3.s.sol`).
     Unlike the v2 upgrade there is no verifier-swap atomicity constraint — the enterprise
     verifiers are untouched, so enterprise ops keep verifying before, during and after.
  The module addresses land in `deploy/modules.<chainid>.json`; the canonical on-chain
  source is the `ModuleRegistered`/`ModuleRemoved` event stream.
- **consumer-only** — `deploy/forge/DeployConsumerOnly.s.sol`, built on
  `initializeConsumerOnly`: **no arbiter key exists at all** (no epoch minted, no KEM pk
  hash, no enterprise verifier wired), rather than a burned placeholder. Every enterprise
  entrypoint reverts on such a pool; the consumer modules are its whole op surface. The
  KEM deploy knobs above do not apply to this profile — there is no authority envelope to
  key. Pinned by `contracts/test/ConsumerOnly.t.sol`.

The consumer end-to-end leg of `deploy/gates/e2e_m0.sh` (`deploy/gates/consumer_leg.ts`)
proves the consumer flows with no arbiter-mode indexer in the loop: profile deploy + V3
upgrade, real CPU-proved consumer ops (including the disburse chunk transport), a
public-mode indexer, and self-scan discovery + a batch-interior spend through the
auth-free `/path`.

## The hybrid PQ authority envelope

Epoch 0 carries an ML-KEM-768 encapsulation-key hash alongside the bjj arbiter key, so every
envelope is hybrid from the pool's first operation.

| on a fresh deploy | value |
|---|---|
| `currentEpoch()` | **0** |
| `arbiterKemPkHash(0)` | `keccak256` of the institutional 1184-byte encapsulation key |
| `KEM_CIPHERTEXT_LEN()` | 1088 |

The key itself is a **public** value distributed off-chain in three places that are equality-tested
against each other: `deploy/arbiter-kem-pk.450815.hex` (the committed material), the `arbiterKemPk`
field of `deploy/addresses.450815.json`, and `ARBITER_KEM_PK` in `packages/core/src/network.ts`,
which ships it to both web apps. The addresses file also records `arbiterKemPkHash` alongside
`arbiterKeyX` / `arbiterKeyY`.

Clients never trust their bundled copy. Before drawing KEM material they read
`arbiterKemPkHash(currentEpoch())` from the pool and refuse to proceed unless it equals
`keccak256(ARBITER_KEM_PK)`. So a stale bundle produces a readable error, never a wasted proof or a
silently mis-keyed envelope.

**`AUTHORITY_KEM_KEY` is an operational requirement for arbiter mode.** An arbiter-mode indexer
needs the ML-KEM-768 *decapsulation* key in that env var alongside `AUTHORITY_KEY`, or it refuses to
boot — as it also does if the key's embedded encapsulation key hashes to something other than the
on-chain value. Both refusals are deliberate: serving without the key would under-record every
envelope, and serving with the wrong one would stamp every honest operation as tampered
([indexer.md](indexer.md#the-kem-boot-guard)). `docker-compose.yml` forwards the variable; like
`AUTHORITY_KEY` it is never logged and never serialized.

## Chain facts

Every fact below has exactly one home — `packages/core/src/network.ts` — from which both apps, the
indexer and the `deploy/live/` drivers read it. Nothing here is named after the chain, so a future
move is that module plus the deploy record rather than another repo sweep.

| fact | value | export |
|---|---|---|
| chain id | 450815 | `CHAIN_ID` |
| chain name | Maroo Testnet | `CHAIN_NAME` |
| RPC | `https://rpc-testnet.maroo.io` | `RPC_URL` |
| WebSocket | `wss://ws-testnet.maroo.io` | `WS_URL` |
| explorer | `https://explorer-testnet.maroo.io` (Blockscout) | `EXPLORER_BASE` |
| faucet | `https://faucet.maroo.io` | `GAS_FAUCET_URL` |
| gas token | tOKRW, 18-dec (sovereign EVM L1; EIP-1559 via Cosmos x/feemarket) | `NATIVE_CURRENCY` |
| per-tx gas cap | none published; every op fits the previous chain's 16,777,216 EIP-7825 cap (asserted in `contracts/test/Disburse256.t.sol`) | — |
| BN254 precompiles | present — the smoke deposit's Groth16 proof verified natively on-chain | — |
| gas price the runners pin | `18000` gwei (quote 9000 gwei = 8000 base + 1000 tip, 2026-09-04) | `GAS_PRICE_PIN_GWEI` |

This is a testnet deployment; every address and measurement in these docs is testnet.

The runners **pin** the gas price rather than let a client estimate it — the constant is a hard pin,
not a floor to be lowered: an auto-estimate can overshoot the real price by orders of magnitude and
drain a faucet grant in a handful of transactions. Every `deploy/live/` driver builds its viem rig
with `gasPrice: parseGwei(GAS_PRICE_PIN_GWEI)`.

## Scripts

| file | does |
|---|---|
| `deploy/forge/Deploy.s.sol` | deploys Poseidon + the 6 verifiers + (optionally) a mock kKRW + the pool implementation + an `ERC1967Proxy` whose constructor runs `initialize` atomically; writes `addresses.<chainid>.json` |
| `deploy/forge/AddressBook.sol` | the field list of `addresses.<chainid>.json`, declared once, with a read + merge-write a script uses to name only the fields it changes |
| `deploy/forge/Smoke.s.sol` | a real `deposit` against the deployed pool using the committed proof fixture |
| `deploy/gates/deploy_local.sh` | anvil + Deploy + getter read-back + Smoke — the local gate |
| `deploy/gates/test_one_shot_deploy.sh` | scratch-anvil drill of the deploy: B=256, all six verifier getters wired and matching the record, Initializable version 1, `currentEpoch() == 0` |
| `deploy/live/payroll_e2e.ts` | the payroll console's whole pay run against the live pool, driving the console's own modules (mint → deposit → forced merge leg → 3-recipient disburse → signed `/notes` checks), every proof via the prover service |
| `deploy/live/transfer10x2_e2e.ts` | the live 10-in / 2-out spend gate (merge leg + padded spend); `--dry` runs the structural checks with no network |
| `deploy/live/gas_survey.ts` | per-action gas measurement against the live pool, feeding the table in [performance.md](performance.md) |
| `deploy/gates/e2e_m0.sh`, `deploy/gates/e2e_orchestrator.ts` | the cross-circuit spend-cycle end-to-end on a local anvil |
| `deploy/gates/upload_circuits.sh` | uploads the wallet's proving assets (wasm + zkey) to the Vercel Blob store under a `CIRCUITS_VERSION` path, refusing assets whose zkey hash misses the pin in the wallet's `config.ts` |

Environment knobs and the exact live invocation are in `deploy/README.md`. Two facts that are easy
to lose and expensive to rediscover:

- **`--skip-simulation` is required.** `Deploy.s.sol` deploys Poseidon via inline-assembly `create`,
  which forge's on-chain simulation cannot model.
- The deployer key lives in `.env` (gitignored, template `.env.example`); `contracts/broadcast/`
  and `contracts/cache/` are gitignored.

## The arbiter key is fixed at deploy, and the fixtures are bound to it

`initialize` stores the arbiter public key in epoch 0, and every operation injects that stored key
into the proof's `authorityPublicKey` public signals before verifying. A proof encrypted to any
other key fails.

```
 contracts/test/fixtures/disburse256.public.json  pub[8..9]
                    ||  (same value)
 contracts/test/fixtures/realproofs.json  .arbiterKey
                    ||  (Deploy.s.sol default for ARBITER_KEY_X / ARBITER_KEY_Y)
                    vv
        pool.arbiterEpochs[0]  ──injected──>  every verifyProof call
```

Every committed proof fixture — the deposit proof the smoke step submits, the real 256-disburse
proof the contract tests accept — was produced against that one key. Overriding `ARBITER_KEY_X` /
`ARBITER_KEY_Y` without re-proving the fixtures deploys a pool whose stored key no longer matches
them, and the smoke deposit reverts `InvalidProof`. Rotate the key **and** the fixtures together, or
neither.

The coupling is a **pair**, because the envelope is hybrid: the fixtures are bound to (arbiter bjj
key, arbiter ML-KEM-768 pk), and the fixture encapsulation key travels as `realproofs.kemPublicKey`
the same way `realproofs.arbiterKey` does. `ARBITER_KEM_PK_HASH` is the matching deploy knob.

Only half of that pair can travel to a live chain, and the consequence is visible. The bjj half
must stay the fixture key or the smoke proof stops verifying; the KEM half must NOT be the fixture
key, because that keypair's seed is public (`_resolveKemPkHash` refuses it off anvil). So the smoke
deposit's envelope is encapsulated to the fixture ML-KEM key while epoch 0 carries the
institution's — and an arbiter-mode indexer, holding the institutional decapsulation key,
decapsulates to a different shared secret and raises

```
ALARM envelope deposit tx=0x… kem binding mismatch — envelope withheld
```

That alarm is **correct**: the envelope genuinely cannot be opened by this pool's arbiter, which is
exactly the condition the alarm exists to report. It is a property of the smoke fixture, not of the
deployment — but it means a live chain deployed this way carries one permanent disclosure alarm
from its own smoke step, so `/alarms` starts at 1 rather than 0. Expect it, and do not read it as
tampering. (It did not arise on the previous chain because the smoke ran while epoch 0 still held
the fixture keypair, and the institutional key only arrived with a later epoch. Collapsing the
initializer moved the institutional key to epoch 0, which is what surfaces it.) To start a live
chain at zero alarms, skip the smoke deposit there and prove the wiring with the `cast` read-backs
instead.

The live pool's stored key is recorded as `arbiterKeyX` / `arbiterKeyY` in
`deploy/addresses.450815.json` and re-exported as `ARBITER_PUBKEY_X` / `ARBITER_PUBKEY_Y` from
`packages/core/src/network.ts`. It is a **public** key — shipping it in the browser bundle is
required, since the wallet encrypts every envelope to it. The same holds for `ARBITER_KEM_PK`. The
matching private halves (the bjj scalar and the ML-KEM-768 decapsulation key) are the arbiter's
alone; see [security-model.md](security-model.md).

## Verifying a deployment

Through the proxy: `B() == 256`, `initialized() == true`, `disburseCiphertextLen() == 2054`,
`KEM_CIPHERTEXT_LEN() == 1088`, the ERC-1967 implementation slot pointing at `poolImpl`,
`currentArbiterKey()` equal to the recorded key, and `arbiterKemPkHash(currentEpoch())` equal to
`keccak256` of the recorded `arbiterKemPk`. All six verifier getters must be non-zero and equal to
the recorded addresses. `Deploy.s.sol` asserts every one of those before writing the addresses file,
`deploy_local.sh` reads `B()` back over `cast` before running the smoke deposit, and
`test_one_shot_deploy.sh` re-checks the whole set from outside the script.
