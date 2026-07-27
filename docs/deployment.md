# Deployment

The live bongtu stack runs on **GIWA Sepolia, chain 91342**. Source of truth for every address is
`deploy/addresses.91342.json`, written by the deploy script and mirrored (with an equality test)
into `packages/core/src/network.ts` so both web apps read one set of constants.

## Live addresses

| role | address |
|---|---|
| BongtuPool — ERC-1967 proxy, the canonical pool | `0x93365980784ef504613EF5822ce1289CF858Fc10` |
| BongtuPool implementation | `0x91fb94B656BE4eb86eD0Cdf4f172f620c61d21f7` |
| Poseidon-v1 hasher | `0xaA7778c778C83cE5655d5F217bDfE7782e01Bc50` |
| DepositVerifier | `0x71F42727670Ad93685665b437711531156E57624` |
| WithdrawVerifier | `0xBA13CB6c005291aa33b7f68A3ABC26002562A9A7` |
| Disburse256Verifier (`disburseVerifier`) | `0x378439670AbD2C497443D21113727fa4827b47ea` |
| TransferVerifier | `0x36B39D3d7ED00EC892a448F7C1a230D35C28B21f` |
| mock kKRW (ERC-20) | `0x17A89cC5FF3395Bb01464c9E422749CcDbFa8C3f` |
| owner / deployer | `0xe92a97e645351268F3d60d5a27EB842A5b293058` |

`deploy/addresses.91342.json` is canonical — the table above is a convenience copy of it, and
`packages/core/test/network.test.ts` holds the module constants to the file field-for-field. When
the two disagree, the JSON is right.

`batchSize` is 256. The **proxy** is the address to integrate against; the implementation and the
four verifiers changed in the 2026-07-27 hybrid upgrade below (and the implementation plus
`TransferVerifier` again in the self-send upgrade after it) and will change again on the next
circuit edit. The live pool is canonical and is not redeployed for new work — a circuit change ships
as a UUPS `upgradeToAndCall` ([contracts.md](contracts.md#proxy-and-wiring)).

`deploy/addresses.31337.json` is the equivalent record for the local anvil stack.

## The hybrid PQ upgrade, 2026-07-27

The live pool was migrated to the hybrid ML-KEM-768 authority envelope in **one atomic
`upgradeToAndCall`** — new implementation, all four regenerated `+1`-public verifiers, and the
`initializeV2` payload minting a fresh arbiter epoch, in a single transaction. Atomicity is
load-bearing: old proofs fail the new verifiers on public count and vice versa, so a two-step
migration would have left a window in which every op reverted.

| after the upgrade | value |
|---|---|
| `currentEpoch()` | **1** (was 0) |
| `arbiterKemPkHash(1)` | `0x0403c92bcdb56d0369c0981754a6f4af6719395d59eef32370dcfad9bb332314` |
| `arbiterKemPkHash(0)` | `0x00…00` — the pre-KEM marker for every epoch-0 op |
| arbiter bjj key | **unchanged** across the epoch |
| `KEM_CIPHERTEXT_LEN()` | 1088 |

The hash is `keccak256` of the institutional 1184-byte ML-KEM-768 encapsulation key. The key itself
is a **public** value distributed off-chain in three places that are equality-tested against each
other: `deploy/arbiter-kem-pk.91342.hex` (the committed material), the `arbiterKemPk` field of
`deploy/addresses.91342.json`, and `ARBITER_KEM_PK` in `packages/core/src/network.ts`, which ships
it to both web apps. The addresses file also records `arbiterKemPkHash` alongside `arbiterKeyX` /
`arbiterKeyY`.

Clients never trust their bundled copy. Before drawing KEM material they read
`arbiterKemPkHash(currentEpoch())` from the pool and refuse to proceed unless it equals
`keccak256(ARBITER_KEM_PK)` — and refuse just as loudly against a pre-KEM pool, since a hybrid build
cannot produce a proof such a pool would accept. So a stale bundle produces a readable error, never
a wasted proof or a silently mis-keyed envelope.

`deploy/UpgradePq.s.sol` is the reusable form of this migration for a local or testnet pool. It
defaults to rotating the *same* bjj key (the epoch boundary exists to be the KEM boundary, not to
churn identities) and must land together with the hybrid clients and the dual-ABI indexer.

**`AUTHORITY_KEM_KEY` is now an operational requirement for arbiter mode.** An arbiter-mode indexer
against a KEM-epoch pool needs the ML-KEM-768 *decapsulation* key in that env var alongside
`AUTHORITY_KEY`, or it refuses to boot — as it also does if the key's embedded encapsulation key
hashes to something other than the on-chain value. Both refusals are deliberate: serving without the
key would under-record every envelope, and serving with the wrong one would stamp every honest
operation as tampered ([indexer.md](indexer.md#the-kem-boot-guard)). `docker-compose.yml` forwards
the variable; like `AUTHORITY_KEY` it is never logged and never serialized.

## The self-send upgrade

A second UUPS upgrade followed the PQ migration, for the U-X3 transfer circuit (§11-8 v1.1: receiver
ciphertext `i` is encrypted under `encryptionNonce + i`, which makes a transfer to yourself
provable). Its payload is `initializeV3` — a **verifier-only** swap: the new `TransferVerifier`
plus the new implementation, and **no epoch**, because no arbiter key material changed. `deposit`,
`withdraw` and `disburse` keep the verifiers the PQ upgrade installed.

`deploy/UpgradeSelfSend.s.sol` is the reusable form. It refuses to run on a pool that has not taken
`initializeV2` first: `reinitializer(3)` would accept a never-V2 pool and burn the version past 2,
stranding it on its pre-PQ verifiers with no way back.

## The transfer10 upgrade

The third UUPS upgrade adds the 10-in/10-out `transfer10` entry point (U-Z1). Its payload is
`initializeV4`, which installs a **new** `Transfer10Verifier` and changes nothing else — the 2-in
`transfer` keeps its own verifier and its own verifying key, `deposit` / `withdraw` / `disburse` are
untouched, and no epoch is minted. Unlike the two upgrades before it this one is purely additive:
every proof that verified before the transaction still verifies after it, so a lagging wallet is not
stranded, it simply cannot reach the new entry point yet.

Atomicity still matters, for the mirror-image reason. `transfer10Verifier` is a **new storage slot**,
appended after every earlier one (the same discipline `arbiterKemPkHash` followed in V2, and for the
same reason: inserting it beside the other four verifier slots would re-stride the IMT root and
nullifier state below it). It is zero until the payload runs, and `transfer10` calls it directly — so
a bare `upgradeTo` would leave a pool that advertises the entry point and reverts on every call to
it.

`deploy/UpgradeTransfer10.s.sol` is the reusable form. Two pre-flight requires, both read from the
Initializable version slot before anything is broadcast:

| require | why |
|---|---|
| version ≥ 3 | `reinitializer(4)` would accept a never-V2/V3 pool and burn the version past both, stranding it on its pre-PQ verifiers or its pre-self-send transfer key. `BongtuPool.initializeV4`'s natspec names this script as where the ordering is enforced. |
| version < 4 | a pre-V4 pool runs an implementation that predates the `transfer10Verifier` getter, so *reading* the verifier to ask "already upgraded?" reverts on exactly the pools that need the answer. The version slot answers it without a call. |

After the swap the script re-reads the live proxy and requires that the other four verifiers, the
arbiter bjj key, the KEM pk hash, the epoch, **and the IMT root + `nextLeafIndex`** are all unchanged
from the values it pinned before broadcasting. The tree pair is there specifically for the new slot:
a mis-declared storage layout does not announce itself, it moves the root.

`transfer10Verifier` is an optional field of `addresses.<chainid>.json` — absent until this script
runs, rather than recorded as a zero, so the field's presence is itself the marker that the pool took
the V4 payload. Read it there rather than from the live-address table above: while
`deploy/addresses.91342.json` carries no such entry, GIWA is still pre-V4 and `transfer10` reverts
there.

## Chain facts

| fact | value |
|---|---|
| chain id | 91342 |
| RPC | `https://sepolia-rpc.giwa.io` |
| explorer | `https://sepolia-explorer.giwa.io` (Blockscout) |
| gas token | ETH (OP Stack L2) |
| per-tx gas cap | 16,777,216 (EIP-7825, Karst) — asserted in `contracts/test/Disburse256.t.sol` |
| BN254 precompiles | present, so Groth16 verification is native |
| gas price floor used by the runners | `0.005` gwei (`GIWA_GAS_FLOOR_GWEI`) |

Mainnet is not launched; everything here is testnet. The runners pin the gas price rather than let
ethers estimate it: GIWA wants ~0.001 gwei and ethers' auto-estimate overpays by ~1500×, draining
the faucet grant. `packages/core/src/network.ts` exports
`GIWA_GAS_FLOOR_GWEI = "0.005"` and `deploy/giwa_disburse256.ts` sets `gasPrice` from it.

## Scripts

| file | does |
|---|---|
| `deploy/Deploy.s.sol` | deploys Poseidon + 4 verifiers + (optionally) a mock kKRW + the pool implementation + an `ERC1967Proxy` whose constructor runs `initialize` atomically; writes `addresses.<chainid>.json` |
| `deploy/UpgradePq.s.sol` | the UUPS migration of an already-deployed pool to the hybrid PQ implementation: deploys the four regenerated verifiers + the new impl, then one `upgradeToAndCall` whose `initializeV2` payload swaps the verifier addresses and mints the epoch carrying both keys; rewrites the verifier/impl entries in `addresses.<chainid>.json` |
| `deploy/UpgradeSelfSend.s.sol` | the UUPS migration to the self-send transfer circuit: deploys the regenerated `TransferVerifier` + the new impl, then one `upgradeToAndCall` whose `initializeV3` payload swaps only that verifier and mints no epoch; pre-flight asserts the pool is already V2 |
| `deploy/UpgradeTransfer10.s.sol` | the UUPS migration that adds the `transfer10` entry point: deploys `Transfer10Verifier` + the new impl, then one `upgradeToAndCall` whose `initializeV4` payload installs only that verifier and mints no epoch; pre-flight asserts the pool is V3 and not already V4, and the post-check asserts the IMT root did not move |
| `deploy/AddressBook.sol` | the field list of `addresses.<chainid>.json`, declared once, with a read + merge-write the four scripts above share (each names only the fields it changes) |
| `deploy/Smoke.s.sol` | a real `deposit` against the deployed pool using the committed proof fixture |
| `deploy/deploy_local.sh` | anvil + Deploy + getter read-back + Smoke — the local gate |
| `deploy/giwa_disburse256.ts` | the live 256-recipient disburse runner (rebuild mirror → deposit → prover service → `disburseWithCiphertexts` → measure L2 gas and L1 data fee) |
| `deploy/e2e_m0.sh`, `deploy/e2e_orchestrator.ts` | the cross-circuit spend-cycle end-to-end on a local anvil |
| `deploy/upload_circuits.sh` | uploads the wallet's proving assets (wasm + zkey) to the Vercel Blob store under a `CIRCUITS_VERSION` path, refusing assets whose zkey hash misses the pin in the wallet's `config.ts` |

Environment knobs and the exact GIWA invocation are in `deploy/README.md`. Two facts that are easy
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

Since the hybrid upgrade the coupling is a **pair**: the fixtures are bound to (arbiter bjj key,
arbiter ML-KEM-768 pk), and the fixture encapsulation key travels as `realproofs.kemPublicKey`
the same way `realproofs.arbiterKey` does. `ARBITER_KEM_PK_HASH` is the matching deploy/upgrade knob.

The live pool's stored key is recorded as `arbiterKeyX` / `arbiterKeyY` in
`deploy/addresses.91342.json` and re-exported as `ARBITER_PUBKEY_X` / `ARBITER_PUBKEY_Y` from
`packages/core/src/network.ts`. It is a **public** key — shipping it in the browser bundle is
required, since the wallet encrypts every envelope to it. The same holds for `ARBITER_KEM_PK`. The
matching private halves (the bjj scalar and the ML-KEM-768 decapsulation key) are the arbiter's
alone; see [security-model.md](security-model.md).

## Verifying a deployment

Through the proxy: `B() == 256`, `initialized() == true`, `disburseCiphertextLen() == 2054`,
`KEM_CIPHERTEXT_LEN() == 1088`, the ERC-1967 implementation slot pointing at `poolImpl`,
`currentArbiterKey()` equal to the recorded key, and `arbiterKemPkHash(currentEpoch())` equal to
`keccak256` of the recorded `arbiterKemPk` (nonzero — a zero here means the pool is still pre-KEM
and every hybrid client will refuse it). `Deploy.s.sol` asserts the stored arbiter key itself before
writing the addresses file, and `deploy_local.sh` reads `B()` back over `cast` before running the
smoke deposit.
