# Deployment

The live bongtu stack runs on **GIWA Sepolia, chain 91342**. Source of truth for every address is
`deploy/addresses.91342.json`, written by the deploy script and mirrored (with an equality test)
into `packages/core/src/network.ts` so both web apps read one set of constants.

## Live addresses

| role | address |
|---|---|
| BongtuPool — ERC-1967 proxy, the canonical pool | `0x93365980784ef504613EF5822ce1289CF858Fc10` |
| BongtuPool implementation | `0x459f80A457f11328eBd67aeBFa9F90D05c58b27f` |
| Poseidon-v1 hasher | `0xaA7778c778C83cE5655d5F217bDfE7782e01Bc50` |
| DepositVerifier | `0xF3b5D0eb5558B9427Fe599792E728b9B2bD20B2E` |
| WithdrawVerifier | `0xaA581CFB50F69144C6a9B6380193858E8f4B00Db` |
| Disburse256Verifier | `0xD030602597CC7F47107e6F96d0d1D6b73a71698F` |
| TransferVerifier | `0x594408F216d096E8BCB21cdceb58a14186895892` |
| mock kKRW (ERC-20) | `0x17A89cC5FF3395Bb01464c9E422749CcDbFa8C3f` |
| owner / deployer | `0xe92a97e645351268F3d60d5a27EB842A5b293058` |

`batchSize` is 256. The **proxy** is the address to integrate against; the implementation changes
on upgrade. The live pool is canonical and is not redeployed for new work — a circuit change ships
as a UUPS `upgradeToAndCall` ([contracts.md](contracts.md#proxy-and-wiring)).

`deploy/addresses.31337.json` is the equivalent record for the local anvil stack.

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
| `deploy/Smoke.s.sol` | a real `deposit` against the deployed pool using the committed proof fixture |
| `deploy/deploy_local.sh` | anvil + Deploy + getter read-back + Smoke — the local gate |
| `deploy/giwa_disburse256.ts` | the live 256-recipient disburse runner (rebuild mirror → deposit → prover service → `disburseWithCiphertexts` → measure L2 gas and L1 data fee) |
| `deploy/e2e_m0.sh`, `deploy/e2e_orchestrator.ts` | the cross-circuit spend-cycle end-to-end on a local anvil |

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

The live pool's stored key is recorded as `arbiterKeyX` / `arbiterKeyY` in
`deploy/addresses.91342.json` and re-exported as `ARBITER_PUBKEY_X` / `ARBITER_PUBKEY_Y` from
`packages/core/src/network.ts`. It is a **public** key — shipping it in the browser bundle is
required, since the wallet encrypts every envelope to it. The matching private key is the arbiter's
alone; see [security-model.md](security-model.md).

## Verifying a deployment

Through the proxy: `B() == 256`, `initialized() == true`, `disburseCiphertextLen() == 2054`, the
ERC-1967 implementation slot pointing at `poolImpl`, and `currentArbiterKey()` equal to the recorded
key. `Deploy.s.sol` asserts the stored arbiter key itself before writing the addresses file, and
`deploy_local.sh` reads `B()` back over `cast` before running the smoke deposit.
