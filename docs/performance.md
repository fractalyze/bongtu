# Performance

> The measuring chain below — Base Sepolia (84532) — is retired; nothing has been re-measured on
> the live Maroo testnet (450815), whose x/feemarket base-fee floor (~8000 gwei) changes the cost
> framing. Every measurement stands as the history it is.

Measured numbers only: each row says when and how it was taken, and anything not reproducible from
this tree or from chain is not here. Two measurement contexts appear and they are not comparable —
**harness** figures are a clean `gasleft()` delta around the pool call, taken by `forge test`
against this tree and independent of which chain the pool is deployed to; **live** figures are
whole-transaction `gasUsed` from a Base Sepolia receipt, which also pays the intrinsic cost and the
calldata cost of everything the call receives. Rows are additionally labelled **pre-KEM** (before
the 2026-07-27 hybrid ML-KEM-768 envelope upgrade) or **hybrid** (after it).

## What gas costs

Three gas prices are in play, and confusing them is the easiest way to misstate this project's cost
by an order of magnitude:

| price | who uses it | value |
|---|---|---|
| the chain's own quote | what a user actually pays | **0.006 gwei** (`cast gas-price`, 2026-08-12) |
| `GAS_PRICE_PIN_GWEI` | our own operational transactions only | 0.05 gwei — about 8.3× the quote |
| 3× `eth_gasPrice` | the two browser apps | whatever the chain quotes at the time |

**Every user-facing cost in this document is priced at the chain's quote, 0.006 gwei.** The pin is
not a product cost: it exists so a live deploy or survey run cannot stall mid-sequence when the
quote moves — a price set too low leaves a transaction stuck with the run's later steps blocked
behind its nonce, while one set too high only overpays a fractional amount of testnet ETH, which is
also why the drivers pin rather than estimate
([deployment.md → Chain facts](deployment.md#chain-facts)). Neither web app pins; both take 3×
`eth_gasPrice`, so what a wallet user pays tracks the chain. Pricing the numbers below at the pin
would overstate the product's cost by 8.3×.

## Live chain, hybrid envelope

Whole-transaction `gasUsed` from Base Sepolia receipts, **measured 2026-09-01**
(`deploy/live/gas_survey.ts` and `deploy/live/transfer10x2_e2e.ts`, fresh identities per run),
against the current pool on its arbiter epoch 0. The withdraw row is the withdraw-v2
(proof-bound recipient) entrypoint shipped by the stealth-exit upgrade; the transfer10x2 rows carry
their 2026-08-12 measurements forward:

| operation | L2 gas | L1 data fee | tx |
|---|---|---|---|
| `deposit` | 2,642,328 | | [`0xa5538ac8…`](https://sepolia.basescan.org/tx/0xa5538ac8af8af0df80b8c824c38db74c17dc5cfb60d349f7efa353c029f02090) |
| `transfer` (2-in / 2-out) | 2,780,006 | | [`0xb46cc15e…`](https://sepolia.basescan.org/tx/0xb46cc15e855367b40bb08417b370dd591f1881215ba8782c4fa6970670e32202) |
| `withdraw` (v2, recipient-bound) | 1,716,736 | | [`0xdc7ebd89…`](https://sepolia.basescan.org/tx/0xdc7ebd891183825c2104c6d6ba21f4530c583cf81d6be65494294d982f98a583) |
| `transfer10x2` (merge, 3-in, zero change) | 3,068,690 | | [`0xdc29fee9…`](https://sepolia.basescan.org/tx/0xdc29fee94a5a10fb32f885e343f3fcbdfd767391cf4c84609c57edfcd955ddb6) |
| `transfer10x2` (payment, 3-in + change) | 3,063,954 | | [`0xf096282a…`](https://sepolia.basescan.org/tx/0xf096282a800761df7faec966075d0497fbc0008941efbefb9ae4e1e07bb3fff7) |

`deposit` is the row that moves: across seven runs it ranged **2,637,594 – 2,647,508**. The spread
is the Merkle frontier — a slot costs about 20k gas the first time it goes non-zero against about 5k
to overwrite — so the same call prices differently depending on how full the tree is. Treat any
single-leaf-appending row as ±10k, not as an exact constant.

`transfer10x2` takes up to ten input notes and produces two outputs, serving both the merge (a
consolidation with no change note) and the payment (recipient plus change), so the wallet routes
every spend of three or more notes through it; the eight unused input slots cost nothing on the
output side, which is the whole point of the 10×2 shape over a ten-output circuit. `transfer10`
remains deployed for verification of historical transactions only and is no longer reachable from
the wallet.

### The 256-recipient disburse — carried over, not re-measured on Base

**3,905,519 L2 gas, 15,256 per recipient.** Measured on the project's previous chain (hybrid epoch,
employer-console pay run, 2026-07-30) and **not** re-run on Base Sepolia. It is carried forward
rather than restated because the chain move changed **zero executable lines in any operation
path** — every changed line in `chains/evm/src/BongtuPool.sol` is inside `initialize` /
`_initVerifiers` or in the deleted `initializeV2..V5` payloads (verify with
`git diff 64ec0f5..HEAD -- chains/evm/src/BongtuPool.sol`) — and L2 `gasUsed` is a function of the
bytecode executed and the calldata received. Re-running it on Base (`deploy/live/payroll_e2e.ts`)
is what would turn this into a measurement rather than an inference.

At the chain's 0.006 gwei quote, one 256-batch costs **≈2.343e-5 ETH** of L2 gas. Its L1 data fee
is estimated at **≈1.0e-7 ETH** — the scale the four measured Base operations show, not a
measurement of a batch on Base. A **100,000-person payroll** is 391 of those batches:

| | per 256-batch | ×391 (100,000 people) |
|---|---|---|
| L2 gas | 3,905,519 | 1,527,057,929 |
| L2 cost @ 0.006 gwei | ≈2.343e-5 ETH | **0.009162 ETH** |
| L1 data fee | ≈1.0e-7 ETH | **0.000039 ETH** |
| **total** | | **0.009201 ETH** — about **$27.60** at $3000/ETH |
| GPU proving @ 0.47 s | 0.47 s | **≈3.1 minutes** |

For contrast, Zeto's own published figure is 2,763,071 gas for **2 recipients** (~1.38M each)
against 15,256 per recipient here — about **90× cheaper per recipient**, a ratio that does not
depend on which chain either runs on. The saving is structural: we replaced Zeto's value-keyed SMT
with an IMT batch-attach and its per-note ciphertext with one aggregated disclosure hash.

## On-chain gas per operation (harness, pre-KEM)

Clean `gasleft()` delta around the single pool call, real verifiers, B=16 pool
(`chains/evm/test/GasReport.t.sol`; `forge --gas-report` inflates via metering and mixes arities,
so it is not used). **Measured 2026-07-26**, before the hybrid upgrade. These are figures about
this tree, not about a chain — they measure the call, not the transaction, so they carry neither
the intrinsic cost nor the calldata cost and are always lower than the live rows above.

| operation | L2 gas | notes |
|---|---|---|
| `deposit` (0-in / 2-out, + authority envelope) | 2,353,950 | 2 leaves appended |
| `transfer` (2-in / 2-out) | 2,483,773 | 2 nullifiers, 2 leaves |
| `withdraw` (2-in / 1-out, + authority envelope) | 1,411,960 | 2 nullifiers, 1 change leaf |
| `disburseWithCiphertexts` (1-in / 16-out, partial block, full ciphertext) | 2,194,716 | B=16 dev arity |

The production 256 arity (`chains/evm/test/Disburse256.t.sol`, real GPU proof against the real
verifier, **measured 2026-07-26**, pre-KEM). Both cases seed a single input note at leaf 0, so both
disburse into a **1-leaf partial block** and both close it in-call before attaching the 256-leaf
subtree:

| measurement | L2 gas | per recipient |
|---|---|---|
| `testDisburseAcceptsAttachesUnderCap` — verify + close + attach + full 2054-element ciphertext | 2,789,946 | 10,898 |
| `testDisburseFromPartialBlockMatchesOracle` — same, plus the 2054-element blob built inside the `gasleft()` window | 2,812,522 | 10,986 |

The 22,576 delta is that measurement-window difference, not an aligned-vs-partial contrast. Both
are far under the 16,777,216 per-transaction cap (EIP-7825, Karst), which the test asserts, and the
second also pins `root()` against the `@bongtu/core` oracle. The partial-block close is O(log B):
inserting the ≤255 pad leaves individually would be O(B) — up to 255 leaves × 32 hashes — and would
not fit under the cap ([protocol.md](protocol.md#batch-attach-is-olog-b-not-ob)).

The live disburse figure exceeds this harness 2.79M for two reasons that stack: a real transaction
also pays the intrinsic cost and the calldata cost of the 2054-element ciphertext array (~66 KB),
and the live figure is hybrid while the harness rows are pre-KEM.

## Where the gas goes

Poseidon in the EVM dominates every operation; Groth16 verification, nullifier storage, the token
move and the events share what is left. A Poseidon(2) call to the deployed hasher costs about
**29k gas** of execution (measured 2026-07-26: `cast estimate` returns 50,349 for the call to a
locally deployed `poseidon2.hex`, of which 21,000 is the intrinsic transaction cost and ~344 is
calldata). At `H = 32`, one appended leaf is 32 folds ≈ 0.93M gas — ~66% of `withdraw` (one leaf)
and ~1.9M, i.e. 75–79%, of `deposit` and `transfer` (two leaves each).

Three levers follow directly, none implemented:

- **Reduce `H`.** Capacity 2^32 is far more than a payroll pool needs; every level removed is ~29k
  gas off every single-leaf append.
- **Stop paying for disburse ciphertext twice.** The 2054-element array arrives as calldata to
  `disburseWithCiphertexts` AND is re-emitted whole in `DisburseCiphertexts` — dropping the event
  in favor of SDK calldata-parsing saves ~0.5M gas per disburse.
- **Poseidon2.** A cheaper permutation would cut the dominant term directly, at the cost of
  regenerating every circuit, zkey and verifier (Poseidon-v1 constants are consensus across
  circuits, contract and `@bongtu/core`).

## Proving

| circuit | constraints | zkey | proven by |
|---|---|---|---|
| `deposit` | 14,127 | 6.5 MB | `circuits/build/prove_all.sh` (CPU); also in-browser |
| `withdraw` | 54,319 | 24 MB | `circuits/build/prove_all.sh` (CPU); also in-browser |
| `transfer` | 64,394 | 28 MB | `circuits/build/prove_all.sh` (CPU); also in-browser |
| `disburse` (1×16) | 208,719 | 92 MB | `circuits/build/prove_all.sh` (CPU) |
| `disburse256` (1×256) | 2,796,719 | 1.3 GB | `prover/` only — rabbitsnark on GPU, zkey held resident |

Constraint counts and zkey sizes measured 2026-07-27 (`snarkjs r1cs info`, `ls` over
`circuits/out/`) on the hybrid circuits. The hybrid key derivation costs a flat **+2,533
constraints** in every circuit — two Poseidon(5), one Poseidon(3) and the two `Num2Bits(128)` limb
range checks — which is +22% on `deposit` and under +0.1% on `disburse256`.

- **disburse256 on GPU** (rabbitsnark, RTX 5090, `CUDA_VISIBLE_DEVICES=0`): warm proof ≈ **0.47 s**;
  the cold zkey compile before the first proof is ≈ 120 s (measured 2026-07-24; recorded in the
  repo `CLAUDE.md` regen recipe and the root `README.md` status). The prover service keeps the
  compiled zkey resident, so production proofs are the warm number; a cold service boot pays the
  compile once.
- **Prover-service round trip** (what the payroll console actually waits on): warm `/prove`
  **disburse256 1.58 s** on an otherwise idle box (measured 2026-07-30; 2.3 s was the 2026-07-29
  figure under load — contention moves this number) · **transfer10x2 0.3 s · deposit 0.2 s**.
  Witness generation dominates the disburse figure. Its measured split (2026-07-30):
  `circuit_main` **0.79 s**, Montgomery conversions 0.13 s, w2s gather 0.06 s — total ~0.98 s
  in-process, down from 5.7–7.5 s under the retired node/WASM subprocess (~5x; pipeline in
  [`prover/README.md`](../prover/README.md)). The Montgomery passes were then cut to the 1,327
  nonzero inputs and the 2.8M gathered outputs (byte-identical on all three circuits), leaving
  `circuit_main` as ~90% of witness time. It is **single-threaded by construction**: the
  circom-MLIR emitter only produces sequential loops and the `.so` links no OpenMP —
  parallelizing the emitter is the standing lever (the GPU compiler path was removed from
  prime-ir deliberately, and circom's `<--` hints rule out the levelized R1CS solver on principle).
- **Browser transfer** (headless Chromium, real): warm proof **3.5–5.4 s** on a 24-thread desktop,
  measured 2026-07-26 on the pre-KEM transfer circuit; the hybrid circuit adds ~4% constraints.
  The laptop figure carried alongside it in `packages/ui/src/prove.ts` — 7–20 s — is a budget, not
  a measurement. COOP/COEP had no effect and are not set.
- CPU `groth16 setup` for disburse256 is a multi-minute step producing the 1.3 GB zkey; it is not
  in the per-change loop ([toolchain.md](toolchain.md)).

## Measuring against a pooled public RPC

The live figures above were taken through a public endpoint — one hostname fronting many nodes, so
a node answering your next request may not have applied the block your last one produced. Three
latent assumptions of the dedicated node the drivers were originally written against surfaced
during this measurement and are fixed in `deploy/live/lib/viem_client.ts` (commit `9507092`);
anyone re-measuring should know they were real:

- **A gas limit sent as exactly its own estimate.** A deposit ran **out of gas at 2,643,613**
  while its siblings in the same run cost 2,637,594–2,647,508 — the frontier-slot pricing above
  means the tree advances between estimate and inclusion, so a later operation can execute a
  costlier path than the one that was priced. The limit is only a cap and unused gas is refunded,
  so the drivers now take headroom over the estimate.
- **A read issued straight after a write** could be answered by a node that had not applied the
  block, so a transaction that correctly appended its two leaves read back as though it had done
  nothing. Writes now hold until the pool will actually show the block they landed in.
- **A receipt lookup treating not-found as terminal** reported a transaction that had in fact
  succeeded, with status 1, as a timeout. It now waits long enough for a lagging node to catch up.

None of this is chain-specific; it was invisible only because the previous endpoint was a single
node. A survey that reports one anomalous row is more likely to be reporting the RPC than the
contract.

## Reproducing

```sh
cd chains/evm && forge test --match-path "test/GasReport.t.sol" -vv
cd chains/evm && forge test --match-path "test/Disburse256.t.sol" -vv
cd circuits  && $SNARKJS r1cs info out/<name>.r1cs        # $SNARKJS: toolchain.md
cast receipt <txhash> --rpc-url "$LIVE_RPC"               # $LIVE_RPC: .env.example
npx tsx deploy/live/gas_survey.ts                         # re-measures the live table (spends gas)
```

The three local commands reproduce the harness rows against this tree. The `cast receipt` line
reads the live chain — the RPC has one home, listed under
[deployment.md → Chain facts](deployment.md#chain-facts) and mirrored into `LIVE_RPC` by
`.env.example` — and resolves the two `transfer10x2` hashes in the live table directly. The rows
without a hash came from survey runs whose receipts were read at measurement time; `gas_survey.ts`
re-takes them, with fresh identities and fresh hashes, at the cost of real testnet gas.
