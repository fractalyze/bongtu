# Performance

Measured numbers only. Each row says when and how it was taken; anything not reproducible from this
tree or from chain is not here.

## On-chain gas per operation

Clean `gasleft()` delta around the single pool call, real verifiers, B=16 pool
(`contracts/test/GasReport.t.sol`; `forge --gas-report` inflates via metering and mixes arities, so
it is not used). **Measured 2026-07-26** on the current tree.

| operation | L2 gas | notes |
|---|---|---|
| `deposit` (0-in / 2-out, + authority envelope) | 2,353,950 | 2 leaves appended |
| `transfer` (2-in / 2-out) | 2,483,773 | 2 nullifiers, 2 leaves |
| `withdraw` (2-in / 1-out, + authority envelope) | 1,411,960 | 2 nullifiers, 1 change leaf |
| `disburseWithCiphertexts` (1-in / 16-out, partial block, full ciphertext) | 2,194,716 | B=16 dev arity |

The production 256 arity (`contracts/test/Disburse256.t.sol`, real GPU proof against the real
verifier, **measured 2026-07-26**):

Both cases seed a single input note at leaf 0, so both disburse into a **1-leaf partial block** and
both close it in-call before attaching the 256-leaf subtree:

| measurement | L2 gas | per recipient |
|---|---|---|
| `testDisburseAcceptsAttachesUnderCap` — verify + close + attach + full 2054-element ciphertext | 2,789,946 | 10,898 |
| `testDisburseFromPartialBlockMatchesOracle` — same, plus the 2054-element blob built inside the `gasleft()` window | 2,812,522 | 10,986 |

The 22,576 delta is that measurement-window difference, not an aligned-vs-partial contrast. Both are
far under the 16,777,216 per-transaction cap (EIP-7825, Karst), which the test asserts, and the
second also pins `root()` against the `@bongtu/core` oracle. The partial-block close is O(log B):
inserting the ≤255 pad leaves individually would be O(B) — up to 255 leaves × 32 hashes — and would
not fit under the cap ([protocol.md](protocol.md#batch-attach-is-olog-b-not-ob)).

### Live chain

The headline 256-recipient private disbursement, run against the live pool
`0x93365980784ef504613EF5822ce1289CF858Fc10` — tx
`0xe254240a5df042a163073c028399a5fc63cf87434a7e7ebbf5ddfea73c803bd6`, block 31560457,
**receipt read 2026-07-26**:

| quantity | value |
|---|---|
| L2 gas used | 3,872,403 (15,126 per recipient) |
| effective gas price | 0.005 gwei (pinned by the runner) |
| L2 cost | ≈ 1.94e-5 ETH |
| L1 data fee | 4,024,818,056,800 wei ≈ 4.02e-6 ETH, over 915,493 L1 gas |
| total | ≈ 2.34e-5 ETH |

Live gas exceeds the test-harness 2.79M because a real transaction also pays the intrinsic cost and
the calldata cost of the 2054-element ciphertext array (~66 KB); the harness measures the call, not
the transaction. The L1 data fee for that payload is ~4e-6 ETH — about 17% of this transaction's
total at the pinned 0.005 gwei L2 price, and small in absolute terms. Blob data availability is not
what makes all-ciphertext-on-chain expensive; L2 execution and calldata are.

Any "L1 fee is a rounding error" figure computed at an unpinned gas price is an artifact of
overpaying on L2: ethers' auto-estimate overpays GIWA by ~1500×, so the runner pins `gasPrice` from
`GIWA_GAS_FLOOR_GWEI` (`packages/core/src/network.ts`, `deploy/giwa_disburse256.ts`) — see
[deployment.md](deployment.md#chain-facts).

## Where the gas goes

A Poseidon(2) call to the deployed hasher costs about **29k gas** of execution (measured 2026-07-26:
`cast estimate` returns 50,349 for the call to a locally deployed `poseidon2.hex`, of which 21,000
is the intrinsic transaction cost and ~344 is calldata).

At `H = 32`, one appended leaf is 32 folds ≈ 0.93M gas. That is ~66% of `withdraw` (one leaf) and
~1.9M — 75–79% — of `deposit` and `transfer` (two leaves each). Poseidon in the EVM dominates every
operation; Groth16 verification, nullifier storage, the token move and the events share what is
left.

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
| `deposit` | 11,594 | 5.6 MB | `circuits/prove_all.sh` (CPU); also in-browser |
| `withdraw` | 51,786 | 24 MB | `circuits/prove_all.sh` (CPU); also in-browser |
| `transfer` | 61,861 | 27 MB | `circuits/prove_all.sh` (CPU); also in-browser |
| `disburse` (1×16) | 206,186 | 92 MB | `circuits/prove_all.sh` (CPU) |
| `disburse256` (1×256) | 2,794,186 | 1.3 GB | `prover/` only — rabbitsnark on GPU, zkey held resident |

Constraint counts and zkey sizes measured 2026-07-26 (`snarkjs r1cs info`, `ls` over
`circuits/out/`).

- **disburse256 on GPU** (rabbitsnark, RTX 5090, `CUDA_VISIBLE_DEVICES=0`): warm proof ≈ **0.47 s**;
  the cold zkey compile that precedes the first proof is ≈ 120 s. Recorded in the repo `CLAUDE.md`
  regen recipe and the root `README.md` status (measured 2026-07-24). The prover service keeps the
  compiled zkey resident so production proofs are the warm number; a cold service boot pays the
  compile once.
- **Browser transfer** (headless Chromium, real): warm proof **3.5–5.4 s** on a 24-thread desktop.
  The laptop figure carried alongside it in `apps/wallet-web/src/lib/prove.ts` — 7–20 s — is a
  budget, not a measurement. COOP/COEP had no effect and are not set.
- CPU `groth16 setup` for disburse256 is a multi-minute step producing the 1.3 GB zkey; it is not in
  the per-change loop ([toolchain.md](toolchain.md)).

## Reproducing

```sh
cd contracts && forge test --match-path "test/GasReport.t.sol" -vv
cd contracts && forge test --match-path "test/Disburse256.t.sol" -vv
cd circuits  && $SNARKJS r1cs info out/<name>.r1cs        # $SNARKJS: toolchain.md
cast receipt <txhash> --rpc-url https://sepolia-rpc.giwa.io
```
