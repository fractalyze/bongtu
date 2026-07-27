# Performance

Measured numbers only. Each row says when and how it was taken; anything not reproducible from this
tree or from chain is not here.

Two measurement contexts appear below and they are not comparable: the **harness** figures are a
clean `gasleft()` delta around the pool call, and the **live** figures are whole-transaction
`gasUsed` from a GIWA receipt, which also pays the intrinsic cost and the calldata cost of
everything the call receives. Rows are additionally labelled **pre-KEM** (before the 2026-07-27
hybrid ML-KEM-768 envelope upgrade) or **hybrid** (after it).

## Live chain, hybrid envelope

Whole-transaction `gasUsed` from the GIWA receipts of the end-to-end run against the live pool
`0x93365980784ef504613EF5822ce1289CF858Fc10` on arbiter epoch 1, **measured 2026-07-27**:

| operation | L2 gas | L1 data fee | tx |
|---|---|---|---|
| `deposit` | 2,630,914 | 1.22e-7 ETH over 27,599 L1 gas | `0xa18ef3c12ae19fd06ba8eff1684b0d9610af861c8c5cb28cf4a539dc403521e1` |
| `transfer` | 2,769,948 | 1.59e-7 ETH over 34,772 L1 gas | `0x7112ed922bc7a7c143f2fcd55a94dbf7a93fc89c5f204c8ddddc17814acddf1c` |
| `withdraw` | 1,729,696 | 1.37e-7 ETH over 29,606 L1 gas | `0x174c28a654f59a4032e576f84cc7fc014a72ce57283fbe9a71ae6ad548ed4ba9` |

All three at the pinned 0.005 gwei L2 price, so an operation costs ≈ 0.9–1.4e-5 ETH. Against the
prior live measurements on the same pool pre-upgrade (2026-07-24: deposit ≈ 2.24M, transfer ≈ 2.48M,
withdraw ≈ 1.28M) the hybrid delta is the 1088-byte `kemCiphertext` carried in calldata **and**
re-emitted in the event, plus one extra Groth16 public input — the same double-pay lever flagged
below for disburse ciphertext.

`disburseWithCiphertexts` has **not** been re-measured live since the upgrade; it is an admin-path
operation and the live 256-recipient figure below is pre-KEM.

## On-chain gas per operation (harness, pre-KEM)

Clean `gasleft()` delta around the single pool call, real verifiers, B=16 pool
(`contracts/test/GasReport.t.sol`; `forge --gas-report` inflates via metering and mixes arities, so
it is not used). **Measured 2026-07-26**, before the hybrid upgrade.

| operation | L2 gas | notes |
|---|---|---|
| `deposit` (0-in / 2-out, + authority envelope) | 2,353,950 | 2 leaves appended |
| `transfer` (2-in / 2-out) | 2,483,773 | 2 nullifiers, 2 leaves |
| `withdraw` (2-in / 1-out, + authority envelope) | 1,411,960 | 2 nullifiers, 1 change leaf |
| `disburseWithCiphertexts` (1-in / 16-out, partial block, full ciphertext) | 2,194,716 | B=16 dev arity |

The production 256 arity (`contracts/test/Disburse256.t.sol`, real GPU proof against the real
verifier, **measured 2026-07-26**, pre-KEM):

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

### Live chain: the 256-recipient disburse (pre-KEM)

The headline 256-recipient private disbursement, run against the live pool
`0x93365980784ef504613EF5822ce1289CF858Fc10` — tx
`0xe254240a5df042a163073c028399a5fc63cf87434a7e7ebbf5ddfea73c803bd6`, block 31560457,
**receipt read 2026-07-26**, on arbiter epoch 0 (pre-KEM):

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
| `deposit` | 14,127 | 6.5 MB | `circuits/prove_all.sh` (CPU); also in-browser |
| `withdraw` | 54,319 | 24 MB | `circuits/prove_all.sh` (CPU); also in-browser |
| `transfer` | 64,394 | 28 MB | `circuits/prove_all.sh` (CPU); also in-browser |
| `disburse` (1×16) | 208,719 | 92 MB | `circuits/prove_all.sh` (CPU) |
| `disburse256` (1×256) | 2,796,719 | 1.3 GB | `prover/` only — rabbitsnark on GPU, zkey held resident |

Constraint counts and zkey sizes measured 2026-07-27 (`snarkjs r1cs info`, `ls` over
`circuits/out/`) on the hybrid circuits. The hybrid key derivation costs a flat **+2,533
constraints** in every circuit — two Poseidon(5), one Poseidon(3) and the two `Num2Bits(128)` limb
range checks — which is +22% on `deposit` and under +0.1% on `disburse256`.

- **disburse256 on GPU** (rabbitsnark, RTX 5090, `CUDA_VISIBLE_DEVICES=0`): warm proof ≈ **0.47 s**;
  the cold zkey compile that precedes the first proof is ≈ 120 s. Recorded in the repo `CLAUDE.md`
  regen recipe and the root `README.md` status (measured 2026-07-24). The prover service keeps the
  compiled zkey resident so production proofs are the warm number; a cold service boot pays the
  compile once.
- **Browser transfer** (headless Chromium, real): warm proof **3.5–5.4 s** on a 24-thread desktop,
  measured 2026-07-26 on the pre-KEM transfer circuit; the hybrid circuit adds ~4% constraints.
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
