# chains/solana/ — the Solana rail program island (S2+S3)

The spec is `.dev/solana-rail-design.md` (**SOLR**); this folder implements its
S2 milestone — the `bongtu_pool` program with the full consumer P2P op set:
`deposit_priv`, `transfer_priv`, `transfer10x2_priv`, `withdraw_priv` (Groth16
verify over alt_bn128 syscalls + sol_poseidon IMT + nullifier/root PDAs + SPL
escrow motion + self-CPI events) plus the five mollusk gate families
(SOLR §3.1.3) — and its S3 milestone: the enterprise op set decided under
OPEN-1 (`deposit`, `withdraw`, `disburse256`) with the 1-tx disclosureHash
disburse (SOLR §3.3): the chain persists the BINDING (`DisburseBatch` PDA);
the 65,728 B disclosure blob is institution-served and refold-verifiable
(gate 6). The ~19-tx consensus-forced-DA variant stays documented only
(SOLR §3.3.3). Plan row: issue #8.

## Layout

| path | role |
|---|---|
| `program/` | the on-chain program (`bongtu_pool_solana`, plain solana-program, no framework) |
| `program/src/op_common.rs` | the shared `_applyOp` mirror + state-write primitives every op composes |
| `program/src/spl.rs` | SPL escrow motion (hand-rolled Transfer CPI, token-account checks, u64 amount belt) |
| `program/src/recipient_binding.rs` | the OPEN-3 truncate-253 recipient binding, isolated (one module to swap on a veto) |
| `program/src/generated/` | GENERATED constants — VKs from the committed vkeys, BN254 moduli, IMT zeros; never hand-edit |
| `harness/` | mollusk test crate: gates 1 (poseidon), 2 (verify parity), 3 (CU budgets), 4 (tx size), 5 (invariants), 6 (disburse refold) |
| `harness/src/enterprise.rs` | the S3 enterprise envs (enterprise `PoolConfig` with arbiter key + B=256, DisburseBatch PDA) |
| `conformance/` | GENERATED vectors + fixture-derived state (committed; regenerate via `scripts/`) |
| `scripts/` | generators (run from the repo root with `node_modules/.bin/tsx`) |
| `gates/mollusk.sh` | the S2/S3 gate: `cargo-build-sbf` + `cargo test --workspace` |
| `cu_budget.json` | per-op CU regression budgets, moved only by explicit commit |

## Instruction set

Discriminator 0/1 reserved (`initialize` / `set_family_flags`, later S2 work).
Event self-CPI = 0xF0; family tag in the event = discriminator - 1.

| ix | disc | wire payload | escrow |
|---|---|---|---|
| `deposit_priv` | 2 | proof(256) + 16 publics + 2×1088 kem cts = 2,944 B | pulls pub[0] payer→vault (payer signs) |
| `transfer_priv` | 3 | proof + 18 carried publics + 2×1088 = 3,008 B | — |
| `transfer10x2_priv` | 4 | proof + 26 carried publics + 2×1088 = 3,264 B | — |
| `withdraw_priv` | 5 | proof + 13 carried publics + 1×1088 + 33 B stealth pair = 1,793 B | pushes pub[0] vault→proof-bound recipient (vault-authority PDA signs) |
| `deposit` (enterprise) | 6 | proof + 17 carried publics + 1×1088 = 1,888 B | pulls pub[0] payer→vault |
| `withdraw` (enterprise) | 7 | proof + 22 carried publics + 1×1088 + 33 B stealth pair = 2,081 B | pushes pub[0] vault→proof-bound recipient |
| `disburse256` (enterprise) | 8 | proof + 8 carried publics + 1×1088 = 1,600 B (the SOLR §3.3.1 ~1.7 KB claim, gate-4-pinned) | — |

Per-op account layouts are in each module's doc comment. The vault authority
PDA is `["authority", config]`; the vault address is config-bound.

Enterprise ops (family flag bits 4..6) additionally inject the arbiter bjj
key from `PoolConfig` into the public vector before verify — a proof made for
any other key fails (`InvalidProof`), and a zeroed key (consumer-only
profile) refuses with `ArbiterKeyUnset` before verify. `disburse256` attaches
its in-circuit 256-leaf subtree at LOG_B (from config `B`) and persists the
per-batch audit anchor `(start_leaf_index, disclosureHash, kemBinding, epoch)`
in a `DisburseBatch` PDA (`["batch", start_leaf_index u64 LE]` — the counter
convention, not the field-element BE form); its self-CPI event carries the
same tuple plus subtreeRoot/resultingRoot/nullifier. Epoch is pinned to 0
until arbiter rotation lands as an instruction (SOLR §3.3.1 S3 note).

## Toolchain (pinned)

- **SBF build**: Agave, version pinned as `AGAVE_VERSION` in
  `.github/ci-pins.env` (`cargo-build-sbf`, platform-tools `v1.52`,
  rustc 1.89) — installed under `~/.local/share/solana/install/active_release`.
- **Host tests**: `rust-toolchain.toml` (rustc 1.98.1) for the mollusk harness
  (`mollusk-svm 0.15.1` + `mollusk-svm-programs-token` for the SPL token ELF;
  Agave 4.x runtime with the full feature set — the poseidon + alt_bn128
  syscalls are active as on mainnet).

## Run

```bash
chains/solana/gates/mollusk.sh
```

Regenerate the generated files after a circuit or packages/core change:

```bash
node_modules/.bin/tsx chains/solana/scripts/gen_vk.ts
node_modules/.bin/tsx chains/solana/scripts/gen_withdraw_solana_fixture.ts   # CPU re-prove (needs BONGTU_NODE_MODULES snarkjs)
node_modules/.bin/tsx chains/solana/scripts/gen_vectors.ts
node_modules/.bin/tsx chains/solana/scripts/gen_enterprise_vectors.ts        # S3 enterprise fixtures + the served-blob refold vector
```

## Consensus conventions (drift-sensitive)

- **Field elements are 32-byte big-endian everywhere** — the alt_bn128 /
  EIP-197 public-input encoding is the ONE canonical byte form: verifier
  inputs, tree node hashes (`sol_poseidon` BigEndian), account state, and PDA
  seeds all use it. Deviation from the SOLR §2.2 table note (`nf_le_bytes`):
  seeds use the BE form deliberately, so no second endianness convention
  exists on this rail (the §4.1 drift-surface rule). Counters (`nextLeafIndex`)
  are u64 LE.
- **Proof wire** = snarkjs `a || b || c` with `b` in the EVM limb order
  (imaginary limb first) — byte-identical to the committed EVM fixture
  calldata, untouched by the program (A is negated internally for the pairing).
- **No derivable publics on the wire** (SOLR §2.3): `enabled[i]` is
  reconstructed as `nullifier[i] != 0` (the EVM module injection rule), and
  withdraw's `recipient` (pub[15]) is injected from the recipient token
  account under the OPEN-3 binding — a proof bound to any other recipient
  fails verify.
- **OPEN-3 recipient binding (truncate-253, DECIDED)**: pub[15] = the
  recipient token account `Pubkey` read as a big-endian 256-bit integer with
  the top 3 bits cleared (`addr mod 2^253` — always < r, every address
  bindable). The whole binding lives in `program/src/recipient_binding.rs`;
  a veto swaps exactly one module plus one re-proven fixture. SPL owner/mint
  checks run on the recipient BEFORE the binding, per the decision record.
- **Amounts are u64 on this rail** (per-rail narrowing): the circuits' value
  belt is 2^100 but SPL amounts are u64; a proof-bound pub[0] >= 2^64 rejects
  `AmountOverflow`. Documented deviation, not a circuit change.
- **KnownRoot is per-op, not per-leaf**: the EVM pool marks `knownRoots` after
  every single-leaf insert; this rail registers one KnownRoot PDA for the
  post-op root (SOLR §2.2's one-root-PDA-per-op shape). An intermediate
  root inside a 2-append op was never observable as a tx boundary on Solana.
- **Check order**: invariant checks run BEFORE verify (EVM modules verify
  first). The accepted set is identical — checks are conjunctive and
  side-effect-free until all pass — but failures are cheap and the gate-5
  table drives every guard with committed real proofs instead of stub
  verifiers.

## CU (measured by mollusk, gate-asserted via cu_budget.json)

| op | measured CU | budget | SOLR §3.1.1 estimate |
|---|---|---|---|
| `deposit_priv` | 220,449 | 232,000 | ~230k |
| `transfer_priv` | 247,772 | 260,000 | ~240k |
| `transfer10x2_priv` | 330,432 | 347,000 | ~330k |
| `withdraw_priv` | 208,443 | 219,000 | ~210k |
| `deposit` | 233,774 | 246,000 | — |
| `withdraw` | 264,215 | 278,000 | — |
| `disburse256` | 202,752 | 213,000 | ~640k (S0 attach line was per-leaf; the O(LOG_B) close makes attach ~30k) |

Measured on mollusk-svm 0.15.1 (Agave 4.x runtime cost model), committed
realproof fixtures, full paths (verify + appends/attach + PDA creates +
escrow CPI + self-CPI event). Worst op ≈ 24% of the 1.4M CU cap; the full
256-out disburse is CHEAPER than a consumer transfer (~14% of cap).

## Tx size (gate 4, worst-case shape per op, Transaction v1 = 4,096 B)

| op | worst-case tx | headroom |
|---|---|---|
| `deposit_priv` | 3,423 B | 673 B |
| `transfer_priv` | 3,487 B | 609 B |
| `transfer10x2_priv` | 4,007 B (10 nullifier PDAs) | **89 B** — the §3.1.2 tightest op; next lever is an address lookup table |
| `withdraw_priv` | 2,404 B | 1,692 B |
| `deposit` | 2,367 B | 1,729 B |
| `withdraw` | 2,692 B | 1,404 B |
| `disburse256` | 2,079 B | 2,017 B |

Computed from the consensus wire format (v0 message, 1 signature, ComputeBudget
ix included) over the real instruction shapes; the gate also re-checks the
fixture-built instructions.

## Fixtures (SOLR §5.2)

deposit/transfer/transfer10x2 replay the committed EVM realproof fixtures
(`chains/evm/test/fixtures/consumer_realproofs.json`) at op level — mollusk
seeds the fixture root as a KnownRoot PDA and the tree state from the ImtTree
oracle. withdrawPriv is the one exception: the op-level happy path runs the
re-proven Solana-recipient fixture
(`chains/evm/test/fixtures/consumer_realproofs_solana.json`, generated by
`scripts/gen_withdraw_solana_fixture.ts` through the existing CPU pipeline —
same inputs, only pub[15] rebound); the EVM withdraw fixture still replays at
verify level (accept + reject-tamper) against the generated VK.

Enterprise (S3): `deposit`/`withdraw` replay `chains/evm/test/fixtures/
realproofs.json` at op level with ZERO re-proving — including withdraw: its
proof-bound uint160 recipient IS a reachable token-account address under
truncate-253, so the harness places the recipient token account at
`BE32(pub[26])` (SOLR §5.2 S3 note). `disburse256` replays the committed GPU
production-arity fixture (`disburse256.{oracle,input,vkey}.json`);
`scripts/gen_enterprise_vectors.ts` re-derives its 2054-element disclosure
blob through `packages/core` envelope.ts (the envelope.test.ts p2 recipe) and
the deterministic fixture KEM draw, pinning `disclosureChain(blob) == pub[2]`
at generation time; gate 6 then refolds the committed blob on the Rust side
and asserts it against the `DisburseBatch.disclosureHash` the attach stored.
One subtlety the fixture encodes: after an attach, the program's
sub-LOG_B frontier is deliberately STALE (the EVM `_attachSubtree` shape),
so the committed post-state splices pre-state values below LOG_B — root and
levels ≥ LOG_B are byte-identical to the ImtTree oracle.

## Not yet here (later per SOLR §6)

`initialize` / `set_family_flags` (discriminators reserved; harness seeds
account images directly), arbiter rotation (epoch pinned to 0), the e2e
`solana-test-validator` gate (`e2e_s.sh`, S6), indexer ingest + disclosure
serving/alarms (S4), client tx building (S5), the §3.3.3 ~19-tx full-DA
disburse (documented option, by design not an instruction).
