# chains/solana — the Solana rail program island

The `bongtu_pool` Solana program: Groth16 verification over the alt_bn128
syscalls, a sol_poseidon IMT, nullifier/root PDAs, SPL escrow motion, and
self-CPI events. It serves both op families:

- **Consumer P2P**: `deposit_priv`, `transfer_priv`, `transfer10x2_priv`,
  `withdraw_priv`.
- **Enterprise** — the FULL family, decided under OPEN-1: `deposit`,
  `withdraw`, `transfer`, `transfer10x2`, `disburse256`, with the 1-tx
  disclosureHash disburse (SOLR §3.3): the chain persists only the BINDING
  (a `DisburseBatch` PDA); the 65,728 B disclosure blob is institution-served
  and refold-verifiable (gate 6). The ~19-tx consensus-forced-DA variant
  stays documented only (SOLR §3.3.3).

The spec is [`.dev/solana-rail-design.md`](../../.dev/solana-rail-design.md)
(**SOLR** — the `SOLR §n` citations below); milestone tracking lives there and
in issue #8. The five mollusk gate families (SOLR §3.1.3) gate every change.

## Layout

| path | role |
|---|---|
| `program/` | the on-chain program (`bongtu_pool_solana`, plain solana-program, no framework) |
| `program/src/op_common.rs` | the shared `_applyOp` mirror + state-write primitives every op composes |
| `program/src/spl.rs` | SPL escrow motion (hand-rolled Transfer CPI, token-account checks, u64 amount belt) |
| `program/src/recipient_binding.rs` | the OPEN-3 truncate-253 recipient binding, isolated (one module to swap on a veto) |
| `program/src/generated/` | GENERATED constants — VKs from the committed vkeys, BN254 moduli, IMT zeros; never hand-edit |
| `harness/` | mollusk test crate: gates 1 (poseidon), 2 (verify parity), 3 (CU budgets), 4 (tx size), 5 (invariants), 6 (disburse refold) |
| `harness/src/enterprise.rs` | the enterprise mollusk envs (enterprise `PoolConfig` with arbiter key + B=256, DisburseBatch PDA) |
| `conformance/` | GENERATED vectors + fixture-derived state (committed; regenerate via `scripts/`). `ledger_{consumer,enterprise}.json` are the recorded-ledger fixtures driving the indexer's Solana conformance leg (`apps/indexer/test/solana.test.ts`, SOLR §5.3): per-op fixtures chained through mollusk from the empty tree, each tx carrying its op instruction(s), inner instructions (the self-CPI event bytes from the program's own `event::*_payload` builders + the foreign SPL CPI), and the post-op TreeState. The consumer ledger additionally records one multi-op tx (transferPriv + transfer10x2Priv) and the withdrawPriv as a wrapper-invoked INNER instruction with its account metas (the recorder doc comment explains the constructed shape). Regenerate: `cargo run -p bongtu-solana-harness --bin record_ledger` (after `cargo-build-sbf`) |
| `scripts/` | generators (run from the repo root with `node_modules/.bin/tsx`) |
| `gates/mollusk.sh` | the folder's gate: `cargo-build-sbf` + `cargo test --workspace` |
| `cu_budget.json` | per-op CU regression budgets, moved only by explicit commit |

## Instruction set

Discriminator 0/1 reserved (`initialize` / `set_family_flags`, later work).
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
| `transfer` (enterprise) | 9 | proof + 33 carried publics + 1×1088 = 2,400 B | — |
| `transfer10x2` (enterprise) | 10 | proof + 56 carried publics + 1×1088 = 3,136 B (widest public vector on the rail; still under transfer10x2_priv — one kem ct, not two) | — |

Per-op account layouts are in each module's doc comment. The vault authority
PDA is `["authority", config]`; the vault address is config-bound.

Enterprise ops (family flag bits 4..8; the flags field is u16 LE at config
bytes 2..4 — bit 8 outgrew the original u8, so the field absorbed the
adjacent reserved byte and existing account images read identically)
additionally inject the arbiter bjj key from `PoolConfig` into the public
vector before verify — a proof made for any other key fails (`InvalidProof`),
and a zeroed key (consumer-only profile) refuses with `ArbiterKeyUnset`
before verify. `disburse256` attaches its in-circuit 256-leaf subtree at
LOG_B (from config `B`) and persists the per-batch audit anchor
`(start_leaf_index, disclosureHash, kemBinding, epoch)` in a `DisburseBatch`
PDA (`["batch", start_leaf_index u64 LE]` — the counter convention, not the
field-element BE form); its self-CPI event carries the same tuple plus
subtreeRoot/resultingRoot/nullifier. Epoch is pinned to 0 until arbiter
rotation lands as an instruction (SOLR §3.3.1).

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
node_modules/.bin/tsx chains/solana/scripts/gen_enterprise_vectors.ts        # enterprise fixtures + the served-blob refold vector
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
| `disburse256` | 202,752 | 213,000 | ~640k (the estimate charged attach per-leaf; the O(LOG_B) close makes attach ~30k) |
| `transfer` | 322,195 | 339,000 | — |
| `transfer10x2` | 491,759 | 517,000 | — (merge fixture: 68-public verify + 11 PDA creates, ~35% of cap) |

Measured on mollusk-svm 0.15.1 (Agave 4.x runtime cost model), committed
realproof fixtures, full paths (verify + appends/attach + PDA creates +
escrow CPI + self-CPI event). Worst op is the enterprise transfer10x2 at
~35% of the 1.4M CU cap; the full 256-out disburse is CHEAPER than a
consumer transfer (~14% of cap).

## Tx size (gate 4, worst-case shape per op, Transaction v1 = 4,096 B)

| op | worst-case tx | headroom |
|---|---|---|
| `deposit_priv` | 3,435 B | 661 B |
| `transfer_priv` | 3,499 B | 597 B |
| `transfer10x2_priv` | 4,019 B (10 nullifier PDAs) | **77 B** — the §3.1.2 tightest op; next lever is an address lookup table |
| `withdraw_priv` | 2,416 B | 1,680 B |
| `deposit` | 2,379 B | 1,717 B |
| `withdraw` | 2,704 B | 1,392 B |
| `disburse256` | 2,091 B | 2,005 B |
| `transfer` | 2,891 B | 1,205 B |
| `transfer10x2` | 3,891 B (10 nullifier PDAs) | 205 B — widest publics but ONE kem ct, so the consumer 10x2 stays the tightest wire (ordering gate-4-pinned) |

Computed from the consensus wire format (v0 message, 1 signature, both
ComputeBudget ixs — unit limit + unit price — included) over the real
instruction shapes; the gate also re-checks the fixture-built instructions.

## Fixtures (SOLR §5.2)

Consumer: deposit/transfer/transfer10x2 replay the committed EVM realproof
fixtures (`chains/evm/test/fixtures/consumer_realproofs.json`) at op level —
mollusk seeds the fixture root as a KnownRoot PDA and the tree state from the
ImtTree oracle. withdrawPriv is the one exception: the op-level happy path
runs the re-proven Solana-recipient fixture
(`chains/evm/test/fixtures/consumer_realproofs_solana.json`, generated by
`scripts/gen_withdraw_solana_fixture.ts` through the existing CPU pipeline —
same inputs, only pub[15] rebound); the EVM withdraw fixture still replays at
verify level (accept + reject-tamper) against the generated VK.

Enterprise: `deposit`/`withdraw`/`transfer`/`transfer10x2` replay
`chains/evm/test/fixtures/realproofs.json` at op level with ZERO re-proving
(the 10x2 fixture is the MERGE entry — all 10 inputs real — so the op-level
replay drives the full 10-nullifier-PDA shape) — including withdraw: its
proof-bound uint160 recipient IS a reachable token-account address under
truncate-253, so the harness places the recipient token account at
`BE32(pub[26])` (SOLR §5.2). `disburse256` replays the committed GPU
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
`solana-test-validator` gate (`e2e_s.sh`), indexer ingest + disclosure
serving/alarms, client tx building, the §3.3.3 ~19-tx full-DA disburse
(documented option, by design not an instruction).
