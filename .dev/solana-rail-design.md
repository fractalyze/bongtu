# Solana rail — S1 design spec

Design record, 2026-09-04. Status: **spec draft — no Solana code exists.** Target file:
`.dev/solana-rail-design.md` (issue #8, milestone S1). Format precedent:
`.dev/op-module-design.md` (OPMOD). Section numbers here are cited as `SOLR §n`; `OPMOD §n`
and `SPEC §n` keep their existing meanings.

Ground truth for every measured/estimated number: the S0 spike summary
(issue #8 comment, 2026-09-04, GO-WITH-CAVEATS; labeled report off-repo). Labels carried
verbatim: **[measured]**, **[code]**, **[est]**. Anything derived here from S0 numbers is
**(est., derivation shown)**; anything unmeasured is **TBD(spike)** naming the spike that
would measure it.

S0 facts this spec builds on:

1. **Groth16 on SVM**: alt_bn128 syscalls live (Agave 4.2.2 [measured]); verify ≈ 78k CU
   @1 public → ~231k CU @36 publics [est from groth16-solana CI benches] — ~16% of the 1.4M
   CU cap. VK constants generate from our existing snarkjs `verification_key.json`; no
   verifier CPI needed.
2. **Poseidon**: `sol_poseidon` == circomlib parameterization (BN254, x^5, circom
   constants); our arities 2..5 bit-identical by design; 786..2,067 CU/hash [code].
3. **Tx size**: Transaction v1 (4,096 B) activates mainnet ~2026-09-09, making every
   non-disburse op single-tx. Full-DA disburse staging = buffer-account write-then-execute;
   the 331 KB consumer-batch shape measured ~87 write txs and ~2.31 SOL refundable rent
   float [est] (that shape is now out of product scope, §1; the numbers scale down to the
   enterprise variant, §3.3).
4. **State**: zero-copy single-frontier ImtTree port fits one ~4.6 KB PDA (Privacy Cash
   precedent at height 26); append 28.4k CU/leaf; 256-leaf batch attach amortizes to
   ~480k CU [est]. Nullifier = one PDA each, ~0.0019 SOL locked forever.
5. **ZK ElGamal incident**: a fully separate subsystem (curve25519 sigma protocols), still
   disabled today [measured]. Lesson: Solana fleet-disables ZK primitives on doubt —
   rail-risk register (§7), not a blocker.
6. **Wedge**: Privacy Cash (2in/2out, live $200M+) is our stack minus batching/compliance;
   nobody on Solana does count-hiding 256-out + op families.

---

## SOLR §1. Scope and non-goals

Locked product decisions (2026-09-04, user; fixed inputs — this spec implements them and
does not relitigate):

- **(a) Solana consumer v1 = the four P2P ops ONLY** — `depositPriv`, `transferPriv`,
  `transfer10x2Priv`, `withdrawPriv` — each **single-transaction**. Batch/mass ops are
  excluded from the consumer product entirely, on every rail.
- **(b) Enterprise disburse on Solana = disclosureHash-on-chain + institution-held DA, one
  transaction.** The ~19-tx full-on-chain-DA variant (buffer-account staging) stays a
  documented option, not the shipped default. The per-rail guarantee change — "auditable
  from chain alone" → "chain-verified bytes served from institution storage" — is a
  documented per-rail difference for `docs/security-model.md` (§3.3.4 wording).
- **(c) Mass disbursement is an institution-managed-pool feature only** (product decision
  2026-09-04). A `ConsumerDisburseModule`-style keyless batch is **not a product surface on
  any rail**. `disbursePriv256` and its chunk transport (OPMOD §4/§5) stay EVM artifacts of
  the shared-pool profile; nothing in this spec ports them.

In scope for the rail overall (this doc): the program architecture for (a); the design for
(b); the shared-artifact boundary; testing and milestones. Non-goals:

- No circuit fork. The acceptance criterion from issue #8 stands: the **same**
  .zkey/verifier artifacts prove ops the Solana program accepts. Any design below that
  would require a circuit edit is rejected or marked OPEN, never silently absorbed.
- No `transfer10` twin (deprecated on EVM; no consumer twin exists, OPMOD intro).
- No enterprise small-op family commitment in v1. Enterprise disburse (b) needs a funding
  path (an institution pool with no `deposit` cannot mint the input note); which enterprise
  ops accompany disburse on Solana is **OPEN-1** (§7) — the disburse design itself does not
  depend on the answer.
- No relayer, portal, or stealth-deposit port. `withdrawPriv` keeps its proof-bound
  recipient so it stays relayable later; the relayer service itself is out of scope.
- No Token-2022 integration. The pool escrows a plain SPL mint (mock kKRW analogue);
  CT/confidential-transfer extensions solve a different (amounts-only) problem and would
  couple us to the ZK ElGamal subsystem this rail deliberately avoids (§7).

---

## SOLR §2. Program architecture

### 2.1 Shape: one program, instruction families, config-flag registry

One program (`bongtu_pool`), instruction families rather than CPI-separated verifier
programs — the S0 shape. Rationale: verify is an in-program syscall sequence (no verifier
CPI needed, S0 #1), and CPI separation would buy isolation we don't need at the cost of a
second upgrade authority and cross-program invariants.

The EVM module registry (registered contracts, `ModuleRegistered`/`ModuleRemoved`) maps to
**family-enable flags in the pool config PDA**. Same deploy-profile semantics as
`docs/deployment.md`: audited-only (consumer flags off), consumer-only (no arbiter key
configured at initialize — "no key exists"), mixed. The posture stays publicly attestable:
the config account's flag history is reconstructable from the ledger (every
`set_family_flags` instruction is signed, permanent ledger data), the analogue of the EVM
event stream. There is no per-op module address to observe; family provenance is the
instruction discriminator, public per tx — the OPMOD "one-hop op-family provenance is
public BY DESIGN" property carries over.

### 2.2 Accounts and PDAs

| account | seeds | size / rent | holds |
|---|---|---|---|
| `PoolConfig` | `["config", mint]` | ~300 B, one-time | admin, mint, vault, `B`, family flags, arbiter bjj key + KEM pk hash (enterprise profiles; absent on consumer-only), root-history mode params |
| `TreeState` | `["tree", config]` | ~4.6 KB, one-time (S0 #4) | zero-copy single-frontier IMT: `filledSubtrees[32]`, `nextLeafIndex`, `currentRoot`; `zeros[32]` as program constants, not account data |
| `Nullifier` | `["nf", nf_le_bytes]` | 0-data PDA, ~0.0019 SOL locked forever (S0 #4) | existence == spent |
| `KnownRoot` | `["root", root_le_bytes]` | 0-data PDA, ~0.0019 SOL-class (est., same rent class as Nullifier) | existence == this root occurred |
| `Vault` | ATA of `["authority", config]` | one-time | SPL token escrow |
| `DisburseBatch` (enterprise, §3.3) | `["batch", start_leaf_index]` | ~100 B | `disclosureHash`, epoch, kem binding — the per-batch audit anchor |

**Nullifier representation — decision: PDA-per-nullifier.** Existence check and creation in
one instruction, O(1), no account-size ceiling, and creation doubles as the double-spend
guard (`create` fails if the PDA exists — the `NullifierAlreadyUsed` analogue is a system
program error, surfaced as our own error by pre-checking). Alternatives considered:

| alternative | verdict |
|---|---|
| PDA-per-nullifier (chosen) | O(1); rent 0.0019 SOL/nullifier locked forever — the register line from S0; no sizing decision to get wrong |
| one big nullifier account (bitmap/sorted set) | fixed capacity or realloc choreography; a full account bricks the pool; 10 MiB cap ≈ 320k nullifiers — a ceiling with no good failure mode |
| indexed/sparse merkle tree of nullifiers | reintroduces exactly the value-keyed-tree machinery bongtu removed (docs/zeto-derivation.md); in-circuit non-membership = circuit fork — rejected |

**Root history — decision: PDA-per-known-root (`KnownRoot`).** Exact parity with the EVM
`knownRoots` any-historical-root semantics (`docs/protocol.md`: the nullifier set is the
double-spend defence; accepting old roots removes the proof-staleness race — a race that is
*worse* on 400 ms slots than on an L2). Cost: one more Nullifier-class PDA per
root-advancing op, created by the op itself; rent is already dominated by nullifier PDAs
(transferPriv: 2 nullifier PDAs + 1 root PDA). Alternative, retained as a fallback if rent
float becomes a product problem: a ring buffer of N roots inside `TreeState` (Privacy Cash
precedent) — cheaper, but reintroduces the staleness window and is a **documented per-rail
semantic deviation** if ever adopted; N sizing would be TBD(S2 mollusk + ledger-latency
measurement). Ship parity first; downgrade only with the deviation documented in
security-model.

### 2.3 Instruction set (consumer v1)

Four op instructions + admin. Each op instruction: (1) reconstructs the full public-signal
vector, (2) verifies via alt_bn128 syscalls against baked-in VK constants generated from the
circuit's `verification_key.json`, (3) applies state through one shared internal gate
mirroring `applyOp`'s invariant list (known root iff spending; nullifiers nonzero+unused,
created sequentially; leaves nonzero; escrow motion last), (4) emits a self-CPI event
(§3.2.2).

**The wire carries no derivable publics.** The EVM modules inject `enabled[i]` and (on
enterprise) the arbiter key into the public vector before verify; the Solana instruction
data goes one step further and does not carry injected-or-derivable publics at all — the
program reconstructs them (`enabled[i] = nullifier[i] != 0`; withdraw's `recipient` from
the accounts list, §4.2 OPEN-3). Same trust posture (the prover never controls them), and it
buys the bytes that make transfer10x2Priv fit (§3.1.2).

| instruction | ix data (payload) | accounts (beyond config/tree/event-authority) | state effect |
|---|---|---|---|
| `initialize` / `initialize_consumer_only` | params | payer, mint | one-shot, mirrors the EVM one-initializer stance: complete profile in one tx |
| `set_family_flags` | flags | admin signer | registry analogue; admin-gated like `registerModule` |
| `deposit_priv` | proof(256 B) + non-derivable publics of `uint[16]` + 2×1088 B kem cts | payer token acct, vault | pulls `pub[0]`, appends 2 leaves |
| `transfer_priv` | proof + non-derivable publics of `uint[20]` + 2×1088 B | 2 Nullifier PDAs, 1 KnownRoot (read), 1 new KnownRoot | spends 2, appends 2 |
| `transfer10x2_priv` | proof + non-derivable publics of `uint[36]` + 2×1088 B | 10 Nullifier PDAs, roots | spends 10, appends 2 |
| `withdraw_priv` | proof + non-derivable publics of `uint[16]` + 1×1088 B + stealth announcement pair | recipient token acct, vault, nullifiers, roots | spends 2, appends 1 change leaf, pushes `pub[0]` to the proof-bound recipient — never the fee payer |

kem ciphertexts and the stealth pair stay non-proof-bound calldata-class bytes with the
same "can only break discovery" property (OPMOD §3.4); the program checks count and exact
1088-byte length per entry, nothing else.

### 2.4 Upgrade authority policy

BPF upgradeable loader. Testnet: the single deployer key holds upgrade authority — the
exact analogue of the EVM single-key `Ownable2Step` testnet posture, and it goes in the
same testnet-caveats register. Mainnet prerequisite: upgrade authority to a multisig
(Squads-class) or burned-with-migration-plan; **never burn on this rail while the ZK
syscall risk (§7) is open** — an upgrade path is the only mitigation if a syscall we depend
on is feature-gated away and re-enabled in changed form. Admin authority (family flags,
arbiter rotation) is a `PoolConfig` field, separable from the upgrade authority later;
testnet keeps them one key.

---

## SOLR §3. The three S1 hard problems

### 3.1 CU + byte choreography per op

Two budgets bind per transaction and both get a worksheet: the **1.4M CU cap** (request via
ComputeBudget instruction; default 200k must always be raised explicitly — a client
obligation) and the **4,096 B Transaction v1 size** (activation dependency, §7).

#### 3.1.1 CU worksheets

Verify cost model from the two S0 points — 78k CU @1 public, ~231k @36 — is linear at
**~4.4k CU/public (est., slope of the two S0 points)**. Tree append: 28.4k CU/leaf (S0,
32 poseidon(2) folds). Every number below is (est.) until the mollusk real-fixture pass
(S0 toolchain note: 1–2 days) replaces it; the committed budget table (§3.1.3) is filled
from mollusk, not from this worksheet.

| op | verify (publics) | appends | PDA creates (nf+root) | token CPI | total (est.) | % of 1.4M |
|---|---|---|---|---|---|---|
| deposit_priv | ~144k (16) | 2 × 28.4k | 1 | yes | **~230k** | ~16% |
| transfer_priv | ~162k (20) | 2 × 28.4k | 3 | — | **~240k** | ~17% |
| transfer10x2_priv | ~231k (36) | 2 × 28.4k | 11 | — | **~330k** | ~24% |
| withdraw_priv | ~144k (16) | 1 × 28.4k | 3 | yes | **~210k** | ~15% |
| enterprise disburse (§3.3) | ~122k (11) | batch attach ~480k (S0) | 2 | — | **~640k** | ~46% |

PDA-create and CPI line items are the loosest guesses here (a few k CU each,
TBD(mollusk)); nothing is within 2× of the cap, so the risk is regression, not feasibility
— hence the harness gates below.

#### 3.1.2 Byte worksheets (Transaction v1, 4,096 B total)

Payload = proof 256 B + non-derivable publics + kem cts (+ announcement pair on withdraw);
overhead = signature(s), message header, account keys, blockhash, ComputeBudget ix,
discriminators — call it ~450–600 B before lookup tables (TBD(S2), measure exactly).

| op | publics carried | payload | headroom vs 4,096 B |
|---|---|---|---|
| deposit_priv | 16 × 32 = 512 | 256+512+2176 = **2,944 B** | comfortable |
| transfer_priv | 18 × 32 = 576 (enabled[2] derived) | **3,008 B** | comfortable |
| transfer10x2_priv | 26 × 32 = 832 (enabled[10] derived) | **3,264 B** | ~**250–400 B** — the tightest op; if measurement eats the margin: address lookup table for the static accounts, then (last resort) split kem-ct delivery, which we do NOT design now |
| withdraw_priv | 13 × 32 = 416 (enabled[2] + recipient derived/account-bound) | 256+416+1088+~40 = **1,800 B** | comfortable |

Carrying full public vectors instead (the naive port) puts transfer10x2_priv at 3,584 B
payload — likely over once overhead lands. The no-derivable-publics wire rule (§2.3) is
what keeps every op single-tx; it is load-bearing, not a nicety.

#### 3.1.3 The mollusk harness — day-1 gates

`solana/` gets a mollusk test crate in the same commit as the first instruction, with these
gates (the CU analogue of the circuits attack-gate suite; CI-run, clean-env-checked per
`.dev/ci.md`):

1. **Poseidon conformance** — `sol_poseidon` over the committed circomlib parity vectors,
   including `Poseidon([1,2]) == 78532...3530` (`docs/protocol.md`) and arity 2..5 vectors
   exported from `packages/core`. Failure = the rail's algebra forked; hard fail.
2. **Verify parity** — each op's verifier accepts the committed EVM realproof fixture for
   that circuit (§5.2) and rejects a tampered public. Pins VK-constant generation against
   snarkjs output.
3. **CU regression budgets** — a committed per-op budget table (filled by the first
   real-fixture mollusk run, replacing §3.1.1's estimates); any op exceeding its budget
   fails the gate. Budgets move only by explicit commit, the way gas tables do in
   `docs/performance.md`.
4. **Tx-size regression** — serialized size of each fully-built op tx asserted under
   4,096 B with the measured overhead, so a wire change that silently breaks
   single-tx-ness fails in CI, not on chain.
5. **Invariant gate conformance** — double-spend (existing Nullifier PDA), unknown root,
   zero leaf, wrong kem-ct length/count, family flag off ⇒ each rejects with the mapped
   error; mirrors `contracts/test/Enforcement.t.sol`.

### 3.2 Discovery / DA without EVM events

#### 3.2.1 What replaces calldata + events

On EVM, all discovery material is logs (plus calldata for chunked kem bytes). On Solana the
ledger's instruction data plays calldata's role — it is consensus-committed and permanent
in the ledger — and **self-CPI events** play the log role: the program invokes itself with
an event payload as instruction data (the emit-cpi pattern), which lands in the tx's inner
instructions, uncapped and unstrippable, unlike `sol_log_data` (RPC-truncatable, not a
DA surface — rejected for anything load-bearing).

Decision: **all discovery-critical bytes ride in instruction data** (op payload = the
ciphertexts, viewTags via publics, kem cts) and **each op emits one self-CPI event**
carrying the post-op anchors: `(family, start_leaf_index, leaf_count or subtree_root,
resulting_root, nullifiers)`. The resulting-root field restores the EVM per-insert mirror
assertion (`docs/indexer.md` Mirror invariant): the indexer's reconstructed root is checked
against the program's own claim **per op**, not merely against `TreeState` at head.

#### 3.2.2 Indexer ingest path

The Solana backend feeds the same read model (`applyLogs`-equivalent stays pure; only the
fetch layer is rail-specific):

```
cursor = (slot, signature)
loop:
  getSignaturesForAddress(program, until=cursor)      # oldest-first replay
  getTransaction(sig, jsonParsed, maxSupportedTransactionVersion)
    -> decode TOP-LEVEL and INNER instructions by (program id, discriminator)
       (inner: an op invoked through a wrapper program must still be ours to ingest —
        the dispatch rule is program id + discriminator, the emitter-address analogue)
    -> op ix data  = publics + ciphertexts + kem cts  (the calldata analogue)
    -> self-CPI event = the per-op anchor; assert mirror root == event root
  persist one batch atomically, advance cursor        # gap-only resume, unchanged
boot: rebuild tree from leaves table; assert root + nextLeafIndex against TreeState
      at the cursor slot before applying anything new  # verified resume, unchanged
```

Geyser/websocket subscription is a latency optimization over the same decode path, not a
correctness surface; the poll loop above is the canonical ingest.

#### 3.2.3 The availability guarantee, stated honestly

KEM ciphertexts and receiver cts are in instruction data ⇒ in the ledger ⇒ recoverable by
anyone with ledger access. The per-rail caveat: default Solana RPC nodes prune transaction
history; "from chain data alone" on this rail means **from the ledger**, which in practice
means either (a) an indexer that has been following since the pool's first slot (our
default posture — the indexer IS the follower), or (b) an archival source (Bigtable-backed
RPC / Old Faithful) for cold-start backfill. Funds safety never depends on this (a user
holding their notes can spend without any indexer — unchanged); discovery-from-genesis
depends on (a) or (b). This is the Solana analogue of the EVM "reading it means
eth_getLogs against an archive node" residual gap and goes in security-model's per-rail
section verbatim-class.

What the **public** indexer consumes for consumer ops: op instruction data + self-CPI
events + `TreeState`. No key, no institution surface — self-scan (`OPMOD §3.6`) works from
this feed with only the wallet's view identity, unchanged.

### 3.3 Enterprise disburse: 1-tx disclosureHash design

#### 3.3.1 What exactly is on-chain

The enterprise disburse circuit is reused verbatim: 11 publics including `disclosureHash` —
the Poseidon(2) fold over the 2054-element disclosure array (`receiverCts[1024] ++
authorityEnvelope[1030]`, `docs/protocol.md`). One transaction carries:

- proof + the non-derivable publics (`disclosureHash`, `subtreeRoot`, nullifier, root,
  nonce, ecdh, kemBinding; arbiter key reconstructed from `PoolConfig` — the key-injection
  discipline survives: a proof against any other key fails),
- the 1,088 B arbiter `kemCiphertext` (length-checked, exactly as on EVM),
- accounts: nullifier PDA, roots, `DisburseBatch` PDA.

Payload ≈ 256 + ~9×32 + 1088 ≈ **1.7 KB** — single-tx with room, even pre-v1-activation.
CU ≈ verify ~122k (11 publics, est. slope) + batch attach ~480k (S0 #4) ≈ **~640k** (est.,
TBD(mollusk)). The program appends nothing per-leaf and hashes no disclosure bytes — the
fold happened in-circuit; the chain holds its output.

The **`DisburseBatch` PDA** persists `(start_leaf_index, disclosureHash, kemBinding,
epoch)` — the durable audit anchor. A verifier does not need ledger history to check served
bytes against a batch; the hash is account state, readable forever. (The self-CPI event
carries the same tuple for the indexer's streaming path.)

#### 3.3.2 Institution-held DA: serving and verifying

The 65,728 B disclosure blob (2054 × 32 B, canonical LE, the exact fold order of
`disclosureChain`) is stored and served by the institution — the same party that already
operates the arbiter indexer and the GPU prover. Serving contract:

- `GET /disclosure/{start_leaf_index}` on the institution's (arbiter-mode) indexer returns
  the blob; **any** party verifies it by refolding (the one `disclosureChain`
  implementation, `packages/core/src/envelope.ts`) and comparing against the on-chain
  `DisburseBatch.disclosureHash`. Verification requires no key and no trust — only
  availability does.
- Elements are transmitted and refolded with the canonical-form rule (reject `>= p` before
  folding) — same rationale as OPMOD §4.4: byte equality, not mod-p equivalence.
- The arbiter-mode indexer treats "the blob I serve must match the chain hash" as a boot
  invariant per batch; the recipient path (trial-decrypt of the receiver run) and the
  arbiter path (envelope tail) both read the served blob.
- Alarm mapping: a served blob that mismatches the hash is the existing `mismatch` class; a
  blob the institution fails to serve past a grace window is `withheld`. What changes is
  who can *observe* `withheld`: on EVM non-publication is impossible (consensus length
  rule); here it is an institutional SLA whose breach is visible to anyone who asks and
  gets no valid bytes — detectable and attributable, but not preventable by the chain.

#### 3.3.3 The documented ~19-tx full-DA option

For a deployment that wants EVM-equivalent availability: buffer-account staging. A
per-batch staging PDA accumulates the 65,728 B blob across ~18–19 write txs (~3.7 KB
payload per v1 tx; 65,728/3,700 ≈ 18), **each write instruction advancing the running
Poseidon fold incrementally** — the S0 caveat is load-bearing here: refolding 2054 elements
in the execute tx alone is 2054 × ~850 CU ≈ 1.75M CU, over the cap, so the fold must
amortize into the writes. The execute tx then requires `staged_fold == disclosureHash`,
verifies, attaches, and closes the staging account (rent refund; ~0.46 SOL float per
in-flight batch — est., S0's 2.31 SOL for 331 KB scaled to 65,728 B). Cost: ~20×
tx-orchestration complexity (resumability, staging GC, a relayer-class submitter) for
availability the institution can also provide by keeping a web server up. That trade is why
it is the option and not the default. No code in S2–S6 builds it; the design is recorded so
a regulator-driven deployment can demand it without a new spec round.

#### 3.3.4 Security-model wording (per-rail difference, to land in docs/security-model.md)

> **Per-rail scope of "from on-chain data alone" (Solana).** On the EVM rail, disburse
> disclosure publication is a consensus rule: the transaction does not exist without the
> full ciphertext array on-chain, so every note is auditor-openable *from chain data
> alone*. On the Solana rail's default (1-tx) disburse, the chain enforces the
> **binding** — `disclosureHash` is a verified public signal persisted per batch — but the
> **bytes** are served from institution storage. The guarantee downgrades from "auditable
> from chain alone" to "chain-verified bytes served from institution storage": any party
> can verify served bytes without trust; a withholding institution is detectable and
> attributable (an unfilled `withheld` request against a chain-committed hash) but not
> forced by consensus to publish. Deployments requiring consensus-forced publication use
> the staged full-DA variant (SOLR §3.3.3) at ~19× the transaction count.

Note what does *not* downgrade: non-repudiation (the envelope is inside the hashed blob;
the institution cannot serve different bytes to different parties), count-hiding (fixed
256-shape, no per-leaf record), and the in-circuit envelope enforcement (unchanged
circuit).

---

## SOLR §4. Shared with the EVM rail vs rail-specific

### 4.1 Shared verbatim (single-sourced; the consensus-drift line from issue #8)

- **Circuits, zkeys, vkeys** — byte-identical artifacts; Solana VK constants are
  *generated from* `verification_key.json`, never hand-ported.
- **Note algebra** — commitment/nullifier/tree-node hashes, the 2^100 value belt, untyped
  notes (`docs/protocol.md`). `sol_poseidon` is bit-identical to circomlib (S0 #2), pinned
  by the conformance gate (§3.1.3 #1).
- **IMT semantics** — height 32, single frontier, fold bit-order, batch attach at
  `LOG_B`; the Rust `TreeState` port is a third implementation of an algebra already
  pinned two ways (`ImtTree` ↔ contract differential test) and gets pinned against the
  same vectors.
- **Discovery crypto** — viewTag derivation, hybrid receiver-ct fold, domain tags
  (`bongtu/consumer-note/v1/*`), `nonce + i`, the self-scan pipeline (OPMOD §3). The
  client's self-scan engine is reused as-is over a rail-specific feed adapter.
- **disclosureChain** — one implementation, one fold order, both rails.
- **KEM** — ML-KEM-768, 1088 B cts, limb packing (`packages/core/src/kem.ts`).

### 4.2 Rail-specific

- Program/account model, nullifier + root representation (§2.2), ingest backend (§3.2),
  tx building in `packages/client` (a Solana connection/spend-flow sibling; the
  proving-wire types are shared).
- **Key derivation seed** — the EVM wallet seeds all three keys from one EIP-712
  signature whose domain is `(name, version, chainId, verifyingContract)`
  (`packages/client/src/derive.ts`, SPEC §6). Solana wallets have no EIP-712;
  the analogue is `signMessage` over a domain-separated payload. **OPEN-2**: exact payload
  bytes, and what plays the `(chainId, verifyingContract)` role — the natural candidates
  are (genesis hash, program id, pool config PDA), but off-curve message-signing UX
  differs per wallet and the bytes are consensus-critical (they rotate every key). Not
  decided here.
- **Cross-rail identity** — because the KDF domain binds the rail, one human with one
  wallet gets *different* bjj identities per rail. Whether that is the product intent
  (isolation) or a UX bug (one balance expectation) is **OPEN-2b** — a product question,
  flagged not decided. Note the EVM KDF cannot simply be reused: the seed is a signature
  from a *different* wallet stack.
- **withdrawPriv recipient binding** — the circuit binds `recipient` as one field element
  the EVM module range-checks to uint160 (OPMOD §2, withdrawPriv pub[15]). A Solana
  recipient (token account address) is 32 bytes and does not fit one BN254 field element.
  **OPEN-3**, options recorded: (i) bind the low/truncated 160 bits (or 253 bits) of the
  recipient token account address — theft requires a second preimage of the truncation
  onto an attacker-controlled account (≥2^160 grinding); (ii) bind
  `Poseidon(limbs(address))` — clean but needs the *program* to hash (cheap, ~1k CU) and
  a decision on limb split; (iii) a circuit variant with 2 limbs — violates no-fork,
  rejected. (i) and (ii) both keep the circuit verbatim; choosing between them is a
  security-review call for S2, not this doc.
- **chainId in publics — there is none.** Verified: no circuit binds a chain id in its
  public vector (the chain binding lives in the client KDF only). Consequence for
  fixtures: §5.2. Flip side, flagged explicitly: **OPEN-4** — nothing in the proof binds
  the rail, so a proof built for one rail's pool verifies on the other rail's verifier.
  Replay across rails is blocked by *state*, not by the proof: the root must be a known
  root of that pool, and roots diverge from the first differing leaf. Two pools with
  identical leaf history would accept each other's proofs (double-nullifier-spend across
  rails = double-spend of *distinct* escrows, i.e. an actual loss only if someone bridges
  1:1 against both). Whether an explicit rail/pool binding should be added at the next
  circuit revision is an open question for the circuit-freeze review, not this rail.

---

## SOLR §5. Testing strategy

### 5.1 Mollusk unit gates

The §3.1.3 gate list, CI-run from day 1 (S2 acceptance). Mollusk is the EVM rail's
`forge test` analogue: per-instruction, no validator, exact CU metering — which is what
makes the CU budget table a *gate* rather than a dashboard.

### 5.2 Fixture strategy — what replays, what re-proves

Committed EVM realproof fixtures replay at the **verify level** on Solana: no public
signal embeds a chain id (§4.2), and the enterprise fixtures' arbiter-key binding
(`realproofs.arbiterKey` == the Deploy.s.sol default, CLAUDE.md) is chain-agnostic bjj
material — the mollusk harness configures the same key in `PoolConfig`. State-level
replay works by seeding: mollusk writes the fixture's root as a `KnownRoot` PDA and the
tree state to match, so op-level tests run against committed fixtures with zero
re-proving for `deposit_priv`, `transfer_priv`, `transfer10x2_priv`, and enterprise
disburse.

The one exception: **withdrawPriv fixtures bind an EVM recipient address** in pub[15].
They still serve verify-parity and reject-tamper gates unchanged; the *happy-path
op-level* withdraw test needs a fixture proven against a Solana-mapped recipient under
whichever OPEN-3 binding S2 picks — **one re-proven fixture**, CPU-provable (small
circuit), generated by the existing fixture pipeline with a new input file, committed
beside the EVM one. No other re-proving is needed.

### 5.3 e2e shape

`solana/gates/e2e_s.sh`, mirroring `deploy/gates/e2e_m0.sh`: `solana-test-validator` →
deploy + initialize (consumer profile) → `deposit_priv` (real proof) → `transfer_priv` →
self-scan discovers the note from ledger data with only the wallet's keys →
`withdraw_priv` to a token account → balances assert. Enterprise leg (once OPEN-1
resolves): fund → disburse 1-tx → arbiter-mode indexer serves the blob → independent
refold verifies against `DisburseBatch`. Heavy-gate discipline carries over: e2e is the
final gate, mollusk is the iteration loop (CLAUDE.md heavy-gates rule, extended).

Indexer: the conformance suite (`apps/indexer` test) grows a Solana-backend leg driven by
recorded ledger fixtures (the `applyLogs`-level double), so read-model parity between
rails is asserted without a validator in the loop.

---

## SOLR §6. Milestone re-map (S2..S6)

Issue #8's plan, adjusted to the locked scope (consumer batch dropped per decision (c);
S3 re-pointed from "disburse batch path / buffer accounts" to the 1-tx enterprise
design):

| milestone | content | acceptance gate |
|---|---|---|
| **S2** | `solana/` program island: tree + nullifier/root PDAs + invariant gate + `transfer_priv` first (tracer bullet), then the other three P2P ops; mollusk harness in the same commit; OPEN-3 (recipient binding) decided by security review | mollusk gates 1–5 green in CI; EVM transfer realproof fixture accepted on-SVM; committed CU budget table populated from real fixtures |
| **S3** | enterprise disburse 1-tx: `DisburseBatch` PDA, arbiter-key injection from config, kem ct transport; the §3.3.3 variant documented only; OPEN-1 (enterprise funding ops) decided | enterprise disburse fixture verifies + attaches on-SVM; batch-attach CU within budget; refold-vs-`DisburseBatch` check passes against a served blob |
| **S4** | indexer Solana backend: signature-cursor ingest, inner-instruction dispatch, self-CPI event decode, per-op mirror assertion, disclosure serving + alarm mapping (§3.3.2) | conformance suite passes on recorded ledger fixtures; kill-and-resume replays gap-only with verified resume; public self-scan feed serves a consumer note end to end |
| **S5** | client: Solana tx building (ComputeBudget, v1 size assertion), wallet KDF (OPEN-2 decided), self-scan feed adapter | a consumer wallet derives keys, deposits, transfers, self-scans balance, withdraws — against test validator via the real client path |
| **S6** | `e2e_s.sh` local-validator gate, deploy profile (`deploy/` addresses record per cluster, upgrade-authority runbook), docs: `docs/solana-rail.md` topic doc + README index + the §3.3.4 security-model per-rail section | e2e green from clean env; all existing EVM gates untouched-green (issue #8 acceptance); docs lint clean |

Issue-level acceptance criteria, re-mapped: "same zkey/verifier artifacts, no circuit
fork" → S2/S3 gates; "consumer wallet self-scans from Solana state with only its keys" →
S5; "256-out disburse settles end-to-end with count-hiding intact" → S3+S6 in the 1-tx
enterprise shape (count-hiding is unchanged — fixed 256 attach, no per-leaf record);
"family selection via the PDA registry" → the §2.1 config-flag registry; "EVM rail and
shared packages unaffected" → S6 gate.

---

## SOLR §7. Open questions and risks

Open questions (each carried above; none decided in this doc):

- **OPEN-1** — which enterprise ops accompany disburse on Solana (deposit at minimum, as
  the institution funding path); scope call, due before S3.
- **OPEN-2** — Solana wallet KDF: exact signMessage payload and the domain fields playing
  the `(chainId, verifyingContract)` role. Consensus-critical bytes; due before S5.
- **OPEN-2b** — cross-rail identity: per-rail keys (implied by any domain-separated KDF)
  vs a one-identity product expectation. Product call.
- **OPEN-3** — withdrawPriv recipient binding for 32-byte addresses under a verbatim
  circuit: truncated-bits vs program-side Poseidon-of-limbs. Security review, due in S2.
- **OPEN-4** — no rail/pool binding in any public vector: cross-rail proof replay is
  blocked by state (root divergence), not by the proof; whether to add an explicit
  binding at the next circuit revision belongs to the circuit-freeze review.

Risk register:

- **ZK syscall fleet-disable (adjacent precedent).** ZK ElGamal — a separate subsystem —
  is still disabled today after its incident (S0 #5): Solana disables ZK primitives
  fleet-wide on doubt. Our dependencies are alt_bn128 + sol_poseidon; a soundness scare in
  either freezes every op on the rail (funds intact; the notes and the ledger survive;
  ops resume on re-enable or on an upgraded program against replacement syscalls — which
  is why the upgrade authority stays live, §2.4). Mitigation: none available beyond
  monitoring feature-gate proposals; recorded as an accepted rail risk.
- **Transaction v1 timing.** Single-tx for `transfer_priv`/`transfer10x2_priv`/
  `deposit_priv` (payloads 2.9–3.3 KB) **requires** the 4,096 B format; legacy 1,232 B
  does not fit any of them. Mainnet activation ~2026-09-09 (S0 #3) — days away, but any
  slip blocks mainnet-shaped testing; devnet/test-validator availability decouples S2–S5
  from the date. If the activation slipped indefinitely (not expected), the fallback is a
  kem-ct staging account per op — a design regression we deliberately do not spec now.
- **transfer10x2_priv byte margin.** ~250–400 B of headroom on the tightest op before
  lookup tables (§3.1.2); measured exactly in S2's tx-size gate. Mitigations in order:
  address lookup table, then payload trimming review.
- **Rent float.** Nullifier PDAs: ~0.0019 SOL × every nullifier ever spent, locked forever
  (S0 #4) — at consumer scale this is a real per-op cost line (transfer_priv ≈ 3 PDA
  creates ≈ ~0.006 SOL ≈ the fee-story item to price in S5 UX). Enterprise full-DA
  variant: ~0.46 SOL refundable per in-flight batch (est., §3.3.3) — only if that variant
  is ever built. Root-PDA parity (§2.2) is the first thing to trade away (→ ring buffer,
  documented deviation) if the rent line becomes a product problem.
- **Ledger history availability.** Discovery-from-genesis depends on a continuously
  following indexer or archival RPC (§3.2.3); a per-rail residual-gap entry for
  security-model, not a blocker.
- **All CU/byte figures are estimates until mollusk.** The S0 toolchain note stands: a
  real-fixture on-SVM CU spike is 1–2 days and is the first S2 task; the §3.1 worksheets
  exist to be replaced by its output, not to be shipped.
