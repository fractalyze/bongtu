# bongtu — Spec (v1 PoC)

> **봉투 (bongtu)** — a digital 월급봉투. Everyone sees envelopes handed out; only the recipient sees the
> amount inside; a designated authority can open every envelope. An institutional privacy token on GIWA
> (OP Stack L2), built on Zeto with enforced auditor disclosure.

Status: **spec — grilled, adversarially reviewed, locked 2026-07-23.** Target: GIWA Sepolia (91342).
"PoC" = this testnet deliverable; "prod" = mainnet-grade, out of scope but flagged.
Section 11 is the honest-caveats register; Section 13 is the deferred-prod-requirements register.

---

## 1. What this is

A UTXO shielded-token on EVM where **every transfer is encrypted to a fixed authority key inside the ZK
proof** (non-repudiation), so an auditor can decrypt sender/receiver/amount for any transfer — but the
public chain and other users cannot. It keeps Zeto's normal payments (private p2p transfer, deposit,
withdraw) and adds the one thing no competitor does: a **single-transaction, 256-recipient private
disbursement** ("bongtu" of 256 envelopes), proven off-chain on GPU, verified on-chain in O(tree height).

**Anchor flow (headline):** an institution shields funds, then pays up to 256 recipients in one tx where
individual amounts/recipients are private but auditor-decryptable. Recipients discover notes by scanning the
chain (no out-of-band channel), then privately transfer or withdraw.

**Buyer:** the institution (payer + compliance). **Users onboarded:** recipients (each 256-batch = up to 256
wallet onboards — the GASOK user-KPI bridge).

---

## 2. Locked decisions (Q1–Q11)

| # | Decision | Rationale |
|---|---|---|
| Q1 | Keep **all** Zeto payment features; add **256-out batch disburse** as headline; **authority = auditor** on every transfer | Commodity features stay; 256-out + GPU proving is the moat |
| Q2 | **Single flavor: non-repudiation on every transfer** (no audit-free path) | Compliance identity; halves the circuit matrix; loosenable later, not un-loosenable |
| Q3 | **Wrapped ERC-20 only**; deposit mints notes 1:1 | Payroll = "deposit token, disburse privately"; issuer-mint preserved but unused |
| Q3b | Demo token = **bongtu-deployed mock `kKRW`** (18-dec, faucet-mintable); WETH9 is the alternative; a real GIWA stablecoin only if it passes the §5 fee-on-transfer/rebasing check | GIWA coinless, no stablecoin confirmed; controllable + narrative-friendly + unblocks deploy |
| Q4 | **All ciphertext on-chain** (calldata + events) | GIWA L2 ≈0.001 gwei makes 65KB ≈ sub-cent; buys trustless discovery + seed-only recovery. (Availability is L1-backed via calldata, see §11-7) |
| Q5 | **Local-first self-hosted proving**; employer proves on own infra | "Payroll data never leaves your infra"; GPU tier is the paid moat later |
| Q6 | v1 = **4 circuits** (`transfer` 2×2, `disburse` 1×256, `withdraw` 2×1, `deposit` 0×2), IMT depth-32, Poseidon-v1, **stock 100-bit value range** | See §4 |
| Q6b | **Drop the merged fund+disburse variant** | Its only benefit was gas ($0.007 at GIWA); merging *links* deposit↔disburse, worse for privacy |
| Q7 | **One open monorepo `bongtu`** (Apache-2.0); Zeto = vendored dep, Foundry-first | Public-signal offsets are version-coupled; indexer is convenience post-Q4, so open costs no moat |
| Q8 | **Name = bongtu** | 월급봉투 metaphor maps 1:1; Korean object; no clash with GIWA "Bojagi" |
| Q9 | Arbiter key = **required `initialize()` arg** + **epoch versioning/rotation**; pubkey injected from storage, never calldata | Kills (0,0) footgun; institutions rotate keys |
| Q10 | **Two apps**: (1) **admin** with **two role-modes** — *employer-mode* (no arbiter key: CSV→prove→disburse, ledger from own CSV+receipts) and *auditor-mode* (holds arbiter key: decrypts event stream) — and (2) **public** (MetaMask, client-side balance, transfer/withdraw) | Amounts can't live decrypted in a public DB; role-mode split preserves "2 apps" while keeping the auditor independent (see §7 + review note) |
| Q11 | **Single-party trusted setup** for PoC; phase-2 MPC is a mainnet prerequisite **after circuit freeze** | Testnet = fake money; ceremony is waste until circuits are frozen |

> **Q10 refinement — CONFIRMED 2026-07-23.** The original "employer + auditor fused, arbiter key on the
> employer server" self-refutes the compliance story (a company decrypting its own payroll proves nothing to
> a regulator, and the payroll operator would gain surveillance over all employee p2p transfers forever).
> **Decided:** the auditor sees everything (holds the arbiter key); the institution does not. This keeps the
> **2-app** structure but makes the admin app **role-moded** — *employer* runs it **without** the arbiter
> key; *auditor* runs it **with** the key (separate profile/host in the demo). Demo beat: "the employer
> **cannot** read employees' later transfers; the auditor **can**."

---

## 3. Architecture

```
                       bongtu monorepo (Apache-2.0, Foundry-first)
┌──────────────────────────────────────────────────────────────────────────────┐
│ circuits/  transfer 2×2 (new small base) · disburse 1×256 (done) ·             │
│            withdraw 2×1 (rebase) · deposit 0×2 (stock)  [IMT d32, Poseidon-v1]  │
│      │ circom → r1cs → (single-party) zkey → Groth16Verifier.sol (×4)           │
│      ▼                                                                          │
│ contracts/ BongtuPool (single-frontier IMT + nullifiers + arbiter epochs +      │
│            ERC20 custody + 4 verifiers + contract-derived enabled) · Poseidon    │
│      │ events carry ALL ciphertext + ecdhPublicKey + nonce (from verified sigs)  │
│      ▼                                                                          │
│ sdk/ keys(signTypedData→bjj) · notes · encrypt · scan/trial-decrypt+nullifier   │
│   proving/  snarkjs(GPL) isolated · rabbitsnark(GPU, repo-external)             │
│ prover-cli/ (employer self-host: CSV→witness→proof→tx)                          │
│ indexer/ event ingest · IMT mirror(==contract root) · path API · disclosureHash │
│          verify · (auditor-mode) arbiter-decrypt ledger                          │
│ apps/ admin(employer-mode | auditor-mode) · public(MetaMask wallet)             │
└──────────────────────────────────────────────────────────────────────────────┘
                    deploy → GIWA Sepolia (Blockscout verify)
```

---

## 4. Circuits (v1 = 4)

All on **append-only IMT depth-32** (`lib/check-imt-proof.circom`, index-keyed, `enabled[]`-gated),
**Poseidon-v1**, **stock 100-bit value range** (unchanged — do **not** re-parameterize; see below).
Non-membership is delegated to the on-chain nullifier set (IMT can't prove non-membership — like stock Zeto).
Commitment = `poseidon4([value, salt, ownerPubX, ownerPubY])`; nullifier = `poseidon3([value, salt,
ownerFormattedPrivKey])`. **Constraint-count convention:** figures below are *nonlinear under circom --O1*
(disburse ≈1.66M nonlinear / 2.79M total).

| Circuit | arity | Membership | Auth env | Publics | Status |
|---|---|---|---|---|---|
| `transfer` | 2-in / 2-out | IMT + nullifiers | yes | **36** | **new small base** |
| `disburse` | 1-in / 256-out | IMT + nullifier | yes | 10 | **done** (current e2e) |
| `withdraw` | 2-in / 1-out | IMT + nullifiers | no | 7 | **rebase** |
| `deposit` | 0-in / 2-out | none (mint) | no (v1 gap §11-1) | 3 | **stock reuse** |

**`transfer` — new small base, not an instantiation.** In the existing 256 IMT base, `cipherTexts` is
*private* and `outputCommitments` was demoted from public — re-using it gives the contract no circuit-bound
leaves to insert. So build `anon_enc_nullifier_non_repudiation_imt_small_base.circom`:
publics `[nullifiers[2], outputCommitments[2], encryptionNonce, root, enabled[2], authorityPublicKey[2]]`
plus circuit outputs `ecdhPublicKey[2], cipherTexts[2][4], cipherTextAuthority[l+1]` = **36 public signals**
(matches stock non-rep 2×2). **No subtree gadget, no disclosureHash** — at this arity the ciphertext rides
as public signals, so the circuit fully binds it and the contract builds its public vector from the very
bytes it emits. ~50–60K constraints.

**`disburse` — done, keep 100-bit.** subtree-root gadget (depth-8) + **disclosureHash** (nPublic=10, because
2,318 publics would cost ~14M verifier gas). Raw ciphertext bytes go in calldata → event. disclosureHash
chains receiver ciphertexts **then** the authority ciphertext; the contract never re-hashes emitted bytes
(2,054 Poseidons ≈ 61M gas, infeasible). **Consequence (§11-6):** a mismatch is self-defeating only for
*receivers* (they can't decrypt); the *authority* envelope can be junk while receivers decrypt fine, so
**disclosureHash verification is assigned to the indexer** (§6b), not left implicit.

**`withdraw` — rebase deltas (complete list):** (1) `check-smt-proof` → `check-imt-proof` in
`check-nullifiers-value-base.circom`; (2) `merkleProof[n][64]` → `pathElements[n][32]` + `leafIndices[n]`
(private); (3) `CheckSMTProof` call → `CheckIMTProof`; (4) top-level re-instantiate `(2,1,32)`; (5) SDK must
produce IMT `leafIndices` (no existing code does); (6) contract does a 1-leaf append of the change output;
(7) **fix comparator to `GreaterEqThan(101)`** — summing two 100-bit inputs can reach 2^101, and the stock
`GreaterEqThan(100)` precondition `<2^100` is violated at the boundary (honest near-max withdrawals would
lose their witness). Publics unchanged.

**Why 100-bit, not 96-bit (reversed from draft):** the shipped circuits are already 100-bit; re-parameterizing
would recompile everything, invalidating the 1.24GB zkey and the measured 0.5s/1.66M numbers for no benefit.
`256 × 2^100 = 2^108 ≪ p`, so `CheckSum` cannot wrap. Input values are never *directly* range-checked;
soundness is inductive — outputs are range-checked (`CheckPositive`) at creation, and the enabled fix (§5)
stops fabricated inputs. Only edit needed is withdraw's comparator width, above.

**Crypto invariant (all circuits, §11-8):** the prover **MUST reject** any transfer/batch containing
**duplicate output owner pubkeys**. All outputs share one ephemeral key + one `encryptionNonce`; two outputs
to the same pubkey leak `c1−c2 = m1−m2` (two-time pad on value/salt). Enforced in CSV-ingest and SDK; the
structural fix (per-output nonce) is v1.1.

**Dropped from v1:** 10×10 batch (256 absorbs it), lock/escrow, burn, NFT, KYC-registry. Recoverable later
as new leaf circuits.

---

## 5. Contracts (Foundry-first)

`BongtuPool` vendors Zeto's proven patterns (UUPS, ERC-7201 storage, CEI + `nonReentrant`, one-shot
`setERC20`, Ownable2Step) as a **new leaf** over our IMT storage — not the Zeto Hardhat chain.

### 5.1 Unified single-frontier IMT (the top novel/soundness-critical component)

Both incremental small-tx inserts and 256-batch attach live in **one tree** with **one definition**, so a
batch-inserted note is spendable by `transfer`/`withdraw` against the same root. Normative:

- **One `nextLeafIndex` counter.** One shared `zeros[0..32]` table (`zeros[0]=0`, `zeros[k]=H(z,z)`),
  computed on-chain in the constructor (matches the circuit/JS generator).
- **Per-level frontier** `filledSubtrees[0..32]` (Tornado-lineage), not a per-deposit fresh block.
- **Incremental append (transfer/withdraw/deposit):** append each real output as one leaf at `nextLeafIndex`,
  updating the frontier and root in O(32). (This *replaces* the PoC V2's "burn a 256-block per note.")
- **Batch attach (disburse):** to append a 256-leaf subtree, first **pad the frontier to a 256-aligned
  boundary** by folding pending partial subtrees with `zeros[..8]` (≤8 hashes; padded slots are permanently
  dead leaves), then attach the in-circuit `subtreeRoot` at `blockIndex = nextLeafIndex/256`, level 8, and
  propagate 24 levels. `nextLeafIndex += 256`.
- **Leaf-index rule** stated as a table so contract, witness-gen (`leafIndices`), and indexer implement one
  definition; misalignment corrupts membership silently. Capacity `2^32` leaves is ample; document the
  ≤254-slot alignment waste per batch.
- **Mandatory Foundry differential test:** contract root == reference JS IMT root across an interleaved
  sequence `deposit(2) → transfer(2) → disburse(pad+attach) → withdraw(1)`.

### 5.2 enabled / nullifier soundness (corrected — the draft's fix was wrong)

Membership is per-input gated by `enabled[i]`, but `CheckNullifiers`/`CheckSum` run over **all** inputs. If
`enabled[i]` came from calldata, a prover sets `enabled[1]=0` to skip membership on a fabricated input whose
value still counts → **mint-from-nothing**. Fix, applied to **every** verifier call:

- The **contract derives** `enabled[i] = (nullifier[i] != 0)` from its own view and injects it into the
  public-signal vector; **never accept `enabled` from calldata.** For `disburse` (nInputs=1, always real)
  this degenerates to `require(pub[6]==1)`.
- **REQUIRED circuit value-belt (NOT optional — contract-derive alone is insufficient).** `CheckNullifiers`
  accepts `nullifier[i]==0` with any value, `CheckHashes` accepts `commitment[i]==0` with any value, and
  `CheckSum` adds `inputValue[i]` unconditionally — so an input `{nullifier=0, commitment=0, value=X,
  enabled=0}` passes every constraint and mints `X` (withdraw pays it out). The contract-derived
  `enabled=(nullifier!=0)=0` *agrees* with that malicious proof, so it does **not** catch it. Every 2-input
  nullifier circuit (`transfer`, `withdraw`) MUST add, per input: `enabled[i]*(enabled[i]-1)===0` and
  **`(1 - enabled[i]) * inputValue[i] === 0`** (a disabled input carries zero value). Then nullifier=0 ⟹
  enabled=0 ⟹ value=0 (no mint); nullifier≠0 ⟹ enabled=1 ⟹ membership required. `disburse` (1 input, contract
  forces `enabled==1` & `nullifier≠0` ⟹ membership always) needs no belt. (Found by U3 adversarial review;
  the earlier "optional belt `IsZero(nullifier)==1-enabled`" was itself insufficient — it never bound value.)
- The draft's `batchInsert require(enabled==1)` alone is **deleted** — it breaks padded single-note spends on
  the 2-input circuits and doesn't close the transfer/withdraw hole. Multi-input semantics ship in v1, not
  deferred. **Test the true vector:** the mint witness (`nullifier=0, value≠0, enabled=0`) must be
  unsatisfiable at witness-gen; a forgery test that only tries `nullifier≠0, enabled=0` misses it.
  (Knowledge: `zeto-enabled-flag-must-be-contract-derived-from-nullifier`.)

> **★ 5.2 CRITICAL correction (2026-07-24, Zeto-derivation audit + 3/3 adversarial verify).** The belt above
> is still **insufficient** — it closes only the `enabled=0` case. A second, distinct mint-from-nothing
> survives at `enabled=1`, introduced by our SMT→IMT swap: `CheckHashes`' zero-commitment escape is sound in
> stock Zeto only because its **value-keyed SMT** makes `commitment==0` structurally un-provable as a member.
> Our **index-keyed IMT** commits `zeros[0]=0` at every position ahead of the frontier and at every disburse
> pad slot, so **0 is a genuine, membership-provable leaf**. An attacker spends a padded 0-leaf declaring
> arbitrary value X (CheckHashes escapes → value unbound; fresh nullifier → `enabled=1`; membership holds;
> belt vacuous at `enabled=1`; `out=X`) — a **permissionless `withdraw`/`transfer` drain**, repeatable. No
> real funds (testnet, mock kKRW), but the contract is unsound. **REQUIRED additional belt, every spending
> base including `disburse`:** `enabled[i] * IsZero(inputCommitment[i]) === 0` (a zero-commitment input can
> never be enabled) — restoring the SMT's implicit invariant explicitly. `disburse` IS in scope here (its
> single input is `enabled=1`, so it is exploitable by a malicious/compromised discloser); adding the belt
> changes its r1cs, so the **1.24 GB disburse-256 zkey is regenerated** (byte-identity reuse retired).
> Mandatory regression: the 0-leaf-spend witness must be unsatisfiable at witness-gen AND revert on-chain.
> Rationale + full trace: [[imt-membership-breaks-zeto-zero-commitment-escape]]; provenance in
> `docs/zeto-derivation.md`.

### 5.3 Roots, nullifiers, custody, arbiter, events

- **Known roots:** adopt the upstream policy — `mapping(uint256 root => bool)` recording **every** historical
  root, `isKnownRoot` = O(1) lookup, accept any past root (nullifiers prevent double-spend regardless of root
  age). **Delete the 30-slot ring** (it reintroduces a proof-staleness race on a ~1s-block unified tree where
  both transfers and batches advance the root).
- **Nullifiers:** `mapping(uint256=>bool)` (stock).
- **ERC-20 custody:** deposit mints then pulls via SafeERC20 (CEI). **Hard constraint:** underlying ERC-20
  **MUST be non-fee-on-transfer and non-rebasing** — the amount is proof-bound before the pull, so a
  fee/rebase makes the pool insolvent by construction (balance-delta minting is not available). Any future
  "GIWA stablecoin" selection is gated on verifying this.
- **Arbiter versioning:** `initialize(...)` **requires** a non-zero key. `arbiterEpochs[e]={key,
  activatedBlock}`; `rotateArbiter(newKey)` appends an epoch + emits an event. The arbiter pubkey public
  input is **read from `arbiterEpochs` storage at execution, never from calldata** (else a sender encrypts to
  their own key and non-repudiation silently dies). Events **emit the epoch index** so an auditor selects the
  exact key even at a rotation-boundary block. In-flight invalidation on rotation is accepted for PoC
  (grace-window = v1.1).
- **Access control:** `disburse` is **caller-gated** (owner / allowlisted employer) in v1 — this makes the
  non-repudiation incentive argument honest (KYC variants are dropped in v1). `transfer` stays permissionless
  (its full public-signal binding is already sound). Role split (gate vs upgrade vs arbiter) is Ownable2Step
  for PoC; finer roles are §13.
- **Events (all ciphertext on-chain):** `transfer` reuses the `UTXOTransferNonRepudiation` shape
  (`encryptedValuesForReceiver`, `encryptedValuesForAuthority`, `ecdhPublicKey`, `encryptionNonce`, epoch).
  `disburse` emits `(ciphertext bytes, disclosureHash, subtreeRoot, ecdhPublicKey, encryptionNonce, epoch)` —
  **all copied from verified `publicSignals`, not free calldata** (without `ecdhPublicKey`+`nonce` recipients
  cannot derive the decryption key at all).
- **Verifier migration:** verifiers are immutable per pool; a circuit change ships via **UUPS impl upgrade**
  (new verifier address in the new impl, ERC-7201 tree/nullifier storage preserved). Any **nPublic-changing**
  edit is BREAKING (new verifier + new `IVerifier` arity + pool upgrade). Stated so multi-input disburse
  (§12) isn't a surprise.
- Custom errors, not string reverts.

---

## 6. SDK / Prover / Indexer

- **SDK (TS, Apache/MIT deps only):** port `zeto-js` crypto to typed TS — `poseidonEncrypt/Decrypt` (Poseidon
  sponge symmetric, **not ElGamal**), salt/nonce, `encodeProof`, note/nullifier builders, event scanner +
  **trial-decrypt**. **Key derivation:** bjj key from `eth_signTypedData_v4` over a **domain-separated struct**
  (`chainId`, pool address, version) — *not* a raw `personal_sign` string (which is wallet-nondeterministic
  and a phishing primitive). KDF = `hash(sig) → reduce mod subgroup order`, specified in code. **v1 = EOA
  wallets with deterministic ECDSA only (MetaMask pinned for the demo);** 4337 accounts need an alternative
  derivation (v1.1). Threat-model sentence, stated: **signature == spending key.**
- **Recovery (corrected):** re-sign → for every ciphertext slice trial-decrypt with `ECDH(myPriv,
  event.ecdhPublicKey)` → **recompute both the commitment AND the nullifier** (`poseidon3(value, salt,
  formattedPrivKey)`) → **filter against the on-chain spent set.** Recompute-nullifier is mandatory or the
  recovered balance is inflated and produced proofs revert. (Works because Q4 puts all ciphertext on-chain;
  stock Zeto's random off-chain salts made this impossible.) DoD test: `balance_after == balance_before`
  across a spend.
- **Prover (`prover-cli/`, employer self-host):** CSV(addr,amount) → witness (circom `witness_calculator`,
  ~89MB witness for disburse) → **rabbitsnark GPU** Groth16 → calldata → tx. Prover-host block: state the GPU
  VRAM floor (measure rabbitsnark high-water), CUDA version, and that **for the PoC "we prove in the demo" is
  the distribution model** (the 1.24GB zkey + private GPU binary aren't shipped to employers yet). snarkjs /
  ffjavascript (GPL-3.0) isolated as subprocess / optional-peer.
- **transfer proving (honest):** 2×2 is ~50–60K constraints. Client-side **browser snarkjs = O(seconds) +
  one-time zkey download**, *not* the 50ms server figure. **Browser GPL decision (explicit):** shipping
  snarkjs to the page **is** distribution, so the Node-subprocess mitigation doesn't apply — choose one and
  record it: (a) accept GPL for the public app, (b) a non-GPL WASM prover, or (c) prove via a local helper.
  Default for PoC: (a), documented.

## 6b. Indexer API (normative)

Post-Q4 the indexer is a **convenience/availability layer, not trust-critical** for funds (see §11-7), but the
public app depends on it for UX. Contract:

- `GET /events?cursor` → `[{ txHash, blockNumber, ecdhPublicKey, encryptionNonce, epoch, slices:[{offset,
  elts, leafIndex}] }]` — the ciphertext feed a wallet trial-decrypts. `leafIndex` per slice is required for
  later merkle paths.
- `GET /path/{leafIndex}` → merkle path against the current root.
- `GET /head` → current root + `nextLeafIndex`.
- **Invariants:** after every ingested event, `indexer.root == contract.root` (conformance test + a
  TS-Poseidon-vs-circomlib fixture test). **disclosureHash duty:** for every `disburse`, recompute the
  Poseidon chain over the emitted bytes, compare to the on-chain `disclosureHash`, and surface any mismatch
  as a **first-class auditor-console alarm** (~2,054 Poseidons, trivial off-chain) — this is what makes
  non-repudiation more than detect-only (§4 disburse note).
- "Instant balance" holds at PoC scale: client work is linear in total slices.

> **§6b addendum (2026-07-24, indexer-core built + adversarially reviewed).**
> - **Alarm classes.** Every disclosure that does not fully check out surfaces on `GET /alarms`:
>   `mismatch` (proven tamper), `unverifiable` (receiver-only publication — the chain covers
>   receiver ++ authority, so it can never complete; this is the live GIWA disburse's flavor), and
>   `withheld` (plain `disburse()`, nothing published). Receiver-only/withheld are auditor-policy
>   judgments, not proven tampers — full alarm coverage requires emitting receiver ++ authority
>   ciphertext, as the conformance scenario's honest disburse does.
> - **Within-batch merkle paths** are structurally unservable from public chain data (only the
>   `subtreeRoot` is emitted; sibling commitments are encrypted to other recipients):
>   `/path/<batch-leaf>` → 422 by design (§11-7). A disburse recipient therefore spends via (a) the
>   employer's own records, or (b) the **deferred arbiter-mode indexer unit**, which decrypts the
>   authority envelope (it carries every recipient's `(pubkey, value, salt)`) and can serve both
>   batch paths and a per-user note directory — `GET /notes?owner=<bjj-pubkey>` (note-query decision
>   2026-07-24: auditor-key indexer; viewing-key separation deferred, outside bongtu's trust model).
>   Both capabilities require the authority envelope to actually be published on-chain. The
>   auditor-free alternative is publishing the B output commitments (~8 KB calldata at B=256).

> **★ §6b v2 — enforced auditor disclosure (2026-07-24, grill-locked; ships in Unit 0 redeploy).** The
> product name is "enforced auditor disclosure", so **every note's creation and destruction must be
> auditor-openable from on-chain data alone** — a convention + off-chain alarm is not enough, a malicious
> employer could still withhold. Decisions:
> - **All four operations emit an authority envelope**, encrypted to the arbiter key inside the proof
>   (contract injects the stored arbiter key → wrong-key or no encryption ⇒ proof fails). Today only
>   transfer/disburse do. **Add in-circuit authority envelopes to `deposit`** (outputs: `(ownerPub, value,
>   salt)` ×2 → 10 ct elements) **and `withdraw`** (inputs `(ownerPub, value, salt)` + change → 13 ct
>   elements), emitted in `Deposited`/`Withdrawn`. This also closes the deposit blind spot where an employer
>   could hand value to an employee via a deposit output the auditor never sees. Supersedes the §11-1 gap.
> - **disburse publication is enforced on-chain, not by convention.** `plain disburse()` is **removed**;
>   the only entry point requires `receiverCiphertexts.length == 4·B + (authority envelope length)` — for
>   B=256 that is `1024 + 1030 = 2054` elements (matching §4's "2,054 Poseidons"). The chain checks **length
>   only** (gas ≈ free); content stays bound by `disclosureHash` (indexer-verified, §11-6). A length-padded
>   junk publish still tx-succeeds but yields a provable `mismatch` alarm + undecryptable receiver notes.
> - **`GET /notes?owner=<bjj-pubkey>` is authenticated by a bjj signature** (`sign(ownerPubKey ‖ timestamp)`;
>   the indexer verifies against the queried pubkey) so only the key owner reads their own notes — the
>   auditor-key indexer sees all users, so an unauthenticated `/notes` would expose everyone's payroll.
>   Auth is SPEC'd here; **implementation deferred** to a follow-up (v1 ships `/notes` without it, documented).
> - Because deposit/withdraw circuits change (envelopes) and every spending base gains the §5.2 zero-leaf
>   belt, **all four verifiers + the disburse-256 zkey are regenerated** and the pool is redeployed behind a
>   **UUPS (ERC-1967) proxy** (last forced redeploy; see `docs/zeto-derivation.md`).

---

## 7. Apps (2, admin is role-moded)

- **admin/ — employer-mode:** CSV upload → local prove → `deposit`+`disburse`; ledger view from **its own CSV
  + receipts** (it authored the batch — no arbiter key needed). Shows the ~0.5s proof + 1-tx 256-payout as
  the demo centerpiece. **Holds no arbiter key**, so it **cannot** decrypt employees' later p2p transfers.
- **admin/ — auditor-mode:** holds the arbiter key (separate browser profile / host in the demo, PoC key
  storage = encrypted file/env keyed per `rotateArbiter` epoch); decrypts the event stream into a ledger view
  and runs the disclosureHash alarm. This is the **independent** regulator seat — the beat that actually
  sells compliance.
- **public/ — self-custody wallet:** MetaMask login → derive bjj key (§6) → pull ciphertext feed + merkle
  paths from indexer → **trial-decrypt in the browser** → balance = sum(unspent notes); receive
  (auto-discovered), `transfer`, `withdraw`. Indexer never sees user keys or balances.
- Recipient gas: PoC uses faucet; GIWA's pre-installed ERC-4337 EntryPoint + paymaster → gasless spend is
  v1.1.

---

## 8. Repo layout

```
bongtu/                       # one monorepo, Apache-2.0
  circuits/                   # circom + vendored zeto lib/basetokens + our IMT bases
  contracts/                  # Foundry: BongtuPool, 4 verifiers, Poseidon, differential + gas tests
  sdk/  proving/              # TS SDK (Apache/MIT); snarkjs(GPL)+rabbitsnark isolated under proving/
  prover-cli/                 # employer self-host prover
  indexer/                    # event ingest, IMT mirror, path API, disclosureHash verify, arbiter ledger
  apps/ admin/  public/       # role-moded admin; MetaMask wallet
  deploy/                     # Foundry scripts → GIWA Sepolia (Blockscout verify)
  docs/                       # spec (this file), milestone records, toolchain
```

---

## 9. GIWA facts (verified 2026-07-23)

Chain 91342, RPC `sepolia-rpc.giwa.io`, Blockscout `sepolia-explorer.giwa.io`, faucet `faucet.giwa.io`.
Coinless (gas=ETH), L2 gas ≈0.001 gwei. BN254 precompiles present → Groth16 native. **Karst (Osaka) per-tx
gas cap = 16,777,216** — disburse256 (1.03M) fits with huge margin; naive 256-insert (263M) does not. Deploy
permissionless, `--verifier blockscout`. Mainnet **not launched** — all PoC data is testnet. Full facts:
knowledge `giwa-chain-facts-for-deployment`.

### Deployed to GIWA Sepolia (2026-07-24) — the full B=256 stack is LIVE

| contract | address |
|---|---|
| BongtuPool (B=256) | `0x22a2F38a24a2647E430dc28a5154D390F93Ccf7b` |
| Poseidon-v1 | `0xFa309Ff90ef2cd1781824Cf8a7Fdb1Bf0D237E9E` |
| DepositVerifier | `0x73AB0c199381B293CE73B85A0aC3CDfa0A06Bf72` |
| Disburse256Verifier | `0xD6CD19bc45adD901003390d9Ba314887B7bbFc8b` |
| TransferVerifier | `0x0DdC36CDCcA2b7408Cc86DEB55A43644A727CBcd` |
| WithdrawVerifier | `0x997339910c19d56FAD48484be30De859664c9d74` |
| mock kKRW | `0x278b3374995c8ec6aEaECBfDCa06f26CB167FC13` |

Owner/deployer `0xe92a97e645351268F3d60d5a27EB842A5b293058`; `B()==256`, `initialized==true` verified on-chain.
Explorer: `https://sepolia-explorer.giwa.io/address/0x22a2F38a24a2647E430dc28a5154D390F93Ccf7b`. A real
`deposit` tx succeeded against it (`0xc7053b4bf0d0f6fce67ed27279bb89ec6e54525646d0b824fa4d8a5a7951668c`,
nextLeafIndex 0→2). **Measured deposit cost = L2 2,518,396 gas × 0.001 gwei (~2.52e-6 ETH) + L1 data fee
24,017,990,112 wei (~2.4e-8 ETH) ≈ 0.0000025 ETH (~$0.008); the L1/DA fee is ~1% of total** (blob DA is
cheap → calldata cost is a non-issue, refuting the earlier §11-7 worry at these params). Full deploy + smoke
spent 0.000014 ETH of the 0.01 faucet grant. Blockscout source-verification (`--verify`) is an optional
follow-up. addresses in `deploy/addresses.91342.json`.

**A real 256-recipient private disburse ran live (2026-07-24, `deploy/giwa_disburse256.ts`):** an employer
deposited a note, then spent it to **256 recipients in one tx** with a rabbitsnark-GPU proof, publishing all
256 receiver ciphertexts on-chain. tx `0xc97836e05651756c333fc18bbb4698182f5d5690e41bd103e3e42eb178abc37e`
— nextLeafIndex 4→512, deposit-note nullifier marked, `disclosureHash` matched (on-chain ciphertext == the
circuit's), authority pubkey == pool's stored arbiter key. **L2 gas 3,026,697 (< Karst 16.7M; 11,823/recipient)**
— higher than the plain 1.03M because the 256×4=1024 ciphertext elements ride as calldata + event (the
"all ciphertext on-chain" choice, SPEC §4/Q4). **L1 data fee only 2,237,831,994,042 wei (~2.2e-6 ETH) even
for 32KB of ciphertext** — blob DA keeps it ~0.05% of cost, confirming §11-7's calldata worry is moot here.
(NB: ethers' auto gas-price overpaid ~1500× on the first run; the runner now pins gasPrice=0.005 gwei so the
true cost is L2 3.03M × ~0.001 gwei + L1 ~2.2e-6 ETH ≈ 0.000005 ETH ≈ $0.016 per 256-payout.)

---

## 10. Definition of Done (PoC)

1. `bongtu` monorepo; 4 circuits compile + single-party zkey; `Groth16Verifier` per circuit.
2. `BongtuPool`: single-frontier IMT (§5.1) + contract-derived enabled (§5.2) + any-historical-root map +
   arbiter epochs + ERC-20 custody; **Foundry differential test** (root == reference JS IMT) + accept /
   replay-revert / tamper-revert / enabled-forgery-revert / arbiter-rotation tests green.
3. Deployed to GIWA Sepolia + Blockscout-verified; **one real 65KB disburse sent, `l1Fee` read from the
   receipt and recorded in §9** (replaces the estimated budget).
4. Indexer running: event ingest, IMT mirror (root-match invariant), path API, disclosureHash-verify alarm,
   auditor-mode arbiter ledger.
5. Both apps working against Sepolia; **recovery test** (balance_after == balance_before across a spend).
6. **End-to-end demo:** employer deposits mock kKRW → disburses to 256 recipients (~0.5s proof, 1 tx) →
   recipient logs in with MetaMask, sees balance → recipient `transfer`/`withdraw` → **auditor-mode** admin
   shows the full decrypted ledger while **employer-mode** cannot read a p2p transfer.

**Gas budget (est., to be replaced by DoD-3 measurement):** disburse dominant term = EIP-7623 calldata floor
on ~65KB high-entropy ciphertext (~2.6M) + LOG (~0.5M) + Groth16 verify (~0.25M) + pad/attach hashes → ~4.2M,
under the 16.7M cap. deposit and disburse are **separate txs**, each independently under-cap. "Sub-cent"
prices L2 execution only; GIWA's L1 DA scalars are unpublished, hence DoD-3.

## 10b. Build order (fast-iteration ladder — apps never block circuits)

- **M0 (retires the two critical risks; seconds-per-iteration loop):** unified pool (§5.1) + contract-derived
  enabled (§5.2); a **small `disburse` variant (1-in/16-out)** — seconds-scale groth16 setup, CPU-provable,
  **no rabbitsnark / no 1.24GB zkey in the loop** — plus the new 36-public `transfer` (2×2×32) and rebased
  `withdraw` (2×1×32) and stock `deposit`. Scripted full cross-circuit cycle on **anvil**: `deposit →
  disburse(1×16) → recipient spends a batch-inserted note via transfer (incl. a padded single-input spend to
  exercise enabled=0) → withdraw`, asserting `contract.root == reference JS IMT root` after every insert and
  that every emitted ciphertext trial-decrypts to a spendable note.
- **M1:** swap 1×16 → 1×256 + rabbitsnark GPU; gas assertions; GIWA Sepolia deploy + Blockscout verify + real
  `l1Fee` (token decision = mock kKRW is the M1 entry gate).
- **M2:** indexer (event ingest, IMT mirror, path API, disclosureHash verify) + public app.
- **M3:** admin employer/auditor role-modes + demo script.

---

## 11. Known gaps / honest caveats

1. **deposit has no authority envelope (single-flavor hole):** stock `deposit` lets the depositor name
   arbitrary output owners → "deposit to a third party's pubkey" is an audit-free transfer (stock Zeto shares
   this). v1 documents it; **v1.1 adds authority encryption to `deposit`.** The headline `disburse` already
   has authority enc.
2. **Total-hidden strength = pool anonymity set; funding path barely hidden at launch.** `disburse` hides the
   total, but deposit is fully public (amount + depositor) and in a fresh institutional pool the employer is
   the only large-note source, so the disburse input note is de-facto linkable to a specific deposit
   (fact-of-funding + magnitude leak despite the hidden split). Input-note unlinkability is bounded by the
   number of independent depositors (~1 at launch). Mitigations: pre-fund well ahead, split deposits; grows
   with adoption. **Do not market "total hidden" as funding-path privacy in the GASOK narrative.**
3. **Recipient count leaks.** Zero-output trimming + the ciphertext blob covering only real outputs publishes
   the exact real recipient count per batch (headcount/hiring/layoff signal). v1 accepts the leak; the
   always-emit-full-256-padded option (hides count, fixed max calldata) is the v1.1 mitigation if buyers ask.
4. **Arbiter rotation invalidates in-flight proofs** (no epoch grace window in v1); rare-rotation assumption.
5. **Single-party trusted setup** (Q11): fine for testnet; phase-2 MPC is a mainnet prerequisite **after
   circuit freeze** (any circuit edit re-runs setup + redeploys the verifier).
6. **Non-repudiation is contract-detect-only for the authority envelope** — closed operationally by the
   **indexer disclosureHash alarm** (§6b), not by the chain. A malicious sender can only produce a mismatch
   that the auditor console flags immediately; `disburse` is also caller-gated to a known employer.
7. **Ciphertext availability is L1-backed but SDK-parsing is unbuilt.** OP Stack posts calldata to L1 and
   re-derives LOGs, so the ciphertext data *is* L1-available (it transits calldata), but the SDK reads it via
   `eth_getLogs`, which needs a live L2 archive node or our indexer. **Funds safety never depends on the
   indexer; discovery *liveness* does.** The full-chain-scan fallback (browser getLogs + client IMT rebuild)
   is currently one sentence — either test it once or declare the indexer a hard PoC dependency. (Redundancy:
   ciphertext is paid twice, calldata + LOG; dropping the event for SDK calldata-parsing would save ~0.5M gas
   — v1.1 option.)
8. **Two-time-pad on duplicate recipient pubkeys** (shared ephemeral key + nonce across outputs) — mitigated
   in v1 by the prover rejecting duplicate owner pubkeys (§4 invariant); structural per-output-nonce fix is
   v1.1. (Knowledge: `zeto-shared-ephemeral-nonce-two-time-pad-on-duplicate-pubkeys`.)
9. **No pausability / blacklist / fine-grained roles** in PoC (UUPS upgrade is the only emergency lever).
10. **Prover distribution undesigned for scale** — 1.24GB zkey + private rabbitsnark GPU; PoC = "we prove."

---

## 12. Open questions (post-spec)

- Multi-input `disburse` (nInputs>1) so a large employer sources a batch from several notes — currently 1-in;
  **note this is nPublic-changing = BREAKING per §5.3.**
- 10만-scale (391 batches) change-note chaining UX in the prover CLI (proof ~0.5s each).
- GASOK application (deadline 2026-07-31) — business decision, out of spec; the DoD is the MVP narrative.

## 13. Deferred prod-requirements register (explicitly out of PoC scope)

- Arbiter key in **HSM / threshold**, and **no persistent plaintext ledger DB** on an internet-facing box
  (the arbiter scalar + decrypted ledger is a total-retroactive-privacy honeypot — critical for prod, moot
  for fake-money testnet).
- Phase-2 MPC ceremony (post circuit-freeze) + verifier redeploy story.
- Fee-on-transfer/rebasing token hardening is **not** planned — such tokens are structurally unsupportable
  (§5.3); prod restricts the underlying set.
- ERC-4337 gasless spend; key rotation for leaked bjj keys; per-output nonce; deposit authority envelope;
  full-256 padded batches (count-hiding); role separation (mint/upgrade/arbiter) via AccessControl/timelock;
  mainnet DA-scalar cost model.
