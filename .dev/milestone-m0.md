# M0 — Goal & Done criteria

> **✅ M0 COMPLETE (2026-07-24).** All 4 units done + committed; the DoD gate
> `bash deploy/e2e_m0.sh` exits 0 — full cross-circuit spend cycle on live anvil with real Groth16 proofs,
> genuine trial-decrypt, contract.root == JS oracle at every step, value conserved (1960 == 40 + 1920).
> The two critical risks are retired: the mixed-mode tree lets a disburse-batch note be spent by transfer
> against one root, and the withdraw-from-nothing hole is closed by the circuit value-belt. Commits:
> c6059bf (U1) · fffb29a (U2) · 3ae314c + ab9d1ec (U3) · U4 next. **Next milestone: M1** (swap 1×16→1×256 +
> rabbitsnark GPU, gas assertions, GIWA Sepolia deploy).

**M0 retires the two critical risks from the SPEC adversarial review:** (a) a note minted via 256-style
subtree-attach on the unified mixed-mode tree is spendable by the *other* circuits against the same root, and
(b) the corrected `enabled` semantics (contract-derives `enabled[i]=(nullifier[i]!=0)`, never from calldata).
It does this at **seconds-per-iteration** — a **1-in/16-out** disburse variant, CPU-proved with snarkjs, **no
1.24GB zkey / no rabbitsnark GPU in the loop** (those are M1). Ref: [spec.md](../docs/spec.md) §4, §5, §10b.

## Done condition (tick at each unit boundary)

M0 is done when ALL hold, each judged by a named artifact:

1. **Reference JS IMT + Poseidon parity** — a single-frontier IMT library (one leaf counter, shared
   `zeros[0..32]`, incremental append, 256-aligned pad+attach per §5.1) with a self-consistency test suite
   green, AND `poseidon([1,2])` in JS == `7853200120…813530` (Poseidon-v1). Gate: `npm test` in `sdk/` green.
2. **4 small circuits prove+verify on CPU** — `transfer` (new 36-public 2×2 small base), `disburse` (1×16),
   `withdraw` (2×1 IMT-rebased, comparator `GreaterEqThan(101)`), `deposit` (0×2 stock), each: compile →
   groth16 setup (pot22) → witness from a valid fixture → `groth16 prove` → `groth16 verify` prints **OK**.
   Input generator **rejects duplicate output owner pubkeys** (§4 two-time-pad guard). Gate: a script
   `circuits/prove_all.sh` exits 0 with 4× "snarkJS: OK".
3. **BongtuPool + differential test** — `contracts/` Foundry: `BongtuPool` with §5.1 single-frontier IMT +
   §5.2 contract-derived `enabled` + any-historical-root `mapping(root=>bool)` + nullifier map + ERC-20
   custody + arbiter epochs; Poseidon-v1 deployed; 4 snarkjs-exported Groth16Verifiers wired. Gate:
   `forge test` green including (i) **differential test** `contract.root == reference JS IMT root` across an
   interleaved `deposit(2)→transfer(2)→disburse(pad+attach 16)→withdraw(1)` sequence, (ii) enabled-forgery
   reverts (a proof with `enabled=0` on a value-carrying fabricated input is rejected), (iii) replay reverts
   (nullifier reuse), (iv) 1-bit public-signal tamper reverts.
4. **Cross-circuit spend cycle e2e on anvil** — scripted end to end: `deposit → disburse(1×16) → a recipient
   trial-decrypts one batch-inserted note → spends it via transfer (including one padded single-input spend
   exercising enabled=0) → withdraw`. Asserts: `contract.root == reference JS root` after every insert; every
   emitted ciphertext trial-decrypts to a spendable note; value conserved end-to-end. Gate: `deploy/e2e_m0.sh`
   (anvil + forge script) exits 0 with all assertions passing. **This is the M0 DoD.**

## Units (ordered cheap-certain → risky-integration; one workflow each, commit between)

- [x] **U1 — scaffold + reference JS IMT + Poseidon parity** (gate = Done#1). No deps.
      Evidence: `sdk/` — `npm test` green 14/14 (poseidon parity 7853…530; frontier root == independent
      naive oracle for single appends / B=16 & B=256 attach / interleaved U3 sequence; merkle paths incl.
      padded dead slots; error-path atomicity). Verified by independent top-down oracle + negative controls.
      Review majors fixed (attachSubtree validates before mutating; isPowerOfTwo de-bitwised).
- [x] **U2 — 4 small circuits compile+prove+verify (CPU)** (gate = Done#2). Deps: U1 (shared repo + fixtures).
      Evidence: `circuits/prove_all.sh` EXIT 0, 4× snarkjs OK. Constraints/publics: deposit 1695/3,
      disburse(1×16) 206183/10, transfer(2×2 new 36-pub base) 61851/36, withdraw(2×1 IMT rebase,
      GreaterEqThan(101)) 41136/7 — all match SPEC §4. Witnesses use REAL ImtTree membership (disburse root
      == ImtTree.getRoot()). SDK npm test 21/21 (added babyjub + note/encrypt + dup-owner guard). Verifier
      .sol saved to circuits/verifiers/ for U3. Verify re-ran gate + tamper negative control.
      **CARRIES a designed dependency into U3 (see below).**

  > **⚠ U3 MUST implement (U2 review major, = SPEC §5.2):** the circuits' `enabled[i]` is a free prover-chosen
  > public that gates ONLY membership; CheckNullifiers/CheckSum/CheckPositive/GreaterEqThan run over ALL
  > inputs unconditionally. So `enabled[i]=0` on a fabricated value-carrying input = **mint-from-nothing**
  > (esp. withdraw `out=sumInputs-sumOutputs`). U3's BongtuPool MUST derive `enabled[i]=(nullifier[i]!=0)`
  > from its own view and inject it — never accept `enabled` from calldata — and the **enabled-forgery-revert
  > test is mandatory** in Done#3. (Circuit belt `enabled*(enabled-1)==0`+`IsZero(nullifier)==1-enabled` was
  > deferred to keep U2's zkeys; contract-derive is the M0 fix.)
  > **U4/SDK note:** U2 fixtures reuse one ephemeral ECDH key + one nonce across circuits (fine for test data,
  > but a two-time pad across txs) — the real spend cycle in U4 must use a FRESH ephemeral keypair + nonce per
  > transaction.
- [x] **U3 — BongtuPool contract + 4 verifiers + differential/soundness Foundry tests** (gate = Done#3).
      Deps: U1 (reference IMT oracle), U2 (verifier .sol + real proofs as fixtures).
      Evidence: `forge test` 19/19 green — differential root==JS oracle at every step of
      deposit(2)→transfer(2)→disburse(attach16)→withdraw(1) (finalNextLeafIndex 33); real-proof accept ×4;
      replay/tamper/UnknownRoot/NotInitialized reverts; disburse allowlist (pos+neg); arbiter epochs;
      Poseidon-v1 parity. contract-derives enabled=(nullifier!=0), injects (never calldata).
      **CRITICAL blocker found by 3-lens review + FIXED:** withdraw/transfer-from-nothing (input {nf=0,
      commitment=0, value=X, enabled=0} passed all constraints + CheckSum → out=X; contract-derive agreed with
      it). Fix = circuit value-belt `(1-enabled[i])*inputValue[i]===0` in transfer+withdraw bases (disburse
      safe, untouched). The mint witness now FAILS witness-gen at the belt line; verifiers regenerated + wired.
      SPEC §5.2 corrected (belt is REQUIRED, not optional). Knowledge note updated.
- [x] **U4 — cross-circuit spend cycle e2e on anvil** (gate = Done#4, the DoD). Deps: U3.
      Evidence: `bash deploy/e2e_m0.sh` exits 0 on live anvil (ethers + snarkjs CPU). Cycle:
      deposit(0×2, V=1960) → disburse(1×16) → recipient #0 trial-decrypts note from the on-chain event
      ciphertext (NOT memory) → transfer spends that batch leaf (index 16) + a padded enabled=0 input →
      withdraw(2×1) unshields the change. contract.root == ImtTree oracle at every insert (verify
      independently recomputed post-disburse + final roots from a naive tree); value conserved
      1960 == withdrawn 40 + shielded 1920; replay reverts; anvil trap-killed (no leak). Added a §5.3-faithful
      `disburseWithCiphertexts` + `DisburseCiphertexts` event to publish receiver ciphertext on-chain (original
      `disburse` untouched → U3 tests stay 19/19). Toolchain paths made PATH-overridable for CI reproducibility.

Status legend: [ ] pending · [~] in-progress · [x] done (with gate evidence) · [!] blocked.
Toolchain + exact commands: [toolchain.md](../docs/toolchain.md). Product decisions: [spec.md](../docs/spec.md). Not git-tracked: zkey/wtns/r1cs.
