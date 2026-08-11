# U-P0 — Post-quantum hardening of the authority envelope (hybrid ECDH || ML-KEM-768)

Decision record, 2026-07-27. Locked by grill: threat = HNDL (harvest-now-decrypt-later);
phase 1 (hybrid authority-envelope key) ADOPTED with ML-KEM-768; phase 2 (per-recipient
KEM) DEFERRED; ML-DSA = phase 3, out of scope. This doc finalizes the mechanism. It does
not re-litigate those choices.

## 1. Threat model — the HNDL surface

Everything bongtu encrypts is emitted on-chain forever (locked spec: full publication;
`disclosureHash` is an integrity binding, not a substitute for publication). Inventory of
ciphertext artifacts and their key agreements, from the actual emit sites in
`contracts/src/BongtuPool.sol`:

| artifact | event / calldata | key agreement | plaintext |
|---|---|---|---|
| deposit authority envelope, ct[10] | `Deposited.encryptedValuesForAuthority` | ECDH(ephemeral, arbiter bjj pk) | both output notes: owner pk, value, salt |
| withdraw authority envelope, ct[13] | `Withdrawn.encryptedValuesForAuthority` | same | input owner, input (value,salt)x2, change note |
| transfer authority envelope, ct[16] | `Transferred.encryptedValuesForAuthority` | same | sender + both inputs + both output notes |
| transfer receiver cts, 2x4 | `Transferred.encryptedValuesForReceiver0/1` | ECDH(ephemeral, recipient bjj pk) | (value, salt) per output |
| disburse receiver cts, 4*B + authority tail 1030 | `disburseWithCiphertexts` calldata + `DisburseCiphertexts` event | both of the above | tail: employer input + all 256 recipient notes |

Both ECDH halves ride on BabyJubJub. The ephemeral pk (`ecdhPublicKey`) is a public
signal copied into every op event; the arbiter pk is on-chain via `ArbiterRotated` and
`arbiterEpochs`. So a future ECDLP break retro-decrypts every AUTHORITY envelope from
on-chain data ALONE (ephemeral pk x arbiter pk are both public). The authority envelope
is the worst harvest target: it carries the op-wide full plaintext, including every
recipient pubkey — which then also unlocks the receiver cts (ECDLP gives
`ecdhPrivateKey` from the on-chain ephemeral pk; the recipient pks needed to finish that
attack are today harvestable from the authority envelope itself).

Hence envelope-first:

- **Phase 1 (this work):** authority-envelope key becomes hybrid
  ECDH(BabyJubJub) || ML-KEM-768. One encapsulation per op (ct 1088 B). After phase 1 an
  on-chain-only quantum adversary gets nothing: the authority envelope needs the KEM
  shared secret, and the receiver cts need recipient pks that no longer appear anywhere
  on-chain in the clear.
- **Phase 2 (DEFERRED):** per-recipient KEM on the receiver cts (`EncryptOutputs`
  surgery). ~38k gas/recipient, ~1.2 KB user addresses, and it only defends against an
  adversary who ALSO holds candidate recipient pubkeys — which are never on-chain.
  Revival criteria: nation-state threat model, a unified-address-style standard carrying
  KEM pks, or DA cost collapse. Interim mitigation (document + operational): bongtu
  addresses are shared off-channel/QR, never published.
- **Phase 3 (out of scope):** ML-DSA/Dilithium authentication. Forgery is a
  forge-LATER problem, migratable pre-Q-day; nothing here blocks it.

## 2. Hybrid KDF — exact spec

ML-KEM-768 encapsulation yields a 32-byte shared secret `ss`. Mapping to BN254 field
elements, bias-free:

```
kemSs[0] = LE-uint128(ss[0..16])     // < 2^128 < r, uniform
kemSs[1] = LE-uint128(ss[16..32])
```

Two 128-bit limbs; no modular reduction ever occurs, so no bias. Byte order is
little-endian (pinned; both circuit-witness builder and arbiter decapsulator use it).

Domain-separation tags (sha256(ASCII) mod r, r = the BN254 scalar field; computed
2026-07-27, frozen as literals in circuits + `@bongtu/core`):

```
TAG_K0   = sha256("bongtu/pq-envelope/v1/key0")    mod r
         = 10398998902367040515226727887904115149378422647845688990538198988921570667720
TAG_K1   = sha256("bongtu/pq-envelope/v1/key1")    mod r
         = 7025394518961265764175593663800963341053996587382265036146196548941915994055
TAG_BIND = sha256("bongtu/pq-envelope/v1/binding") mod r
         = 5518019128667894418081277213291049553290157756968653594844689494754896839788
```

Derivation (in-circuit and in `@bongtu/core`; `poseidonN` in
`packages/core/src/poseidon.ts` already supports arbitrary arity):

```
ecdh[2]     = Ecdh(ecdhPrivateKey, authorityPublicKey)        // unchanged
hybridKey[0] = Poseidon(5)([TAG_K0,   ecdh[0], ecdh[1], kemSs[0], kemSs[1]])
hybridKey[1] = Poseidon(5)([TAG_K1,   ecdh[0], ecdh[1], kemSs[0], kemSs[1]])
kemBinding   = Poseidon(3)([TAG_BIND, kemSs[0], kemSs[1]])    // NEW public signal
```

Key derivation and binding are separated by both tag and arity. `kemSs[2]` is a new
PRIVATE witness input in all four circuits; `kemBinding` a new circuit OUTPUT. Optionally
`Num2Bits(128)` on each limb (~256 constraints) pins canonical encoding in-circuit; not
security-required (a non-canonical limb just self-sabotages into the alarm path below)
but cheap hygiene — adopt it.

Drop-in points — the four `SymmetricEncrypt(... key <== sharedSecretAuthority ...)`
call sites change to `key <== hybridKey`:

- `circuits/lib/deposit_authority_imt_base.circom:104` (deposit base)
- `circuits/lib/check-nullifiers-value-imt-base.circom:177` (withdraw base)
- `circuits/lib/anon_enc_nullifier_non_repudiation_imt_small_base.circom:150` (transfer base)
- `circuits/lib/anon_enc_nullifier_non_repudiation_imt_base.circom:163` (disburse/disburse256 base)

`SymmetricEncrypt`'s `key[2]` interface is unchanged (it never required a curve point —
`packages/core/src/note.ts` `poseidonEncrypt/poseidonDecrypt` take a 2-element key).
Receiver-side `EncryptOutputs` is untouched (phase 2).

The trade-off, head-on: today a wrong-key authority envelope FAILS THE PROOF (the
contract injects the stored arbiter bjj key into `authorityPublicKey` before verify).
The KEM half cannot get that guarantee without in-circuit encapsulation (see §9), so it
downgrades to alarm-enforcement: a junk-wrapped KEM ct produces a `kemBinding` mismatch
at the arbiter = first-class ALARM + envelope withheld — the same outcome class as
today's authority-tampered disburse publish (`disclosureHash` posture). The ECDH half
keeps proof-fails-on-wrong-key, so classical enforcement is not weakened.

## 3. Public-surface change per circuit

`kemBinding` is declared as the LAST circuit output, so all existing output indices are
unchanged and every public-INPUT index shifts by exactly +1. Current layouts verified
against the circuit headers and the index comment block in `BongtuPool.sol` (lines
81–91). New layouts:

- **deposit 18 -> 19**: `[0]=out [1..2]=ecdhPub [3..12]=cta[10] [13]=kemBinding
  [14..15]=oc [16]=nonce [17..18]=authorityPubKey`
- **withdraw 25 -> 26**: `[0]=out [1..2]=ecdhPub [3..15]=cta[13] [16]=kemBinding
  [17..18]=nf [19]=root [20..21]=enabled [22]=oc0 [23]=nonce [24..25]=authorityPubKey`
- **transfer 36 -> 37**: `[0..1]=ecdhPub [2..9]=cipherTexts[2][4] [10..25]=cta[16]
  [26]=kemBinding [27..28]=nf [29]=root [30..31]=enabled [32..33]=oc [34]=nonce
  [35..36]=authorityPubKey`
- **disburse256 10 -> 11**: `[0..1]=ecdhPub [2]=disclosureHash [3]=subtreeRoot
  [4]=kemBinding [5]=nf [6]=root [7]=enabled [8]=nonce [9..10]=authorityPubKey`

Consequences: FIVE verifier/zkey pairs regenerate, not four — the shared disburse base
is instantiated by both `circuits/disburse256.circom` (on-chain, B=256) AND the 1x16
dev-loop `circuits/disburse.circom`, whose chain is load-bearing (`prove_all.sh` proves
it; `contracts/src/verifiers/DisburseVerifier.sol` is consumed by `Base.sol`,
`RealProof.t.sol`, `GasReport.t.sol`, `Enforcement.t.sol`, `Arbiter.t.sol`). Its public
count shifts 10 -> 11 identically. disburse256 = the 1.3 GB GPU recipe (CLAUDE.md);
`CIRCUITS_VERSION` in `apps/wallet-web/src/config.ts` (currently `"d1712abf"`) bumps —
it is sha256 over the zkeys, so the wallet cache bucket rolls automatically once
recomputed; `contracts/test/fixtures/realproofs.json` re-proves entirely. The
CLAUDE.md fixture coupling rule extends: fixtures are now bound to (arbiter bjj key,
arbiter KEM pk) — the fixture KEM keypair joins `realproofs.json` metadata the same way
`arbiterKeyX/Y` does today, and `Deploy.s.sol`/`Smoke.s.sol` gain the matching default.

## 4. On-chain shape

Current signatures (BongtuPool.sol): `deposit(a,b,c,uint[18] pub)`,
`transfer(a,b,c,uint[36] pub)`, `withdraw(a,b,c,uint[25] pub)`,
`disburseWithCiphertexts(a,b,c,uint[10] pub, uint256[] receiverCiphertexts)`. Deltas:

```
deposit (a,b,c, uint[19] pub, bytes calldata kemCiphertext)
transfer(a,b,c, uint[37] pub, bytes calldata kemCiphertext)
withdraw(a,b,c, uint[26] pub, bytes calldata kemCiphertext)
disburseWithCiphertexts(a,b,c, uint[11] pub, uint256[] receiverCiphertexts,
                        bytes calldata kemCiphertext)
```

- Length check per op: `if (kemCiphertext.length != 1088) revert
  WrongKemCiphertextLength(...)` (mirrors `WrongCiphertextLength`). Content is NOT
  verifiable on-chain (that is the §2 trade-off); length + emission is.
- Arbiter-key injection indices shift with §3: deposit `injected[17],[18]`; withdraw
  enabled at `[20],[21]`, key at `[24],[25]`; transfer enabled `[30],[31]`, key
  `[35],[36]`; disburse enabled `injected[7]`, key `[9],[10]`. `kemBinding` is read
  from the proof's own public signals, never injected — the contract has nothing to
  check it against.
- Events: append `uint256 kemBinding, bytes kemCiphertext` to each of `Deposited`,
  `Transferred`, `Withdrawn`, `Disbursed` (the arbiter must reach both without reading
  tx calldata).
- **Storage — struct is frozen**: arbiter epochs live in `ArbiterEpoch[] public
  arbiterEpochs` with 3-word elements `{keyX, keyY, activatedBlock}`. Appending a field
  would re-stride the dynamic array and corrupt existing epochs on upgrade. Instead V2
  appends `mapping(uint256 => bytes32) public arbiterKemPkHash` (epoch -> keccak256 of
  the 1184-byte ML-KEM-768 encapsulation key), consuming one slot of the `uint256[50]
  __gap`. Rotation: `rotateArbiter(uint256[2] newKey, bytes32 newKemPkHash)` writes
  both; the full KEM pk is distributed off-chain (indexer `/head`, deploy artifacts)
  and clients verify it against the on-chain hash before encapsulating. Epochs 0..k
  minted pre-upgrade have `arbiterKemPkHash == 0` — the pre-KEM marker (§5).
- UUPS: one `upgradeToAndCall` swaps the impl AND the four ON-CHAIN verifier addresses
  (the fifth, 1x16 DisburseVerifier, is a test-only artifact regenerated alongside) (new
  vkeys), and the call payload seeds `arbiterKemPkHash[currentEpoch()]` (or rotates to
  a fresh epoch carrying both keys — preferred, see §7). The pool proxy address is
  preserved across the swap; whichever deployment is current, that address is the
  `pool` field of the committed `deploy/addresses.<chainid>.json`.

Gas estimate per op (measured 2026-07-26 baselines from `docs/performance.md`):

| component | gas |
|---|---|
| kemCiphertext calldata, 1088 B (~all nonzero, 16/B) | ~17,400 |
| event data 1088 B (8/B) + kemBinding word + abi | ~9,100 |
| +1 public input in Groth16 verifier (1 mul + add) | ~6,100 |
| `arbiterKemPkHash` cold sload (only if read in-op; optional) | ~2,100 |
| **total per op** | **~33k** |

Against baselines: deposit 2,353,950 -> ~+1.4%; transfer 2,483,773 -> ~+1.3%; withdraw
1,411,960 -> ~+2.3%; disburse256 2,789,946 harness / 3,872,403 live -> ~+1.2% / +0.9%
(~+130 gas per recipient on 15,126). Matches the locked "~+27k, ~+1%" order.

## 5. Client and arbiter flows

**Wallet (browser prover).** `freshDepositCrypto`
(`apps/wallet-web/src/lib/deposit.ts:68`) and `freshSpendCrypto`
(`apps/wallet-web/src/lib/spend.ts:174`) grow a KEM draw: encapsulate against the
arbiter KEM pk (config `DEFAULTS`, verified against `arbiterKemPkHash` on-chain) using
`ml_kem768` from `@noble/post-quantum/ml-kem` (NEW dependency — nothing in the tree imports it
today; encapsulation is sub-millisecond, noise vs the 3.5–5.4 s browser transfer
proof). Yields `{kemSs: [limb0, limb1], kemCiphertext: 0x...1088B}`; limbs join the
witness input, the ct joins the tx calldata in the flows (`depositFlow.ts` /
`spendFlow.ts` -> chain call).

**Admin/disburse (GPU prover).** `apps/admin-web/src/lib/disburse.ts` assembles the
ProvingRequest (it already carries `ecdhPrivateKey`/`encryptionNonce`/
`authorityPublicKey`, lines ~197–215); it adds `kemSs` the same way. The prover service
schema (`prover/prover_service/schema.py`) passes the two limbs through as witness
fields; the KEM ct never touches the prover — admin-web keeps it for tx assembly
(`chain.ts`). rabbitsnark path unchanged apart from the regenerated zkey.

**Arbiter (indexer).** New env `AUTHORITY_KEM_KEY` (the ML-KEM-768 decapsulation key)
alongside `AUTHORITY_KEY`; same handling rule: never logged, never serialized. Ingest
(`apps/indexer/src/ingest.ts`) reads `kemBinding` + `kemCiphertext` off each op event
into `OpEnvelope` (`apps/indexer/src/ledger.ts:101`) as a nullable
`kem: {binding, ciphertext} | null`. `deriveOp` (ledger.ts:152), per op with `kem`:

1. `ss' = ML-KEM.Decaps(AUTHORITY_KEM_KEY, ciphertext)`; limbs per §2.
2. If `Poseidon(3)([TAG_BIND, ss'0, ss'1]) != kemBinding`: push an `EnvelopeAlarm`
   (`detail: "kem binding mismatch — envelope withheld"`) and STOP for this op — no
   notes recorded, no batch fill, no history; surfaces on `GET /alarms` via the
   existing `"envelope"` alarm branch (`apps/indexer/src/api/routes/alarms.ts`).
3. Else derive `hybridKey` per §2 and decrypt (`parseEnvelope` in
   `packages/core/src/envelope.ts` grows a key parameter; the ECDH-only derivation
   stays for legacy ops).

**Pre-KEM history must not false-alarm.** The ledger has NO epoch plumbing today
(`OpEnvelope` carries none; ingest even stores `epoch: null` for deposit/withdraw in
the public feed), so the gate is structural, not epoch-arithmetic: historical logs
decode only under the V1 event ABI (no kem fields) -> `kem: null` -> legacy ECDH-only
decrypt, KEM checks skipped. Ingest carries both ABI fragment sets across the upgrade
block. The contract-side `arbiterKemPkHash[epoch] == 0` marker is the audit-facing
statement of the same boundary.

## 6. Security analysis

- **Junk `kemSs` vs binding**: `kemBinding` is a circuit output computed from the
  witness `kemSs` — a prover cannot claim a binding that mismatches its own witness.
  (Proof simply cannot exist with an inconsistent pair.)
- **Consistent-but-junk ct** (encapsulate to self / random 1088 B, prove with the
  matching-or-arbitrary `kemSs`): tx succeeds; arbiter decapsulation (implicit
  rejection makes `ss'` pseudorandom for malformed cts) mismatches `kemBinding` ->
  ALARM + envelope withheld + no notes recorded. Same outcome class as today's
  length-padded junk disburse publish (alarm + undecryptable). Note the envelope is
  then unopenable by ANYONE including the arbiter — the attacker buys an immediate,
  attributable alarm and nothing else.
- **KEM ct replay across ops**: a third party replaying someone else's ct does not
  know its `ss`, so cannot produce a consistent binding + decryptable envelope ->
  alarm. A prover reusing its OWN ct across ops stays decryptable and alarm-free —
  keys remain unique per op because the ECDH half and nonce are drawn fresh (the
  clients draw fresh material per tx, spend.ts/deposit.ts two-time-pad comments).
  Caveat: reuse collapses the PQ compartment (one future `ss` recovery opens several
  ops); clients always encapsulate fresh, and the arbiter MAY warn on duplicate cts.
- **ss-encoding bias**: none — two exact 128-bit limbs, no reduction (§2).
- **Domain-separation collisions**: key-derivation (arity 5) vs binding (arity 3)
  differ in both arity and tag; tags are sha256-derived, not small integers; the
  legacy key (raw ECDH point) is not Poseidon-derived at all, so no cross-protocol
  confusion with pre-upgrade envelopes.
- **Downgrade**: structurally impossible. The circuit ALWAYS folds `kemSs` into
  `hybridKey`; there is no ECDH-only encryption path in the upgraded circuits, and the
  contract rejects `kemCiphertext.length != 1088`. "Opting out" degenerates to the
  consistent-but-junk case above, i.e. an alarm.
- **Quantum-adversary view**: breaking ECDLP alone yields the ECDH point — one of
  four Poseidon preimage components. Without `kemSs` (Module-LWE, ML-KEM-768 ~
  Category 3) the hybrid key is unrecoverable and post-upgrade envelopes stay sealed.
  Breaking ML-KEM alone symmetrically leaves the ECDH half intact.
- **Honest scope of the stranding claim**: envelopes minted BEFORE the upgrade are
  ECDH-only forever and are already harvested — at Q-day they open, and every
  recipient bjj pk they contain is burned. For those identities the receiver-ct
  attack is NOT stranded (past or future slices decrypt once the pk is known); the
  full stranding applies only to identities never present in a pre-upgrade envelope.
  Mitigation lever (optional migration step, §7): bump the KDF `keyVersion` at
  cutover — every user deterministically derives a FRESH bjj identity that no
  pre-upgrade envelope ever saw, and moves funds by spending old notes to the new
  key. Cost: all users re-onboard once and old balances must be migrated; on testnet
  this is cheap, in production it is a coordinated event.
- **Alarm evidentiary asymmetry (honest note)**: the disclosure alarm is recomputable
  by ANYONE from public data; the KEM-binding alarm is arbiter-attested — verifying
  it requires `Decaps` under the arbiter's secret key, so third parties cannot
  independently confirm a raised (or suppressed) alarm. Publishing the mismatching
  `kemSs` would break security; a ZK proof of failed decapsulation is possible in
  principle but out of scope. Accepted as-is: the alarm's consumer is the same
  institution that operates the arbiter.

## 7. Migration

Order: (1) circuits (§2/§3 edits, all four bases) -> (2) zkeys + verifiers + vkeys
(CPU for deposit/withdraw/transfer, GPU recipe for disburse256) -> (3) re-prove
`realproofs.json` fixtures against the fixture arbiter bjj key AND a committed fixture
KEM pk; contract tests (`RealProof.t.sol`, `Disburse256.t.sol`, `GasReport.t.sol`,
`Enforcement.t.sol`, `Upgrade.t.sol`) go green locally -> (4) UUPS `upgradeToAndCall`:
new impl + new verifier addresses + `rotateArbiter(sameBjjKey, kemPkHash)` minting a
fresh epoch that carries both keys (clean epoch boundary == KEM boundary) -> (5)
clients (wallet `CIRCUITS_VERSION` bump + new circuit assets, admin, prover service)
-> (6) indexer (dual-ABI ingest + `AUTHORITY_KEM_KEY`).

Partial-deploy behavior: old proofs vs new verifiers (and vice versa) FAIL on public
count — there is no window where a non-hybrid proof passes the upgraded pool, so steps
(4) and (5) must land together operationally; a lagging wallet gets `InvalidProof`,
never a silent non-PQ op. A lagging indexer, however, fails SILENTLY, not loudly:
`getLogsChunked` wraps `interface.parseLog` in try/catch-continue, so the new-topic0
envelope events are skipped while the unchanged `Appended`/`SubtreeAppended` keep the
tree mirror advancing — `/health` stays green while the feed and note ledger
under-record. U-P3 therefore MUST add a boot guard: read
`arbiterKemPkHash(currentEpoch())`; nonzero + V1 ABI build -> refuse to serve (the
same fail-fast posture as the Postgres-only boot). Rollback: UUPS
downgrade to the V1 impl + old verifier addresses restores the pre-KEM system intact
(tree/nullifier/epoch state untouched; `arbiterKemPkHash` entries become inert; ledger
rows already derived remain valid).

## 8. Costs

- Gas: §4 table — ~+33k/op, +0.9%..+2.3% against the 2026-07-26 measured baselines.
  ~26.5k of that is the kemCiphertext carried in BOTH calldata and the event — the
  same double-pay lever performance.md already flags for DisburseCiphertexts;
  dropping the event copy for SDK calldata-parsing would cut it to ~17.4k.
- Constraints/proving: +2x Poseidon(5) + 1x Poseidon(3) + optional 2x Num2Bits(128)
  ≈ +1k constraints per circuit — deposit 11,594 -> ~12.6k (proving delta well under
  100 ms in-browser), disburse256 2,794,186 -> +0.04% (GPU warm 0.47 s unchanged at
  measurement precision). Client-side encapsulation ~sub-ms (noble).
- zkey regen: five setups (deposit/transfer/withdraw/disburse-1x16 are seconds-cheap
  CPU); disburse256 is the multi-minute CPU `groth16 setup` to a
  ~1.3 GB zkey + rabbitsnark cold compile ~120 s — the CLAUDE.md GPU regen recipe,
  with `timeout >= 300000` on the Bash calls.
- New dependency: `@noble/post-quantum` (import subpath `/ml-kem`; wallet-web,
  admin-web, indexer; or once in
  `@bongtu/core` and re-exported — preferred, keeps the codec-owns-both-directions
  rule of `envelope.ts`).

## 9. Deferred / rejected

- **Phase 2 — per-recipient receiver-ct KEM**: ~38k gas x 256 recipients ≈ +9.7M
  gas/disburse (vs 3.87M total today), ~1.2 KB KEM pk per user address, and
  `EncryptOutputs` surgery across transfer + both disburse arities — against an
  adversary who must ALREADY hold candidate recipient pks (never on-chain; post-phase-1
  not even inside a breakable envelope). Revival: nation-state threat model, a
  unified-address standard for KEM pks, or DA cost collapse.
- **Classic McEliece card** (revive if per-op gas ever matters): ct 96–128 B (vs
  1088 B) cuts the ~26.5k ct-carry cost to ~3k; pk ~261 KB is a non-issue because the
  arbiter is a single institutional recipient distributing off-chain. Rejected now for
  tooling maturity only.
- **In-circuit ML-KEM encapsulation** (would restore proof-fails instead of
  alarm-enforcement): K-PKE encryption needs the matrix-A SHAKE-128 expansion plus
  G/H/PRF — order 40–50 Keccak-f[1600] permutations at ~90–150k R1CS constraints each
  ≈ 4–7M constraints of hashing, plus NTT/CBD/compression arithmetic ≈ 5–10M
  constraints PER OP: ~2–4x disburse256 in every circuit, ~100x the browser transfer.
  Infeasible in Groth16/circom today; revisit under lookup/folding-native systems.
- **ML-DSA / Dilithium**: authentication, forge-LATER; migratable pre-Q-day; phase 3,
  explicitly not part of this work.
