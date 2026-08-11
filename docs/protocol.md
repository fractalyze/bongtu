# Protocol

Note algebra, the append-only tree every note lives in, and the authority-envelope layouts
that make every note creation and destruction auditor-openable. Source of truth:
`packages/core/src/{note,imt,envelope}.ts` (the off-chain oracle) and
`contracts/src/BongtuPool.sol` (the on-chain twin). The two are pinned equal by
`contracts/test/Differential.t.sol`.

## Notes, commitments, nullifiers

A note is `(value, salt, ownerPublicKey)` where the owner key is a BabyJubJub point.
`value` lives in `[0, 2^100)`: every base runs upstream `CheckPositive` (`GreaterEqThan(100)`)
over its outputs, so a witness with a value at or above `2^100` does not exist — a hard
constraint on anyone assembling inputs, not a convention.

| object | definition | hash |
|---|---|---|
| commitment | `Poseidon([value, salt, ownerPub.x, ownerPub.y])` | Poseidon-v1, arity 4 |
| nullifier | `Poseidon([value, salt, ownerFormattedPrivateKey])` | Poseidon-v1, arity 3 |
| tree node | `Poseidon([left, right])` | Poseidon-v1, arity 2 |

"Poseidon-v1" means the circomlib constants — one hash function across circuits, contract and
TypeScript. The parity constant every layer is pinned against:

```
Poseidon([1,2]) == 7853200120776062878684798364095072458815029376092732009249414926327459813530
```

(`contracts/test/Poseidon.t.sol`; the on-chain hasher is the circomlibjs creation bytecode in
`contracts/test/fixtures/poseidon2.hex`.)

The commitment goes in the tree; the nullifier goes in a spent-set map. Because the nullifier is
derived from the owner's *private* scalar over the same `(value, salt)`, a spend proves ownership
without revealing which leaf it consumed.

```
  deposit / disburse / transfer / withdraw output
        |
        v
   commitment  --append-->  IMT leaf @ nextLeafIndex   (public, on-chain)
        |
        |  owner trial-decrypts ciphertext, rebuilds commitment, matches the leaf
        v
     spendable note
        |
        |  spend: prove membership of the commitment + reveal nullifier
        v
   nullifier --> nullifierUsed[nf] = true      (note destroyed, leaf stays)
```

Leaves are never removed. Absence and double-spend are enforced by the nullifier set, not by tree
non-membership — that is what allows an index-keyed tree instead of a value-keyed one.

## The single-frontier IMT

One height-32 append-only Incremental Merkle Tree holds **both** single-leaf appends
(deposit / transfer / withdraw outputs) and B-leaf batch subtrees (disburse), sharing one
`nextLeafIndex` and one `filledSubtrees` frontier. A batch-inserted note is therefore spendable by
`transfer`/`withdraw` against the same root as a singly-inserted one.

| parameter | value | where |
|---|---|---|
| height `H` | 32 (2^32 leaf capacity) | `BongtuPool.H`, `ImtTree` default |
| batch size `B` | 256 on the live pool | `BongtuPool.B`, `deploy/addresses.84532.json` |
| `LOG_B` | 8 — the level a batch subtree attaches at | derived in `initialize` |
| empty subtree | `zeros[0] = 0`, `zeros[k] = Poseidon(zeros[k-1], zeros[k-1])` | both implementations |
| frontier | `filledSubtrees[i]` = the left sibling waiting at level `i` | Tornado lineage |
| root history | `mapping(uint256 root => bool)` — **every** historical root stays valid | no ring buffer |

Any past root is accepted forever. A proof built against a stale root cannot be replayed into a
double-spend, because the nullifier set is the double-spend defence; dropping the window removes a
proof-staleness race on a fast-block L2 where both transfers and batches move the root.

### The fold bit-order hazard

Membership is checked by folding the leaf up the tree, taking left/right order at level `j` from
**bit `j` of the leaf index**:

```
bit j == 0  ->  node is the LEFT child :  Poseidon(cur, sibling[j])
bit j == 1  ->  node is the RIGHT child:  Poseidon(sibling[j], cur)
```

`CheckIMTProof` (`circuits/lib/check-imt-proof.circom`) implements this with `Num2Bits` +
`Switcher`; `foldToRoot` and `ImtTree.merklePath` (`packages/core/src/imt.ts`) implement the same
convention, and `merklePath`'s `pathIndices[j]` *is* bit `j` of the requested leaf index — there is
exactly one convention and no second `pathIndices` flavour to flip.

Invert it and nothing complains locally: the path folds to some other root, `ForceEqualIfEnabled`
fails inside the circuit, and the only symptom is an unsatisfiable witness or a rejected proof.
Any new path producer must be closed against `foldToRoot(leaf, siblings, leafIndex) == getRoot()`.

### Batch attach is O(log B), not O(B)

Attaching a disburse batch first closes the pending partial block up to a `B` boundary, then places
the in-circuit `subtreeRoot` at level `LOG_B`:

```
 nextLeafIndex = 4, B = 256      close partial block      attach subtree
 ┌───┬───┬───┬───┬─ ─ ─ ─ ─┐     ┌──────────────┐        ┌──────────────┬──────────────┐
 │ 0 │ 1 │ 2 │ 3 │  empty  │ ==> │ block 0 node │  ==>   │ block 0 node │ subtreeRoot  │
 └───┴───┴───┴───┴─ ─ ─ ─ ─┘     └──────────────┘        └──────────────┴──────────────┘
   4 real leaves, 252 dead        LOG_B = 8 folds         one O(H-LOG_B) insert
```

The close walks `LOG_B` levels, using bit `i` of `nextLeafIndex % B` to pick the real left sibling
`filledSubtrees[i]` or an empty right sibling `zeros[i]` — root-identical to padding one zero leaf
at a time, which at `B = 256` would be up to 255 leaves × 32 hashes and put the transaction out of
reach of any block limit. The sub-`LOG_B` frontier is left stale on purpose: `nextLeafIndex` is now
`B`-aligned, so a fresh block overwrites those levels as a left child before any read.
`_attachSubtree` in `contracts/src/BongtuPool.sol` and `ImtTree.attachSubtree` are the two sides.

## Authority envelopes

Every operation encrypts one envelope to the pool's stored arbiter public key **inside the proof**.
Encryption is a Poseidon sponge (`SymmetricEncrypt` in-circuit, `poseidonEncrypt` in
`packages/core/src/note.ts`) under a two-element key. Given the arbiter's key material plus the
on-chain `(ecdhPublicKey, encryptionNonce, ciphertext, kemCiphertext)`, the auditor recovers the
plaintext with no user key and no nullifier linkage.

`encryptionNonce` MUST be < 2^128: the circuit packs it with `messageLength` into one Poseidon
state slot, so a full-width field draw fails witness generation (probability ~1−2^-120). Every
client draws through the 128-bit clamp (`toEncryptionNonce` in `@bongtu/client/spend`) — an
unclamped draw shipped once and made console pay runs unprovable until `45601e9`.

Plaintext field order is a consensus artifact — reordering passes a TypeScript round-trip and
breaks decryption of live-chain envelopes. `packages/core/src/envelope.ts` owns both directions.

### The hybrid envelope key

The sponge key is a hybrid of a classical ECDH secret and an ML-KEM-768 shared secret, so opening an
envelope requires breaking both. `packages/core/src/kem.ts` owns the tags and the fold; the circuits
carry the same literals.

```
ecdh[2]      = Ecdh(ephemeralPrivateKey, arbiterPublicKey)          // BabyJubJub, as before
kemSs[0]     = LE-uint128(ss[0..16])                                // ML-KEM-768 shared secret,
kemSs[1]     = LE-uint128(ss[16..32])                               //   two exact 128-bit limbs
hybridKey[0] = Poseidon(5)([TAG_K0,   ecdh[0], ecdh[1], kemSs[0], kemSs[1]])
hybridKey[1] = Poseidon(5)([TAG_K1,   ecdh[0], ecdh[1], kemSs[0], kemSs[1]])
kemBinding   = Poseidon(3)([TAG_BIND, kemSs[0], kemSs[1]])
```

`TAG_K0` / `TAG_K1` / `TAG_BIND` are `sha256("bongtu/pq-envelope/v1/{key0,key1,binding}") mod r`,
frozen as literals. Key derivation and binding are separated by both tag and arity. The limbs are
never reduced, so the mapping into the field is bias-free.

`kemSs` is a private witness in all four circuits; `kemBinding` is a public output. The 1088-byte
`kemCiphertext` itself never enters the proof — it travels as a calldata argument, is length-checked
on-chain, and is re-emitted in the op event so the arbiter can decapsulate from logs alone. The
arbiter recomputes `Poseidon(3)([TAG_BIND, …])` from its own decapsulation and compares; a mismatch
means the ciphertext does not match the secret the envelope was actually keyed under, which is an
alarm rather than a revert ([security-model.md](security-model.md#post-quantum-the-hybrid-authority-envelope-key)).

Receiver ciphertexts are unaffected: they stay keyed by plain `ECDH(ephemeral, recipientPublicKey)`.

### Op shapes and epoch semantics

Every op takes the KEM ciphertext alongside its public-signal vector, and each vector grew by one
signal (`kemBinding`, declared last so no existing output index moved):

| op | signature | publics |
|---|---|---|
| deposit | `deposit(a,b,c, uint[19] pub, bytes kemCiphertext)` | 18 → **19** |
| transfer | `transfer(a,b,c, uint[37] pub, bytes kemCiphertext)` | 36 → **37** |
| withdraw | `withdraw(a,b,c, uint[26] pub, bytes kemCiphertext)` | 25 → **26** |
| disburse | `disburseWithCiphertexts(a,b,c, uint[11] pub, uint256[] receiverCiphertexts, bytes kemCiphertext)` | 10 → **11** |

Exact index layouts are in [circuits.md](circuits.md#public-surfaces).

Arbiter epochs carry the KEM boundary. An epoch is `{keyX, keyY, activatedBlock}` in
`arbiterEpochs` plus `arbiterKemPkHash[epoch]`, the keccak256 of that epoch's 1184-byte ML-KEM-768
encapsulation key. Every epoch the pool mints carries a real hash — `initialize` and `rotateArbiter`
both revert `ZeroKemPkHash` — so a **zero** hash means exactly one thing to a reader: that epoch
index was never minted. There is no second, KEM-less regime to distinguish. Clients read
`arbiterKemPkHash(currentEpoch())` and verify their bundled encapsulation key against it before
encapsulating.

| op | plaintext | len | authority ct |
|---|---|---|---|
| deposit (0-in/2-out) | `[o0.x,o0.y, o1.x,o1.y, v0,s0, v1,s1]` | 8 | **10** |
| withdraw (2-in/1-out) | `[inOwn.x,inOwn.y, iv0,is0, iv1,is1, ch.x,ch.y, cv,cs]` | 10 | **13** |
| transfer (2-in/2-out) | `[inOwn.x,inOwn.y, iv0,is0, iv1,is1, o0.x,o0.y, o1.x,o1.y, ov0,os0, ov1,os1]` | 14 | **16** |
| disburse (1-in/B-out) | `[inOwn.x,inOwn.y, iv,is, (o.x,o.y)×B, (ov,os)×B]` | `4+4B` | `1030` at B=256 |

Ciphertext length is the plaintext padded up to a multiple of 3 (sponge rate) plus one final
squeeze. transfer and withdraw share one input owner across both inputs — the circuits take a
single `inputOwnerPrivateKey` — and a padded input carries value 0 by the value belt, so a padded
slot discloses nothing real.

### disburse: receiver run + disclosure chain

disburse also publishes a **receiver** ciphertext run: 4 elements per output note
(`SymmetricEncrypt` of `[value, salt]` under the recipient's own ECDH secret), so a recipient can
discover its note by trial-decrypt. The on-chain array is receiver run ++ authority envelope:

```
4 * 256  =  1024   receiver elements
             1030   authority envelope
           ------
             2054   == BongtuPool.disburseCiphertextLen, enforced on-chain
```

Re-hashing 2054 field elements on-chain is not affordable, so the circuit commits to them instead.
`disclosureHash` is a Poseidon(2) fold seeded at 0 over the receiver elements followed by the
authority elements:

```
dh = 0;  for each ct element x:  dh = Poseidon(dh, x)
```

emitted as a public signal. The chain enforces the *length*; the indexer recomputes the fold and
raises an alarm on any mismatch. See [security-model.md](security-model.md) for what that buys and
[indexer.md](indexer.md) for the alarm classes. The one implementation is
`disclosureChain` in `packages/core/src/envelope.ts`, pinned byte-identical to the in-circuit gadget
by `packages/core/test/envelope.test.ts`.
