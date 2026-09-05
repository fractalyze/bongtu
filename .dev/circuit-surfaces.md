# Circuit public-signal index inventory

The exhaustive per-op index tables for every circuit's public vector, moved here from
`docs/circuits.md` — which owns the ordering rule (outputs first, then public inputs), the
summary tables, and the breaking-change consequence. The pool (enterprise) or module (consumer)
indexes these vectors literally. Each consumer top also restates its own layout in its file
header (`circuits/*Priv.circom`).

## Enterprise (pool-verified)

### deposit — `uint[19]`

| idx | signal |
|---|---|
| 0 | `out` (sum of output values; the amount pulled from the depositor) |
| 1..2 | `ecdhPublicKey[2]` |
| 3..12 | `cipherTextAuthority[10]` |
| 13 | `kemBinding` |
| 14..15 | `outputCommitments[2]` |
| 16 | `encryptionNonce` |
| 17..18 | `authorityPublicKey[2]` |

### transfer — `uint[37]`

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2..9 | `cipherTexts[2][4]` (receiver-decryptable, one per output) |
| 10..25 | `cipherTextAuthority[16]` |
| 26 | `kemBinding` |
| 27..28 | `nullifiers[2]` |
| 29 | `root` |
| 30..31 | `enabled[2]` |
| 32..33 | `outputCommitments[2]` |
| 34 | `encryptionNonce` |
| 35..36 | `authorityPublicKey[2]` |

### transfer10 — `uint[141]`

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2..41 | `cipherTexts[10][4]` (receiver-decryptable, one per output) |
| 42..105 | `cipherTextAuthority[64]` |
| 106 | `kemBinding` |
| 107..116 | `nullifiers[10]` |
| 117 | `root` |
| 118..127 | `enabled[10]` |
| 128..137 | `outputCommitments[10]` |
| 138 | `encryptionNonce` |
| 139..140 | `authorityPublicKey[2]` |

Same base as transfer, so the *declaration* order is identical and only the run lengths change —
but every index past 1 moves, so transfer10 needs its own verifier and its own contract indexing.

### transfer10x2 — `uint[68]`

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2..9 | `cipherTexts[2][4]` (receiver-decryptable, one per output) |
| 10..40 | `cipherTextAuthority[31]` |
| 41 | `kemBinding` |
| 42..51 | `nullifiers[10]` |
| 52 | `root` |
| 53..62 | `enabled[10]` |
| 63..64 | `outputCommitments[2]` |
| 65 | `encryptionNonce` |
| 66..67 | `authorityPublicKey[2]` |

The authority run is 31 rather than a multiple of 3 plus one by accident: the plaintext is
`2 + 2*10 + 4*2 = 30`, already a multiple of 3, so the sponge adds no padding and only the final
squeeze.

### withdraw — `uint[27]`

| idx | signal |
|---|---|
| 0 | `out` (= `sum(inputs) − sum(outputs)`, the ERC-20 amount pushed) |
| 1..2 | `ecdhPublicKey[2]` |
| 3..15 | `cipherTextAuthority[13]` |
| 16 | `kemBinding` |
| 17..18 | `nullifiers[2]` |
| 19 | `root` |
| 20..21 | `enabled[2]` |
| 22 | `outputCommitments[0]` (the change note) |
| 23 | `encryptionNonce` |
| 24..25 | `authorityPublicKey[2]` |
| 26 | `recipient` (L1 payout address as a field element; the contract range-checks uint160 and pays it instead of msg.sender — the relayable stealth exit) |

### disburse / disburse256 — `uint[11]`

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2 | `disclosureHash` |
| 3 | `subtreeRoot` |
| 4 | `kemBinding` |
| 5 | `nullifiers[0]` |
| 6 | `root` |
| 7 | `enabled[0]` |
| 8 | `encryptionNonce` |
| 9..10 | `authorityPublicKey[2]` |

Neither the batch's ciphertext nor the 1088-byte `kemCiphertext` rides in the public vector: the
former travels as a separate calldata argument bound by `disclosureHash`, the latter as a `bytes`
argument bound by `kemBinding` ([protocol.md](../docs/protocol.md),
[contracts.md](../docs/contracts.md)).

## Consumer (module-verified)

### depositPriv — `uint[16]` (enterprise deposit: `uint[19]`)

| idx | signal |
|---|---|
| 0 | `out` (sum of output values; the amount the module pulls) |
| 1..2 | `ecdhPublicKey[2]` |
| 3..10 | `cipherTexts[2][4]` (receiver-decryptable, one per output) |
| 11..12 | `viewTags[2]` |
| 13..14 | `outputCommitments[2]` |
| 15 | `encryptionNonce` |

### transferPriv — `uint[20]` (enterprise transfer: `uint[37]`)

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2..9 | `cipherTexts[2][4]` |
| 10..11 | `viewTags[2]` |
| 12..13 | `nullifiers[2]` |
| 14 | `root` |
| 15..16 | `enabled[2]` (module-injected: `nullifier[i] != 0`) |
| 17..18 | `outputCommitments[2]` |
| 19 | `encryptionNonce` |

### transfer10x2Priv — `uint[36]` (enterprise transfer10x2: `uint[68]`)

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2..9 | `cipherTexts[2][4]` |
| 10..11 | `viewTags[2]` |
| 12..21 | `nullifiers[10]` |
| 22 | `root` |
| 23..32 | `enabled[10]` (module-injected) |
| 33..34 | `outputCommitments[2]` |
| 35 | `encryptionNonce` |

### withdrawPriv — `uint[16]` (enterprise withdraw: `uint[27]`)

| idx | signal |
|---|---|
| 0 | `out` (= `sum(inputs) − change`, the ERC-20 amount the module pushes) |
| 1..2 | `ecdhPublicKey[2]` |
| 3..6 | `cipherTexts[1][4]` (the change note) |
| 7 | `viewTags[1]` |
| 8..9 | `nullifiers[2]` |
| 10 | `root` |
| 11..12 | `enabled[2]` (module-injected) |
| 13 | `outputCommitments[0]` (the change note) |
| 14 | `encryptionNonce` |
| 15 | `recipient` (L1 payout address; the module range-checks uint160 and pays it, never msg.sender — relayable like the enterprise withdraw) |

### disbursePriv / disbursePriv256 — `uint[8]` (enterprise disburse: `uint[11]`)

| idx | signal |
|---|---|
| 0..1 | `ecdhPublicKey[2]` |
| 2 | `disclosureHash` (the EXTENDED fold over `receiverCts[4B] ++ viewTags[B] ++ outputCommitments[B]`) |
| 3 | `subtreeRoot` |
| 4 | `nullifiers[0]` |
| 5 | `root` |
| 6 | `enabled[0]` (module-injected constant 1 after a `ZeroNullifier` check) |
| 7 | `encryptionNonce` |

The batch's 6·B-element `disclosure` array and every circuit's per-recipient 1088-byte KEM
ciphertexts ride module calldata, not the public vector; the on-chain checks they get are the
module's ([contracts.md](../docs/contracts.md#the-op-module-layer)).
