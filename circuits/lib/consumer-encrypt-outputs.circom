// SPDX-License-Identifier: Apache-2.0
//
// PROVENANCE (bongtu U2 consumer family, 2026-09-03)
// ---------------------------------------------------
// project-authored, derived from circuits/lib/encrypt-outputs-per-output-nonce.circom
// (itself derived from zeto's lib/encrypt-outputs.circom). Shared per-output
// receiver encryption + view tags for the five consumer (no-auditor) circuits —
// OPMOD §3.2 / §3.3 / §3.5 (.dev/op-module-design.md).
//
// MODIFICATIONS vs encrypt-outputs-per-output-nonce.circom:
//   (1) VIEW-key ECDH (OPMOD §3.1/§3.3): the per-output shared secret is
//       S_i = Ecdh(ecdhPrivateKey, outputViewPublicKeys[i]) — the recipient's
//       note-layer VIEW pubkey, a plain private witness DISTINCT from the spend
//       key the commitment binds. The CommitmentInputs bus is replaced by plain
//       value/salt/viewPub arrays because the encryption target is no longer
//       the commitment owner.
//   (2) hybrid receiver key (OPMOD §3.3): ct i is encrypted not under the raw
//       ECDH point but under rk_i = tagged Poseidon(5) folds of
//       (S_i, kemSs_i) where kemSs_i are PER-OUTPUT ML-KEM-768 shared-secret
//       limbs (PRIVATE witness, Num2Bits(128) limb hygiene), under the NEW
//       consumer tags below — the arbiter tags (bongtu/pq-envelope/v1/*) are
//       never reused. NO kemBinding output exists: there is no arbiter to
//       alarm, and a junk encapsulation self-sabotages only the sender's own
//       delivery (the recipient's leaf-match acceptance rejects the garbage
//       decrypt; the note's funds are untouched) — OPMOD §2/§3.3.
//   (3) NEW output viewTags[nOutputs] (OPMOD §3.2): viewTag_i = the CANONICAL
//       low 8 bits of Poseidon(3)([TAG_VIEWTAG, S_i.x, S_i.y]), decomposed
//       with Num2Bits_strict (254 bits + AliasCheck). Plain Num2Bits(254) is
//       NOT acceptable: 2^254 − 1 > p, so every tagField < 2^254 − p (~a
//       quarter of field elements) admits a second valid decomposition
//       (tagField + p), and p is odd, so the alternate bits flip the low
//       byte — a prover could publish a wrong tag for its own recipient
//       (silent undiscoverability). The strict form closes that for
//       ~127 constraints/output.
//   (4) the per-output nonce rule (encryptionNonce + i) is KEPT verbatim
//       (U-X3 / §11-8 v1.1) and is uniform across ALL five consumer circuits
//       (OPMOD §3.5) — including the deposit and disburse shapes whose
//       enterprise twins share one nonce. SymmetricEncrypt's own LessThan(252)
//       range check is alias-prone on a free field element and therefore
//       ADVISORY — the operative clamp is client-side (toEncryptionNonce plus
//       the TS offsetNonce guard); a nonce >= 2^128 only self-sabotages the
//       sender's recipient (discovery fails loudly), never soundness. So nonce+i
//       overflows only at encryptionNonce >= 2^128 - (nOutputs-1), the same
//       negligible witness-generation-failure class as a salt collision.
//
// The TS twin of every derivation here is packages/core/src/consumer.ts —
// drift breaks recipient discovery of live consumer notes, so the tag
// literals are FROZEN and must stay byte-equal to the TS literals.
pragma circom 2.2.2;

include "lib/ecdh.circom";
include "lib/encrypt.circom";
include "node_modules/circomlib/circuits/babyjub.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "node_modules/circomlib/circuits/poseidon.circom";

// Per-output hybrid receiver encryption + canonical view tags. One ephemeral
// private key serves every output's ECDH, exactly as upstream; keys, nonces
// and KEM material are per-output.
template ConsumerEncryptOutputs(nOutputs) {
  signal input ecdhPrivateKey;
  signal input encryptionNonce;
  // note-layer VIEW pubkeys (bjj), one per output — never the spend key.
  signal input outputViewPublicKeys[nOutputs][2];
  signal input outputValues[nOutputs];
  signal input outputSalts[nOutputs];
  // ML-KEM-768 shared-secret limbs (LE-uint128 halves of ss_i; PRIVATE),
  // one fresh encapsulation per output (OPMOD §3.3).
  signal input kemSs[nOutputs][2];

  // the public key of the ephemeral private key used in the per-output ECDH
  signal output ecdhPublicKey[2];
  // the receiver-decryptable [value, salt] ciphertexts, one per output
  signal output cipherTexts[nOutputs][4];
  // the canonical 8-bit discovery tags, one per output, in [0, 256)
  signal output viewTags[nOutputs];

  // Frozen domain-separation tags (sha256(ASCII) mod r, computed 2026-09-03;
  // OPMOD §3.3) — byte-equal to packages/core/src/consumer.ts:
  //   TAG_RK0     = sha256("bongtu/consumer-note/v1/key0")    mod r
  //   TAG_RK1     = sha256("bongtu/consumer-note/v1/key1")    mod r
  //   TAG_VIEWTAG = sha256("bongtu/consumer-note/v1/viewtag") mod r
  var TAG_RK0 = 15911670041651909454486960207337169366505934455020053916031847212914070689294;
  var TAG_RK1 = 18959445568053998966444410456355743824415104493789084861475706421378089710793;
  var TAG_VIEWTAG = 4236837455644426462098222144565872234823396873019476831333450393757091506254;

  component kemSsRange[nOutputs][2];
  signal rk[nOutputs][2];
  signal tagField[nOutputs];
  component tagBits[nOutputs];

  for (var i = 0; i < nOutputs; i++) {
    // per-output shared secret against the recipient's VIEW key
    var S[2];
    S = Ecdh()(privKey <== ecdhPrivateKey, pubKey <== outputViewPublicKeys[i]);

    // canonical-encoding hygiene: each limb is a genuine 128-bit value
    for (var j = 0; j < 2; j++) {
      kemSsRange[i][j] = Num2Bits(128);
      kemSsRange[i][j].in <== kemSs[i][j];
    }

    // hybrid receiver key (OPMOD §3.3)
    rk[i][0] <== Poseidon(5)([TAG_RK0, S[0], S[1], kemSs[i][0], kemSs[i][1]]);
    rk[i][1] <== Poseidon(5)([TAG_RK1, S[0], S[1], kemSs[i][0], kemSs[i][1]]);

    // encrypt [value, salt] for output i under ITS OWN nonce (OPMOD §3.5)
    cipherTexts[i] <== SymmetricEncrypt(2)(plainText <== [outputValues[i], outputSalts[i]], key <== rk[i], nonce <== encryptionNonce + i);

    // canonical view tag (OPMOD §3.2): strict decomposition pins the bit
    // string to the one canonical (< p) encoding; the tag is bits 0..7.
    tagField[i] <== Poseidon(3)([TAG_VIEWTAG, S[0], S[1]]);
    tagBits[i] = Num2Bits_strict();
    tagBits[i].in <== tagField[i];
    var tag = 0;
    for (var j = 0; j < 8; j++) {
      tag += tagBits[i].out[j] * 2 ** j;
    }
    viewTags[i] <== tag;
  }

  (ecdhPublicKey[0], ecdhPublicKey[1]) <== BabyPbk()(in <== ecdhPrivateKey);
}
