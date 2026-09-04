// SPDX-License-Identifier: Apache-2.0
pragma circom 2.2.2;

// GATE-ONLY harness (not a product circuit — no verifier, no zkey): exposes
// the consumer viewTag bit extraction of lib/consumer-encrypt-outputs.circom
// over a DIRECT field-element input, so the OPMOD §2.1 viewTag-canonicality
// gate (consumer_viewtag_canonicality_check.ts) can drive it with
// alias-sensitive edge values a real fixture cannot reach (in the product
// circuits tagField is a Poseidon output, not steerable). Same construction
// verbatim: Num2Bits_strict (254 bits + AliasCheck — the strict form makes
// the non-canonical `in + p` decomposition unsatisfiable), tag = bits 0..7.
include "node_modules/circomlib/circuits/bitify.circom";

template ViewTagHarness() {
  signal input in;
  signal output tag;

  component bits = Num2Bits_strict();
  bits.in <== in;
  var t = 0;
  for (var j = 0; j < 8; j++) {
    t += bits.out[j] * 2 ** j;
  }
  tag <== t;
}

component main = ViewTagHarness();
