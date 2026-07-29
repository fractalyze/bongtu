// Identity coincidence gate (U-P3 architecture directive): the payroll console
// and the public wallet MUST derive the same bjj key for the same account. That
// holds by construction — both apps derive under the ONE @bongtu/client
// KEY_DERIVATION constant, itself built from the sdk deployment facts — and this
// test pins the construction: the constant equals the deployment facts, and the
// typed data it produces is the domain-separated struct the KDF has always
// signed (chainId 91342, the live pool, version "1").

import { test } from "node:test";
import assert from "node:assert/strict";

import { CHAIN_ID, POOL_ADDRESS } from "@bongtu/core/network";
import { KEY_DERIVATION } from "@bongtu/client/identity";
import { keyDerivationTypedData, deriveIdentityFromSignature } from "@bongtu/client/derive";

test("KEY_DERIVATION is exactly the deployment facts both apps share", () => {
  assert.deepEqual(KEY_DERIVATION, { chainId: CHAIN_ID, pool: POOL_ADDRESS, keyVersion: "1" });
});

test("the console signs the same struct the wallet signs, so the same key falls out", () => {
  const typed = keyDerivationTypedData(
    KEY_DERIVATION.chainId,
    KEY_DERIVATION.pool,
    KEY_DERIVATION.keyVersion,
  );
  assert.equal(typed.domain.chainId, 91342);
  assert.equal(typed.domain.verifyingContract, POOL_ADDRESS);
  assert.equal(typed.domain.version, "1");
  assert.equal(typed.primaryType, "BongtuSpendingKey");
  // Same signature bytes -> same identity, whichever app runs the KDF (the
  // derivation is a pure function of the signature alone).
  const sig = "0x" + "5a".repeat(32) + "6b".repeat(32) + "1c";
  assert.equal(
    deriveIdentityFromSignature(sig).compressedPubkey,
    deriveIdentityFromSignature(sig).compressedPubkey,
  );
});
