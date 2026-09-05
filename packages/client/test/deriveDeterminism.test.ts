// The rail-free half of the key-derivation migration belt (SPEC §6). The full
// belt pins two hinges; this file owns the signature-to-identity half — the
// pure KDF: a FIXED 65-byte signature in, the pinned bjj/KEM identity out —
// because derive.ts's byte plumbing (the keccak/hex shim) is ENGINE code, so
// `npm test -w @bongtu/client` alone must catch a KDF regression, with zero
// viem in the suite. The other half — the EIP-712 digest pins and the
// signing-path checks — lives in packages/client-evm/test/deriveDeterminism.test.ts,
// because the typed-data seed (keyDerivationTypedData) and the signing edge
// belong to the EVM rail.
//
// Unlike the digest pin over there, NOTHING here moves on a deployment change:
// the KDF hashes the SIGNATURE, not the typed data. A failure in this file is
// always a real KDF regression — every user's key would silently rotate and
// their balance view is gone. Revert the change; never touch these pins.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import { kemPkFromSecret } from "@bongtu/core/kem";
import {
  deriveIdentityFromSignature,
  viewScalarFromSignature,
} from "@bongtu/client/derive";

// --- pinned derivation facts ------------------------------------------------------

/** A fixed stand-in for the wallet's deterministic 65-byte signature. */
const FIXED_SIG = ("0x" + "a1".repeat(32) + "b2".repeat(32) + "1c") as `0x${string}`;

/** deriveIdentityFromSignature(FIXED_SIG), captured from the PRE-migration (ethers
 *  v5) code and never regenerated since. These do NOT move on a deployment change —
 *  the KDF hashes the SIGNATURE, not the typed data — so a failure here is always
 *  a real KDF regression. */
const PIN_SCALAR = 2232542207878167874305209947598685605095785653266525372150719396610432433903n;
const PIN_COMPRESSED = "0x05c818db6e4feb82639a2170ec769abcdbfc9077833153ed2266a52b653c1f96";

/** The consumer view identity derived from FIXED_SIG (OPMOD §3.1), recorded
 *  2026-09-03 when the derivation shipped. Like PIN_SCALAR these hash the
 *  SIGNATURE (under distinct ascii suffix tags), not the typed data, so they
 *  never move on a deployment change — a failure here is a KDF regression that
 *  would silently strand every consumer note behind a rotated view identity.
 *  The spend pins above are UNTOUCHED by the extension: "every live key
 *  survives" is the S3.1 contract this file now also witnesses. */
const PIN_VIEW_SCALAR = 1667726457022364403377257978503016485956539627643118706499228418183446227977n;
const PIN_VIEW_COMPRESSED = "0xeb198c8f34d687dc0aa64d1c89f612c15bd496d30324faf0b3d6244867756e23";
const PIN_KEM_EK_SHA256 = "57ff87f169fb4159b55220a51940a9476310cff0441db8995550ff9eee83e461";
const PIN_KEM_DK_SHA256 = "11f5775965db21121d53c429e317eee9fd209cbb5919925a011ae830e4ddc130";

// ------------------------------------------------------------------------------------

test("the fixed signature derives the pinned spend identity", () => {
  const identity = deriveIdentityFromSignature(FIXED_SIG);
  assert.equal(identity.keypair.formattedPrivateKey, PIN_SCALAR);
  assert.equal(identity.compressedPubkey, PIN_COMPRESSED);
});

test("the consumer view identity derives deterministically beside the untouched spend pins", () => {
  const identity = deriveIdentityFromSignature(FIXED_SIG);

  // Spend half: byte-identical to the pre-extension derivation (S3.1: every
  // live key survives — the extension may not perturb these).
  assert.equal(identity.keypair.formattedPrivateKey, PIN_SCALAR);
  assert.equal(identity.compressedPubkey, PIN_COMPRESSED);

  // View half: pinned, distinct from the spend scalar, and reproducible via
  // the standalone KDF (the delegated-scanner entry point).
  assert.equal(identity.viewKeypair.formattedPrivateKey, PIN_VIEW_SCALAR);
  assert.equal(identity.compressedViewPubkey, PIN_VIEW_COMPRESSED);
  assert.equal(viewScalarFromSignature(FIXED_SIG), PIN_VIEW_SCALAR);
  assert.notEqual(identity.viewKeypair.formattedPrivateKey, identity.keypair.formattedPrivateKey);

  // KEM half: FIPS 203 wire sizes, pinned bytes, and internal ek/dk consistency.
  assert.equal(identity.kemKeypair.ek.length, 1184);
  assert.equal(identity.kemKeypair.dk.length, 2400);
  assert.equal(createHash("sha256").update(identity.kemKeypair.ek).digest("hex"), PIN_KEM_EK_SHA256);
  assert.equal(createHash("sha256").update(identity.kemKeypair.dk).digest("hex"), PIN_KEM_DK_SHA256);
  assert.deepEqual(kemPkFromSecret(identity.kemKeypair.dk), identity.kemKeypair.ek);
});

test("malformed signature hex throws instead of deriving (the KDF input domain stays viem-strict)", () => {
  // The pre-split code fed viem's hexToBytes, which REJECTS a missing 0x prefix;
  // the noble-backed shim must keep that boundary, or bare-hex strings that never
  // derived a key before would silently start deriving one.
  assert.throws(() => deriveIdentityFromSignature(FIXED_SIG.slice(2)));
  assert.throws(() => deriveIdentityFromSignature("0x" + "a1".repeat(32) + "b"));
  assert.throws(() => deriveIdentityFromSignature("0x" + "zz".repeat(65)));
});
