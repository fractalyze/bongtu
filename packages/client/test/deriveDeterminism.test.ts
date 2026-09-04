// THE migration belt for the bjj key derivation (SPEC §6). The spending key is a pure
// function of the EIP-712 payload the wallet signs: if a wallet-stack migration (ethers
// -> viem, hand-rolled connect -> wagmi) changes ONE byte of that payload, every user's
// key silently rotates and their balance view is gone. So this file pins:
//
//   (1) the EIP-712 digest of keyDerivationTypedData(chainId, pool, keyVersion) — the
//       32 bytes every wallet actually signs (eth_signTypedData_v4 hashes the payload;
//       equal digests == equal signatures for a deterministic signer);
//   (2) the bjj identity derived from a FIXED signature — the KDF half of the hinge.
//
// A mock EIP-1193 provider returns the fixed signature; the test asserts the REAL
// signing path (signKeyDerivation over a viem wallet client) both (a) sends an
// eth_signTypedData_v4 payload hashing to the pinned digest and (b) turns the returned
// signature into the pinned key.
//
// ── HOW TO READ A FAILURE HERE ──────────────────────────────────────────────────
// PIN_DIGEST is NOT a snapshot to refresh when it goes red. Two DIFFERENT things
// make it move, and only one of them is legitimate:
//
//   (a) A CODE change — the struct, its field names, the statement text, the
//       hashing path. This is the bug the pin exists to catch. Every user on the
//       SAME deployment would silently derive a different key and lose sight of
//       their notes. Revert the change; do not touch the pin.
//
//   (b) A DEPLOYMENT change — chainId or the pool address, both of which sit
//       inside the EIP-712 domain. The digest MUST move, because the domain
//       separation is the point: a signature harvested for one chain/pool cannot
//       derive the key for another. This is not a rebaseline to wave through
//       either — it is a USER-VISIBLE IDENTITY BREAK. Every account derives a
//       NEW bjj key on the new deployment and cannot see notes it owned on the
//       old one; recovering them means pointing a client back at the old
//       chainId + pool. Only re-pin together with that decision.
//
// Case (b) is what happened on the move to the current chain: BOTH domain fields
// changed (new chain, new pool), so the digest was recomputed by running the repo's own
// keyDerivationTypedData through the same viem hashTypedData path this file uses.
// The old inputs still reproduce the old digest through that path, which is what
// makes the new value a computation rather than a plausible-looking hex string.
// PIN_SCALAR/PIN_COMPRESSED did NOT move and must not: the KDF is
// keccak256(signature) mod L, which never sees the typed data.

import { test } from "node:test";
import assert from "node:assert/strict";

import { createWalletClient, custom, hashTypedData } from "viem";
import { CHAIN_ID, POOL_ADDRESS } from "@bongtu/core/network";
import { liveChain } from "@bongtu/client/chain";
import { createHash } from "node:crypto";
import { kemPkFromSecret } from "@bongtu/core/kem";
import {
  keyDerivationTypedData,
  deriveIdentityFromSignature,
  viewScalarFromSignature,
} from "@bongtu/client/derive";
import { signKeyDerivation, type Connection } from "@bongtu/client/connection";
import { deriveLoginIdentity } from "@bongtu/client/identity";

// --- pinned derivation facts ------------------------------------------------------

/** The EIP-712 digest of keyDerivationTypedData(CHAIN_ID, POOL_ADDRESS, "1") — what
 *  the wallet signs — for the CURRENT deployment (chain 450815, the Maroo pool).
 *  Recomputed 2026-09-04 for the chain move, through the same viem hashTypedData
 *  path this file uses (the old inputs — 84532, the Base pool — still reproduce
 *  the old digest 0x64f5a878…, which is what makes this a computation rather
 *  than a plausible hex string); see the identity-break note above before ever
 *  changing it. */
const PIN_DIGEST = "0x07ea59d7abef0cfaa34cb72a2d41ee008eb6e2ab08af9fa0f72e0824650d51b3";

/** The live deployment's KDF domain facts — what wallet-web's config.ts
 *  KEY_DERIVATION threads into the engine (same one home: @bongtu/core/network). */
const KDF = { chainId: CHAIN_ID, pool: POOL_ADDRESS, keyVersion: "1", stealthKeyVersion: "1" };

/** A fixed stand-in for the wallet's deterministic 65-byte signature. */
const FIXED_SIG = ("0x" + "a1".repeat(32) + "b2".repeat(32) + "1c") as `0x${string}`;

/** deriveIdentityFromSignature(FIXED_SIG), captured from the PRE-migration (ethers
 *  v5) code and never regenerated since. Unlike PIN_DIGEST these do NOT move on a
 *  deployment change — the KDF hashes the SIGNATURE, not the typed data — so a
 *  failure here is always a real KDF regression. */
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

const ACCOUNT = "0x00000000000000000000000000000000000000a1" as const;

/** A Connection over a mock wallet: records every eth_signTypedData_v4 payload it is
 *  asked for and answers the fixed signature — the migration-proof seam (the fake
 *  models the WALLET, so the whole client stack in between is the code under test). */
function mockConnection(signedPayloads: string[]): Connection {
  const provider = {
    async request({ method, params }: { method: string; params?: unknown[] }): Promise<unknown> {
      if (method === "eth_signTypedData_v4") {
        signedPayloads.push((params as [string, string])[1]);
        return FIXED_SIG;
      }
      if (method === "eth_chainId") return "0x" + liveChain.id.toString(16);
      throw new Error(`unexpected RPC ${method}`);
    },
  };
  const walletClient = createWalletClient({
    account: ACCOUNT,
    chain: liveChain,
    transport: custom(provider),
  });
  return {
    address: ACCOUNT,
    walletClient,
    publicClient: {} as Connection["publicClient"],
    injected: provider,
    transport: "injected",
  };
}

// ------------------------------------------------------------------------------------

test("the typed-data struct still hashes to the pinned EIP-712 digest", () => {
  const typed = keyDerivationTypedData(KDF.chainId, KDF.pool, KDF.keyVersion);
  const digest = hashTypedData({
    domain: {
      name: typed.domain.name,
      version: typed.domain.version,
      chainId: typed.domain.chainId,
      verifyingContract: typed.domain.verifyingContract as `0x${string}`,
    },
    types: typed.types,
    primaryType: typed.primaryType,
    message: typed.message,
  });
  assert.equal(digest, PIN_DIGEST, "the signed payload drifted — every derived key would rotate");
});

test("signKeyDerivation sends a payload hashing to the pinned digest, and the fixed signature derives the pinned key", async () => {
  const typed = keyDerivationTypedData(KDF.chainId, KDF.pool, KDF.keyVersion);
  const signedPayloads: string[] = [];
  const connection = mockConnection(signedPayloads);

  const sig = await signKeyDerivation(connection, typed);
  assert.equal(sig, FIXED_SIG);
  assert.equal(signedPayloads.length, 1, "exactly one signature request");

  // Hash what actually went over the wire (the JSON payload of the
  // eth_signTypedData_v4 request) — a deterministic wallet signs this digest, so
  // digest equality IS signature equality, hence bjj-key equality.
  const asked = JSON.parse(signedPayloads[0]) as Parameters<typeof hashTypedData>[0];
  assert.equal(
    hashTypedData(asked),
    PIN_DIGEST,
    "the payload handed to the wallet is not the pinned one",
  );

  const identity = deriveIdentityFromSignature(sig);
  assert.equal(identity.keypair.formattedPrivateKey, PIN_SCALAR);
  assert.equal(identity.compressedPubkey, PIN_COMPRESSED);
});

test("the full login derivation path reproduces the pinned identity from the mock wallet", async () => {
  // deriveLoginIdentity builds the typed data itself (from the threaded KDF config)
  // and signs through the connection — the exact path a real login takes.
  const signedPayloads: string[] = [];
  const identity = await deriveLoginIdentity(mockConnection(signedPayloads), { doubleSign: false }, KDF);
  assert.equal(identity.compressedPubkey, PIN_COMPRESSED);
  assert.equal(identity.keypair.formattedPrivateKey, PIN_SCALAR);
  assert.equal(
    hashTypedData(JSON.parse(signedPayloads[0]) as Parameters<typeof hashTypedData>[0]),
    PIN_DIGEST,
    "the login signs the pinned payload, byte-for-byte",
  );
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
