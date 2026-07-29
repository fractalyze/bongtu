// THE migration belt for the bjj key derivation (SPEC §6). The spending key is a pure
// function of the EIP-712 payload the wallet signs: if a wallet-stack migration (ethers
// -> viem, hand-rolled connect -> wagmi) changes ONE byte of that payload, every user's
// key silently rotates and their balance view is gone. So this file pins, as constants
// captured from the PRE-migration (ethers v5) code and never regenerated since:
//
//   (1) the EIP-712 digest of keyDerivationTypedData(chainId, pool, keyVersion) — the
//       32 bytes every wallet actually signs (eth_signTypedData_v4 hashes the payload;
//       equal digests == equal signatures for a deterministic signer);
//   (2) the bjj identity derived from a FIXED signature — the KDF half of the hinge.
//
// A mock EIP-1193 provider returns the fixed signature; the test asserts the REAL
// signing path (signKeyDerivation over a viem wallet client) both (a) sends an
// eth_signTypedData_v4 payload hashing to the pinned digest and (b) turns the returned
// signature into the pinned key. These constants must NEVER be regenerated from
// current code — they ARE the compatibility contract with pre-migration deployments.

import { test } from "node:test";
import assert from "node:assert/strict";

import { createWalletClient, custom, hashTypedData } from "viem";
import { CHAIN_ID, POOL_ADDRESS } from "@bongtu/core/network";
import { giwaSepolia } from "../src/chain.js";
import { keyDerivationTypedData, deriveIdentityFromSignature } from "../src/derive.js";
import { signKeyDerivation, type Connection } from "../src/connection.js";
import { deriveLoginIdentity } from "../src/identity.js";

// --- pinned pre-migration facts (captured 2026-07-28 from the ethers v5 code) -------

/** ethers.utils._TypedDataEncoder.hash(domain, types, message) over
 *  keyDerivationTypedData(91342, <live pool>, "1") — what the wallet signs. */
const PIN_DIGEST = "0xbcd5b9b0aff8503b5e576e8b430743428a29a97354e57052d7e7c450f73676b9";

/** The live deployment's KDF domain facts — what wallet-web's config.ts
 *  KEY_DERIVATION threads into the engine (same one home: @bongtu/core/network). */
const KDF = { chainId: CHAIN_ID, pool: POOL_ADDRESS, keyVersion: "1" };

/** A fixed stand-in for the wallet's deterministic 65-byte signature. */
const FIXED_SIG = ("0x" + "a1".repeat(32) + "b2".repeat(32) + "1c") as `0x${string}`;

/** deriveIdentityFromSignature(FIXED_SIG) under the pre-migration code. */
const PIN_SCALAR = 2232542207878167874305209947598685605095785653266525372150719396610432433903n;
const PIN_COMPRESSED = "0x05c818db6e4feb82639a2170ec769abcdbfc9077833153ed2266a52b653c1f96";

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
      if (method === "eth_chainId") return "0x" + giwaSepolia.id.toString(16);
      throw new Error(`unexpected RPC ${method}`);
    },
  };
  const walletClient = createWalletClient({
    account: ACCOUNT,
    chain: giwaSepolia,
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

test("the typed-data struct still hashes to the pre-migration EIP-712 digest", () => {
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
    "the payload handed to the wallet is not the pre-migration one",
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
    "the login signs the pre-migration payload, byte-for-byte",
  );
});
