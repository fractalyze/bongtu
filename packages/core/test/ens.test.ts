// ENS wire helpers (SPEC: payment-name R1/R4/R13). The gateway-signature
// parity vector here is shared with chains/evm/test/PortalPrivResolver.t.sol:
// both sides pin the SAME committed digest for the same inputs, so a drift
// in either preimage implementation turns a suite red instead of producing
// responses the on-chain verifier rejects (the stealth parity-vector
// discipline).
import { test } from "node:test";
import assert from "node:assert/strict";

import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

import {
  chainForCoinType,
  coinTypeForChain,
  directoryLabel,
  dnsDecodeName,
  dnsEncodeName,
  gatewaySignatureHash,
  namehash,
  recoverGatewaySigner,
  signGatewayResponse,
} from "@bongtu/core/ens";

test("namehash matches the EIP-137 reference vectors", () => {
  assert.equal(namehash(""), "0x" + "00".repeat(32));
  assert.equal(namehash("eth"), "0x93cdeb708b7545dc668eb9280176169d1c33cfd8ed6f04690a0bcc88a93fc4ae");
  assert.equal(namehash("foo.eth"), "0xde9b09fd7c5f901e23a3f19fecc54828e9c848539801e86591bd9801b019f84f");
  assert.equal(namehash("foo.eth"), namehash("foo.eth."));
});

test("dnsEncodeName produces length-prefixed labels and round-trips", () => {
  const wire = dnsEncodeName("test.offchaindemo.eth");
  assert.equal(
    bytesToHex(wire),
    "04" + bytesToHex(new TextEncoder().encode("test")) +
      "0c" + bytesToHex(new TextEncoder().encode("offchaindemo")) +
      "03" + bytesToHex(new TextEncoder().encode("eth")) + "00",
  );
  assert.equal(dnsDecodeName(wire), "test.offchaindemo.eth");
  assert.equal(bytesToHex(dnsEncodeName("")), "00");
  assert.throws(() => dnsEncodeName("a..b"), /label length 0/);
  assert.throws(() => dnsEncodeName("x".repeat(64) + ".eth"), /label length 64/);
});

test("directoryLabel lowercases and fails closed to the directory grammar", () => {
  assert.equal(directoryLabel("Jun"), "jun");
  assert.equal(directoryLabel("pay-me-42"), "pay-me-42");
  assert.equal(directoryLabel("한글"), null);
  assert.equal(directoryLabel("has.dot"), null);
  assert.equal(directoryLabel(""), null);
  assert.equal(directoryLabel("x".repeat(65)), null);
});

test("ENSIP-11 coinType mapping round-trips and pins known chains", () => {
  assert.equal(coinTypeForChain(1), 60n);
  assert.equal(coinTypeForChain(8453), 2147492101n); // Base, the survey's cross-check value
  assert.equal(coinTypeForChain(11155111), 2158638759n); // Sepolia
  assert.equal(chainForCoinType(60n), 1);
  assert.equal(chainForCoinType(2147492101n), 8453);
  assert.equal(chainForCoinType(2158638759n), 11155111);
  assert.equal(chainForCoinType(0n), null); // Bitcoin's SLIP-44 slot is not an EVM chain
  assert.equal(chainForCoinType(501n), null);
  assert.throws(() => coinTypeForChain(-1));
  assert.throws(() => coinTypeForChain(0x80000000));
});

// The committed TS<->Solidity parity vector (see the module header).
const PARITY = {
  resolver: "0x1111111111111111111111111111111111111111",
  expires: 1893456000n,
  request: hexToBytes("deadbeef"),
  result: hexToBytes("cafe"),
  digest: "0d66a888b54ad0e6696f9e7843e16d226b9a571832be789b860ed34249892636",
};

test("gateway signature parity vector: fixed inputs reproduce the committed digest", () => {
  const digest = gatewaySignatureHash(PARITY.resolver, PARITY.expires, PARITY.request, PARITY.result);
  assert.equal(bytesToHex(digest), PARITY.digest);
});

test("gateway signature signs and recovers to the key's address", () => {
  const priv = hexToBytes("aa".repeat(32));
  const digest = gatewaySignatureHash(PARITY.resolver, PARITY.expires, PARITY.request, PARITY.result);
  const sig = signGatewayResponse(priv, digest);
  assert.equal(sig.length, 65);
  assert.ok(sig[64] === 27 || sig[64] === 28);
  const expected =
    "0x" + bytesToHex(keccak_256(secp256k1.getPublicKey(priv, false).subarray(1)).subarray(12));
  assert.equal(recoverGatewaySigner(digest, sig), expected);
  const tampered = Uint8Array.from(sig);
  tampered[0] ^= 1;
  assert.notEqual(
    (() => {
      try {
        return recoverGatewaySigner(digest, tampered);
      } catch {
        return expected;
      }
    })(),
    expected,
    "a tampered signature must not recover the signer",
  );
});
