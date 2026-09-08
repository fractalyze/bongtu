// ENS wire helpers for the payment-name front door (SPEC: payment-name R1,
// R4, R13): DNS wire encoding, namehash, ENSIP-11 coinType mapping, and the
// CCIP-Read gateway response signature.
//
// Dependency-free by the core rule (no viem, no ENS libraries — C9 in the
// spec): keccak and secp256k1 already live in this package, and the four
// wire formats below are small and frozen by their specs (RFC 1035 name
// encoding, ENSIP-1 namehash, ENSIP-11, and the ensdomains offchain-resolver
// signature preimage). The Solidity verifier side is
// chains/evm/src/PortalPrivResolver.sol; the two are held together by a
// committed parity vector (test/ens.test.ts <-> PortalPrivResolver.t.sol,
// the stealth parity-vector discipline).
//
// LABEL GRAMMAR: the gateway resolves only labels the name directory can
// hold. ENS normalization (ENSIP-15) is a superset problem this module does
// NOT solve; instead `directoryLabel` lowercases ASCII and then FAILS CLOSED
// to the directory grammar `[a-z0-9-]{1,64}` — anything fancier resolves
// nowhere and mints nothing (spec C8 posture).

import { keccak_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

const ZERO32 = new Uint8Array(32);
const encoder = new TextEncoder();

/** Lowercase an ASCII label and fail closed to the name-directory grammar.
 *  Returns null for anything the directory cannot hold (spec C8). */
export function directoryLabel(label: string): string | null {
  const lowered = label.toLowerCase();
  return /^[a-z0-9-]{1,64}$/.test(lowered) ? lowered : null;
}

/** RFC 1035 wire encoding of a dot-separated name: length-prefixed labels,
 *  zero terminator. Throws on an empty or oversized (>63 byte) label. */
export function dnsEncodeName(name: string): Uint8Array {
  const trimmed = name.replace(/\.$/, "");
  if (trimmed === "") return Uint8Array.of(0);
  const parts = trimmed.split(".").map((label) => {
    const bytes = encoder.encode(label);
    if (bytes.length === 0 || bytes.length > 63) {
      throw new Error(`dnsEncodeName: label length ${bytes.length} out of range in "${name}"`);
    }
    return concatBytes(Uint8Array.of(bytes.length), bytes);
  });
  return concatBytes(...parts, Uint8Array.of(0));
}

/** Decode an RFC 1035 wire name back to its dot-separated form. */
export function dnsDecodeName(wire: Uint8Array): string {
  const labels: string[] = [];
  const cursor = { at: 0 };
  for (const _ of Array(128).keys()) {
    const len = wire[cursor.at];
    if (len === undefined) throw new Error("dnsDecodeName: truncated wire name");
    if (len === 0) return labels.join(".");
    if (len > 63) throw new Error(`dnsDecodeName: label length ${len} out of range`);
    const start = cursor.at + 1;
    labels.push(new TextDecoder().decode(wire.subarray(start, start + len)));
    cursor.at = start + len;
  }
  throw new Error("dnsDecodeName: name too deep");
}

/** ENSIP-1 namehash of a dot-separated name (empty string = zero node). */
export function namehash(name: string): string {
  const node = name
    .replace(/\.$/, "")
    .split(".")
    .filter((label) => label !== "")
    .reduceRight<Uint8Array>(
      (acc, label) => keccak_256(concatBytes(acc, keccak_256(encoder.encode(label)))),
      ZERO32,
    );
  return "0x" + bytesToHex(node);
}

/** ENSIP-11 coinType for an EVM chain: mainnet keeps SLIP-44 ether (60),
 *  every other chain is 0x80000000 | chainId. */
export function coinTypeForChain(chainId: number): bigint {
  if (!Number.isInteger(chainId) || chainId < 0 || chainId > 0x7fffffff) {
    throw new Error(`coinTypeForChain: chainId ${chainId} out of ENSIP-11 range`);
  }
  return chainId === 1 ? 60n : BigInt(0x80000000 + chainId);
}

/** Inverse of coinTypeForChain. Returns null for coinTypes that name no EVM
 *  chain under ENSIP-11 (the gateway answers those empty, R13). */
export function chainForCoinType(coinType: bigint): number | null {
  if (coinType === 60n) return 1;
  if (coinType >= 0x80000000n && coinType <= 0xffffffffn) return Number(coinType - 0x80000000n);
  return null;
}

/** The offchain-resolver signature preimage the Solidity side re-derives:
 *  keccak256(0x1900 ‖ resolver ‖ expires(uint64 BE) ‖ keccak(request) ‖
 *  keccak(result)). `resolver` is the 0x-hex contract address. */
export function gatewaySignatureHash(
  resolver: string,
  expires: bigint,
  request: Uint8Array,
  result: Uint8Array,
): Uint8Array {
  const addressBytes = hexToBytes(resolver.replace(/^0x/, "").toLowerCase());
  if (addressBytes.length !== 20) throw new Error("gatewaySignatureHash: resolver must be a 20-byte address");
  if (expires < 0n || expires > 0xffffffffffffffffn) throw new Error("gatewaySignatureHash: expires out of uint64");
  const expiresBytes = new Uint8Array(8);
  new DataView(expiresBytes.buffer).setBigUint64(0, expires);
  return keccak_256(
    concatBytes(Uint8Array.of(0x19, 0x00), addressBytes, expiresBytes, keccak_256(request), keccak_256(result)),
  );
}

/** Sign a gateway response hash with the gateway key: 65-byte r‖s‖v
 *  (v = 27 + recovery id), the shape `ecrecover` and the Solidity verifier
 *  expect. The digest is signed raw (no EIP-191 prefix; the 0x1900 preimage
 *  IS the domain separation). */
export function signGatewayResponse(privateKey: Uint8Array, digest: Uint8Array): Uint8Array {
  const compact = secp256k1.sign(digest, privateKey, { prehash: false });
  const pub = bytesToHex(secp256k1.getPublicKey(privateKey, false));
  const recid = [0, 1].find((rid) => {
    try {
      const sig = secp256k1.Signature.fromBytes(compact, "compact").addRecoveryBit(rid);
      return bytesToHex(sig.recoverPublicKey(digest).toBytes(false)) === pub;
    } catch {
      return false;
    }
  });
  if (recid === undefined) throw new Error("signGatewayResponse: no recovery id matched");
  return concatBytes(compact, Uint8Array.of(27 + recid));
}

/** Recover the signer ADDRESS from a 65-byte r‖s‖v gateway signature — the
 *  TS twin of the Solidity verifier's ecrecover, used by tests and the
 *  gate's wallet-shaped driver. */
export function recoverGatewaySigner(digest: Uint8Array, signature: Uint8Array): string {
  if (signature.length !== 65) throw new Error("recoverGatewaySigner: signature must be 65 bytes");
  const v = signature[64];
  if (v !== 27 && v !== 28) throw new Error(`recoverGatewaySigner: v must be 27 or 28, got ${v}`);
  const sig = secp256k1.Signature.fromBytes(signature.subarray(0, 64), "compact").addRecoveryBit(v - 27);
  const pub = sig.recoverPublicKey(digest).toBytes(false);
  return "0x" + bytesToHex(keccak_256(pub.subarray(1)).subarray(12));
}
