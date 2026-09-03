// Deterministic BabyJubJub spending-key derivation from a MetaMask signature
// (SPEC §6). This is the whole security hinge of the public wallet, so it is PURE
// and side-effect-free: the same code runs in the browser view and in the headless
// derivation test, and it imports the sdk key primitives DIRECTLY (not a copy) so a
// derived key hashes into the exact commitments/nullifiers the circuit consumes.
//
//   sig  = eth_signTypedData_v4(account, DOMAIN-SEPARATED struct)   (MetaMask)
//   s    = keccak256(sig)  mod  L                                   (the KDF)
//   key  = deriveKeypair(s)   ->  { formattedPrivateKey: s, publicKey: s·Base8 }
//   recv = packPubkey(publicKey)                                    (compressed, on-wire)
//
// Why a *typed* struct, not personal_sign (SPEC §6, threat-model sentence):
//   - eth_signTypedData_v4 over EIP-712 is DETERMINISTIC for a fixed (account,
//     domain, message): MetaMask's ECDSA is RFC-6979, so the 65-byte signature —
//     and therefore the derived bjj key — is identical every time the same account
//     signs the same struct. Same account + same pool + same version => same key.
//   - The domain binds chainId + the pool address + a key version, so a signature
//     harvested for one pool/chain/version cannot derive the key for another, and a
//     phishing site cannot present a raw string that silently yields the spending
//     key (personal_sign is wallet-nondeterministic AND a phishing primitive).
//
// THREAT MODEL (SPEC §5.1): the MetaMask signature IS the spending key. Anyone who
// can make the account sign this exact struct can reconstruct the bjj key. v1 is
// EOA + deterministic ECDSA only (MetaMask pinned); 4337 accounts need a different
// derivation (v1.1).

import { hexToBytes, keccak256 } from "viem";
import { deriveKeypair } from "@bongtu/core/note";
import type { Keypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { SUBGROUP_ORDER } from "@bongtu/core/babyjub";
import { ml_kem768 } from "@bongtu/core/kem";

/** The wallet's deterministic ML-KEM-768 keypair — the PQ leg of the consumer
 *  view identity (OPMOD §3.1). `ek` is registered/published (1184 B); `dk`
 *  decapsulates consumer receiver cts (2400 B) and never leaves memory. */
export interface KemKeypair {
  ek: Uint8Array;
  dk: Uint8Array;
}

/** The derived wallet identity: the bjj SPEND keypair, plus — for consumer
 *  wallets — the note-layer VIEW identity (OPMOD §3.1). Commitments and
 *  nullifiers keep using `keypair` (spend) exclusively — the untyped-note
 *  invariant. The view fields are OPTIONAL because enterprise flows (e.g. the
 *  sweeper's synthetic portal identity) never carry or read view material;
 *  consumer code takes `ConsumerWalletIdentity`, where they are required. */
export interface WalletIdentity {
  /** the bjj spending keypair (formattedPrivateKey + publicKey point) — unchanged. */
  keypair: Keypair;
  /** compressed bjj pubkey ("0x" + 32-byte hex) — the wallet's receive address. */
  compressedPubkey: string;
  /** the bjj VIEW keypair (viewPriv, viewPub = viewPriv·Base8) — consumer
   *  receiver cts ECDH against viewPub, never the spend key. Absent on
   *  enterprise-only identities. */
  viewKeypair?: Keypair;
  /** compressed bjj view pubkey ("0x" + 32-byte hex) — the registry's noteViewPub leg. */
  compressedViewPubkey?: string;
  /** deterministic ML-KEM-768 keypair — the registry's kemEk leg + its dk. */
  kemKeypair?: KemKeypair;
}

/** A wallet identity whose consumer view identity is present — what the
 *  signature derivation always produces. The view identity =
 *  (viewKeypair.formattedPrivateKey, kemKeypair.dk) as a pair: both are needed
 *  to decrypt consumer receiver cts, neither can spend. */
export interface ConsumerWalletIdentity extends WalletIdentity {
  viewKeypair: Keypair;
  compressedViewPubkey: string;
  kemKeypair: KemKeypair;
}

/** An EIP-712 typed-data payload ready for `signer._signTypedData(domain, types, message)`
 *  / `eth_signTypedData_v4`. */
export interface KeyDerivationTypedData {
  domain: {
    name: string;
    version: string;
    chainId: number;
    verifyingContract: string;
  };
  types: Record<string, { name: string; type: string }[]>;
  primaryType: string;
  message: Record<string, string>;
}

/**
 * The domain-separated struct the wallet asks MetaMask to sign (SPEC §6). The
 * spending key is a pure function of this payload + the signing account, so the
 * exact bytes here are consensus-critical: changing `name`/`version`/the message
 * text rotates every user's key. `verifyingContract` = the pool, `chainId` +
 * `version` complete the separation.
 */
export function keyDerivationTypedData(
  chainId: number,
  poolAddress: string,
  version: string,
): KeyDerivationTypedData {
  return {
    domain: {
      name: "bongtu",
      version,
      chainId,
      verifyingContract: poolAddress,
    },
    types: {
      // EIP712Domain is filled in by the wallet / ethers automatically.
      BongtuSpendingKey: [
        { name: "statement", type: "string" },
        { name: "warning", type: "string" },
      ],
    },
    primaryType: "BongtuSpendingKey",
    message: {
      statement: "Derive my bongtu BabyJubJub spending key for this pool.",
      warning:
        "Signing this message reveals your bongtu spending key to whoever requested it. " +
        "Only sign inside the official bongtu wallet.",
    },
  };
}

/**
 * The KDF: keccak256 of the raw signature, reduced mod the BabyJubJub prime-order
 * subgroup order L. Reducing mod L (not the base-field prime) yields a canonical
 * spending scalar in [1, L) — exactly the "formatted private key" the circuit
 * consumes (A = s·Base8) and the nullifier preimage. Throws only on the (~2^-252)
 * degenerate all-zero reduction.
 */
export function scalarFromSignature(signature: string): bigint {
  // keccak256 over the DECODED signature bytes (viem hashes the hex-decoded
  // bytes exactly as ethers.utils.keccak256 did — the determinism fixture test
  // pins the derived key against the pre-migration value).
  const digest = BigInt(keccak256(signature as `0x${string}`));
  const s = digest % SUBGROUP_ORDER;
  if (s === 0n) {
    throw new Error("scalarFromSignature: signature hashed to 0 mod L (astronomically rare). Re-sign");
  }
  return s;
}

// ── Consumer view identity (OPMOD §3.1) ────────────────────────────────────────
//
// One seed, three derivations. The same 65-byte signature that yields spendPriv
// also yields the note-layer view scalar and the ML-KEM keypair, each behind
// keccak under a DISTINCT ascii suffix tag appended to the raw signature BYTES:
//
//   spendPriv = keccak256(sig)                                    mod L   (UNCHANGED)
//   viewPriv  = keccak256(bytes(sig) ‖ ascii("bongtu/view-key/v1")) mod L
//   kemSeed   = keccak256(bytes(sig) ‖ ascii("bongtu/consumer-kem/v1/d"))
//             ‖ keccak256(bytes(sig) ‖ ascii("bongtu/consumer-kem/v1/z"))  (64 B)
//   (ek, dk)  = ML-KEM-768.keygen(kemSeed)
//
// Recovery stays "re-sign the same struct", and viewPriv/dk are not computable
// FROM spendPriv (they hang off the raw signature, behind keccak), so handing
// the view pair to a delegated scanner never leaks spend authority. These are
// the note-layer keys — DISTINCT from the stealth meta-address pair
// (stealthKeys.ts), which signs a different EIP-712 struct entirely.

const VIEW_KEY_TAG = "bongtu/view-key/v1";
const KEM_SEED_TAG_D = "bongtu/consumer-kem/v1/d";
const KEM_SEED_TAG_Z = "bongtu/consumer-kem/v1/z";

/** keccak256 over the decoded signature bytes with an ascii tag appended. */
function taggedSignatureDigest(signature: string, tag: string): Uint8Array {
  const sig = hexToBytes(signature as `0x${string}`);
  const tagBytes = new TextEncoder().encode(tag);
  const preimage = new Uint8Array(sig.length + tagBytes.length);
  preimage.set(sig, 0);
  preimage.set(tagBytes, sig.length);
  return hexToBytes(keccak256(preimage));
}

/** The view-scalar KDF: keccak256(bytes(sig) ‖ VIEW_KEY_TAG) mod L, with the
 *  same canonical reduction and (~2^-252) zero rejection as the spend path. */
export function viewScalarFromSignature(signature: string): bigint {
  const digest = taggedSignatureDigest(signature, VIEW_KEY_TAG);
  const s = digest.reduce<bigint>((v, b) => (v << 8n) | BigInt(b), 0n) % SUBGROUP_ORDER;
  if (s === 0n) {
    throw new Error("viewScalarFromSignature: signature hashed to 0 mod L (astronomically rare). Re-sign");
  }
  return s;
}

/** The 64-byte (d ‖ z) ML-KEM-768 keygen seed, tag-derived from the signature. */
export function kemSeedFromSignature(signature: string): Uint8Array {
  const d = taggedSignatureDigest(signature, KEM_SEED_TAG_D);
  const z = taggedSignatureDigest(signature, KEM_SEED_TAG_Z);
  const seed = new Uint8Array(64);
  seed.set(d, 0);
  seed.set(z, 32);
  return seed;
}

/**
 * Full derivation: a MetaMask signature over the domain struct -> the wallet
 * identity (bjj spend keypair + compressed receive pubkey + the consumer view
 * identity: bjj view keypair + deterministic ML-KEM-768 keypair).
 * Deterministic in `signature`.
 */
export function deriveIdentityFromSignature(signature: string): ConsumerWalletIdentity {
  const scalar = scalarFromSignature(signature);
  const keypair = deriveKeypair(scalar);
  const viewKeypair = deriveKeypair(viewScalarFromSignature(signature));
  const kem = ml_kem768.keygen(kemSeedFromSignature(signature));
  return {
    keypair,
    compressedPubkey: packPubkey(keypair.publicKey),
    viewKeypair,
    compressedViewPubkey: packPubkey(viewKeypair.publicKey),
    kemKeypair: { ek: kem.publicKey, dk: kem.secretKey },
  };
}
