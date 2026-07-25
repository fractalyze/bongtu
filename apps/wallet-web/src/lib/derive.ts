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

import { ethers } from "ethers";
import { deriveKeypair } from "@bongtu/sdk/note";
import type { Keypair } from "@bongtu/sdk/note";
import { packPubkey } from "@bongtu/sdk/pubkey";
import { SUBGROUP_ORDER } from "@bongtu/sdk/babyjub";

/** The derived wallet identity: the bjj keypair plus its compressed public key —
 *  the RECEIVE identifier a payer types into their wallet to pay this user. */
export interface WalletIdentity {
  /** the bjj spending keypair (formattedPrivateKey + publicKey point). */
  keypair: Keypair;
  /** compressed bjj pubkey ("0x" + 32-byte hex) — the wallet's receive address. */
  compressedPubkey: string;
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
  const digest = BigInt(ethers.utils.keccak256(signature));
  const s = digest % SUBGROUP_ORDER;
  if (s === 0n) {
    throw new Error("scalarFromSignature: signature hashed to 0 mod L (astronomically rare) — re-sign");
  }
  return s;
}

/**
 * Full derivation: a MetaMask signature over the domain struct -> the wallet
 * identity (bjj keypair + compressed receive pubkey). Deterministic in `signature`.
 */
export function deriveIdentityFromSignature(signature: string): WalletIdentity {
  const scalar = scalarFromSignature(signature);
  const keypair = deriveKeypair(scalar);
  return { keypair, compressedPubkey: packPubkey(keypair.publicKey) };
}
