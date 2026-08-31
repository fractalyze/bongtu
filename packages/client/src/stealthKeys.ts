// Stealth meta-key derivation (the browser wiring around @bongtu/core/stealth).
//
// Same shape as the spending-key KDF (derive.ts / identity.ts) with its own
// EIP-712 struct: `BongtuStealthKey` is a DIFFERENT primary type, so its
// signature can never be replayed as (or harvested from) the spending-key
// popup, and vice versa — the domain separation is structural, not
// convention. ONE popup yields both stealth scalars: the view half and the
// spend half are keccak-derived from the same signature under distinct
// suffix tags, each reduced into its own group order (bjj L for the view
// key the announcements are scanned with; secp256k1 N for the key that
// controls the one-time EOAs).
//
// KEY-CUSTODY RULE (identity.ts): stealth scalars are memory-only, exactly
// like the spending key. They are derived at the moment a flow needs them and
// handed to that flow; nothing persists them and no module caches them.
// The exact struct bytes are consensus for which EOAs hold the user's funds:
// changing the statement/version orphans every previously announced address,
// so STEALTH_KEY_VERSION is pinned per deployment like keyVersion.

import { keccak256 } from "viem";
import { SUBGROUP_ORDER } from "@bongtu/core/babyjub";
import {
  SECP256K1_ORDER,
  stealthKeysFromScalars,
  type StealthKeys,
} from "@bongtu/core/stealth";
import type { KeyDerivationTypedData } from "./derive.js";
import { KEY_DERIVATION } from "./identity.js";
import { signKeyDerivation, type Connection } from "./connection.js";

/** Stealth KDF domain version — rotating it rotates every stealth meta key
 *  (and orphans announced-but-unswept addresses). Pinned per deployment. */
export const STEALTH_KEY_VERSION = "1";

/** The EIP-712 struct the stealth popup signs. Distinct primary type from
 *  BongtuSpendingKey — see the module header. */
export function stealthKeyTypedData(
  chainId: number,
  poolAddress: string,
  version: string,
): KeyDerivationTypedData {
  return {
    domain: { name: "bongtu", version, chainId, verifyingContract: poolAddress },
    types: {
      BongtuStealthKey: [
        { name: "statement", type: "string" },
        { name: "warning", type: "string" },
      ],
    },
    primaryType: "BongtuStealthKey",
    message: {
      statement: "Derive my bongtu stealth meta keys for this pool.",
      warning:
        "Signing this message reveals the keys to your stealth (one-time) addresses " +
        "to whoever requested it. Only sign inside the official bongtu wallet.",
    },
  };
}

// Suffix tags folding one signature into two independent scalars. Appended as
// hex BYTES to the signature before hashing, so the two digests share no
// input relation beyond the signature itself.
const VIEW_TAG = "01";
const SPEND_TAG = "02";

/** The stealth KDF: one signature -> (viewPriv mod L, spendPriv mod N). */
export function stealthKeysFromKdfSignature(signature: string): StealthKeys {
  const sig = signature as `0x${string}`;
  const v = BigInt(keccak256(`${sig}${VIEW_TAG}`)) % SUBGROUP_ORDER;
  const s = BigInt(keccak256(`${sig}${SPEND_TAG}`)) % SECP256K1_ORDER;
  if (v === 0n || s === 0n) {
    throw new Error("stealth KDF: signature hashed to 0 mod the group order (astronomically rare). Re-sign");
  }
  return stealthKeysFromScalars(v, s);
}

/**
 * One eth_signTypedData_v4 popup -> the full stealth identity. Deterministic
 * per (account, pool, version): a wiped browser re-derives the SAME meta keys,
 * which is what makes announced addresses recoverable with no seed.
 */
export async function deriveStealthKeys(connection: Connection): Promise<StealthKeys> {
  const typed = stealthKeyTypedData(
    KEY_DERIVATION.chainId,
    KEY_DERIVATION.pool,
    STEALTH_KEY_VERSION,
  );
  const signature = await signKeyDerivation(connection, typed);
  return stealthKeysFromKdfSignature(signature);
}
