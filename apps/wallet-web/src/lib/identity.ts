// Spending-key derivation (the browser wiring around derive.ts).
//
// KEY-CUSTODY RULE (user-mandated): the bjj private key may live in MEMORY ONLY.
// It is never written to localStorage / sessionStorage / IndexedDB / cookies, never
// put in React state, and never survives a page load. Between actions it is held by
// exactly one module — keyCache.ts, the wallet's lock, which drops it on logout, on
// an account switch, and after 10 idle minutes. Flows take their identity from that
// lock, and the login hands what it derives straight to the lock (keyCache.seed);
// nothing else may keep the value this function returns.

import { DEFAULTS } from "../config.js";
import {
  keyDerivationTypedData,
  deriveIdentityFromSignature,
  type WalletIdentity,
} from "./derive.js";
import { signKeyDerivation, type Connection } from "./metamask.js";

/**
 * One eth_signTypedData_v4 popup in the connected wallet -> the full wallet identity
 * (bjj keypair + compressed pubkey). Deterministic per (account, pool, key version),
 * so a derivation after any wipe reproduces the SAME key the session's notes are
 * owned by — which is what makes re-locking cheap to recover from.
 *
 * The ONE derivation site: the login (App.connectWallet, which then seeds the lock)
 * and the lock's own lazy derive both come through here, so the two can never drift
 * into deriving different keys from the same account.
 */
export async function deriveTransientIdentity(connection: Connection): Promise<WalletIdentity> {
  const typed = keyDerivationTypedData(DEFAULTS.chainId, DEFAULTS.pool, DEFAULTS.keyVersion);
  const sig = await signKeyDerivation(connection, typed);
  return deriveIdentityFromSignature(sig);
}

// No brand name: the connected wallet may be any injected wallet (walletBrand.ts), and
// this message is thrown from a pure module that cannot see which one.
export const ACCOUNT_MISMATCH_MESSAGE =
  "This account doesn't match your signed-in wallet — switch back or reconnect.";

/**
 * Refuse to act under a key that is not the logged-in session's.
 *
 * The derivation above resolves whatever account the wallet has selected AT DERIVE
 * TIME (the ethers signer follows the extension, not the stored session), so a
 * mid-session account switch would otherwise mint or spend under a different
 * person's bjj key — silently, since the flow only ever sees "an identity".
 * keyCache.unlock runs this on every key it derives, before handing it out.
 */
export function assertSessionIdentity(derivedCompressedPubkey: string, sessionCompressedPubkey: string): void {
  const norm = (k: string): string => k.trim().toLowerCase();
  if (norm(derivedCompressedPubkey) !== norm(sessionCompressedPubkey)) {
    throw new Error(ACCOUNT_MISMATCH_MESSAGE);
  }
}
