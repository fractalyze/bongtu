// Spending-key derivation (the browser wiring around @bongtu/client/derive).
//
// KEY-CUSTODY RULE (user-mandated): the bjj private key may live in MEMORY ONLY.
// It is never written to localStorage / sessionStorage / IndexedDB / cookies, never
// put in React state, and never survives a page load. Between actions it is held by
// exactly one module — keyCache.ts, the wallet's lock, which drops it on logout, on
// an account switch, and after 10 idle minutes. Flows take their identity from that
// lock, and the login hands what it derives straight to the lock (keyCache.seed);
// nothing else may keep the value this function returns.
//
// The KDF domain facts (KEY_DERIVATION) and the session-identity checks stay in
// the rail-agnostic engine (@bongtu/client/identity); this module is the EVM
// wiring that turns them into a signature request and a derived identity.

import {
  deriveIdentityFromSignature,
  type WalletIdentity,
} from "@bongtu/client/derive";
import type { KeyDerivationConfig, LoginSignaturePlan } from "@bongtu/client/identity";
import { assertDeterministicSignatures } from "@bongtu/client/login";
import { keyDerivationTypedData } from "./derive.js";
import { signKeyDerivation, type Connection } from "./connection/index.js";

/**
 * One eth_signTypedData_v4 popup in the connected wallet -> the full wallet identity
 * (bjj keypair + compressed pubkey). Deterministic per (account, pool, key version),
 * so a derivation after any wipe reproduces the SAME key the session's notes are
 * owned by — which is what makes re-locking cheap to recover from.
 *
 * `doubleSign` asks for that same signature a SECOND time and refuses the pair if the
 * bytes differ. It costs a second popup, so it is spent only where the determinism it
 * checks is not already established: the first login of a WalletConnect wallet this
 * browser has never derived under. See session/login.ts for the whole rule.
 *
 * The ONE derivation site: the login (via login.runLogin, which then seeds the
 * lock) and the lock's own lazy derive both come through here, so the two can never
 * drift into deriving different keys from the same account.
 */
export async function deriveLoginIdentity(
  connection: Connection,
  plan: LoginSignaturePlan,
  kdf: KeyDerivationConfig,
  sign: typeof signKeyDerivation = signKeyDerivation,
): Promise<WalletIdentity> {
  const typed = keyDerivationTypedData(kdf.chainId, kdf.pool, kdf.keyVersion);
  const sig = await sign(connection, typed);
  if (plan.doubleSign) assertDeterministicSignatures(sig, await sign(connection, typed));
  return deriveIdentityFromSignature(sig);
}

/** The lock's lazy re-derive (keyCache.unlock). Always a single signature: by the time
 *  a key is re-derived the login has already established that this wallet is
 *  deterministic, and the derived key is checked against the session's anyway. */
export function deriveTransientIdentity(
  connection: Connection,
  kdf: KeyDerivationConfig,
): Promise<WalletIdentity> {
  return deriveLoginIdentity(connection, { doubleSign: false }, kdf);
}
