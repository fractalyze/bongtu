// Spending-key derivation (the browser wiring around derive.ts).
//
// KEY-CUSTODY RULE (user-mandated): the bjj private key may live in MEMORY ONLY.
// It is never written to localStorage / sessionStorage / IndexedDB / cookies, never
// put in React state, and never survives a page load. Between actions it is held by
// exactly one module — keyCache.ts, the wallet's lock, which drops it on logout, on
// an account switch, and after 10 idle minutes. Flows take their identity from that
// lock, and the login hands what it derives straight to the lock (keyCache.seed);
// nothing else may keep the value this function returns.

import { CHAIN_ID, POOL_ADDRESS } from "@bongtu/core/network";
import {
  keyDerivationTypedData,
  deriveIdentityFromSignature,
  type WalletIdentity,
} from "@bongtu/client/derive";
import { assertDeterministicSignatures } from "@bongtu/client/login";
import { signKeyDerivation, type Connection } from "@bongtu/client/connection";

/** Whether this derivation has to prove the wallet is deterministic before trusting
 *  what it signed (session/login.ts loginNeedsDeterminismCheck decides). */
export interface LoginSignaturePlan {
  doubleSign: boolean;
}

/** The EIP-712 domain facts the KDF signs over (SPEC §6). Same values => same
 *  struct => same derived key, so a deployment must pass identical values
 *  everywhere it derives — which is why the deployment's own values live below
 *  (KEY_DERIVATION), not per app. */
export interface KeyDerivationConfig {
  chainId: number;
  pool: string;
  keyVersion: string;
  /** Stealth KDF domain version (stealthKeys.ts): part of the BongtuStealthKey
   *  EIP-712 domain. Rotating it rotates every stealth meta key — and orphans
   *  announced-but-unswept one-time addresses — so it is pinned here beside
   *  keyVersion: the deployment's KDF domain facts have ONE home. */
  stealthKeyVersion: string;
}

/** KDF domain version (SPEC §6): part of the EIP-712 domain, so bumping it
 *  rotates every derived key. Pinned per deployment; never silently changed. */
const KEY_VERSION = "1";

/** Stealth KDF domain version — same pinning rule as KEY_VERSION, for the
 *  stealth struct (stealthKeys.stealthKeyTypedData consumes it via KEY_DERIVATION). */
const STEALTH_KEY_VERSION = "1";

/**
 * THIS deployment's KDF domain facts — the ONE home both apps derive under.
 * Built from the sdk deployment facts (@bongtu/core/network, equality-tested
 * against the deploy record), so wallet-web and payroll-web deriving
 * the same key for the same account holds by construction: neither app carries
 * its own copy of these values.
 */
export const KEY_DERIVATION: KeyDerivationConfig = {
  chainId: CHAIN_ID,
  pool: POOL_ADDRESS,
  keyVersion: KEY_VERSION,
  stealthKeyVersion: STEALTH_KEY_VERSION,
};

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

// No brand name: the connected wallet may be any injected wallet (walletBrand.ts), and
// this message is thrown from a pure module that cannot see which one.
export const ACCOUNT_MISMATCH_MESSAGE =
  "This account doesn't match your signed-in wallet — switch back or reconnect.";

/**
 * Refuse to act under a key that is not the logged-in session's.
 *
 * The derivation above resolves whatever account the wallet has selected AT DERIVE
 * TIME (the wagmi account store follows the wallet, not the stored session), so a
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
