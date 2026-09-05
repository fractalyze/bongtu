// The deployment's KDF domain facts and the session-identity checks — the
// rail-agnostic half of the spending-key derivation wiring. The EVM signature
// acquisition (the eth_signTypedData_v4 popup, deriveLoginIdentity /
// deriveTransientIdentity) lives in @bongtu/client-evm/identity and derives
// under THIS module's config, so the two apps and the lock can never drift
// into deriving different keys from the same account.

import { CHAIN_ID, POOL_ADDRESS } from "@bongtu/core/network";

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
 * against the deploy record), so treasury-web and payroll-web deriving
 * the same key for the same account holds by construction: neither app carries
 * its own copy of these values.
 */
export const KEY_DERIVATION: KeyDerivationConfig = {
  chainId: CHAIN_ID,
  pool: POOL_ADDRESS,
  keyVersion: KEY_VERSION,
  stealthKeyVersion: STEALTH_KEY_VERSION,
};

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
