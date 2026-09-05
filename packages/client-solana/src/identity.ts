// Spending-key derivation — the Solana wiring around @bongtu/client/derive,
// the sibling of @bongtu/client-evm/identity. The KDF core (signature bytes in,
// bjj/view/KEM identity out), the key-binding store, and the refusal messages
// all stay in the rail-agnostic engine; this module is the signMessage edge
// plus the ONE rule that is deliberately STRICTER here than on EVM:
//
//   doubleSign on EVERY first derivation for an account this browser has no
//   stored key binding for — regardless of transport.
//
// Why stricter (the OPEN-2 determinism audit): RFC 8032 ed25519 is
// deterministic by construction, so Phantom/Solflare/Backpack local signers
// and Ledger are safe — but MPC/TSS/KMS-backed wallets (embedded-wallet KMS,
// Privy, Web3Auth, Fireblocks-class custody) inject per-signing randomness in
// threshold nonce generation, and NO Solana standard forbids that: the Wallet
// Standard says nothing about signMessage determinism. On EVM the injected
// path had one pinned deterministic brand (MetaMask, RFC 6979); on Solana no
// brand is pinned, so nothing on the wire distinguishes an MPC signer from a
// good one. The double-sign-then-byte-compare is therefore load-bearing — the
// ONLY defense against the MPC class and against wallet envelope migrations
// (the sRFC 38 risk noted in derive.ts) — not belt-and-braces.
//
// Both refusals reuse the engine machinery unchanged: two first-login
// signatures that differ throw NONDETERMINISTIC_WALLET_MESSAGE; a later login
// deriving a different key than the stored binding throws KEY_CHANGED_MESSAGE;
// either way runLogin has written nothing (session/login.ts owns the ordering).
//
// KEY-CUSTODY RULE (unchanged from the EVM wiring): the derived identity lives
// in memory only — the caller hands it to the lock and drops it.

import {
  deriveIdentityFromSignature,
  type ConsumerWalletIdentity,
  type WalletIdentity,
} from "@bongtu/client/derive";
import type { LoginSignaturePlan } from "@bongtu/client/identity";
import { assertDeterministicSignatures } from "@bongtu/client/login";
import {
  runTokenlessLogin,
  type LoginContext,
  type LoginResult,
  type RunLoginDeps,
  type TokenlessLoginIo,
} from "@bongtu/client/login";
import { SessionStore } from "@bongtu/client/session";
import type { SolanaKdfConfig } from "./derive.js";
import { ensureSolanaCluster, signKeyDerivation, type SolanaConnection } from "./connection/edge.js";

/**
 * Whether this derivation must spend the second signature: yes exactly when
 * this browser remembers NO key for the account. Unlike the EVM
 * loginNeedsDeterminismCheck the transport plays no role (see the module doc);
 * once a binding exists, the binding itself is the stronger reference and one
 * signature checked against it suffices (assertKeyUnchanged, engine-side).
 */
export function solanaLoginNeedsDeterminismCheck(knownPubkey: string | null): boolean {
  return knownPubkey === null;
}

/**
 * One signMessage popup over the derivation payload -> the full wallet
 * identity. `plan.doubleSign` asks for the same signature a SECOND time and
 * refuses the pair if the bytes differ — spent per the stricter rule above.
 * Deterministic per (account, cluster, program, key version) for the
 * supported wallet class, so a derivation after any wipe reproduces the SAME
 * key the wallet's notes are owned by.
 */
export async function deriveSolanaLoginIdentity(
  connection: SolanaConnection,
  plan: LoginSignaturePlan,
  kdf: SolanaKdfConfig,
  sign: typeof signKeyDerivation = signKeyDerivation,
): Promise<ConsumerWalletIdentity> {
  const sig = await sign(connection, kdf);
  if (plan.doubleSign) assertDeterministicSignatures(sig, await sign(connection, kdf));
  return deriveIdentityFromSignature(sig);
}

/** The lock's lazy re-derive (keyCache wiring): always a single signature — by
 *  the time a key is re-derived the login has established determinism, and the
 *  lock checks the derived key against the session's anyway. */
export function deriveTransientSolanaIdentity(
  connection: SolanaConnection,
  kdf: SolanaKdfConfig,
): Promise<WalletIdentity> {
  return deriveSolanaLoginIdentity(connection, { doubleSign: false }, kdf);
}

/** What a Solana login must be handed: the wallet edge and the deployment's
 *  KDF domain facts (derive.ts solanaKeyDerivation). Everything else — the
 *  binding store, the session store, the cluster guard — defaults to the real
 *  ones and stays injectable for the headless suite. */
export type SolanaLoginIo<C extends SolanaConnection> = {
  openConnection: () => Promise<C>;
  kdf: SolanaKdfConfig;
} & Partial<Omit<RunLoginDeps<C>, "openConnection" | "deriveIdentity" | "obtainViewToken">>;

/**
 * The Solana login: the engine's runTokenlessLogin (this rail's reads are the
 * PUBLIC feed — the consumer contract — so no view token exists to obtain)
 * with the derivation plan recomputed under the stricter rule. The engine
 * still computes its own transport-based plan; this wiring recomputes
 * doubleSign from the SAME key-binding store the login reads, so the plan the
 * signature edge actually executes is `known === null`, regardless of what
 * the connection's transport tag would have said. Refusal ordering, binding
 * writes, and the KEY_CHANGED check remain the engine's, unchanged.
 */
export function runSolanaLogin<C extends SolanaConnection>(
  ctx: LoginContext,
  deps: SolanaLoginIo<C>,
): Promise<LoginResult<C>> {
  const store = new SessionStore();
  const loadKeyBinding = deps.loadKeyBinding ?? store.loadKeyBinding;
  const io: TokenlessLoginIo<C> = {
    ...deps,
    loadKeyBinding,
    ensureChain: deps.ensureChain ?? ((connection) => ensureSolanaCluster(connection, deps.kdf.genesisHash)),
    deriveIdentity: (connection) =>
      deriveSolanaLoginIdentity(
        connection,
        { doubleSign: solanaLoginNeedsDeterminismCheck(loadKeyBinding(connection.address)) },
        deps.kdf,
      ),
  };
  return runTokenlessLogin(ctx, io);
}
