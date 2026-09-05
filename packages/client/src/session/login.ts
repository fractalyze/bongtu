// Logging in, as a flow rather than as React (the runSpendChain/runDeposit pattern): open
// the wallet, derive the identity, CHECK it, trade it for a view token, persist. The
// shell (App.connectWallet) is left with the parts that are genuinely its own — the
// lock, the screen state, the one-shot read a tokenless session does.
//
// The order below is the security-relevant part and is the reason this is not inline
// in a component: BOTH refusals happen before anything is written. A wallet that
// derived the wrong key must not overwrite the session record or the remembered
// binding — the stored pubkey is the user's only pointer back to notes that a
// randomised signature would otherwise strand (the guard section below).

import type { WalletIdentity } from "@bongtu/client/derive";
import type { LoginSignaturePlan } from "@bongtu/client/identity";
import { obtainViewToken } from "@bongtu/core/indexerApi";
import type { Connection } from "@bongtu/client/rail";
import { SessionStore, type StoredSession, type WalletTransport } from "./session.js";
export type { WalletTransport } from "./session.js";

export interface LoginContext {
  indexerUrl: string;
}

/** Every I/O edge a login touches, injectable so the refusals gate headlessly.
 *  Generic in the rail's own Connection shape (`C`), inferred from
 *  `openConnection`, so a caller gets its rail's full connection back out of
 *  the LoginResult rather than the engine's structural seam slice. */
export interface RunLoginDeps<C extends Connection = Connection> {
  /** The wallet the connect modal just opened (treasury-web wagmi.ts
   *  requireConnection). Its `transport` decides the determinism rule below — a
   *  WalletConnect wallet this browser has never derived under pays the double
   *  signature. */
  openConnection: () => Promise<C>;
  /** Prompt the wallet onto the live chain BEFORE anything signs: the derivation's
   *  typed data pins domain.chainId to it, and wallets reject a v4 request whose
   *  domain chain differs from the active one — a wallet on another network
   *  must get the add/switch prompt, not raw provider text. */
  ensureChain: (connection: C) => Promise<void>;
  deriveIdentity: (connection: C, plan: LoginSignaturePlan) => Promise<WalletIdentity>;
  obtainViewToken: typeof obtainViewToken;
  loadKeyBinding: (eoaAddress: string) => string | null;
  saveKeyBinding: (eoaAddress: string, compressedPubkey: string) => void;
  saveSession: (session: StoredSession) => void;
}

/** What every login must be handed: how to reach a wallet (`openConnection` — the
 *  wagmi edge), how to derive under this deployment's KDF config
 *  (`deriveIdentity` — deriveLoginIdentity partially applied), and the rail's
 *  chain guard (`ensureChain` — a rail-client edge since the rail split, so the
 *  engine's own defaults stay rail-free). The remaining engine-side edges
 *  default to the real ones. */
export type LoginIo<C extends Connection = Connection> = Pick<
  RunLoginDeps<C>,
  "openConnection" | "deriveIdentity" | "ensureChain"
> &
  Partial<RunLoginDeps<C>>;

// ONE store over the browser's real localStorage: every storage edge of a
// default-wired login goes through the same receiver (arrow-bound methods, so
// plucking them here keeps `this`).
const sessionStore = new SessionStore();

const DEFAULT_DEPS: Omit<RunLoginDeps, "openConnection" | "deriveIdentity" | "ensureChain"> = {
  obtainViewToken,
  loadKeyBinding: sessionStore.loadKeyBinding,
  saveKeyBinding: sessionStore.saveKeyBinding,
  saveSession: sessionStore.saveSession,
};

export interface LoginResult<C extends Connection = Connection> {
  connection: C;
  /** The derived spending identity. The caller hands it to the lock and drops it —
   *  nothing here persists it (KEY-CUSTODY RULE, see session.ts). */
  identity: WalletIdentity;
  session: StoredSession;
  /** True when the indexer issued no view token: the session is page-local, is NOT
   *  persisted, and the caller must load owner data ONCE with the key it still holds. */
  tokenless: boolean;
}

/**
 * Open a wallet and log in with it. Throws with a user-readable message when the
 * wallet cannot be trusted to reproduce this account's key — and when it throws,
 * nothing has been written.
 */
export async function runLogin<C extends Connection>(
  ctx: LoginContext,
  deps: LoginIo<C>,
): Promise<LoginResult<C>> {
  const io: RunLoginDeps<C> = { ...DEFAULT_DEPS, ...deps };
  const connection = await io.openConnection();
  await io.ensureChain(connection);

  // What this browser last saw this account derive — the reference both checks use.
  const known = io.loadKeyBinding(connection.address);
  const identity = await io.deriveIdentity(connection, {
    doubleSign: loginNeedsDeterminismCheck(connection.transport, known),
  });
  assertKeyUnchanged(identity.compressedPubkey, known);

  const { session, tokenless } = await (async (): Promise<{ session: StoredSession; tokenless: boolean }> => {
    try {
      const view = await io.obtainViewToken(
        ctx.indexerUrl,
        identity.compressedPubkey,
        identity.keypair.formattedPrivateKey,
      );
      const authed: StoredSession = {
        eoaAddress: connection.address,
        compressedPubkey: identity.compressedPubkey,
        token: view.token,
        exp: view.exp,
        transport: connection.transport,
      };
      io.saveSession(authed); // address + pubkey + view token; never key material
      return { session: authed, tokenless: false };
    } catch {
      // An indexer without /auth (older build) or an unreachable one: log in for this
      // page only. loadSession drops tokenless records, so this is never persisted.
      return {
        session: {
          eoaAddress: connection.address,
          compressedPubkey: identity.compressedPubkey,
          token: "",
          exp: 0,
          transport: connection.transport,
        },
        tokenless: true,
      };
    }
  })();

  // Recorded even for a tokenless login: the binding is about which key the ACCOUNT
  // derives, which the indexer has no say in.
  io.saveKeyBinding(connection.address, identity.compressedPubkey);
  return { connection, identity, session, tokenless };
}

/** The deps seam a tokenless app fills in: same as LoginIo, minus the view-token
 *  slot — by type, a caller cannot even supply one. */
export type TokenlessLoginIo<C extends Connection = Connection> = Pick<
  RunLoginDeps<C>,
  "openConnection" | "deriveIdentity" | "ensureChain"
> &
  Partial<Omit<RunLoginDeps<C>, "obtainViewToken">>;

/** The consumer login: identical flow and refusal ordering, but the view-token
 *  step is refused INSIDE the engine, so the flow lands on its tokenless branch
 *  every time. Exists so a tokenless app never names the token machinery at all —
 *  "no view-token session" becomes a property of the wiring, not of app
 *  discipline (the consumer contract: every read is public). */
export async function runTokenlessLogin<C extends Connection>(
  ctx: LoginContext,
  deps: TokenlessLoginIo<C>,
): Promise<LoginResult<C>> {
  return runLogin(ctx, {
    ...deps,
    obtainViewToken: () => Promise.reject(new Error("tokenless login requested a view token")),
  });
}
// When a login must sign TWICE, and when a login must be REFUSED.
//
// The whole wallet rests on one assumption (derive.ts): eth_signTypedData_v4 is
// DETERMINISTIC, so the same account signing the same struct always yields the same
// 65 bytes and therefore the same bjj spending key. MetaMask's ECDSA is RFC-6979, so
// that holds for the injected path and always has.
//
// WalletConnect breaks the assumption open: the signer is now whatever wallet app the
// user scanned with, and a wallet that adds randomness to its ECDSA nonce produces a
// DIFFERENT signature — hence a different key, hence an empty balance and notes that
// nothing can spend — on every single login. Nothing on the wire distinguishes that
// wallet from a good one, so the only way to find out is to look:
//
//   FIRST WalletConnect login on this browser (nothing remembered for the account):
//     ask for the same signature twice and require byte-equality. Two popups, once,
//     and only for a wallet we have never derived under.
//   ANY login where this browser already remembers a key for the account:
//     the freshly derived key must BE that key. One popup, and the check is free —
//     it is the same comparison, against a stronger reference.
//
// Both refusals are hard: the login stops and nothing stored is overwritten, because
// overwriting the remembered key is exactly how a user would lose sight of their notes.


export const NONDETERMINISTIC_WALLET_MESSAGE =
  "This wallet signed the same message two different ways, so it can't produce a stable " +
  "bongtu key, so every login would look like a different account. Connect with a wallet " +
  "that signs deterministically.";

export const KEY_CHANGED_MESSAGE =
  "This wallet produced a different signing key than last time. It may not support " +
  "deterministic signatures. Use the wallet you first connected with.";

/** Hex from two different wallets can differ in case and padding whitespace and still
 *  be the same bytes (the KDF hashes the decoded bytes, so case is not a difference). */
function sameHex(a: string, b: string): boolean {
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * Whether this login has to spend the second signature: a WalletConnect wallet this
 * browser has never derived a key under. An injected wallet never does (MetaMask-class
 * determinism is established), and neither does any account we already remember a key
 * for — there the remembered key is the better reference.
 */
export function loginNeedsDeterminismCheck(
  transport: WalletTransport,
  knownPubkey: string | null,
): boolean {
  return transport === "walletconnect" && knownPubkey === null;
}

/** Refuse a wallet whose two signatures over the SAME struct differ. */
export function assertDeterministicSignatures(first: string, second: string): void {
  if (!sameHex(first, second)) throw new Error(NONDETERMINISTIC_WALLET_MESSAGE);
}

/**
 * Refuse a login that derived a different key than this browser last recorded for the
 * account. `knownPubkey === null` (a first login here) passes — there is nothing to
 * contradict yet.
 */
export function assertKeyUnchanged(derivedPubkey: string, knownPubkey: string | null): void {
  if (knownPubkey !== null && !sameHex(derivedPubkey, knownPubkey)) {
    throw new Error(KEY_CHANGED_MESSAGE);
  }
}
