// Logging in, as a flow rather than as React (the spendFlow/depositFlow pattern): open
// the wallet, derive the identity, CHECK it, trade it for a view token, persist. The
// shell (App.connectWallet) is left with the parts that are genuinely its own — the
// lock, the screen state, the one-shot read a tokenless session does.
//
// The order below is the security-relevant part and is the reason this is not inline
// in a component: BOTH refusals happen before anything is written. A wallet that
// derived the wrong key must not overwrite the session record or the remembered
// binding — the stored pubkey is the user's only pointer back to notes that a
// randomised signature would otherwise strand (loginGuard.ts).

import type { WalletIdentity } from "@bongtu/client/derive";
import type { LoginSignaturePlan } from "@bongtu/client/identity";
import { obtainViewToken } from "@bongtu/client/indexerClient";
import { assertKeyUnchanged, loginNeedsDeterminismCheck } from "@bongtu/client/loginGuard";
import { ensureChain } from "@bongtu/client/connection";
import type { Connection } from "@bongtu/client/connection";
import { SessionStore, type StoredSession } from "@bongtu/client/session";

export interface LoginContext {
  indexerUrl: string;
}

/** Every I/O edge a login touches, injectable so the refusals gate headlessly. */
export interface RunLoginDeps {
  /** The wallet the connect modal just opened (wallet-web wagmi.ts
   *  requireConnection). Its `transport` decides the determinism rule below — a
   *  WalletConnect wallet this browser has never derived under pays the double
   *  signature. */
  openConnection: () => Promise<Connection>;
  /** Prompt the wallet onto the live chain BEFORE anything signs: the derivation's
   *  typed data pins domain.chainId to it, and wallets reject a v4 request whose
   *  domain chain differs from the active one — a wallet on another network
   *  must get the add/switch prompt, not raw provider text. */
  ensureChain: (connection: Connection) => Promise<void>;
  deriveIdentity: (connection: Connection, plan: LoginSignaturePlan) => Promise<WalletIdentity>;
  obtainViewToken: typeof obtainViewToken;
  loadKeyBinding: (eoaAddress: string) => string | null;
  saveKeyBinding: (eoaAddress: string, compressedPubkey: string) => void;
  saveSession: (session: StoredSession) => void;
}

/** What every login must be handed: how to reach a wallet (`openConnection` — the
 *  wagmi edge) and how to derive under this deployment's KDF config
 *  (`deriveIdentity` — deriveLoginIdentity partially applied). The engine-side
 *  edges default to the real ones. */
export type LoginIo = Pick<RunLoginDeps, "openConnection" | "deriveIdentity"> & Partial<RunLoginDeps>;

// ONE store over the browser's real localStorage: every storage edge of a
// default-wired login goes through the same receiver (arrow-bound methods, so
// plucking them here keeps `this`).
const sessionStore = new SessionStore();

const DEFAULT_DEPS: Omit<RunLoginDeps, "openConnection" | "deriveIdentity"> = {
  ensureChain,
  obtainViewToken,
  loadKeyBinding: sessionStore.loadKeyBinding,
  saveKeyBinding: sessionStore.saveKeyBinding,
  saveSession: sessionStore.saveSession,
};

export interface LoginResult {
  connection: Connection;
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
export async function runLogin(ctx: LoginContext, deps: LoginIo): Promise<LoginResult> {
  const io: RunLoginDeps = { ...DEFAULT_DEPS, ...deps };
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
