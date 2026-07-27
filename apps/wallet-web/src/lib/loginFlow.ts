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

import type { WalletIdentity } from "./derive.js";
import { deriveLoginIdentity, type LoginSignaturePlan } from "./identity.js";
import { obtainViewToken } from "./indexerClient.js";
import {
  assertKeyUnchanged,
  loginNeedsDeterminismCheck,
  type WalletTransport,
} from "./loginGuard.js";
import { connect } from "./metamask.js";
import type { Connection } from "./metamask.js";
import { loadKeyBinding, saveKeyBinding, saveSession, type StoredSession } from "./session.js";
import { connectWalletConnect } from "./walletconnect.js";

export interface LoginContext {
  transport: WalletTransport;
  indexerUrl: string;
}

/** Every I/O edge a login touches, injectable so the refusals gate headlessly. */
export interface RunLoginDeps {
  connectInjected: () => Promise<Connection>;
  connectWalletConnect: () => Promise<Connection>;
  deriveIdentity: (connection: Connection, plan: LoginSignaturePlan) => Promise<WalletIdentity>;
  obtainViewToken: typeof obtainViewToken;
  loadKeyBinding: (eoaAddress: string) => string | null;
  saveKeyBinding: (eoaAddress: string, compressedPubkey: string) => void;
  saveSession: (session: StoredSession) => void;
}

const DEFAULT_DEPS: RunLoginDeps = {
  connectInjected: connect,
  connectWalletConnect,
  deriveIdentity: deriveLoginIdentity,
  obtainViewToken,
  loadKeyBinding,
  saveKeyBinding,
  saveSession,
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
export async function runLogin(
  ctx: LoginContext,
  deps: Partial<RunLoginDeps> = {},
): Promise<LoginResult> {
  const io = { ...DEFAULT_DEPS, ...deps };
  const connection =
    ctx.transport === "walletconnect" ? await io.connectWalletConnect() : await io.connectInjected();

  // What this browser last saw this account derive — the reference both checks use.
  const known = io.loadKeyBinding(connection.address);
  const identity = await io.deriveIdentity(connection, {
    doubleSign: loginNeedsDeterminismCheck(ctx.transport, known),
  });
  assertKeyUnchanged(identity.compressedPubkey, known);

  let session: StoredSession;
  let tokenless = false;
  try {
    const view = await io.obtainViewToken(
      ctx.indexerUrl,
      identity.compressedPubkey,
      identity.keypair.formattedPrivateKey,
    );
    session = {
      eoaAddress: connection.address,
      compressedPubkey: identity.compressedPubkey,
      token: view.token,
      exp: view.exp,
      transport: ctx.transport,
    };
    io.saveSession(session); // address + pubkey + view token; never key material
  } catch {
    // An indexer without /auth (older build) or an unreachable one: log in for this
    // page only. loadSession drops tokenless records, so this is never persisted.
    session = {
      eoaAddress: connection.address,
      compressedPubkey: identity.compressedPubkey,
      token: "",
      exp: 0,
      transport: ctx.transport,
    };
    tokenless = true;
  }

  // Recorded even for a tokenless login: the binding is about which key the ACCOUNT
  // derives, which the indexer has no say in.
  io.saveKeyBinding(connection.address, identity.compressedPubkey);
  return { connection, identity, session, tokenless };
}
