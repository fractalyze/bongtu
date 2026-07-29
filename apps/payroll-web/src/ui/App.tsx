// bongtu payroll — the login-gated shell (LOCKED design, 2026-07-29): a Login
// page and the one Console page, nothing else. The session IS the in-memory
// KeyCache hold (lib/keyCache.ts): logging in chains connect -> EIP-712 sign
// (the SHARED @bongtu/client KDF, so this console derives exactly the wallet's
// key for the same account) -> seed the lock -> Console. Nothing is persisted,
// so a page refresh — and the lock's own 10-minute idle wipe, and an account
// switch in the wallet — all land back on Login.

import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { ToastHost } from "@bongtu/ui/Toast";
import { KEY_DERIVATION, deriveLoginIdentity } from "@bongtu/client/identity";
import { ensureChain, type Connection } from "@bongtu/client/connection";
import { obtainViewToken } from "@bongtu/client/indexerClient";
import { DEFAULTS } from "../config.js";
import { payrollErrorMessage } from "../lib/errors.js";
import { openInjectedConnection, watchInjectedAccount } from "../lib/connect.js";
import { keyCache } from "../lib/keyCache.js";
import { toasts } from "../lib/toasts.js";
import { Console } from "./Console.js";
import { Login } from "./Login.js";

interface AdminSession {
  connection: Connection;
  /** the employer's compressed bjj pubkey — what every note read/spend is keyed on. */
  pubkey: string;
  /** the indexer's view token, or null when the indexer has no /auth — then the
   *  Console signs its reads with the held key instead. In-memory only, like
   *  everything else about this login. */
  viewToken: string | null;
}

export function App(): ReactNode {
  const [session, setSession] = useState<AdminSession | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);

  const signOut = useCallback((): void => {
    keyCache.lock();
    toasts.clear();
    setSession(null);
  }, []);

  // The session lives exactly as long as the lock holds the key: the idle wipe
  // (or an explicit lock) drops the page back to Login — an admin console must
  // not keep rendering balances for a key it no longer holds.
  useEffect(() => {
    return keyCache.subscribe(() => {
      if (!keyCache.isUnlocked()) setSession(null);
    });
  }, []);

  // A held spending key belongs to ONE wallet account; a switch ends the session.
  useEffect(() => watchInjectedAccount(signOut), [signOut]);

  const login = useCallback(async (): Promise<void> => {
    setConnecting(true);
    setLoginError(null);
    try {
      const connection = await openInjectedConnection();
      // The derivation's typed data pins domain.chainId to GIWA, and wallets
      // reject a v4 request whose domain chain differs from the active one — so
      // the add/switch prompt must come BEFORE the signature.
      await ensureChain(connection);
      // Injected wallets are MetaMask-class deterministic signers — no
      // double-sign check needed (loginGuard's rule for the injected transport).
      const identity = await deriveLoginIdentity(connection, { doubleSign: false }, KEY_DERIVATION);
      // The login popup already paid for the key: hand it to the lock so the
      // whole session runs on it (idle-wiped, memory-only).
      keyCache.seed(identity, connection.address, identity.compressedPubkey);
      // Trade the key for a view token while it is in hand, so background
      // balance reads never need it again. An indexer without /auth just means
      // key-signed reads (Console handles both).
      let viewToken: string | null = null;
      try {
        const view = await obtainViewToken(
          DEFAULTS.indexerUrl,
          identity.compressedPubkey,
          identity.keypair.formattedPrivateKey,
        );
        viewToken = view.token;
      } catch {
        viewToken = null;
      }
      setSession({ connection, pubkey: identity.compressedPubkey, viewToken });
    } catch (e) {
      // The login's own inline slot, in the console's Korean — a declined signature
      // is the most common outcome here and must not read as an English error.
      setLoginError(payrollErrorMessage(e));
    } finally {
      setConnecting(false);
    }
  }, []);

  return (
    <div className="relative min-h-full">
      {session ? (
        <Console
          connection={session.connection}
          pubkey={session.pubkey}
          viewToken={session.viewToken}
          onLogout={signOut}
        />
      ) : (
        <Login onLogin={() => void login()} busy={connecting} error={loginError} />
      )}
      <ToastHost queue={toasts} />
    </div>
  );
}
