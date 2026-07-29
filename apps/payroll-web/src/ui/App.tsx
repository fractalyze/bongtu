// bongtu payroll — the two-stage shell (LOCKED design): a service Login page
// and the one Console page, nothing else.
//
// The SERVICE session (this file's gate): id/password validated against the
// prover's GET /auth/check and held as an HTTP Basic value in sessionStorage
// (lib/serviceAuth.ts) — a refresh keeps it, closing the browser ends it, and
// a 401 from any later prover call drops it (the adapter calls
// serviceAuth.drop(), the subscription here lands the page back on Login).
//
// The WALLET session lives INSIDE the Console: MetaMask connect → EIP-712
// sign → the in-memory KeyCache hold. Nothing about it is persisted, so a
// refresh, the lock's 10-minute idle wipe, or an account switch all drop the
// wallet session — while the service session stands.

import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { ToastHost } from "@bongtu/ui/Toast";
import { DEFAULTS } from "../config.js";
import { keyCache } from "../lib/keyCache.js";
import { serviceAuth, signInToProver } from "../lib/serviceAuth.js";
import { toasts } from "../lib/toasts.js";
import { Console } from "./Console.js";
import { Login } from "./Login.js";

export function App(): ReactNode {
  const [authed, setAuthed] = useState(() => serviceAuth.header() !== null);
  const [signingIn, setSigningIn] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);

  // The service session's one source of truth is the holder itself: signing in,
  // the Sign out button, and the adapter's 401 path all land here. Ending it
  // also empties the lock — a console that lost its service session must not
  // keep a spending key warm behind the login page.
  useEffect(() => {
    return serviceAuth.subscribe(() => {
      const held = serviceAuth.header() !== null;
      if (!held) {
        keyCache.lock();
        toasts.clear();
      }
      setAuthed(held);
    });
  }, []);

  const signIn = useCallback(async (id: string, password: string): Promise<void> => {
    setSigningIn(true);
    setLoginError(null);
    try {
      const result = await signInToProver(DEFAULTS.proverUrl, id, password);
      if (!result.ok) setLoginError(result.error);
      // ok -> serviceAuth.set already notified; the subscription flips authed.
    } catch {
      setLoginError("Could not reach the prover service. Check the connection and try again.");
    } finally {
      setSigningIn(false);
    }
  }, []);

  return (
    <div className="relative min-h-full">
      {authed ? (
        <Console onSignOut={() => serviceAuth.drop()} />
      ) : (
        <Login onSignIn={(id, pw) => void signIn(id, pw)} busy={signingIn} error={loginError} />
      )}
      <ToastHost queue={toasts} />
    </div>
  );
}
