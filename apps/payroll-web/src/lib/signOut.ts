// The Sign out button's ONE action, as a lib function so the coupling is
// headlessly gated (test/signOut.test.ts): ending the SERVICE session must also
// empty the key lock — a console that lost its login must not keep a spending
// key warm behind the login page. Transient view state (worksheet rows, wallet
// session, dialogs) clears by construction: dropping the service session
// unmounts the Console component, and none of that state is persisted.
//
// App.tsx additionally locks the cache on ANY session drop (the prover
// adapter's 401 path lands there) — this function is the direct button path,
// and the two are idempotent together.

import { keyCache } from "./keyCache.js";
import { serviceAuth } from "./serviceAuth.js";
import { toasts } from "./toasts.js";

/** End the service session AND lock the key cache (and drop queued toasts). */
export function signOutOfService(): void {
  keyCache.lock();
  toasts.clear();
  serviceAuth.drop();
}
