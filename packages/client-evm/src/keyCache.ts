// The EVM construction of the wallet's lock. The KeyCache state machine — the
// custody rules, the idle wipe, the session-account checks — is rail-agnostic
// and lives in @bongtu/client/keyCache; this module owns only the wiring that
// binds it to THIS rail's derivations (the EIP-712 spending-key and stealth
// meta-key popups).

import type { StealthKeys } from "@bongtu/core/stealth";
import type { WalletIdentity } from "@bongtu/client/derive";
import { KEY_DERIVATION } from "@bongtu/client/identity";
import { KeyCache } from "@bongtu/client/keyCache";
import { deriveTransientIdentity } from "./identity.js";
import { deriveStealthKeys } from "./stealthKeys.js";
import type { Connection, WalletEdge } from "./connection/index.js";

/**
 * The one sanctioned app construction: wire the lock to the wallet edge's
 * live-account read under the deployment's KDF config, with BOTH derivations
 * (spending + stealth) supplied here. The key-custody rule — no app may hold a
 * cache missing the stealth seam, and both apps must derive the same key for
 * the same account — is structural this way: an app would have to bypass this
 * helper deliberately (and re-wire the derivations by hand) to get anything
 * else. The parameter is the slice the lock actually consumes (apps pass their
 * full WalletEdge, which satisfies it). Each app owns its ONE instance; the
 * flows take it through their deps seam so tests run their own with a fake
 * clock.
 */
export function createKeyCache(edge: Pick<WalletEdge, "currentAccount">): KeyCache {
  return new KeyCache({
    derive: (connection: Connection): Promise<WalletIdentity> =>
      deriveTransientIdentity(connection, KEY_DERIVATION),
    deriveStealth: (connection: Connection): Promise<StealthKeys> => deriveStealthKeys(connection),
    currentAccount: () => edge.currentAccount(),
  });
}
