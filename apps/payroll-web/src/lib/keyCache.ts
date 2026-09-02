// The console's ONE lock instance — the same in-memory-only KeyCache state
// machine the wallet runs (@bongtu/client/keyCache: idle wipe, session-account
// refusals), wired to the injected wallet's live-account read and the SHARED
// KDF config (@bongtu/client/identity KEY_DERIVATION — one home for both apps,
// so the console derives exactly the wallet's key for the same account).
//
// KEY-CUSTODY RULE (user-mandated): the bjj private key may live in memory only.
// The payroll session IS this cache — nothing about a login is persisted, so a
// page refresh means logging in again. That is deliberate for an admin tool.

import { KeyCache } from "@bongtu/client/keyCache";
import { KEY_DERIVATION, deriveTransientIdentity } from "@bongtu/client/identity";
import { deriveStealthKeys } from "@bongtu/client/stealthKeys";
import type { Connection } from "@bongtu/client/connection";
import type { WalletIdentity } from "@bongtu/client/derive";
import type { StealthKeys } from "@bongtu/core/stealth";
import { currentAccount } from "./connect.js";

export const keyCache = new KeyCache({
  derive: (connection: Connection): Promise<WalletIdentity> =>
    deriveTransientIdentity(connection, KEY_DERIVATION),
  // The console has no stealth screen today, but the lock's seam is mandatory:
  // if it ever grows one, the keys can only live here — never beside it.
  deriveStealth: (connection: Connection): Promise<StealthKeys> => deriveStealthKeys(connection),
  currentAccount,
});
