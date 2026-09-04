// KEY-CUSTODY RULE (user-mandated): the bjj private key may live in memory only.
// The payroll session IS this cache — nothing about a login is persisted, so a
// page refresh means logging in again; deliberate for an admin tool. Construction
// goes through the shared createKeyCache, so the console derives exactly the
// wallet's key for the same account and carries the stealth seam by construction.

import { createKeyCache } from "@bongtu/client/keyCache";
import { walletEdge } from "./connect.js";

export const keyCache = createKeyCache(walletEdge);
