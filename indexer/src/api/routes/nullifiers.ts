import type { Route } from "../router.js";

// SPEC §6b `/nullifiers` (PUBLIC — always registered). The spent nullifier set
// collected from Transferred / Withdrawn / Disbursed events, as a plain string[]
// of decimal nullifiers. Cheap and key-free: a wallet or auditor uses it to tell
// whether a note it already knows has been spent, WITHOUT any envelope decrypt.
// Zero (padded/disabled) nullifiers are never included — the contract skips them.
export const nullifiers: Route = {
  method: "GET",
  pattern: "/nullifiers",
  handle({ ix }) {
    return { status: 200, body: ix.store.nullifiers() };
  },
};
