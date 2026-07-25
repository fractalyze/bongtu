import type { Route } from "../router.js";

// SPEC §6b `/alarms`: every non-passing disclosure (mismatch = proven tamper,
// unverifiable/withheld = publication gap for the auditor to judge).
export const alarms: Route = {
  method: "GET",
  pattern: "/alarms",
  handle({ ix }) {
    return { status: 200, body: ix.store.getAlarms() };
  },
};
