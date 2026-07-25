import type { Route } from "../router.js";
import type { Alarm } from "@bongtu/core/indexerApi";

/**
 * The single discriminated alarm feed served by GET /alarms — one wire shape
 * for the auditor console, covering BOTH producers:
 *   - "disclosure": a non-passing disclosureHash check (public data; mismatch =
 *     proven tamper, unverifiable/withheld = publication gap to judge);
 *   - "envelope": an arbiter-mode envelope cross-check failure — the decrypted
 *     authority envelope does not reproduce the on-chain commitments, i.e. the
 *     proof that a publisher lied about note contents (SPEC §6b: first-class
 *     ALARM, never silently kept). Public mode has no ledger, so its feed only
 *     ever carries "disclosure" entries.
 *
 * The union itself is owned by @bongtu/core/indexerApi (the normative wire
 * shapes); typing `body` against it here is the server-adapter half of that
 * contract — internal DisclosureResult / EnvelopeAlarm drift breaks THIS line,
 * not the apps at runtime.
 */
export type { Alarm } from "@bongtu/core/indexerApi";

export const alarms: Route = {
  method: "GET",
  pattern: "/alarms",
  handle({ ix }) {
    const body: Alarm[] = [
      ...ix.store.getAlarms().map((a) => ({ type: "disclosure" as const, ...a })),
      ...(ix.ledger?.getEnvelopeAlarms() ?? []).map((a) => ({ type: "envelope" as const, ...a })),
    ];
    return { status: 200, body };
  },
};
