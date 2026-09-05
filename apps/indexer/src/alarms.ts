// The alarm surface's single owner: the aggregate every serving route reads,
// and the one operator-console ALARM renderer.
//
// AGGREGATE — "the current alarm set" is a three-source union:
//   - store.getAlarms(): disclosure verdicts baked at ingest (EVM consensus-
//     published bytes, consumer-disburse checks, a Solana ingest-time blob);
//   - disclosures.alarms(now): the served-blob registry's own verdicts (late-
//     loaded blobs, boot-conflict recomputes) plus a synthesized "withheld"
//     for every batch unserved past the grace window;
//   - ledger.getEnvelopeAlarms(): arbiter-mode envelope cross-check failures
//     (public mode has no ledger, so its feed only carries "disclosure").
// GET /alarms serves currentAlarms() and GET /health counts the same call, so
// the list and the count are structurally unable to disagree (previously each
// route hand-built its own union with its own clock read).
//
// The wire union is owned by @bongtu/core/indexerApi (the normative shapes);
// typing the return against it is the server-adapter half of that contract —
// internal DisclosureResult / EnvelopeAlarm drift breaks THIS module at
// compile time, not the apps at runtime.

import type { Alarm } from "@bongtu/core/indexerApi";

import type { DisclosureResult } from "./disclosure.js";
import type { EnvelopeAlarm } from "./ledger.js";

/** The three producers, exactly as the IndexerHost read model exposes them
 *  (structural on purpose: the unit test drives fakes, the routes pass `ix`). */
export interface AlarmSources {
  store: { getAlarms(): DisclosureResult[] };
  disclosures: { alarms(nowSeconds: number): DisclosureResult[] };
  ledger: { getEnvelopeAlarms(): EnvelopeAlarm[] } | null;
}

/** The current alarm set, discriminated for the wire, at ONE injected clock
 *  read. An empty registry + no ledger (the EVM public mode) degrades to the
 *  baked disclosure list, so the feed is byte-identical across backends. */
export function currentAlarms(src: AlarmSources, nowSeconds: number): Alarm[] {
  return [
    ...src.store.getAlarms().map((a) => ({ type: "disclosure" as const, ...a })),
    ...src.disclosures.alarms(nowSeconds).map((a) => ({ type: "disclosure" as const, ...a })),
    ...(src.ledger?.getEnvelopeAlarms() ?? []).map((a) => ({ type: "envelope" as const, ...a })),
  ];
}

// ---- console rendering ------------------------------------------------------

/** What kind of operator-facing ALARM a producer classified. Producers pick a
 *  class and preformat the tail; the renderer owns the severity mapping, so
 *  "which console channel does an alarm land on" has one answer:
 *    - chain-provable or key-provable evidence (a failing disclosure verdict,
 *      an envelope cross-check failure, a post-ingest blob swap) = error;
 *    - "attribution-gap" (an OpApplied with no decodable family event — the
 *      mirror still advanced, so it is an attribution gap, not a divergence)
 *      = warn. */
export type AlarmLogClass = "disclosure" | "envelope" | "verdict-conflict" | "attribution-gap";

/** Render one operator-console ALARM line: the single owner of the `ALARM `
 *  prefix and the class -> severity mapping. `tail` arrives preformatted —
 *  a message a test pins byte-for-byte (consumer.test.ts pins the OpApplied
 *  warn) passes its exact tail unchanged. */
export function emitAlarm(cls: AlarmLogClass, tail: string): void {
  const line = `ALARM ${tail}`;
  if (cls === "attribution-gap") console.warn(line);
  else console.error(line);
}

/** The shared disclosure-verdict line (three producers, one format): `source`
 *  tags which pipeline computed the verdict (absent = the EVM enterprise
 *  disburse's consensus-published bytes). */
export function emitDisclosureAlarm(result: DisclosureResult, source?: "consumer" | "served blob"): void {
  const tag = source === undefined ? "" : ` (${source})`;
  emitAlarm(
    "disclosure",
    `disclosure ${result.status.toUpperCase()}${tag} tx=${result.txHash} start=${result.startLeafIndex} recomputed=${result.recomputed} expected=${result.expected}`,
  );
}
