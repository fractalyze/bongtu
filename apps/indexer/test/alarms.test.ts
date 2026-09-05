// Alarm-surface owner unit tests — CPU lane, no HTTP, no Postgres, no anvil.
//   (a) the /alarms list and the /health count come from ONE aggregate
//       (src/alarms.ts currentAlarms) over the three producers;
//   (b) verdict precedence (DisclosureRegistry.currentStatus): a blob swapped
//       AFTER ingest makes the registry recompute disagree with the baked
//       verdict; the fresher registry verdict must project, no HTTP involved;
//   (c) the grace-window comparison has one owner (pastGrace) and one
//       boundary, so statusOf and alarms() agree by construction;
//   (d) the console renderer owns the `ALARM ` prefix + severity mapping.
//
//   node --import tsx --test test/alarms.test.ts   # (== npm run test:alarms)

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { currentAlarms, emitAlarm, emitDisclosureAlarm } from "../src/alarms.js";
import { DisclosureRegistry, pastGrace, type DisburseBatchAnchor } from "../src/solana/served.js";
import type { DisclosureResult } from "../src/disclosure.js";
import type { EnvelopeAlarm } from "../src/ledger.js";

const B = 2; // receiverCount 8 — the tiny 3-element test blobs can never alias it
const RECORDED_AT = 1_700_000_000;
const GRACE = 100;

const anchor = (startLeafIndex: number): DisburseBatchAnchor => ({
  startLeafIndex,
  txHash: `0xanchor${startLeafIndex}`,
  // Never the poseidon refold of the tiny blobs below, so a held blob always
  // classifies "mismatch" deterministically.
  disclosureHash: 999n,
  kemBinding: 0n,
  epoch: 0,
  recordedAt: RECORDED_AT,
});

const baked = (status: DisclosureResult["status"], startLeafIndex = 0): DisclosureResult => ({
  status,
  txHash: "0xbaked",
  startLeafIndex,
  emittedCount: 0,
  receiverCount: B * 4,
  recomputed: "0",
  expected: "999",
});

const ENV_ALARM: EnvelopeAlarm = { kind: "disburse", txHash: "0xenv", detail: "output 0 mismatch", recomputed: "1", expected: "2" };

/** Capture one console channel for the duration of fn. */
const capture = (channel: "error" | "warn", fn: () => void): string[] => {
  const lines: string[] = [];
  const orig = console[channel];
  console[channel] = (...a: unknown[]): void => {
    lines.push(a.map(String).join(" "));
  };
  try {
    fn();
  } finally {
    console[channel] = orig;
  }
  return lines;
};

test("aggregate: the /alarms list and the /health count are the same call over three sources", () => {
  const registry = new DisclosureRegistry(null, GRACE);
  registry.recordBatch(anchor(256), B); // no dir => unserved; the grace clock governs
  const src = {
    store: { getAlarms: () => [baked("mismatch", 0), baked("unverifiable", 16)] },
    disclosures: registry,
    ledger: { getEnvelopeAlarms: () => [ENV_ALARM] },
  };

  // At the grace boundary the unserved batch is operational, not an alarm.
  const list = currentAlarms(src, RECORDED_AT + GRACE);
  const count = currentAlarms(src, RECORDED_AT + GRACE).length; // /health's question
  assert.equal(list.length, count, "serving and counting are the same aggregate");
  assert.equal(list.length, 3);
  assert.deepEqual(list.map((a) => a.type), ["disclosure", "disclosure", "envelope"]);

  // One second past grace, at the SAME injected now for both questions: the
  // synthesized withheld joins the list AND the count together.
  const past = currentAlarms(src, RECORDED_AT + GRACE + 1);
  assert.equal(past.length, currentAlarms(src, RECORDED_AT + GRACE + 1).length);
  assert.equal(past.length, 4);
  assert.equal(past.filter((a) => a.type === "disclosure" && a.status === "withheld").length, 1);

  // Public mode: no ledger — the feed only carries "disclosure" entries.
  const publicList = currentAlarms({ ...src, ledger: null }, RECORDED_AT + GRACE + 1);
  assert.equal(publicList.length, 3);
  assert.ok(publicList.every((a) => a.type === "disclosure"));
});

test("precedence: a blob swapped after ingest projects the registry verdict over the baked one", () => {
  const dir = mkdtempSync(join(tmpdir(), "bongtu-alarms-swap-"));
  try {
    // The persisted (baked) verdict passed at ingest; the dir now holds tampered
    // bytes whose refold cannot match the committed hash — the boot shape of a
    // post-ingest blob swap.
    writeFileSync(join(dir, "256.json"), JSON.stringify(["1", "2", "3"]));
    const registry = new DisclosureRegistry(dir, GRACE);
    const lines = capture("error", () => {
      registry.recordBatch(anchor(256), B, { boot: { persistedStatus: "verified" } });
    });
    assert.ok(
      lines.some((l) => l.startsWith("ALARM disclosure verdict CONFLICT: batch 256")),
      `the conflict line names the batch (got: ${JSON.stringify(lines)})`,
    );

    const now = RECORDED_AT + 1;
    // /events' one question: the registry's CURRENT verdict wins over the stale baked fact.
    assert.equal(registry.currentStatus({ kind: "disburse", batchId: 256, disclosure: baked("verified", 256) }, now), "mismatch");
    // ...and the registry owns the alarm (the store's baked entry must not double-report).
    const alarms = registry.alarms(now);
    assert.equal(alarms.length, 1);
    assert.equal(alarms[0].status, "mismatch");
    assert.equal(alarms[0].startLeafIndex, 256);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("precedence: registry silent => baked stands; non-disburse kinds never consult the registry", () => {
  const registry = new DisclosureRegistry(null, GRACE);
  registry.recordBatch(anchor(256), B); // recorded, unserved
  const now = RECORDED_AT + 1; // within grace: statusOf is silent

  // Unserved within grace, and an unknown batch (every EVM disburse): baked wins.
  assert.equal(registry.currentStatus({ kind: "disburse", batchId: 256, disclosure: baked("verified") }, now), "verified");
  assert.equal(registry.currentStatus({ kind: "disburse", batchId: 999, disclosure: baked("mismatch") }, now), "mismatch");
  // No batchId => baked; no baked either => undefined (no verdict on the wire).
  assert.equal(registry.currentStatus({ kind: "disburse", disclosure: baked("unverifiable") }, now), "unverifiable");
  assert.equal(registry.currentStatus({ kind: "deposit" }, now), undefined);
  // A consumer disbursePriv carries a batchId too — it must NOT hit the registry.
  assert.equal(registry.currentStatus({ kind: "disbursePriv", batchId: 256, disclosure: baked("verified") }, now), "verified");
  // Past grace the recorded-but-unserved batch projects withheld even over a baked verdict.
  assert.equal(registry.currentStatus({ kind: "disburse", batchId: 256, disclosure: baked("verified") }, RECORDED_AT + GRACE + 1), "withheld");
});

test("grace: one predicate, one boundary — statusOf and alarms agree by construction", () => {
  assert.equal(pastGrace(RECORDED_AT, RECORDED_AT + GRACE, GRACE), false, "exactly graceSeconds is still operational");
  assert.equal(pastGrace(RECORDED_AT, RECORDED_AT + GRACE + 1, GRACE), true, "one second past graceSeconds is withheld");

  const registry = new DisclosureRegistry(null, GRACE);
  registry.recordBatch(anchor(0), B);
  for (const now of [RECORDED_AT + GRACE, RECORDED_AT + GRACE + 1]) {
    const projected = registry.statusOf(0, now) === "withheld";
    const alarmed = registry.alarms(now).some((a) => a.status === "withheld");
    assert.equal(projected, alarmed, `statusOf and alarms() agree at now=${now}`);
  }
  assert.equal(registry.statusOf(0, RECORDED_AT + GRACE), undefined);
  assert.equal(registry.statusOf(0, RECORDED_AT + GRACE + 1), "withheld");
});

test("renderer: one ALARM prefix owner; attribution gaps warn, evidence errors", () => {
  const errs = capture("error", () => {
    emitAlarm("disclosure", "disclosure MISMATCH tx=0x1 start=0 recomputed=1 expected=2");
    emitAlarm("envelope", "envelope disburse tx=0x2 detail recomputed=1 expected=2");
    emitAlarm("verdict-conflict", "disclosure verdict CONFLICT: batch 0");
  });
  assert.equal(errs.length, 3);
  assert.ok(errs.every((l) => l.startsWith("ALARM ")));

  const warns = capture("warn", () => {
    emitAlarm("attribution-gap", "OpApplied unconsumed: module=0xm tx=0xt start=0 nullifiers=0 leaves=1");
  });
  assert.deepEqual(warns, ["ALARM OpApplied unconsumed: module=0xm tx=0xt start=0 nullifiers=0 leaves=1"]);

  const line = capture("error", () => emitDisclosureAlarm(baked("mismatch", 7), "served blob"));
  assert.deepEqual(line, ["ALARM disclosure MISMATCH (served blob) tx=0xbaked start=7 recomputed=0 expected=999"]);
});
