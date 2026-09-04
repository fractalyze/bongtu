// Headless gates for the pay-by-name resolve seam: a consumer payment seals to
// the payee's registered v2 triple, so the triple is REQUIRED on resolve — a
// v1-only record refuses with the plain "can't receive yet" words instead of
// silently minting undiscoverable notes, and a network failure propagates
// rather than reading as "unregistered".

import { test } from "node:test";
import assert from "node:assert/strict";

import type { NameRecord } from "@bongtu/core/indexerApi";
import {
  RECIPIENT_NOT_REGISTERED_MESSAGE,
  RECIPIENT_V1_ONLY_MESSAGE,
  resolveConsumerRecipient,
} from "../src/lib/payName.js";

const V2_RECORD: NameRecord = {
  name: "alice",
  owner: "0x" + "ab".repeat(32),
  viewPub: "0x" + "01".repeat(32),
  spendPub: "0x" + "02".repeat(33),
  noteViewPub: "0x" + "03".repeat(32),
  kemEk: "0x" + "04".repeat(1184),
  updatedAt: 1,
};

const resolveWith = (record: NameRecord | null) => async (): Promise<NameRecord | null> => record;

test("a v2 record resolves to the payable triple (owner + note view pub + kem ek)", async () => {
  const out = await resolveConsumerRecipient("/indexer", "  Alice ", resolveWith(V2_RECORD));
  assert.ok(out.ok);
  assert.equal(out.name, "alice", "the canonical (normalized) name comes back");
  assert.deepEqual(out.recipient, {
    owner: V2_RECORD.owner,
    noteViewPub: V2_RECORD.noteViewPub,
    kemEk: V2_RECORD.kemEk,
  });
});

test("a v1-only record REFUSES with the can't-receive-yet copy — never a soft fallback", async () => {
  const legacy: NameRecord = { ...V2_RECORD, noteViewPub: undefined, kemEk: undefined };
  const out = await resolveConsumerRecipient("/indexer", "alice", resolveWith(legacy));
  assert.ok(!out.ok);
  assert.equal(out.message, RECIPIENT_V1_ONLY_MESSAGE);
  assert.match(out.message, /can’t receive private payments yet/);
});

test("an unregistered or non-normalizing name reads as not registered", async () => {
  const missing = await resolveConsumerRecipient("/indexer", "alice", resolveWith(null));
  assert.ok(!missing.ok);
  assert.equal(missing.message, RECIPIENT_NOT_REGISTERED_MESSAGE);

  const never = async (): Promise<NameRecord | null> => {
    throw new Error("resolve must not be called for a name that cannot normalize");
  };
  const junk = await resolveConsumerRecipient("/indexer", "x".repeat(64), never);
  assert.ok(!junk.ok);
  assert.equal(junk.message, RECIPIENT_NOT_REGISTERED_MESSAGE);
});

test("a network failure PROPAGATES: the indexer being down must not read as unregistered", async () => {
  const down = async (): Promise<NameRecord | null> => {
    throw new Error("/names -> 503");
  };
  await assert.rejects(
    () => resolveConsumerRecipient("/indexer", "alice", down),
    /503/,
  );
});
