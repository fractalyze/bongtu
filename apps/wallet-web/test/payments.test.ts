// Headless gates for the received-payments fold (src/lib/payments.ts): the
// view-key ownership scan over the ATTRIBUTION-FREE public feed, the
// received -> swept -> shielded status ladder, the unfunded-row drop, and the
// newest-first order. No React, no transport — records, keys, note set and
// balance reader are all injected.
//
//   node --import tsx --test test/payments.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";

import type { PortalPublicRecord } from "@bongtu/core/indexerApi";
import { deriveStealthAddress, stealthKeysFromScalars } from "@bongtu/core/stealth";

import { buildPaymentRows, isOwnAnnouncement, shortDestination, type ScanKeys } from "../src/lib/payments.js";

const OURS = stealthKeysFromScalars(1111n, 2222n);
const THEIRS = stealthKeysFromScalars(5555n, 6666n);
const KEYS: ScanKeys = { viewPriv: OURS.viewPriv, spendPub: OURS.meta.spendPub };

function announcementFor(
  meta: { viewPub: string; spendPub: string },
  scalar: bigint,
  over: Partial<PortalPublicRecord> = {},
): PortalPublicRecord {
  const d = deriveStealthAddress(meta, scalar);
  return {
    kind: "portal",
    seq: 0,
    rail: "evm",
    factory: "0x" + "c1".repeat(20),
    ephemeralPub: d.ephemeralPub,
    viewTag: d.viewTag,
    stealthAddr: d.address,
    destination: "0x" + "d0".repeat(20),
    createdAt: 1_700_000_000,
    swept: false,
    sweptTxHash: null,
    sweptAmount: null,
    ...over,
  };
}

test("ownership scan: our announcements match, foreign and malformed ones never do", () => {
  assert.equal(isOwnAnnouncement(KEYS, announcementFor(OURS.meta, 42n)), true);
  assert.equal(isOwnAnnouncement(KEYS, announcementFor(THEIRS.meta, 42n)), false);
  // The unauthenticated announce surface can hold garbage — not ours, no throw.
  assert.equal(
    isOwnAnnouncement(KEYS, announcementFor(OURS.meta, 42n, { ephemeralPub: "0x" + "00".repeat(32) })),
    false,
  );
  assert.equal(
    isOwnAnnouncement(KEYS, announcementFor(OURS.meta, 42n, { ephemeralPub: "0xnot-hex" })),
    false,
  );
  // A matching ephemeral with a swapped-in stealthAddr (hijack shape) is not ours.
  assert.equal(
    isOwnAnnouncement(KEYS, announcementFor(OURS.meta, 42n, { stealthAddr: "0x" + "99".repeat(20) })),
    false,
  );
});

test("status ladder: swept+note-found = shielded, swept-only = swept, funded-unswept = received", async () => {
  const shielded = announcementFor(OURS.meta, 1n, {
    seq: 0, swept: true, sweptTxHash: "0xmint", sweptAmount: "300000",
  });
  const sweeping = announcementFor(OURS.meta, 2n, {
    seq: 1, swept: true, sweptTxHash: "0xpending", sweptAmount: "120000",
  });
  const received = announcementFor(OURS.meta, 3n, { seq: 2, destination: "0x" + "aa".repeat(20) });
  const foreign = announcementFor(THEIRS.meta, 4n, { seq: 3, swept: true, sweptTxHash: "0xmint", sweptAmount: "1" });

  const rows = await buildPaymentRows(
    [shielded, sweeping, received, foreign],
    KEYS,
    new Set(["0xmint"]),
    async () => 58_000n,
  );
  // Newest first, the foreign row filtered out entirely.
  assert.deepEqual(rows.map((r) => [r.seq, r.status, r.amount]), [
    [2, "received", "58000"],
    [1, "swept", "120000"],
    [0, "shielded", "300000"],
  ]);
});

test("an unfunded unswept issuance is dropped (a page visit is not money)", async () => {
  const unfunded = announcementFor(OURS.meta, 7n);
  const rows = await buildPaymentRows([unfunded], KEYS, new Set(), async () => 0n);
  assert.deepEqual(rows, []);
});

test("the balance read is consulted ONLY for unswept rows", async () => {
  const swept = announcementFor(OURS.meta, 8n, { swept: true, sweptTxHash: "0xt", sweptAmount: "5" });
  const reads: string[] = [];
  await buildPaymentRows([swept], KEYS, new Set(), async (d) => {
    reads.push(d);
    return 1n;
  });
  assert.deepEqual(reads, []);
});

test("shortDestination keeps head and tail", () => {
  assert.equal(shortDestination("0x7f3Aabcdefabcdefabcdefabcdefabcdefab9c4E"), "0x7f3A…9c4E");
});
