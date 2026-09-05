// Headless gates for the Receive identity surface: the own-name status fold
// (which record may render as "yours"), the store's blocked-storage degrade,
// and the pinned registration copy. The registration PAYLOAD rules (v2
// signature over the five-segment binding, zero-sentinel clears) are the
// engine's, gated in core/indexer — this suite gates only what the APP decides.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { KEM_EK_ZERO, NOTE_VIEW_PUB_ZERO } from "@bongtu/core/indexerApi";
import type { NameRecord } from "@bongtu/core/indexerApi";
import {
  clearOwnPayName,
  loadOwnPayName,
  ownNameStatus,
  saveOwnPayName,
} from "../src/lib/payNameStore.js";
import {
  NAME_INVALID_MESSAGE,
  NAME_NEEDS_UPDATE_NOTICE,
  NAME_RULES_HINT,
  RECEIVE_SHARE_LINE,
} from "../src/ui/screens/Receive.js";

const OWNER = "0x" + "ab".repeat(32);
const RECORD: NameRecord = {
  name: "alice",
  owner: OWNER,
  viewPub: "0x" + "01".repeat(32),
  spendPub: "0x" + "02".repeat(33),
  noteViewPub: "0x" + "03".repeat(32),
  kemEk: "0x" + "04".repeat(1184),
  updatedAt: 1,
};

// ========================= own-name status table =============================

test("own-name status table: unregistered / not-ours / needs-update / registered", () => {
  // no record: the name is free — the register form is the screen.
  assert.equal(ownNameStatus(null, OWNER), "unregistered");

  // registered to a DIFFERENT owner: never render it as identity.
  assert.equal(ownNameStatus({ ...RECORD, owner: "0x" + "cd".repeat(32) }, OWNER), "not-ours");

  // ours but without the consumer pair — a legacy v1 record: senders refuse to
  // pay it, so the screen must push the update, not celebrate the name.
  assert.equal(ownNameStatus({ ...RECORD, noteViewPub: undefined, kemEk: undefined }, OWNER), "needs-update");

  // ours with the pair CLEARED (signed zero-sentinels): same verdict — a clear
  // is a statement that the name cannot receive, not a soft absence.
  assert.equal(
    ownNameStatus({ ...RECORD, noteViewPub: NOTE_VIEW_PUB_ZERO, kemEk: KEM_EK_ZERO }, OWNER),
    "needs-update",
  );

  // ours and payable: the identity panel's happy state.
  assert.equal(ownNameStatus(RECORD, OWNER), "registered");
});

// ============================ store degrade ==================================

test("payNameStore degrades without localStorage: no throw, null load (the register form)", () => {
  assert.equal(loadOwnPayName(OWNER), null);
  assert.doesNotThrow(() => saveOwnPayName(OWNER, "alice"));
  assert.doesNotThrow(() => clearOwnPayName(OWNER));
});

// ============================== copy pins ====================================

test("the identity copy is pinned: share the NAME, and the update push names the gap", () => {
  assert.equal(NAME_RULES_HINT, "3 to 32 characters: lowercase letters, numbers, and hyphens.");
  assert.equal(NAME_INVALID_MESSAGE, `That name can't be registered. ${NAME_RULES_HINT}`);
  assert.equal(RECEIVE_SHARE_LINE, "People pay you by this name. Share the name, nothing else.");
  assert.equal(
    NAME_NEEDS_UPDATE_NOTICE,
    "This name doesn't carry your payment keys yet. Update it so people can pay you privately.",
  );
});

// ============================= source pins ===================================

const RECEIVE_SRC = readFileSync(
  new URL("../src/ui/screens/Receive.tsx", import.meta.url).pathname,
  "utf8",
);

test("registration is v2-only: the triple registers together, never the v1 payload", () => {
  assert.match(RECEIVE_SRC, /buildNameRegistrationV2/);
  assert.doesNotMatch(RECEIVE_SRC, /buildNameRegistration[^V]/, "no v1 payload path exists to drift onto");
  // both halves of the consumer pair come from the SAME identity read
  assert.match(RECEIVE_SRC, /noteViewPub: self\.noteViewPub, kemEk: self\.kemEk/);
});

test("the QR and copy affordances carry the NAME, never the raw triple", () => {
  assert.match(RECEIVE_SRC, /NameQr name=\{ownName\}/);
  assert.doesNotMatch(RECEIVE_SRC, /toDataURL\((?!name)/, "the QR payload is the name argument only");
  assert.doesNotMatch(RECEIVE_SRC, /useCopyFeedback\(.*kemEk/, "nothing copies key material");
});
