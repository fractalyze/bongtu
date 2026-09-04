// Name-auth v2 digest + domain separation (OPMOD §6.4).
//
// The consumer registry triple extends the name-binding signature: v2 digests
// FIVE segments (zero-sentinels for an absent pair — absence is a signed
// statement) under a NEW domain tag, so no v1 signature verifies as v2 or vice
// versa. These pins are the client/server shared half; the server's form
// selection + column rules live in apps/indexer test/names.test.ts.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  nameAuthMessage,
  nameBindingField,
  nameAuthMessageV2,
  nameBindingFieldV2,
  NOTE_VIEW_PUB_ZERO,
  KEM_EK_ZERO,
  signNotesAuth,
  verifyNotesAuth,
  parseSignature,
} from "@bongtu/core/eddsa";
import { buildNameRegistrationV2 } from "@bongtu/core/indexerApi";
import { deriveKeypair } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";

const OWNER = deriveKeypair(123456789123456789n);
const META = { viewPub: "0x" + "ab".repeat(32), spendPub: "0x" + "02".repeat(33) };
const NOTE_VIEW = "0x" + "cd".repeat(32);
const KEM_EK = "0x" + "ef".repeat(1184);

test("sentinels have the full field width (32B / 1184B of zero hex)", () => {
  assert.equal(NOTE_VIEW_PUB_ZERO, "0x" + "0".repeat(64));
  assert.equal(KEM_EK_ZERO, "0x" + "0".repeat(2368));
});

test("v2 binding: five segments always — the sentinel form differs from every real pair", () => {
  const withPair = nameBindingFieldV2("alice", META.viewPub, META.spendPub, NOTE_VIEW, KEM_EK);
  const withSentinels = nameBindingFieldV2("alice", META.viewPub, META.spendPub, NOTE_VIEW_PUB_ZERO, KEM_EK_ZERO);
  assert.notEqual(withPair, withSentinels);
  // deterministic + case-normalising, like v1
  assert.equal(
    withPair,
    nameBindingFieldV2("alice", META.viewPub.toUpperCase(), META.spendPub, NOTE_VIEW.toUpperCase(), KEM_EK),
  );
});

test("v1 and v2 messages never collide, even over equal bindings", () => {
  // Force the SAME binding value into both wrappers: only the domain tag
  // differs, and that alone must separate them.
  const binding = nameBindingField("alice", META.viewPub, META.spendPub);
  const ts = 1_700_000_000;
  const v1 = nameAuthMessage(OWNER.publicKey, binding, ts);
  const v2 = nameAuthMessageV2(OWNER.publicKey, binding, ts);
  assert.notEqual(v1, v2);
  // A signature over the v1 message must not verify against the v2 message.
  const sig = signNotesAuth(OWNER.formattedPrivateKey, v1);
  assert.equal(verifyNotesAuth(OWNER.publicKey, v1, sig), true);
  assert.equal(verifyNotesAuth(OWNER.publicKey, v2, sig), false);
});

test("buildNameRegistrationV2: payload carries the pair and a v2-verifying signature", () => {
  const ownerCompressed = packPubkey(OWNER.publicKey);
  const reg = buildNameRegistrationV2(
    "alice", ownerCompressed, OWNER.formattedPrivateKey, META,
    { noteViewPub: NOTE_VIEW, kemEk: KEM_EK }, 1_700_000_000,
  );
  assert.equal(reg.noteViewPub, NOTE_VIEW);
  assert.equal(reg.kemEk, KEM_EK);
  const msg = nameAuthMessageV2(
    OWNER.publicKey,
    nameBindingFieldV2("alice", META.viewPub, META.spendPub, NOTE_VIEW, KEM_EK),
    reg.ts,
  );
  assert.equal(verifyNotesAuth(OWNER.publicKey, msg, parseSignature(reg.sig)), true);
});

test("buildNameRegistrationV2 'clear': the payload signs the zero-sentinels explicitly", () => {
  const ownerCompressed = packPubkey(OWNER.publicKey);
  const reg = buildNameRegistrationV2(
    "alice", ownerCompressed, OWNER.formattedPrivateKey, META, "clear", 1_700_000_000,
  );
  assert.equal(reg.noteViewPub, NOTE_VIEW_PUB_ZERO);
  assert.equal(reg.kemEk, KEM_EK_ZERO);
});
