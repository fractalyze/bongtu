// copyText must never throw at the UI: it reports success as a boolean (Copied
// feedback hinges on it) and degrades to false when the clipboard is missing or the
// browser rejects the write.

import { test } from "node:test";
import assert from "node:assert/strict";

import { copyText, type ClipboardLike } from "../src/lib/clipboard.js";

test("copyText writes the exact text and reports success", async () => {
  const writes: string[] = [];
  const clip: ClipboardLike = {
    writeText: async (t) => {
      writes.push(t);
    },
  };
  assert.equal(await copyText("0xdeadbeef", clip), true);
  assert.deepEqual(writes, ["0xdeadbeef"]);
});

test("copyText reports false when the clipboard rejects", async () => {
  const clip: ClipboardLike = {
    writeText: async () => {
      throw new Error("NotAllowedError");
    },
  };
  assert.equal(await copyText("x", clip), false);
});

test("copyText reports false when no clipboard exists (headless)", async () => {
  assert.equal(await copyText("x"), false);
});
