// The boolean-returning clipboard edge behind "Copy details": true only when the
// write really landed; a refusing or absent clipboard reports false, never throws.

import { test } from "node:test";
import assert from "node:assert/strict";

import { copyText } from "@bongtu/ui/clipboard";

test("copyText: true when the injected clipboard accepts", async () => {
  const clip = { wrote: "" };
  const ok = await copyText("details…", {
    writeText: async (t) => {
      clip.wrote = t;
    },
  });
  assert.equal(ok, true);
  assert.equal(clip.wrote, "details…");
});

test("copyText: false when the clipboard rejects or is absent — never a throw", async () => {
  const refused = await copyText("x", {
    writeText: async () => {
      throw new Error("not allowed outside a user gesture");
    },
  });
  assert.equal(refused, false);
  assert.equal(await copyText("x"), false, "headless env has no navigator.clipboard");
});
