// Render gates for the two error surfaces (react-dom/server — output is a pure
// function of the queue/props, same pattern as wallet-web's copy.test.ts):
//   TOAST — the host IS the polite live region (present before any toast), a bug
//     toast grows "Copy details", every toast has a dismiss button;
//   BANNER — message + optional Retry, warn vs info tones.

import { test } from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ToastQueue } from "../src/toastQueue.js";
import { ToastHost } from "../src/Toast.js";
import { Banner } from "../src/Banner.js";

const h = createElement;
const noTimer = { schedule: () => () => {} };

test("ToastHost is an aria-live=polite region even while empty", () => {
  const q = new ToastQueue(noTimer);
  const html = renderToStaticMarkup(h(ToastHost, { queue: q }));
  assert.match(html, /aria-live="polite"/, "the live region must exist before the first toast");
});

test("a plain toast renders its message and a dismiss button, no Copy details", () => {
  const q = new ToastQueue(noTimer);
  q.show("Refresh failed. Showing the last loaded data.");
  const html = renderToStaticMarkup(h(ToastHost, { queue: q }));
  assert.match(html, /Refresh failed\. Showing the last loaded data\./);
  assert.match(html, /aria-label="Dismiss"/);
  assert.doesNotMatch(html, /Copy details/);
});

test("a bug toast (details set) grows the Copy details affordance", () => {
  const q = new ToastQueue(noTimer);
  q.show("Something unexpected went wrong.", { details: "Error: boom\n  at somewhere" });
  const html = renderToStaticMarkup(h(ToastHost, { queue: q }));
  assert.match(html, /Copy details/);
  // The raw stack is NOT rendered into the page — it goes to the clipboard only.
  assert.doesNotMatch(html, /at somewhere/);
});

test("Banner renders the state message; Retry only when a handler is given", () => {
  const bare = renderToStaticMarkup(h(Banner, { message: "Balance may be out of date." }));
  assert.match(bare, /Balance may be out of date\./);
  assert.doesNotMatch(bare, /Retry/);
  assert.match(bare, /warn/, "warn tone by default");

  const withRetry = renderToStaticMarkup(
    h(Banner, { message: "Can't reach the indexer.", onRetry: () => {} }),
  );
  assert.match(withRetry, />Retry</);
});

test("Banner info tone for calm session notices", () => {
  const html = renderToStaticMarkup(
    h(Banner, { message: "Your login expired. Please reconnect.", tone: "info" }),
  );
  assert.match(html, /info/);
  assert.doesNotMatch(html, /warn/);
});
