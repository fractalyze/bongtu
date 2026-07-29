// Headless gates for the error-surface standard's wallet wiring
// (.dev/error-surface-design.md, docs/errors.md):
//
//   (1) REFRESH SURFACES — runRefresh routes every read outcome to exactly one
//       surface: success applies + CLEARS the banner; a background failure sets the
//       banner and NEVER toasts (the locked rule); only a manual refresh toasts; a
//       401 signs out with the notice; and NO failure path blanks the data on
//       screen (there is no sink that could — asserted structurally).
//   (2) BUG TOASTS — the global handlers route uncaught errors/rejections to the
//       class-5 toast, whose details carry the stack for Copy details.
//   (3) RENDER WIRING — source scans (the repo's honest gate for state-bound JSX):
//       the app frame mounts ONE ToastHost; Home/Activity render the shared Banner
//       with a manual (`refresh(true)`) Retry; Onboarding shows the session-fatal
//       notice; background call sites stay manual-free.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  runRefresh,
  EXPIRED_MESSAGE,
  RECONNECT_NOTICE,
  REFRESH_FAILED_TOAST,
  type OwnerSnapshot,
  type RefreshSinks,
} from "@bongtu/client/refresh";
import { installGlobalErrorSurface, toasts, toastBug, BUG_TOAST_MESSAGE } from "../src/lib/toasts.js";

const SNAP: OwnerSnapshot = { notes: [], history: [], historyNextBefore: null };
const SESSION = { token: "v1.tok", compressedPubkey: "0xowner" };
const INDEXER = "http://localhost:8600";

/** Sinks that record every call — the full surface audit trail of one refresh. */
function recordingSinks(): { sinks: RefreshSinks; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    sinks: {
      applySnapshot: () => calls.push("apply"),
      setBanner: (m) => calls.push(`banner:${m}`),
      toast: (m) => calls.push(`toast:${m}`),
      signOut: (n) => calls.push(`signout:${n}`),
      setNotice: (m) => calls.push(`notice:${m}`),
    },
  };
}

// ============================ (1) REFRESH SURFACES ===========================

test("success applies the snapshot and clears the banner (recovery auto-clears)", async () => {
  const { sinks, calls } = recordingSinks();
  await runRefresh(SESSION, async () => SNAP, sinks, { indexerUrl: INDEXER });
  assert.deepEqual(calls, ["notice:null", "apply", "banner:null"]);
});

test("a BACKGROUND failure sets the banner and never toasts — five minutes of outage is one banner, zero toasts", async () => {
  const { sinks, calls } = recordingSinks();
  const failing = async (): Promise<OwnerSnapshot> => {
    throw new TypeError("Failed to fetch");
  };
  // Three loop ticks of an outage: the banner is (re)set each time, no toast ever.
  for (let i = 0; i < 3; i++) {
    await runRefresh(SESSION, failing, sinks, { indexerUrl: INDEXER, manual: false });
  }
  assert.ok(!calls.some((c) => c.startsWith("toast:")), "background loops NEVER toast (locked rule)");
  assert.ok(!calls.some((c) => c.startsWith("signout:")), "a transport failure is no sign-out");
  assert.equal(calls.filter((c) => c.startsWith("banner:") && !c.endsWith("null")).length, 3);
  assert.ok(!calls.includes("apply"), "nothing is applied — and nothing blanks what's on screen");
});

test("only a MANUAL refresh failure toasts (class-1 event), on top of the state banner", async () => {
  const { sinks, calls } = recordingSinks();
  await runRefresh(
    SESSION,
    async () => {
      throw new Error(`${INDEXER}/notes -> 500: boom`);
    },
    sinks,
    { indexerUrl: INDEXER, manual: true },
  );
  assert.ok(calls.includes(`toast:${REFRESH_FAILED_TOAST}`), "the user's tap failing IS an event");
  assert.ok(calls.some((c) => c.startsWith("banner:") && !c.endsWith("null")), "the holding state still banners");
});

test("a 401 signs out with the notice — manual or not, never a banner/toast", async () => {
  for (const manual of [false, true]) {
    const { sinks, calls } = recordingSinks();
    await runRefresh(
      SESSION,
      async () => {
        throw new Error(`${INDEXER}/notes -> 401: token expired`);
      },
      sinks,
      { indexerUrl: INDEXER, manual },
    );
    assert.deepEqual(calls, ["notice:null", `signout:${EXPIRED_MESSAGE}`], `manual=${manual}`);
  }
});

test("a tokenless session never issues the read: notice only, banner cleared", async () => {
  const { sinks, calls } = recordingSinks();
  await runRefresh(
    { token: "", compressedPubkey: "0xowner" },
    async () => {
      throw new Error("must not be called");
    },
    sinks,
    { indexerUrl: INDEXER, manual: true },
  );
  assert.deepEqual(calls, [`notice:${RECONNECT_NOTICE}`, "banner:null"]);
});

test("the sink contract has no way to blank on-screen data on failure", () => {
  // Structural: RefreshSinks exposes apply/banner/toast/signout/notice and nothing
  // else — a failed read CANNOT clear notes/history/balance because no sink does.
  const keys = Object.keys(recordingSinks().sinks).sort();
  assert.deepEqual(keys, ["applySnapshot", "setBanner", "setNotice", "signOut", "toast"]);
});

// ============================ (2) BUG TOASTS =================================

test("installGlobalErrorSurface routes uncaught errors + rejections to the bug toast", () => {
  const listeners = new Map<string, (ev: object) => void>();
  const target = {
    addEventListener: (t: string, l: (ev: object) => void) => listeners.set(t, l),
    removeEventListener: (t: string) => listeners.delete(t),
  };
  const seen: unknown[] = [];
  const uninstall = installGlobalErrorSurface(target, (thrown) => seen.push(thrown));

  const boom = new Error("boom");
  listeners.get("error")?.({ error: boom, message: "boom" });
  listeners.get("unhandledrejection")?.({ reason: "rejected!" });
  assert.deepEqual(seen, [boom, "rejected!"]);

  uninstall();
  assert.equal(listeners.size, 0, "uninstall removes both handlers");
});

test("toastBug shows the generic headline with the stack in details; repeats dedup to one toast", () => {
  toasts.clear();
  const e = new Error("invariant violated");
  toastBug(e);
  toastBug(e); // a crash loop must not stack toasts
  const items = toasts.snapshot();
  assert.equal(items.length, 1);
  assert.equal(items[0].message, BUG_TOAST_MESSAGE);
  assert.match(items[0].details ?? "", /invariant violated/, "Copy details carries the real error");
  toasts.clear();
});

// ============================ (3) RENDER WIRING ==============================

const read = (p: string): string => readFileSync(new URL(p, import.meta.url).pathname, "utf8");

test("the app frame mounts ONE ToastHost over the shared queue", () => {
  const app = read("../src/ui/App.tsx");
  assert.match(app, /<ToastHost queue=\{toasts\} \/>/);
  assert.match(app, /installGlobalErrorSurface\(\)/, "class 5 has a route to the toast");
});

test("Home and Activity render the shared Banner with a MANUAL retry, keeping data below it", () => {
  for (const file of ["../src/ui/screens/Home.tsx", "../src/ui/screens/Activity.tsx"]) {
    const src = read(file);
    assert.match(src, /from "@bongtu\/ui\/Banner"/, `${file} uses the shared Banner`);
    assert.match(src, /onRetry=\{\(\) => void refresh\(true\)\}/, `${file}'s Retry is the manual refresh`);
    assert.doesNotMatch(src, /dataError \? \(/, `${file} no longer hides content behind the error`);
  }
});

test("Onboarding shows the session-fatal notice (route change + notice path)", () => {
  const src = read("../src/ui/screens/Onboarding.tsx");
  assert.match(src, /dataError && <Banner tone="info" message=\{dataError\} \/>/);
});

test("background call sites never pass manual: the session-change effect and the post-action fallback", () => {
  const app = read("../src/ui/App.tsx");
  assert.match(app, /if \(session\) void refresh\(\);/, "the auto-load effect is background");
  assert.match(app, /await refresh\(\); \/\/ every poll failed/, "the post-action fallback is background");
  assert.doesNotMatch(app, /refresh\(true\)/, "App itself never claims a manual refresh");
});
