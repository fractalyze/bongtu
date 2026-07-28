// Headless gates for the toast model (src/toastQueue.ts): ordering + cap, DEDUP
// (a repeating failure occupies one slot and restarts its timer), auto-dismiss on
// an injected timer, manual dismiss, and subscriber notification. No DOM anywhere —
// the render face (Toast.tsx) is gated separately by render.test.ts.

import { test } from "node:test";
import assert from "node:assert/strict";

import { ToastQueue } from "../src/toastQueue.js";

/** A hand-cranked timer: collects scheduled callbacks, fires them on demand. */
function fakeTimers(): {
  schedule: (fn: () => void, ms: number) => () => void;
  fire: (ms: number) => void;
  pending: () => number;
} {
  let seq = 0;
  const timers = new Map<number, { fn: () => void; ms: number }>();
  return {
    schedule: (fn, ms) => {
      const id = seq++;
      timers.set(id, { fn, ms });
      return () => timers.delete(id);
    },
    fire: (ms) => {
      for (const [id, t] of [...timers]) {
        if (t.ms <= ms) {
          timers.delete(id);
          t.fn();
        }
      }
    },
    pending: () => timers.size,
  };
}

test("show stacks oldest-first and caps at max, dropping the oldest", () => {
  const t = fakeTimers();
  const q = new ToastQueue({ max: 3, schedule: t.schedule });
  q.show("one");
  q.show("two");
  q.show("three");
  assert.deepEqual(q.snapshot().map((x) => x.message), ["one", "two", "three"]);
  q.show("four");
  assert.deepEqual(q.snapshot().map((x) => x.message), ["two", "three", "four"], "oldest dropped at the cap");
  assert.equal(t.pending(), 3, "the dropped toast's timer is cancelled with it");
});

test("dedup: an identical visible toast is not stacked — its timer restarts", () => {
  const t = fakeTimers();
  const q = new ToastQueue({ durationMs: 100, schedule: t.schedule });
  const a = q.show("refresh failed");
  const b = q.show("refresh failed");
  assert.equal(a, b, "the existing toast's id comes back");
  assert.equal(q.snapshot().length, 1, "one slot, not a growing pile");
  // Same message but different details = a different toast (a distinct bug payload).
  q.show("refresh failed", { details: "stack…" });
  assert.equal(q.snapshot().length, 2);
});

test("auto-dismiss fires on the timer; a deduped re-show extends the life", () => {
  const t = fakeTimers();
  const q = new ToastQueue({ durationMs: 100, schedule: t.schedule });
  q.show("gone soon");
  t.fire(100);
  assert.equal(q.snapshot().length, 0, "dismissed when its time elapses");

  q.show("kept alive");
  q.show("kept alive"); // dedup restarts the timer: the old one is cancelled
  assert.equal(t.pending(), 1, "exactly one live timer after the restart");
  t.fire(100);
  assert.equal(q.snapshot().length, 0);
});

test("a non-finite duration is sticky: manual dismiss only", () => {
  const t = fakeTimers();
  const q = new ToastQueue({ schedule: t.schedule });
  const id = q.show("sticky bug toast", { durationMs: Infinity, details: "stack" });
  assert.equal(t.pending(), 0, "no timer armed");
  q.dismiss(id);
  assert.equal(q.snapshot().length, 0);
  q.dismiss(id); // unknown id: no-op, no throw
});

test("subscribe: notified on show and dismiss; snapshot identity changes per update", () => {
  const t = fakeTimers();
  const q = new ToastQueue({ schedule: t.schedule });
  let fires = 0;
  const unsub = q.subscribe(() => fires++);
  const before = q.snapshot();
  const id = q.show("hello");
  assert.equal(fires, 1);
  assert.notEqual(q.snapshot(), before, "new array identity so useSyncExternalStore repaints");
  q.dismiss(id);
  assert.equal(fires, 2);
  unsub();
  q.show("after unsub");
  assert.equal(fires, 2, "unsubscribed listeners stay quiet");
});

test("clear drops everything and cancels every timer", () => {
  const t = fakeTimers();
  const q = new ToastQueue({ durationMs: 100, schedule: t.schedule });
  q.show("a");
  q.show("b");
  q.clear();
  assert.equal(q.snapshot().length, 0);
  assert.equal(t.pending(), 0);
});

test("toasts default to the error variant and carry no details unless given", () => {
  const t = fakeTimers();
  const q = new ToastQueue({ schedule: t.schedule });
  q.show("plain");
  q.show("informative", { variant: "info", details: "why" });
  const [plain, info] = q.snapshot();
  assert.equal(plain.variant, "error");
  assert.equal(plain.details, null);
  assert.equal(info.variant, "info");
  assert.equal(info.details, "why");
});
