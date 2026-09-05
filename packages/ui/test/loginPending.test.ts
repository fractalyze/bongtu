// Headless gates for Onboarding's connect-then-login machine (packages/ui/src/loginPending.ts).
// The wave-1 review finding this pins: dismissing the connect modal without
// connecting must CLEAR the pending flag — a stale flag would auto-fire a
// signature popup at the next unrelated connect.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  LOGIN_IDLE,
  loginPendingStep,
  startLoginPending,
  type LoginPendingState,
} from "../src/loginPending.js";

function drive(
  start: LoginPendingState,
  envs: { modalOpen: boolean; connected: boolean }[],
): { state: LoginPendingState; effects: string[] } {
  const effects: string[] = [];
  const state = envs.reduce((s, env) => {
    const r = loginPendingStep(s, env);
    if (r.effect !== "none") effects.push(r.effect);
    return r.state;
  }, start);
  return { state, effects };
}

test("connect during the modal round fires the login exactly once and disarms", () => {
  const r = drive(startLoginPending(), [
    { modalOpen: false, connected: false }, // press → modal not open yet (async)
    { modalOpen: true, connected: false }, // modal appeared
    { modalOpen: true, connected: true }, // wallet connected
    { modalOpen: false, connected: true }, // modal closes after connect
  ]);
  assert.deepEqual(r.effects, ["login"], "one login, and no re-fire when the modal closes");
  assert.deepEqual(r.state, LOGIN_IDLE);
});

test("dismissing the modal without connecting DISARMS — no login on a later connect", () => {
  const r = drive(startLoginPending(), [
    { modalOpen: true, connected: false }, // modal appeared
    { modalOpen: false, connected: false }, // dismissed with nothing connected
    { modalOpen: false, connected: true }, // some LATER connect (warm reconnect etc.)
  ]);
  assert.deepEqual(r.effects, ["dismissed"], "the stale flag must not auto-fire a signature popup");
  assert.deepEqual(r.state, LOGIN_IDLE);
});

test("the async modal open is not mistaken for a dismissal", () => {
  // Between the press and RainbowKit actually opening, modalOpen is still false —
  // the round must stay armed (modalSeen gates the dismissal verdict).
  const r = drive(startLoginPending(), [
    { modalOpen: false, connected: false },
    { modalOpen: false, connected: false },
  ]);
  assert.deepEqual(r.effects, []);
  assert.equal(r.state.pending, true, "still waiting for the modal round");
});

test("connect and modal-close arriving in ONE step still logs in (connection wins)", () => {
  const r = drive(startLoginPending(), [
    { modalOpen: true, connected: false },
    { modalOpen: false, connected: true }, // RainbowKit closes as the connect lands
  ]);
  assert.deepEqual(r.effects, ["login"]);
});

test("idle state ignores environment changes (no phantom logins)", () => {
  const r = drive(LOGIN_IDLE, [
    { modalOpen: true, connected: false },
    { modalOpen: false, connected: true },
  ]);
  assert.deepEqual(r.effects, []);
  assert.equal(r.state, LOGIN_IDLE);
});

test("step returns the SAME state reference when nothing changed (React identity contract)", () => {
  const armed = startLoginPending();
  const r = loginPendingStep(armed, { modalOpen: false, connected: false });
  assert.equal(r.state, armed, "a fresh-but-equal object would re-render the effect forever");
  const idle = loginPendingStep(LOGIN_IDLE, { modalOpen: false, connected: false });
  assert.equal(idle.state, LOGIN_IDLE);
});
