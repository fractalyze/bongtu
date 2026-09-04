// Gate for the desktop-only verdict (src/device.ts): phones and tablets are
// refused, desktops — including NARROW desktop windows, which is why the
// check must not look at the viewport — are let through, and the iPadOS
// masquerade ("Macintosh" UA with a touch screen) is caught by the
// maxTouchPoints probe.

import { test } from "node:test";
import assert from "node:assert/strict";

import { isMobileDevice } from "@bongtu/client/device";

const IPHONE =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";
const ANDROID =
  "Mozilla/5.0 (Linux; Android 14; SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36";
const MAC_DESKTOP =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
const WINDOWS_DESKTOP =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
const LINUX_DESKTOP =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";

test("phones and tablets are mobile regardless of touch-point info", () => {
  assert.equal(isMobileDevice(IPHONE), true);
  assert.equal(isMobileDevice(ANDROID), true);
  assert.equal(isMobileDevice(ANDROID, 0), true, "a missing probe must not unblock a phone");
});

test("desktops pass, with or without a touch screen worth of points", () => {
  assert.equal(isMobileDevice(WINDOWS_DESKTOP), false);
  assert.equal(isMobileDevice(LINUX_DESKTOP), false);
  assert.equal(isMobileDevice(MAC_DESKTOP, 0), false);
  assert.equal(
    isMobileDevice(WINDOWS_DESKTOP, 10),
    false,
    "a touch-screen Windows laptop is still a desktop",
  );
});

test("the iPadOS desktop-mode masquerade (Macintosh UA + touch) is caught", () => {
  assert.equal(isMobileDevice(MAC_DESKTOP, 5), true);
  assert.equal(isMobileDevice(MAC_DESKTOP, 1), false, "one point is a mouse, not a touch screen");
});
