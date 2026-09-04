// Desktop-only gate shared by both apps. On a phone the flows break halfway
// rather than at the door: MetaMask lives inside its own in-app browser (no
// injected provider in the system browser), the wallet pulls multi-MB circuit
// assets, and the payroll worksheet is a 255-row table. Both apps therefore
// refuse mobile up front and say "use a PC".
//
// The verdict is USER-AGENT based, not viewport based: a narrow desktop
// window must keep working (operators tile windows), and a phone must stay
// blocked in landscape. iPadOS 13+ masquerades as macOS ("Macintosh" with a
// touch screen), which only `navigator.maxTouchPoints` exposes — the caller
// passes it alongside the UA so this stays a pure, testable function.

const MOBILE_UA = /Android|iPhone|iPod|iPad|IEMobile|Opera Mini|Mobile/i;

export function isMobileDevice(userAgent: string, maxTouchPoints = 0): boolean {
  if (MOBILE_UA.test(userAgent)) return true;
  return userAgent.includes("Macintosh") && maxTouchPoints > 1;
}
