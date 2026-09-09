# The recipient sees a payment the moment it arrives

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

On the live demo the recipient's first signal that anyone paid them is the
shielded balance, which exists only after the bot's sweep lands and the
wallet re-scans in a signed session. Between the sender's Transfer and the
sweep there is a real window (detection lag + proof + tx) in which the
recipient's receive screen shows nothing: no "payment arrived", no "sweep
pending". During the live acceptance run the recipient had to learn
out-of-band that the 20 USDC had landed. For a product whose pitch is
"share a name, get paid", the paid moment being invisible is a trust gap:
the sender says "sent", the recipient's screen says nothing, and both wait.

The gap is wider than the pre-sweep window (user direction 2026-09-09,
"receive쪽 process만 잘하고 싶은거야"): even AFTER the sweep, the balance
is invisible until the recipient re-signs — the derive signature is the
viewing key, so every page visit starts blind. The receive-side product
the user described is one page: my private balance just there, a fresh
one-time address on demand, and incoming money appearing on its own with
zero action after the one-time registration.

## Proposed outcome

The recipient's receive surface makes an incoming payment visible with no
action at any stage:

- The moment a Transfer lands on one of the recipient's issued
  destinations, the receive view (or a notification) surfaces "payment
  arrived, sweep pending" with the amount, and flips to the shielded
  balance once the sweep completes.
- With an opt-in per-device view session, the balance is visible WITHOUT a
  fresh wallet signature: the device stores only the view-side key
  material (note scanning and decryption), never spend authority — moving
  money still requires the signature. Registration stays the one-time
  setup it already is.
- The surface itself is receive-first: one page showing the live shielded
  balance, a fresh one-time address on demand, and incoming payments as
  they arrive (whether this is a slimmed wallet-web view or a standalone
  page is a spec decision).

Falsifiable: register once, enable the device session, close everything;
send USDC to a destination issued for the name; reopening the page (or
leaving it open) shows the pending payment before the sweep transaction
exists and the updated shielded balance after it, with zero clicks and
zero signatures on the receive side.

## Affected users and systems

Recipient, on the consumer receive product. Components: wallet-web
(receive view, hooks, key/session handling), indexer API (per-destination
funded state). Builds on the event-driven funded detection intent: that
flag is the data source; without it this feature would reintroduce
client-side balance polling.

## Constraints

Which rows belong to the recipient is view-key knowledge (self-scan); the
server must not need to learn more than announcements already reveal.
Issuance is unauthenticated, so the display must tolerate junk rows.
Pre-sweep amounts are public on-chain Transfer values, so showing them
leaks nothing new. The device session stores VIEW capability only: anyone
opening that browser can see the balance and incoming history but cannot
move funds — an explicit opt-in with that tradeoff stated in plain
language, defaulting off. No protocol or contract change.

## Open questions

Poll vs push (SSE or websocket) for the wallet's pending-state updates.
Whether pending state is computed client-side (scan announcements, join
the funded flag) or served as a query. Whether pay-web's sender side also
gets a "payment seen" confirmation from the same signal. How a pending
entry behaves if the sweep fails or the funding Transfer reorgs out.
Exactly which key material the view session persists (stealth view key,
note view key, KEM decapsulation key) and that none of it carries spend
authority. Storage mechanism and hardening (plain localStorage vs
passkey/WebAuthn-wrapped). Standalone receive page vs a wallet-web mode,
and what the non-session (signed-out) view shows.
