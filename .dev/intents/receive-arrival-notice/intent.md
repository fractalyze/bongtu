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

## Proposed outcome

wallet-web's receive surface shows an arrived payment before it is swept:
the moment a Transfer lands on one of the recipient's issued destinations,
the receive view (or a notification) surfaces "payment arrived, sweep
pending" with the amount, and flips to the shielded balance once the sweep
completes. Falsifiable: send USDC to a destination issued for a registered
name; the recipient's receive view shows the pending payment before the
sweep transaction exists; after the sweep the pending entry resolves into
the shielded balance.

## Affected users and systems

Recipient, on the consumer receive product. Components: wallet-web
(receive view, hooks), indexer API (per-destination funded state). Builds
on the event-driven funded detection intent: that flag is the data source;
without it this feature would reintroduce client-side balance polling.

## Constraints

Which rows belong to the recipient is view-key knowledge (self-scan); the
server must not need to learn more than announcements already reveal.
Issuance is unauthenticated, so the display must tolerate junk rows.
Pre-sweep amounts are public on-chain Transfer values, so showing them
leaks nothing new. No protocol or contract change.

## Open questions

Poll vs push (SSE or websocket) for the wallet's pending-state updates.
Whether pending state is computed client-side (scan announcements, join
the funded flag) or served as a query. Whether pay-web's sender side also
gets a "payment seen" confirmation from the same signal. How a pending
entry behaves if the sweep fails or the funding Transfer reorgs out.
