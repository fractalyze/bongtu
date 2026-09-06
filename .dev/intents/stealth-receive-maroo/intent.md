# Stealth payment receiving on Maroo: pay page to shielded balance

Author: JunBeom Lee. Status: accepted.
Origin: conversation

## Problem

The consumer product's position (2026-09-06) is identity + receive: a recipient shares one
handle and receives payments privately, from senders who use ANY stock wallet and know
nothing about bongtu. Nothing ships that today. The existing portal stealth-deposit
machinery is depositor-facing (the sender is the bongtu user); Umbra-class protocols put
the stealth derivation on the sender's software, which violates the stock-wallet
constraint. The receive side is the product; this intent builds its core spine on the
chain where the pool already lives.

## Proposed outcome

A tracer bullet from an uninformed sender to a shielded balance, with NO name layer yet
(the pay page is the entry point; the name resolver is the `payment-name` intent):

- A recipient registers a stealth meta-address and gets a hosted **pay page** that shows a
  FRESH stealth address on every visit, plus the payment coordinates (chain, token, QR).
- A sender with a stock wallet (or an exchange withdrawal) pays that address on Maroo with
  a plain transfer; no bongtu software, no special transaction shape.
- The announcement/scan channel lets the recipient's client derive and claim each payment;
  the sweeper moves stealth-address funds into the pool so they land as the recipient's
  shielded notes (amount and onward flow shielded, the Fluidkey/Umbra differentiator).
- A minimal receive view lists payments (fresh address, status: received → swept →
  shielded).
- A gate proves the privacy claim: two payments to the same recipient share no on-chain
  link to each other or to the recipient's identity, and both end shielded.

## Affected users and systems

Consumer (recipient); sender is any wallet holder. Components: stealth key machinery and
portal/sweeper (chains/evm + apps/sweeper), packages (client/core stealth derivation), a
new pay-page surface, apps/indexer (scan channel), docs.

## Constraints

- Sender-side requirements are ZERO: any flow that needs the sender to run bongtu code is
  out (that is the existing portal's job, not this one).
- The pay page/gateway learns the payment mapping by construction (it serves the
  addresses); on-chain unlinkability is the claim, operator-blindness is not — state the
  trust posture in the security model honestly.
- Live Maroo pool reused as-is; no circuit changes expected (stealth + portal + sweep are
  existing machinery classes).
- Third-chain extensibility: the meta-address and pay-page shapes must not hard-code the
  EVM rail (the `stealth-receive-tron` intent reuses them).

## Open questions

- Recipient registration and meta-address custody UX (which app surface owns it until the
  wallet exists).
- Announcement channel shape: on-chain ephemeral-pubkey log vs indexer-served (cost vs
  self-sovereign scan).
- Sweep economics and timing (who pays sweep gas, batching, dust threshold).
