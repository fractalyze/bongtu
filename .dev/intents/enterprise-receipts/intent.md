# Off-chain receipts for ct-free enterprise payments

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

On a ct-free enterprise pool the chain carries no recipient-readable record: a recipient
depends entirely on the institution's indexer to learn (value, salt, leafIndex), so they
hold no trustless proof of what they were paid and no cold-spend path if the institution
disappears or stonewalls. The decided #10 model closes this with an off-chain receipt
convention: the institution hands each recipient (value, salt, leafIndex) at payment time;
verification is trustless against the on-chain leaf, and a withheld receipt is a payslip
problem (legal/social), not a chain problem.

## Proposed outcome

A receipt format shipped end to end, falsifiable by a test that runs exactly this path:

- The payroll console emits a receipt per payment.
- The wallet verifies Poseidon(value, salt, pubkey) == the on-chain leaf at leafIndex,
  needing nothing from the institution beyond the receipt itself.
- A recipient holding only a receipt and chain access can verify and cold-spend without
  the institution's indexer.

## Affected users and systems

Employer (emission), recipient (verify + spend). Components: the payroll console app,
wallet-web, packages/core (receipt verify), docs.

## Constraints

- Zero chain cost: pure off-chain convention, no contract or circuit change.
- Verification must not require institution availability.
- Format must be stable enough to hand to third-party wallets later (it is the recipient's
  exit hatch).

## Open questions

- Serialization and transport: file, QR, in-app message.
- Which app owns emission (payroll-web vs treasury-web after the 2026-09-05 rename).
- Mixed-mode wallet discovery ordering: self-scan + receipts + institution API.
