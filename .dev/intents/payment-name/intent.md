# Payment name: rotating resolver over the stealth meta-address

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

With `stealth-receive-maroo` in place a recipient shares a pay-page LINK; the product
vision is sharing a NAME (jun.frx): the sender types it into a stock wallet and the
transfer lands privately, no page visit needed. A static name-to-address mapping would
destroy the privacy (every payment to one visible address); the name must resolve to a
FRESH stealth address on every query while remaining resolvable by unmodified wallets.

## Proposed outcome

- A name root the product controls, issuing per-user names under it (exact root — an
  owned .eth second-level with wildcard subdomains vs a DNSSEC-imported domain — is a
  spec decision; the ".frx" rendering is branding on top).
- A CCIP-Read (ERC-3668) wildcard resolver whose gateway derives a fresh stealth address
  from the recipient's registered meta-address on every resolution, so stock ENS-aware
  wallets get per-payment addresses with zero sender-side software.
- Gateway responses are verifiable against the recipient's meta-address (signed, bounded
  TTL), so a compromised gateway cannot silently redirect funds without producing
  cryptographic evidence.
- The name also serves the human fallback: opening it in a browser lands on the pay page
  (for exchanges and wallets that do not resolve names).
- Falsifiable: a stock wallet resolves the name twice and gets two different addresses,
  both spendable by the recipient and both sweeping into the shielded balance; a
  mis-derived gateway response is detected by the verification check.

## Affected users and systems

Consumer (recipient + any sender). Components: the resolver gateway service, the
registration flow from `stealth-receive-maroo`, docs. Depends on `stealth-receive-maroo`
(same meta-address and sweep spine).

## Constraints

- Must work with unmodified ENS-aware wallets (CCIP-Read is the standard path); where a
  wallet or network does not resolve (e.g. custom-network sends), the pay page stays the
  documented route — measure MetaMask behavior on Maroo rather than assuming.
- The gateway is availability-trust only: it can refuse service but must not be able to
  steal undetected (verification requirement above).
- Name issuance cost/custody must not require users to hold ETH (gasless subdomains or
  offchain issuance).

## Open questions

- The concrete name root and its acquisition/ownership.
- Query privacy: the gateway sees resolver queries (sender IP, name); what mitigation, if
  any, ships in this slice.
- Ephemeral announcement dedup between resolver-issued and pay-page-issued addresses.
