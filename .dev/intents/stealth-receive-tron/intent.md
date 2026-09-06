# Stealth payment receiving on Tron

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

The receive product must be universal, and the chain where payment demand actually lives
is Tron (TRC20-USDT). Today bongtu has nothing on Tron — no pool, no stealth receive —
and the `tron-rail-spike` intent only evaluates the POOL question. Payment receiving does
not need the pool: per-payment fresh addresses (unlinkability tier) are achievable with
the stealth machinery alone, and Tron's key/address scheme (secp256k1 + keccak, base58
presentation) is close enough to the EVM's that the derivation ports rather than being
redesigned.

## Proposed outcome

The `stealth-receive-maroo` spine extended to Tron at the unlinkability tier (no
shielding — that tier arrives only if the tron-rail-spike leads to a pool):

- The same recipient meta-address serves Tron: the pay page grows a Tron tab issuing a
  FRESH Tron address per visit, accepting TRX and TRC20 with **USDT as the acceptance
  asset** (open question below).
- A sender with a stock Tron wallet (TronLink) or an exchange withdrawal pays plainly; no
  sender-side software.
- The recipient's client scans, derives, and controls each payment address; the receive
  view lists Tron payments alongside Maroo ones (status: received; no sweep/shield tier).
- A gate proves per-payment unlinkability on Tron: two payments share no on-chain link to
  each other or to the recipient's identity, and the recipient can move funds from a
  stealth address with derived keys.

## Affected users and systems

Consumer (recipient); Tron senders. Components: the stealth derivation packages (Tron
address flavor), the pay page, the scan channel (Tron node/API ingestion), the receive
view, docs. Depends on `stealth-receive-maroo`'s shared machinery; independent of the
name layer (Tron wallets resolve no names — the pay page is the route).

## Constraints

- No pool, no shielding claims: the docs and UI must state the Tron tier honestly
  (fresh-address unlinkability, amounts visible per address) versus Maroo's shielded tier.
- Fee reality: moving funds off a stealth address needs TRX energy/bandwidth at that
  address; the design must not strand dust (fee funding or consolidation strategy is part
  of the slice).
- Derivation stays one code path with an address-presentation flavor, not a fork.

## Open questions

- Acceptance asset confirmation: USDT-TRC20 as the gate asset (plus TRX), or TRX-only
  first.
- Scan infrastructure: public API vs own node vs a hosted indexer extension.
- Whether receiving requires activation of the stealth account (Tron account creation
  economics) and who funds it.
