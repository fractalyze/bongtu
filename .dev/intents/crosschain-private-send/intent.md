# Cross-chain private send: mechanism design

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

The global wallet's defining flow — "send this asset on chain A to a recipient on chain C,
privately" — has no mechanism. bongtu pools are per-chain islands: each custodies one token
on one chain, and nothing connects them. The only recorded seam is the cross-pool payment
sketch from the dedicated-pools decision (stealth-exit from one pool, portal-hop into
another), which is a SAME-CHAIN frame; crossing chains adds the whole bridge problem on
top — the asset must exist on the destination chain, someone must move or provide it, and
the bridge hop is exactly where the privacy the pools bought can leak (amount, timing, and
address linkage between the exit and the re-entry). Building wallet UI or protocol pieces
before this design exists risks pointing the product at an unworkable mechanism.

## Proposed outcome

A design document (.dev/crosschain-send-design.md) that:

- Enumerates and compares the candidate mechanisms with their trust and privacy models —
  at minimum: stealth-exit → external bridge → portal re-entry (user-driven), a
  liquidity/relayer network settling out of the destination pool against a source-pool
  claim, and burn-mint style asset issuance where bongtu controls the asset.
- Analyzes the privacy of the bridge gap explicitly: what an observer of both chains
  links, under each mechanism, at what anonymity-set cost, and which mitigations
  (timing jitter, amount splitting, stealth addresses) actually hold.
- Pins the asset model: which assets exist on which chains (native, bridged, issued), and
  what the first shippable corridor is (e.g. Maroo ↔ Solana devnet).
- States the interaction with the authorization/arbiter model per pool family — a
  cross-chain hop must not become an audit escape hatch on enterprise-sourced funds.
- Ends in an explicit recommendation and, on go, the build-campaign slicing.

Falsifiable: the document exists with the comparison and privacy analysis attached, and it
ends in a recommendation, not a survey.

## Affected users and systems

None in production. Output is a .dev design document. The global wallet shell
(`wallet-multi-rail`) is the UI this plugs into later; the stealth/portal machinery and
both rails' pools are the raw material.

## Constraints

- No production code changes; design only.
- No mechanism may weaken a pool's own security model or its family's disclosure
  guarantees; a design that needs that is a no-go finding, not a trade-off.
- The wallet shell must stay buildable without this (the `wallet-multi-rail` intent does
  not block on it).

## Open questions

- Bridge trust: reuse an existing third-party bridge (whose?) vs operator-run liquidity vs
  issuing the asset on both chains.
- Whether the first corridor is consumer-only or must also serve enterprise-sourced funds
  (which drags the envelope/receipt story across chains).
- Where the relayer/fee economics live, and who runs the matching infrastructure.
