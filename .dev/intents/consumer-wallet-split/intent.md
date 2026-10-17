# Split the consumer wallet onto its own product URL

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

The end product direction (2026-09-06) is a consumer multi-chain privacy wallet, but today
the consumer wallet (wallet-web) and the enterprise apps (treasury-web, payroll-web) ship
under one product identity and URL surface. The two products have different audiences and
different trust postures — the enterprise side is institution consoles over
dedicated/audited pools, the consumer side is a self-sovereign wallet — and one shared
identity muddies both pitches. Decided: **bongtu stays the enterprise URL; the consumer
wallet gets its own product identity and domain.**

## Proposed outcome

- wallet-web deploys to its own domain as the consumer product (product name and domain
  are a spec-stage decision — deliberately open here).
- treasury-web and payroll-web remain under the bongtu enterprise URL surface, unchanged.
- The repo records the app-to-URL mapping (docs + Vercel project wiring), and neither
  product's UI presents itself as the other.
- Falsifiable: two URLs serve the two products, and the mapping is documented in-repo.

## Affected users and systems

Consumer (wallet user), employer/institution (unchanged apps). Components: apps/wallet-web,
Vercel deployment config, docs. No chain, circuit, or indexer change.

## Constraints

- The monorepo stays single; this is a deploy/identity split, not a code split.
- package-lock.json is fragile against Vercel `npm ci` (repo CLAUDE.md) — any dependency
  work follows the regen recipe, ideally none is needed.
- App naming follows the no-enterprise-wording rule (2026-09-05).
- Overlaps with `wallet-multi-rail` on wallet-web files; whichever runs second rebases.

## Open questions

- The consumer product name and domain.
- Whether any enterprise-facing remnants inside wallet-web move out to the enterprise apps
  as part of the split, or stay behind until the multi-rail work.
- Whether the split includes app-level branding (name in UI chrome) or URL-only for now.
