# Split deploy/ per chain rail

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

deploy/ is flat and EVM-implicit: address/module records for three chain ids plus arbiter
KEM keys sit at the root next to forge/, gates/, live/, with solana/ as the only carved-out
rail. The dedicated enterprise-pool model multiplies record files
(`addresses.<chainid>.<name>.json` per pool): at N institutions across M chains the flat
root becomes unreadable sprawl, and nothing in the layout says which rail a file belongs to.

## Proposed outcome

deploy/evm/ and deploy/solana/ are the two rail roots. All EVM material (records, forge/,
EVM gates, live/) lives under deploy/evm/; every referencing path — CI workflows, the
packages/core network.ts mirror test, docs, scripts — is updated in the same change.
Falsifiable: all gates green, and a repo-wide grep finds no reference to the old flat paths.

## Affected users and systems

No user roles. Components: deploy/, CI workflows, packages/core (network mirror test), docs.

## Constraints

- Pure restructure, zero behavior change; record file contents byte-identical, only paths
  move.
- Live-chain records stay canonical: the network.ts mirror test keeps holding
  addresses.450815.json field-for-field at its new path.
- Sequencing with `enterprise-ctfree-pool`: whichever lands second rebases; new enterprise
  records should land in the new layout.

## Open questions

- Does gates/ split per rail, or keep shared entrypoints at deploy/gates/ that dispatch.
- Whether deploy/README.md stays the single index or each rail root gets its own.
