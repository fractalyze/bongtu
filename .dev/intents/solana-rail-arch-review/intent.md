# Architecture review of the Solana rail

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

The Solana rail landed as a rapid campaign (culminating in PR #69: initialize instruction,
two-profile validator e2e, deploy runbook) reviewed per-PR against each diff, never as a
whole surface. The risks of that mode: structural drift from the EVM rail's patterns (the
feed projection and rail-engine unification of PRs #65-#68 happened mid-campaign),
duplicated abstractions between the two rails' clients, and seams that will hurt when the
dedicated enterprise-pool work has to touch both rails.

## Proposed outcome

An independent architecture review of the complete Solana rail surface on main: the
program, packages/client-solana, the core solana chain module, the indexer's solana
engine, deploy/solana, and the gates. Falsifiable:

- Blocker and major findings are fixed in this intent's feature PR.
- Smaller findings are each filed as an issue or a draft intent — every finding ends up
  fixed or tracked, none dropped.
- The review record itself is committed (location decided in spec).

## Affected users and systems

No user roles directly. Components: chains/solana, packages/client-solana, packages/core,
apps/indexer, deploy/solana.

## Constraints

- Behavior-neutral beyond what findings demand; committed fixtures and gates stay
  compatible.
- No changes to deployed programs or live artifacts.

## Open questions

- Review lens: reuse .dev/review.md as-is or extend it with architecture-specific criteria
  (rail symmetry, abstraction ownership).
- Where the review record lives (.dev/ file vs the tracking issue).
- Scope boundary: whether wallet-web's solana-facing UI is in scope.
