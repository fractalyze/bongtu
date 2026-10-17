# Indexer internal mode for dedicated enterprise pools

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

The decided model for issue #10 makes the institution's dedicated indexer the ONLY
discovery path on an enterprise pool: no receiver-cts on chain, no public API obligation.
Today the indexer always serves its public routes; arbiter mode (AUTHORITY_KEY) adds
decrypted-note authority but there is no way to run an instance with the public surface
off. A dedicated-pool deployment would either expose public routes it should not, or rely
on out-of-band network policy to hide them — policy the repo cannot test or guarantee.

## Proposed outcome

The indexer supports an explicit internal mode in which public routes are disabled and only
institution-facing paths serve. Falsifiable:

- With internal mode on, public routes refuse (the conformance test asserts it) while
  institution note-serving works.
- With internal mode off, behavior is unchanged and the existing conformance suite stays
  green.
- apps/indexer/README.md documents the mode next to arbiter mode.

## Affected users and systems

Arbiter/institution role. Components: apps/indexer (mode wiring, conformance test, README).

## Constraints

- AUTHORITY_KEY is never logged or returned, in any mode.
- The mode is explicit configuration, never inferred from other settings.
- No behavior change for existing public deployments.

## Open questions

- Exact route partition: which routes count as institution-facing.
- Whether internal mode requires arbiter mode or is orthogonal to it.
- Auth story for the institution-facing routes when the public surface is off.
