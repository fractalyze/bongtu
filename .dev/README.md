# .dev/ — agent-facing working artifacts

This directory holds decision-process documents, kept out of `docs/` so that `docs/` stays
a clean set of current facts.

Sorting rule: a document that answers **"what is true now"** goes in `docs/`; one that answers
**"why we chose / what we tried / what remains"** goes here.

## Contents

- [`milestone-m0.md`](milestone-m0.md) — M0 Goal and Done-criteria tracker (core soundness: 4 units,
  gates, the two retired critical risks).
- [`milestone-m1.md`](milestone-m1.md) — M1 Goal and Done-criteria tracker (1×256 GPU disburse,
  the first testnet deploy, gas evidence).
- [`milestone-m2.md`](milestone-m2.md) — M2 Goal and Done-criteria tracker (product surface: React
  wallet, indexer Postgres store, `@bongtu/core` rename).
- [`architecture-review.md`](architecture-review.md) — the 2026-07-25 depth/seam review: applied,
  deferred (with revival criteria), and rejected decisions — check before re-suggesting a refactor.
- [`monorepo-layout.md`](monorepo-layout.md) — layout decision record: why the tree is split as it is,
  plus the rejected alternatives.
- [`ci.md`](ci.md) — CI design decisions: artifact-cache soundness argument, pins-file design,
  measured wall times, and the hosted-runner local-pass/CI-fail lessons.
- [`intents/`](intents/README.md) — the intent chain: per-work-item intent/spec/plan artifacts,
  their PR gates, and the stage commands (`/intent` … `/maintain`).
- [`review.md`](review.md) — the stage-5 review rubric: passes, severity, and the
  path→owning-docs routing table the `reviewer` sub-agent follows.
