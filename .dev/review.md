# Review rubric

What the `reviewer` sub-agent (stage 5 of the intent chain) checks a diff against. This file
owns only the review process: the passes, the severity scale, and which owning document to
read per touched path. Domain rules stay with their owners — never copy them here.

## Passes (in order)

1. **Bugs** — correctness of the changed logic, edge cases, error paths. Every behavior
   change carries a test; a behavior change without one is a finding, not a note.
2. **Security** — when the diff touches a trust surface, check it against the invariants in
   `docs/security-model.md` (who sees what, enforced disclosure, zero-commitment guard).
   Always: no key material or `.env` content in the diff; any on-chain address appearing in
   the diff was taken from the deploy record by field name, not transcribed.
3. **Compliance** — the diff stays within the files `plan.md` names (a deviation must appear
   as a plan.md update in the same branch); each `spec.md` requirement is addressed or
   explicitly deferred; commit/PR text follows repo conventions (CLAUDE.md + README
   Contributing). For chain-exempt small fixes this pass reduces to: the diff matches what
   the commit message claims.

## Severity

- **blocker** — soundness/security/money-state impact, or a gate broken.
- **major** — a correctness bug, a missing test for a behavior change, or an unmet spec requirement.
- **minor** — style, naming, docs debt.

Findings are reported ranked, each with file:line, the rule or doc violated, and a concrete
failure scenario. Zero findings requires stating what was checked.

## Path → owning docs

Read the owner for every top-level area the diff touches before judging that part:

| diff touches | read |
|---|---|
| `circuits/**` | `docs/circuits.md`, `docs/zeto-derivation.md` |
| `chains/evm/**` | `docs/contracts.md`, `docs/security-model.md` |
| `chains/solana/**` | `chains/solana/README.md` |
| `packages/core/**` | `docs/protocol.md` |
| `packages/client/**`, `apps/*-web/**` | `docs/wallet.md`, `docs/errors.md` |
| `apps/indexer/**` | `docs/indexer.md` |
| `apps/relayer/**` | `docs/relayer.md` |
| `apps/sweeper/**` | `docs/portal.md` |
| `prover/**` | `prover/README.md` |
| `deploy/**` | `docs/deployment.md` |
| `package-lock.json` | CLAUDE.md lock-regen rule (check the optional-entry counts) |
| `.github/workflows/**` | `.dev/ci.md` |
| `apps/indexer/abi/*.json` | must match the current `chains/evm` ABI (CI drift-gates it) |

## Review-only checks (owned here)

- No stray artifacts in the diff: build outputs, logs, fixtures not referenced by a test, `.env*`.
- TypeScript diffs respect the const-only rule (owner: CLAUDE.md) — flag any `let` outside comments.
- A diff that changes a pool ABI surface also refreshes `apps/indexer/abi/BongtuPool.abi.json`.
