---
name: intent
description: Stage 1 of bongtu's intent chain - capture a work idea as .dev/intents/<slug>/intent.md through an interview, then gate it through its own PR (merge = accepted, close = rejected). Also triages maintainer-written draft intents. Use when starting feature-scale work, when the user says "intent 잡자" / "new intent", or when a draft intent needs triage.
---

# /intent — capture an intent

The chain and its gates are defined in `.dev/intents/README.md`. This stage produces the
intent artifact and runs its acceptance gate.

**Scope check first.** The chain is for feature-scale work — anything that would get its own
PR and issue anyway. For a bugfix or chore, say so and use the normal loop instead.

## New intent

1. **Interview** the user until each template section below has a real answer. Push back on
   vague outcomes; an intent whose "Proposed outcome" cannot be falsified is not done. Keep
   asking one question at a time (grill-me style) for anything materially ambiguous.
2. **Write** `.dev/intents/<slug>/intent.md` (slug: short kebab-case) from the template.
   `Status: draft`.
3. **Gate**: branch `intent/<slug>` from current main, commit via the `workflow:commit`
   skill, open a PR via `workflow:create-pr` (short body: the Problem and Proposed outcome).
   - **Accept** = user says merge: flip the line to `Status: accepted` in a final commit,
     squash-merge, then open the tracking issue (below).
   - **Reject** = close the PR unmerged and delete the branch. The closed PR is the record.
4. **Tracking issue** (on acceptance): `gh issue create` — a plain public issue (no board,
   no project). Title = the intent title; body = Problem + Proposed outcome summary and a
   link to `.dev/intents/<slug>/`. Note the issue number back in intent.md is NOT needed —
   the issue links the folder, git links the rest.
5. Point the user at `/spec` as the next stage.

## Triage a maintainer draft

Given `.dev/intents/<slug>/` with `Status: draft` and `Origin: maintainer` (uncommitted
working files): read it, interview the user only where the draft is thin, then either run
the same gate (step 3) or delete the folder if the user discards it.

## Template

```markdown
# <title>

Author: <name>. Status: draft.
Origin: conversation | maintainer | incident

## Problem
What hurts today, with evidence. No solutions here.

## Proposed outcome
The observable end state — falsifiable, not a feature list.

## Affected users and systems
Which roles (employer, recipient, arbiter, consumer) and which components
(circuits / contracts / indexer / wallets / prover / deploy).

## Constraints
Hard limits: protocol invariants, gas, proving time, compatibility with the live pool,
timeline.

## Open questions
What must be resolved in the spec stage.
```
