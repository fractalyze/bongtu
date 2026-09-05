---
name: spec
description: Stage 2 of bongtu's intent chain - draft spec.md for an accepted intent via the spec-drafter sub-agent, review it with the user, and gate it through its own PR (merge = approved). Use after an intent PR merges, or when the user says "spec 뽑자" / "draft the spec".
---

# /spec — design an accepted intent

Preconditions: `.dev/intents/<slug>/intent.md` is on main with `Status: accepted`. If the
intent PR is merged but no tracking issue exists yet, create it now (see the intent skill,
step 4) before drafting.

1. **Draft**: spawn the `spec-drafter` sub-agent with the slug. It reads the intent plus the
   owning docs and writes `.dev/intents/<slug>/spec.md` from `template.md` in this skill's
   directory, returning its flagged-concerns list.
2. **Human review**: present the draft and the concerns to the user section by section. The
   user resolves each flagged concern (this is the gate the playbook gives the product
   owner); edit the file in-session as they decide. Do not proceed with unresolved concerns
   still marked open unless the user explicitly defers them into plan-stage open questions.
3. **Gate**: branch `spec/<slug>` from main, commit via `workflow:commit`, PR via
   `workflow:create-pr` (body: one-paragraph design summary + the resolved concerns).
   - **Approve** = flip to `Status: accepted` in a final commit, squash-merge.
   - **Reject/rework** = close unmerged, or keep iterating on the branch.
4. Comment the spec PR link on the tracking issue (`gh issue comment`), then point the user
   at `/plan`.
