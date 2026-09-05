---
name: run-intent
description: Auto mode for bongtu's intent chain - given an accepted intent, drive spec, plan, build, verify and review to a finished PR without per-stage human gates. Stops only for blocker-class concerns. Use when the user says "run-intent <slug>", "돌려", or wants an accepted intent executed end to end.
---

# /run-intent — drive an accepted intent to a PR

Auto mode per the playbook: autonomous implementation with post-hoc artifact review. The
human gates collapse to two — the intent PR merge (already done) and the final feature PR.
Every artifact is still committed, so the record is identical to manual mode; only the
mid-chain PR ceremonies are skipped. Manual stage commands remain available and unchanged.

Precondition: `.dev/intents/<slug>/intent.md` on main with `Status: accepted`. If not,
route through `/intent` first — capturing intent is never automated.

1. **Workspace**: create the feature worktree `feat/<slug>`. Each run owns its worktree, so
   several accepted intents can run in parallel from separate sessions.
2. **Spec**: spawn `spec-drafter`. Triage its flagged concerns yourself:
   - blocker-class (security-model invariants, protocol/circuit soundness, live-pool
     compatibility) → **stop and ask the user**; do not proceed on your own judgment.
   - everything else → record the resolution or deferral in the spec's Concerns section.
   Commit spec.md (`Status: accepted` — the final PR merge is the acceptance record).
3. **Plan**: write plan.md per the plan skill's template (files, order, risks, proving
   gates), grounded in reading the actual code. Commit it. No interactive plan mode in auto.
4. **Build**: implement the plan's work units in order, `workflow:commit` per unit. A
   deviation from plan.md is fixed by updating plan.md in the same branch, not silently.
5. **Verify + review in parallel**: spawn `verifier` (scope per plan.md's proving gates) and
   `reviewer` (with the slug) concurrently. Fix what they report, then re-spawn BOTH — the
   final state must be a fresh verifier PASS and a fresh reviewer APPROVE over the final
   diff. Three fix rounds without convergence → stop and report to the user.
6. **PR**: `workflow:create-pr`, `Closes #N`, body notes this was an auto-mode run and
   surfaces the spec's deferred concerns as the review points.

Stop-and-ask conditions (never push through): a blocker-class spec concern, a gate failure
that survives three fix attempts, scope the intent does not cover, or anything requiring a
live-chain transaction or a deploy.

## Parallel runs and file conflicts

Concurrent intents do not negotiate with each other; git is the coordination mechanism.

- **Before building** (end of step 3): list the other in-flight runs
  (`git worktree list` + open feature PRs) and diff this plan.md's file list against
  theirs. Overlap on the same files → tell the user and let them pick an order; do not
  race. No overlap → proceed.
- **At PR time**: if main moved, rebase onto main (repo rule: never merge commits) and
  resolve conflicts in this branch — first merged wins, the later run adapts. Any conflict
  resolution changes the diff, so re-run BOTH verifier and reviewer before the PR is
  (re)marked ready.
- The same rule applies when a bot or human review lands after main moved: rebase, resolve,
  re-verify, re-review.
