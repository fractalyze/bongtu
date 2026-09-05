---
name: plan
description: Stage 3 of bongtu's intent chain - turn an approved spec into plan.md (files to change, work order, risks, proving tests) in plan mode, then commit it as the first commit of the feature branch. Use after a spec PR merges, or when the user says "plan 짜자" / "plan this out".
---

# /plan — plan an approved spec

Preconditions: `.dev/intents/<slug>/spec.md` on main with `Status: accepted`.

1. **Workspace**: create the feature worktree/branch `feat/<slug>` (EnterWorktree; never
   reuse another session's worktree).
2. **Plan mode**: enter plan mode. Read intent.md + spec.md, explore the code the spec
   touches, and produce `.dev/intents/<slug>/plan.md`:

   ```markdown
   # <title> — plan

   Spec: [spec.md](spec.md)

   ## Changes
   Ordered work units. Per unit: the files that change, what changes, and the test that
   proves it (per repo rule, every behavior change needs one).

   ## Risks
   What could go wrong and the check that catches it (gates, differential tests,
   live-pool compatibility).

   ## Proving gates
   Which gates must pass before PR: quick set always; e2e_m0.sh + indexer conformance
   when the diff warrants (see the verifier agent's scope rules).
   ```

3. **Gate**: the user's plan-mode approval is the acceptance. On approval, commit plan.md to
   the feature branch via `workflow:commit` as its first commit.
4. **Build** proceeds in this session against plan.md, committing per work unit. If reality
   deviates from the plan, update plan.md in the same branch so the deviation is visible in
   the PR diff — the stage-5 review checks diff-vs-plan.
5. After the last unit: `/verify`, then `/review`, then `workflow:create-pr` referencing the
   tracking issue (`Closes #N`).
