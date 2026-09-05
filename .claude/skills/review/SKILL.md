---
name: review
description: Stage 5 of bongtu's intent chain - review the branch diff through the independent reviewer sub-agent against spec.md, plan.md, and the .dev/review.md rubric, then resolve findings before the PR. Use after /verify passes, or when the user says "review" / "리뷰 돌려".
---

# /review — independent review

1. Spawn the `reviewer` sub-agent with the diff range (default `main...HEAD`) and, for chain
   work, the intent slug so it can run the compliance pass against spec.md and plan.md.
2. Relay the ranked findings. For each blocker and major, apply `workflow:respond-to-review`
   rigor: verify the finding is real before implementing; a finding you can demonstrate is
   wrong is answered with evidence, not silently applied.
3. Fix what stands, then re-spawn the reviewer until it returns APPROVE (blockers and majors
   resolved; minors may ship as noted follow-ups at the user's call).
4. Only then open the PR (`workflow:create-pr`). The PR body follows repo convention: short
   summary, the review points a human should scrutinize, `Closes #N`.

The session that wrote the code never self-approves: APPROVE must come from a fresh reviewer
run over the final diff, not from an earlier run plus untracked fixes.
