---
name: verify
description: Stage 4 of bongtu's intent chain - run the repo's real gates through the independent verifier sub-agent and act on its evidence. Use before /review and before any PR, or when the user says "verify" / "게이트 돌려".
---

# /verify — independent gate run

1. Spawn the `verifier` sub-agent on the current worktree. Scope:
   - `quick` (default while iterating): core tests, root tsc, workspace typechecks,
     conditional forge test.
   - `full` (required once before the PR): quick + `deploy/gates/e2e_m0.sh` + the indexer
     conformance suite. Warn that full takes minutes (anvil + CPU proofs).
2. Relay the evidence report to the user verbatim in substance: per-gate PASS/FAIL, failing
   excerpts, reproduction commands.
3. On FAIL: fix in this session, then re-spawn the verifier — do not re-run gates by hand in
   this session and call it verified; the point of the stage is that the writer does not
   grade its own work.
4. Do not proceed to `/review` or a PR until the verifier reports an overall PASS at the
   scope plan.md's "Proving gates" section demands.
