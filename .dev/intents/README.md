# .dev/intents/ — the intent chain

bongtu's adoption of the [AI-Native SDLC playbook](https://claude.com/blog/the-ai-native-sdlc-playbook):
every feature-scale work item runs through a chain of committed artifacts, one folder per item:

```
.dev/intents/<slug>/
  intent.md   what problem, what outcome, for whom     (stage 1)
  spec.md     requirements + design, concerns flagged  (stage 2)
  plan.md     files to change, order, risks, proving tests (stage 3)
```

The stage commands are repo-local skills (`.claude/skills/`), the independent stages are
repo-local sub-agents (`.claude/agents/`):

| stage | command | who does the work | gate |
|---|---|---|---|
| 1 capture | `/intent` | interview in the main session | intent PR: **merge = accepted, close = rejected** |
| 2 design | `/spec` | `spec-drafter` sub-agent, human edits after | spec PR: merge = approved |
| 3 plan | `/plan` | plan mode in the main session | plan approval, then committed on the feature branch |
| 3' build | (main session) | implement per plan.md, `workflow:commit` per unit | — |
| 4 verify | `/verify` | `verifier` sub-agent runs the real gates | all gates PASS |
| 5 review | `/review` | `reviewer` sub-agent vs spec/plan + [`.dev/review.md`](../review.md) | findings resolved, then PR |
| 6 maintain | `/maintain` | `maintainer` sub-agent health-checks, writes draft intents | human triages drafts via `/intent` |

## State is git, not a tracker

Per the playbook, an artifact's lifecycle is recorded by git events, not status machinery:

- `intent.md` / `spec.md` land via their own PR. Merging the PR **is** the acceptance record;
  closing it unmerged is the rejection record. The `Status:` line in the file is flipped from
  `draft` to `accepted` in the PR's final commit, at the moment the decision is made.
- `plan.md` is committed on the feature branch; its gate is the in-session plan approval, and
  the final PR review checks the diff against it. A deviation discovered while building is
  reflected by updating plan.md in the same branch, so the deviation is visible in the PR diff.
- Done = the feature PR merges and the linked issue closes. Folders are never moved or archived.

A public GitHub issue is opened when an intent is accepted (bongtu tracks work as plain public
issues, no board); the issue links the folder and is the discussion surface, the files are the
record.

## Auto mode

`/run-intent <slug>` drives an **accepted** intent through stages 2–5 to a finished PR with
no per-stage gates: spec.md and plan.md are committed on the feature branch (the record is
identical), verify and review run in parallel at the end, and the human gates collapse to
two — the intent PR merge and the final feature PR. It stops and asks only for
blocker-class concerns (security-model invariants, soundness, live-pool compatibility),
unconverging gates, or anything touching the live chain. Manual stage commands stay
available; capturing an intent is never automated.

Parallel intents each run in their own `feat/<slug>` worktree; overlap is checked against
other runs' plan.md file lists before building, and merge conflicts are resolved by the
later run rebasing onto main and re-running verify + review (see the run-intent skill).

## When the chain applies

Feature-scale work: anything that would get its own PR and issue anyway. Bugfixes and chores
skip stages 1–3 and use the normal loop — `/verify` and `/review` still apply to any PR.
Findings that outgrow the current work item are written back as a new intent (stage 6 closes
the loop), not expanded in place.
