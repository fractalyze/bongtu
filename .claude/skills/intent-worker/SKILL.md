---
name: intent-worker
description: One worker in bongtu's intent pool - each iteration claims the next accepted-but-unstarted intent via an atomic branch push and drives it through the run-intent chain to a PR. Run as "/loop /intent-worker" in a dedicated session; start several sessions for a parallel fleet. Use when the user says "worker 띄워", "intent-worker", or wants standing sessions that pick up intents on their own.
---

# /intent-worker — a worker session in the pool

Run via `/loop /intent-worker` (self-paced) in a dedicated session on the dev box — the
only host whose gates run. A fleet is just more sessions; workers never talk to each
other, they coordinate through git claims. To start three from a shell:

```sh
for i in 1 2 3; do
  tmux new-session -d -s bongtu-worker-$i -c ~/Workspace/bongtu \
    "claude '/loop /intent-worker'"
done
```

## One iteration

1. **Find work**: `git fetch -q origin main`; candidates are slugs under `.dev/intents/`
   on origin/main whose intent.md says `Status: accepted` and which have no
   `refs/heads/feat/<slug>` on origin (`git ls-remote`). None → this tick is a no-op;
   let the loop reschedule (idle pace, 20–30 min).
2. **Claim atomically** (oldest candidate first): create local `feat/<slug>` at
   origin/main, add an empty commit `chore(<slug>): claim intent for auto run`, and push.
   The push either creates the ref or is rejected because another worker's claim commit
   got there first — rejected means claimed elsewhere; delete the local branch and try
   the next candidate. Never force-push a claim.
3. **Run the chain**: enter a worktree on the claimed branch and follow
   `.claude/skills/run-intent/SKILL.md` end to end (spec → plan → build → verify ∥ review
   → PR). The claim commit disappears in the squash merge.
4. **Report**: PushNotification with the PR URL, or with the stop-and-ask reason.
5. **If stopped** (blocker concern, unconverging gates, live-chain action): leave the
   branch claimed with the partial work committed, notify, and move on to the next
   candidate on the next tick. The user's answer in this session resumes the parked
   intent before new claims are considered.

## Fleet rules

- One worker per session; never point two workers at the same worktree.
- Heavy-gate contention: full-scope verify (anvil e2e, indexer conformance, GPU) is
  serialized across workers by the verifier's lock — expect queueing, don't kill a peer's
  gate run.
- Workers never merge PRs, never answer stop-and-ask conditions themselves, and never
  touch another worker's `feat/*` branch. The two human gates stay human.
- The loop dies with the session; after a reboot, restart the fleet with the tmux
  one-liner. Claims survive (they're branches), so nothing is picked up twice.
