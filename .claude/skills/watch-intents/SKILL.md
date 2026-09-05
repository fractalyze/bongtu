---
name: watch-intents
description: Persistent watcher for bongtu's intent chain - polls origin/main for newly accepted intents and immediately dispatches each through the run-intent auto chain as a background agent, in parallel. Run in a dedicated session on the GPU box (the only host where the gates run). Use when the user says "watch intents", "상주 세션 시작", or wants accepted intents picked up without asking.
---

# /watch-intents — the standing pickup session

Run this in its own session on the dev box and leave it alive; it turns "merge an intent
PR" into "a PR shows up when it's done". The watch is session-local — if the session dies,
restart it with this command.

1. **Arm the watch** (Monitor tool, `persistent: true`). The event condition: an intent on
   `origin/main` with `Status: accepted` and no `feat/<slug>` branch on origin yet. Poll
   read-only against origin — no checkout needed, so any worktree can host the session:

   ```sh
   SEEN=/tmp/claude-watch-intents-seen
   touch $SEEN
   while true; do
     git fetch -q origin main
     for f in $(git ls-tree -r --name-only origin/main .dev/intents | grep '/intent\.md$'); do
       slug=$(basename $(dirname $f))
       grep -qx "$slug" $SEEN && continue
       if git show origin/main:$f | grep -q 'Status: accepted' \
          && ! git ls-remote --exit-code -q origin "refs/heads/feat/$slug" >/dev/null 2>&1; then
         echo "$slug" >> $SEEN
         echo "NEW_INTENT $slug"
       fi
     done
     sleep 180
   done
   ```

2. **On each `NEW_INTENT <slug>` event**: dispatch a background agent (general-purpose,
   its own worktree) whose prompt is: follow `.claude/skills/run-intent/SKILL.md` for
   `<slug>` end to end. Each intent gets its own agent and worktree, so several run in
   parallel; the run-intent overlap check still serializes runs whose plan.md file lists
   collide.
3. **On an agent's completion report**: relay the outcome (PR URL, or the stop-and-ask
   reason) in the session AND send a PushNotification — the user is not watching this
   session. A stopped run (blocker concern, unconverging gates) waits for the user's answer
   here; resume the same agent via SendMessage rather than starting over.
4. **Never** auto-merge anything, and never answer a stop-and-ask condition on the user's
   behalf — the two human gates (intent PR, final PR) stay human.

Known limits, stated so nobody rediscovers them: the watch lives only as long as this
session; polling is ~3 min granularity; the seen-file resets on reboot (`/tmp`), which is
harmless — already-built slugs are skipped by the `feat/<slug>` branch check.
