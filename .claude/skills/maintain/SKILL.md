---
name: maintain
description: Stage 6 of bongtu's intent chain - health-check the live pool, CI, deployed apps, and repo drift through the maintainer sub-agent, then triage its draft intents with the user. Use on demand ("maintain 돌려", "health check"), typically from a clean main checkout; scheduling comes later.
---

# /maintain — close the loop

1. Run from a clean tree (the maintainer writes draft intent files into the working tree;
   they must be distinguishable from your own work). Spawn the `maintainer` sub-agent.
2. Relay its check table (pool RPC / CI / apps / drift) and evidence.
3. **Triage** each draft intent it wrote, one at a time, with the user:
   - pursue → run the `/intent` gate on it (interview to fill thin sections, branch, PR);
   - discard → delete the folder now, and say why in the session so the reasoning is on
     record in the transcript.
4. Findings the maintainer reported as transient noise (no draft written) need no action,
   but if the same noise shows up two runs in a row, promote it to a draft intent.

This stage is manual for now; if the check list stabilizes, wire it to a schedule as a
separate decision (do not do this unilaterally).
