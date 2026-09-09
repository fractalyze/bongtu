# Event-driven funded detection — plan

Spec: [spec.md](spec.md)

Parallel-run check (2026-09-09): no other in-flight feature run (open PRs are
all intent captures; the other worktrees are parked branches). No file
overlap to negotiate.

## Changes

Ordered work units, one `workflow:commit` each.

### U1 — funded row state: wire type, schema, registry

Files: `packages/core/src/wire/indexerNames.ts` (PortalRecord gains
`funded: boolean`, `fundedAmount: string | null`, `fundedTxHash: string |
null`, `fundedAt: number | null` — on the ATTRIBUTED record only;
`PortalPublicRecord` and `toPublic` untouched), `apps/indexer/src/schema.sql`
(additive `ALTER TABLE portal_announcements ADD COLUMN IF NOT EXISTS` for the
four columns, defaults so pre-feature rows read `funded=false`, plus the
single-row `funded_cursor` table mirroring `ingest_cursor`),
`apps/indexer/src/portal.ts` (boot loads the new columns; a
destination-keyed index beside `bySalt`; `markFunded(destination, value,
txHash, blockNumber, logIndex, blockTimestamp)` following the `markSwept`
write-behind discipline — set-once flag, cumulative `fundedAmount`, per-row
`(blockNumber, logIndex)` watermark for replay dedup (kept in memory and
persisted so a restart replay cannot double-accumulate), first-transfer
`fundedTxHash`/`fundedAt`; `flushInto` gains the funded UPDATE; unswept
rows keep serving regardless of funded state — filtering is the bot's).

Watermark persistence: two more additive columns (`funded_block`,
`funded_log_index` — the high-water pair), loaded at boot.

Proves it: `apps/indexer/test/portal.test.ts` — flag sets once and never
clears; amount accumulates across two transfers; the same (block, logIndex)
replayed does not double-count; a transfer to a swept row no-ops; `toPublic`
output byte-identical to today (pinned positively); boot round-trips the new
columns (the existing pg-less memory-mode pattern). Gate: `cd apps/indexer
&& npm run test:unit && npx tsc --noEmit`; `packages/core` tsc.

### U2 — the funded tail in ingest + boot reconciliation

Files: `apps/indexer/src/ingest.ts` (read `pool.token()` at first ingest
(cache on the instance); a `scanTransfers(from, to)` phase after
`applyLogs` inside `ingest()`: viem `getLogs` with the ERC-20 `Transfer`
event + `args.to` = the open (unswept) destination list, address-chunked
(cap ~500 per call) and block-windowed via the existing `LOG_CHUNK` +
bisect-on-error shape; each hit calls `portal.markFunded`; scans
`[fundedCursor+1, min(head - FUNDED_CONFIRMATIONS, head)]` and never past
the pool cursor's head; `FUNDED_CONFIRMATIONS` env, default 2),
`apps/indexer/src/portal.ts` or a small `fundedcursor.ts` (the cursor as a
persist participant staged in the SAME `persistAtomically` transaction,
after the registry, before the block cursor), `apps/indexer/src/chain.ts`
(cfg: `fundedConfirmations`, `fundedReconcileOnBoot`),
`apps/indexer/src/index.ts` (env plumbing). Boot reconciliation in
`bootPostgres`: when no `funded_cursor` row exists (pre-feature store) or
`FUNDED_RECONCILE_ON_BOOT=1`, read `balanceOf` for every open row
(sequential; demo scale) and `markFunded` the nonzero ones with a synthetic
watermark (block = reconciliation head, logIndex = -1), then seed the
cursor at `head - FUNDED_CONFIRMATIONS`.

Proves it: `apps/indexer/test/ingest.test.ts` — synthetic Transfer logs
flip only matching open rows; the confirmation lag holds (a transfer at
`head - 1` with depth 2 is not flagged this round, is flagged next);
replaying the same window is idempotent; `apps/indexer/test/persist.test.ts`
— funded flip + cursor commit atomically, a mid-persist failure rolls both
back (the existing crash-replay harness). Gate: indexer unit suite + tsc.

### U3 — the bot consumes the flag

Files: `apps/sweeper/src/sweep.ts` (`runOnce` gates rows on
`record.funded === true` before any chain read; priv mode additionally
skips rows whose `fundedAmount` (when present) is below `minSweep` with no
RPC read; `sweepRecord`/`sweepPrivRecord` pipelines unchanged),
`apps/sweeper/README.md` deferred to U5.

Proves it: `apps/sweeper/test/sweep.test.ts` — fake clients count
`balanceOf` calls: zero against unfunded rows; at most two per funded row;
the priv dust skip issues zero reads; a feed with no funded field at all
(un-upgraded indexer, the C1 shape) sweeps nothing and leaves
`state.unswept` visible; the existing pipeline asserts unchanged for a
funded row. Gate: `cd apps/sweeper && npm test && npx tsc --noEmit`.

### U4 — gates: portal_priv_leg funded asserts + backfill leg

Files: `deploy/gates/portal_priv_leg.ts` — after the two distinct-EOA
payments land, mine `FUNDED_CONFIRMATIONS` blocks (`anvil_mine`), wait one
ingest poll, assert the operator feed serves both rows `funded=true` with
the paid amounts BEFORE the sweeps run (keeping the default depth
exercised rather than zeroing it); after the sweeps, all existing asserts
unchanged. Backfill leg appended in the same file: issue + fund a third
destination while the indexer process is STOPPED (kill, fund, restart the
spawn), assert the row flips funded after resume (R3). The sweeper in the
gate consumes the flag end to end by construction.

Proves it: the gate's own asserts; run the standalone priv-leg smoke
(the `portal_priv_leg.ts` direct-run mode used in the maroo build) per
iteration if cheap, full `e2e_m0.sh` only as the final gate.

### U5 — docs

Files per the spec's docs-debt list: `docs/portal.md` (sweep mechanics +
PoC boundary wording), `docs/indexer.md` (ingest walkthrough: funded tail
phase, lagging cursor in the atomic persist, boot reconciliation; env
table; `/portal/unswept` field delta), `docs/security-model.md` (one line:
funded flag is chain-public data served operator-side; proof-of-payment
discipline unchanged), `apps/indexer/README.md` (env + schema + route
delta), `apps/sweeper/README.md` (trigger description + PoC boundaries),
`deploy/README.md` (Sepolia demo section: indexer env additions + the
indexer-first restart ordering note from concern C1).

Proves it: docs-only; the U4 gate run stands.

## Risks

- **RPC `to`-topic list caps**: providers cap topic-array sizes untypically
  low. Check: the address list is chunked (~500) with the chunk size a
  constant next to `LOG_CHUNK`; the unit test drives a multi-chunk set.
- **Anvil determinism of the confirmation lag**: auto-mine means head
  advances only on txs. Check: the gate mines the depth explicitly
  (`anvil_mine`) before the funded assert; unit tests own the lag
  semantics.
- **Conformance / pg suites pin row shapes**: additive fields can still
  break deep-equality pins. Check: run the indexer conformance suite
  (`apps/indexer && npm test`) in the final gate; fix pins additively.
- **Replay double-accumulation of `fundedAmount`**: the crash-replay path
  re-delivers the same window. Check: the watermark is persisted with the
  row and the persist test replays the same window across a simulated
  crash.
- **C1 rollout coupling**: new bot + old indexer sweeps nothing. Check: the
  sweep unit test pins the no-funded-field behavior; the deploy/README note
  states indexer-first ordering (the one live fleet is currently stopped).
- **Live-pool safety**: no contract, circuit, or record file changes; the
  Maroo pool untouched. Check: diff contains no `chains/`, `circuits/`, or
  `deploy/addresses.*` changes.

## Proving gates

Per iteration: `packages/core` tests + tsc, `apps/indexer` unit suite +
tsc, `apps/sweeper` tests + tsc, `npm run typecheck --workspaces
--if-present` at the root. Final gate before PR: `deploy/gates/e2e_m0.sh`
(with the extended portal_priv_leg + backfill leg; PATH prefix in the same
command) and the indexer conformance suite (`cd apps/indexer && npm
test`). `name_leg.ts` must pass unmodified. Verifier scope: full.
