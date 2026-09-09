# Event-driven funded detection for issued destinations — spec

Author: spec-drafter (reviewed by JunBeom Lee). Status: accepted.
Intent: [intent.md](intent.md)

## Context: what exists (load-bearing reuse)

The sweeper bot (`apps/sweeper/src/sweep.ts`) finds money by polling: every
round it fetches `/portal/unswept` and issues a `balanceOf` RPC read per row,
forever, against a candidate set that unauthenticated issuance lets anyone
grow (the recorded PoC spam posture, `apps/indexer/src/api/routes/portal.ts`).
The indexer already owns the opposite pattern this intent generalizes: a
cursor-persisted log tail over `LOG_CHUNK` windows with bisect-on-RPC-error
(`getLogsChunked`, `apps/indexer/src/ingest.ts`), atomic single-transaction
persist with gap-only verified resume ([docs/indexer.md](../../../docs/indexer.md)),
and the `PortalRegistry` (`apps/indexer/src/portal.ts`) whose `Swept`-event
flip (`markSwept`) is exactly the chain-derived, write-behind, replay-idempotent
row mutation the funded flag mirrors. The pool's token address is on-chain
state (`BongtuPool.token`, public on both the enterprise and consumer-only
profiles), so the tail needs no new address configuration. Owning docs:
[docs/portal.md](../../../docs/portal.md),
[docs/indexer.md](../../../docs/indexer.md),
[docs/security-model.md](../../../docs/security-model.md#stealth-receiving-the-portalreceive-edge).

Measured on the live Sepolia demo (2026-09-08, the stack recorded in
`deploy/addresses.consumer.11155111.json`): never-funded rows accumulate and
cost RPC reads every cycle; the rate-capped public RPC's load balancer lags,
making fresh `balanceOf` reads flap to zero; sweep latency is bounded by
`POLL_MS`, not by the payment.

## Requirements

Traceability: R1, R5 are the Proposed outcome's two halves (indexer marks,
bot consumes, no per-row polling); R2 from the reorg-safety constraint; R3
from the restart-backfill open question; R4 from the rate-capped-RPC
constraint; R6 from the Problem's "rows are hints" posture (issuance stays
unauthenticated) plus the flapping-reads measurement; R7 from the
pool-token-vs-native open question; R8 from the flag-visibility open question;
R9 from the Problem's attacker-growable-candidate-set observation; R10 from
the reconciliation-poll open question; R11 from the Constraints (live demo
stack keeps working) and Affected systems (no circuits, contracts, or wallet
changes).

- **R1 (MUST) Event-driven funded marking.** The indexer tails the pool
  token's ERC-20 `Transfer` logs and marks the matching issuance row funded
  when a confirmed transfer with `value > 0` lands at an open (unswept)
  destination. Falsifiable: on the demo stack, a USDC transfer to an issued
  destination flips its row's `funded` field within one ingest poll of the
  transfer clearing the confirmation depth; stopping the indexer's tail
  stalls the flip.
- **R2 (MUST) Confirmation depth before flagging.** The funded tail scans
  only up to `head - FUNDED_CONFIRMATIONS` (env, default 2); a transfer
  inside the unconfirmed window is flagged on a later pass, never in the one
  that first sees it. A flag is set at most once per row and is never
  cleared by the tail: the reorg residual beyond the depth is absorbed by
  the bot's zero-balance skip (R6), so a reorged-out transfer can cost
  skipped rounds, never a revert loop or a wrong sweep.
- **R3 (MUST) Restart backfill, gap-only.** Funded state and the funded
  tail's own scan cursor persist inside the ingest's single atomic
  transaction, so a restart resumes the funded scan from its cursor exactly
  as the pool ingest does — a payment landing while the indexer is down is
  flagged after resume with no full rescan. On the first boot against a
  store that predates the feature (no funded cursor), a one-time
  reconciliation pass reads the balance of every open row and flags the
  funded ones, then the event tail owns detection from the current head.
  Falsifiable: fund a destination while the indexer is stopped; the row is
  funded after restart.
- **R4 (MUST) Rate-capped RPC discipline.** The transfer tail fetches logs
  in `LOG_CHUNK`-sized windows with the existing bisect-on-error behavior,
  filtered server-side (token address + `Transfer` topic + the open
  destination set as the `to`-topic filter, chunked to provider caps), so
  each block window is scanned once regardless of how many open rows exist —
  scan cost is per window, never per row per poll.
- **R5 (MUST) The bot's trigger is the flag; zero reads against unfunded
  rows.** `runOnce` processes only rows served `funded` (and unswept, and
  its own factory's); it issues no balance read against any row not marked
  funded. Per funded row the existing pipeline keeps its two reads: the
  proof-sizing read (`pub[0]` binds to it) and the pre-send re-read. The
  bot still polls the indexer's work feed (an HTTP read of our own service,
  not chain RPC) — what is removed is per-row chain polling. Falsifiable
  headlessly: the fake-client unit suite counts `balanceOf` calls — zero
  for unfunded rows, at most two per funded row.
- **R6 (MUST) Funded is still a hint; the balance read stays the proof of
  payment.** The sweep pipeline's discipline is unchanged for flagged rows:
  read balance, skip zero, build+prove binding `pub[0]` to the read,
  re-read, sweep. A flag with no balance behind it (deep reorg, tail bug,
  dust below `MIN_SWEEP`) produces a skip, never a `SweepExceedsBalance`
  revert loop. No trust-surface change: the flag adds public on-chain data
  to rows the operator already holds
  ([docs/security-model.md](../../../docs/security-model.md#stealth-receiving-the-portalreceive-edge)).
- **R7 (MUST) Pool-token-only detection.** Only the pool's ERC-20 flags
  funded — the one asset the sweeper family can sweep. Native-asset
  transfers emit no log (detecting them would reintroduce polling or need
  trace APIs the rate-capped RPC lacks) and are out of detection scope; the
  stranding posture and its docs wording are unchanged
  ([docs/security-model.md](../../../docs/security-model.md#stealth-receiving-the-portalreceive-edge),
  "Stranded assets").
- **R8 (MUST) Flag visibility: operator feed now, public not foreclosed.**
  The funded fields are served on the attributed operator feed
  (`GET /portal/unswept`, behind the operator token) — the bot is the one
  consumer this intent has. `PortalPublicRecord` and the public
  announcement route are unchanged. The fields live on the row and its
  Postgres columns, so the accepted receive-arrival-notice intent (#94) can
  later serve them publicly as a `toPublic` projection change with no
  migration; nothing here builds for that, nothing forecloses it.
- **R9 (SHOULD) Dust gating without reads.** Each row carries the
  cumulative observed funded amount (replay-idempotent via a per-row
  (block, logIndex) watermark); in priv mode the bot skips flagged rows
  whose observed amount is below `MIN_SWEEP` without any RPC read, so
  dust-priced flag griefing burns the attacker's gas, not the operator's
  RPC budget.
- **R10 (SHOULD) Reconciliation safety net, indexer-side and slow.** A
  low-frequency balance reconciliation over open rows (env-tunable period,
  default off or ≥ 10 minutes; age-capped) backstops tail bugs by setting
  the same flag through the same store. The bot itself keeps no balance
  polling in any mode — the safety net, if enabled, lives where the flag
  lives. The enable/period/age-cap decision is Concern C2.
- **R11 (MUST) Live-stack and gate compatibility.** The live Sepolia demo
  stack keeps working, wired from the consumer record pair by field name;
  the Maroo pool and every contract, circuit, and wallet surface are
  untouched; `deploy/gates/portal_priv_leg.ts` and `name_leg.ts` keep
  passing (portal_priv_leg gains funded-flag asserts, Design "Gate"); the
  indexer conformance suite stays green. The pool ABI does not change, so
  `apps/indexer/abi/BongtuPool.abi.json` needs no refresh.

## Design

### The funded tail (indexer)

A third scan phase inside the existing ingest round, reusing `scanRange`'s
window/bisect machinery against a different address: the pool token (read
from `pool.token()` at boot — chain state, no new address env). Filter:
`topic0 = Transfer(address,address,uint256)`, `topic2 ∈` the open destination
set (rows with `!swept && !funded`, plus `funded` rows while R9's
accumulation applies), zero-padded addresses, the list chunked across
multiple `getLogs` calls when it exceeds provider topic caps. Matching goes
through a destination-keyed index on the registry (the `bySalt` twin).

The tail keeps its own persisted cursor, lagging the pool cursor by
`FUNDED_CONFIRMATIONS`: each round scans
`[fundedCursor + 1, head - FUNDED_CONFIRMATIONS]`. The cursor is one more row
in the same atomic persist (`persist.ts` participant order), so funded flips,
the pool state, and both cursors commit together — a crash replays the same
funded window, and the flip is replay-idempotent exactly like `markSwept`
(set-if-unset; the R9 amount accumulation dedups on the per-row watermark).
Announce-before-display guarantees every honest payment postdates its row,
so a row entering the watch-set at issuance time can never miss its own
payment; a transfer to an address nobody announced matches no row and is
dropped.

Registry mutation follows the `markSwept` discipline verbatim: applied to
the read model immediately, staged in the write-behind buffer, flushed
inside the ingest transaction, buffer cleared only after COMMIT.

### Row state and wire shape

`portal_announcements` gains additive columns; `PortalRecord`
(`packages/core/src/wire/indexerNames.ts`) gains the corresponding fields,
served only on the operator feed (R8):

- `funded: boolean` — set once by the tail (or the boot/reconciliation
  passes), never cleared.
- `fundedAmount: string | null` — cumulative observed transfer value
  (decimal, token base units; R9).
- `fundedTxHash: string | null`, `fundedAt: number | null` — the first
  qualifying transfer's coordinates, for operator forensics and the
  arrival-notice future.

`PortalPublicRecord`, `toPublic`, `POST /portal/announce`, `POST /pay/{name}`,
and the public feed are byte-identical to today.

### The bot's trigger

`runOnce` swaps its per-row gate: instead of reading every row's balance and
skipping zeros, it processes only rows the feed serves as `funded` (R5),
applying the R9 observed-amount dust skip before any RPC call in priv mode.
From there `sweepRecord`/`sweepPrivRecord` are unchanged — balance read,
zero-skip, dust gate on the real balance, prove, re-read, sweep — preserving
the funded-only proof-of-payment posture (R6) and the no-local-state rule
(the indexer still flips `swept` off the `Swept` event). Both modes share
the change: the mechanism is mode-agnostic because the work feed is.

The bot and indexer ship together; a new bot against an un-upgraded indexer
sees no `funded` field and sweeps nothing (visible as a stuck `unswept`
count in `/health`) — rollout ordering is Concern C1.

### Config summary

New env, all indexer-side: `FUNDED_CONFIRMATIONS` (default 2),
`FUNDED_RECONCILE_MS` + age cap if C2 lands enabled. The sweeper gains no
required env; `POLL_MS` becomes the feed-poll cadence only. The demo stack
consumes everything from the committed consumer record pair by field name,
unchanged (R11).

### What does not change

Contracts, circuits, proofs, announcement issuance, first-write-wins, the
attribution split, the operator-token gate, the public feeds, `swept`
semantics, the pay page, wallet-web, and the Maroo deployment. A second
payment to an already-swept destination stays unserved by the bot (today's
behavior: swept rows leave the work feed; fresh address per payment is the
product's contract).

### Gate

Per iteration, headless: (a) sweeper unit suite — fake clients count
`balanceOf` calls: zero against unfunded rows, the existing pipeline
asserts for funded ones, dust skip without reads (R5, R9); (b) indexer unit
suite — synthetic `Transfer` logs flip rows funded, respect the confirmation
lag, replay without double-counting, and survive a simulated crash-replay of
the same window (R1, R2, R3). Final gate, per the heavy-gate rule:
`deploy/gates/e2e_m0.sh` with `portal_priv_leg.ts` extended — after the two
payments land, assert the operator feed serves both rows `funded` BEFORE
`runOnce` executes, then all existing sweep/unlinkability asserts unchanged;
plus a backfill leg (fund a destination while ingest is paused, resume,
assert the flip); plus the indexer conformance suite (`apps/indexer` npm
test). `name_leg.ts` keeps passing unmodified. The live Sepolia stack is the
intent's falsifiable field check, run by the operator after ship.

## Non-goals

- No public/client-visible funded serving — receive-arrival-notice (#94)
  owns that; this slice only avoids foreclosing it (R8).
- No native-ETH or foreign-token detection, and no new stranded-asset
  surfacing; the payment-name C1 posture and docs wording stand.
- No change to issuance authentication or rate limiting: rows stay
  unauthenticated hints (the recorded PoC posture); this slice only makes
  never-funded hints cost ~nothing.
- No re-sweep path for already-swept destinations, no batching, no fee
  model — the sweeper's PoC boundaries stand.
- No subscription transport (websocket `eth_subscribe`): the tail stays
  polled `getLogs`, the shape the rate-capped public RPC and the existing
  ingest support.
- No contract, circuit, proof, or wallet change of any kind.

## Concerns

Flagged for the human gate; classes per the intent-chain rule. Triage
resolutions recorded 2026-09-09 (auto-mode run; the feature PR is the veto
surface).

- **C1 (triaged to judgment, resolved: indexer-first ordering, documented):
  rollout coupling on running deployments.** The bot's only trigger becomes
  a field the indexer must serve; an un-upgraded indexer under a new bot
  stalls sweeps silently — funds sit at public destinations until ops
  notices (observable: a stuck `unswept` count in the bot's `/health`).
  Downgraded from blocker-class: the intent-chain blocker category is
  live-POOL compatibility, and this slice touches no contract or pool — the
  coupling is service restart ordering. The boot reconciliation (R3) makes
  indexer-first restart sufficient, the ordering lands as an explicit note
  in `deploy/README.md` (docs debt), and the one currently-deployed fleet
  (the Sepolia demo) is stopped in its entirety right now, so its next
  start brings both services up on the new code together.
- **C2 (judgment, resolved: no periodic net; boot pass is the lever): the
  reconciliation safety net vs the intent's falsifiability.** Decision:
  ship NO periodic reconciliation loop — the funded cursor is gap-only
  (it advances only past scanned windows), so the tail cannot miss a
  transfer short of a code bug, and a background net would mask exactly
  that bug while breaking the intent's falsifiable "stopping the tail
  stalls detection". The R3 boot reconciliation doubles as the ops
  recovery lever via `FUNDED_RECONCILE_ON_BOOT=1` (forces the same
  one-time pass on a suspect store at restart). R10's periodic form is
  recorded as a follow-up candidate, not built.
- **C3 (judgment, resolved: confirmed operator-internal).** Funded fields
  serve on the attributed operator feed only; the public projection is
  #94's surface. Columns and row fields are shaped so #94 is a `toPublic`
  change, per R8.
- **C4 (judgment, resolved: R9 kept; posture reconfirmed): the flag raises
  the spam price but adds a gas-priced griefing lever.** R9 stays: the
  per-row watermark is one (block, logIndex) pair and directly turns the
  1-base-unit grief into a zero-read skip, the cheapest defense on offer.
  The unauthenticated growth of the `to`-topic filter set is accepted under
  the recorded rows-are-hints posture — scan cost is per window (R4) and
  the filter chunking bounds each call; issuance rate limiting stays the
  ops-layer concern it already was.
- **C5 (judgment, resolved: accepted): confirmation depth and the
  never-clear rule.** `FUNDED_CONFIRMATIONS=2` default stands; a
  beyond-depth reorged-out transfer leaves one permanently flagged row
  costing one skip read per round — accepted as negligible (requires a
  >2-block reorg exactly straddling a payment). No clear-after-N policy.
- **C6 (minor, resolved: accepted): additive field discipline.** Additive
  columns + optional-shaped wire fields; old rows read `funded=false` and
  are healed by the boot pass. No version negotiation — the single-PR ship
  plus C1's ordering covers the demo-scale fleet.

## Docs debt

- [docs/portal.md](../../../docs/portal.md): the sweep-mechanics and
  operator-boundary paragraphs — funded detection is now the indexer's
  transfer tail, the bot consumes the flag, the balance read remains the
  proof of payment; the PoC-boundaries wording ("only a nonzero ERC-20
  balance triggers work") updated to the flag-then-verify shape.
- [docs/indexer.md](../../../docs/indexer.md): the ingest walkthrough (the
  funded tail phase, its lagging cursor in the atomic persist, the boot
  reconciliation), the `LOG_CHUNK` section (token-scan filter shape), the
  HTTP API table (`/portal/unswept` row fields), the env table.
- [docs/security-model.md](../../../docs/security-model.md): the stealth
  receiving edge — one line on the funded flag being chain-public data
  served operator-side, and that the sweep's proof-of-payment discipline is
  unchanged.
- `apps/indexer/README.md`: env (`FUNDED_CONFIRMATIONS`, reconciliation
  knobs), schema note, route field delta.
- `apps/sweeper/README.md`: the trigger description (flag-driven, no
  per-row polling), the PoC-boundaries paragraph, the Sepolia profile note.
- `deploy/README.md`: the Sepolia demo-stack section (indexer env
  additions, the C1 indexer-first restart ordering).
- `packages/core/README.md` (wire types index) if it enumerates the portal
  record fields.
