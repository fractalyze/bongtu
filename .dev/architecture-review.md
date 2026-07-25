# Architecture review — 2026-07-25

The deepening review that produced commit `9a15beb` ("one owner per concept"). This is
the cheap-ADR record a future review should consult **before re-suggesting** anything
here: the deferred items carry revival criteria, and the rejected items carry the
reason they should stay rejected.

## Method

Five parallel explorers, one per area (sdk, indexer, web apps, prover, fixtures/e2e
gates), each hunting with a depth/seam/locality lens: deep modules vs pass-through
wrappers, real seams (two adapters) vs hypothetical ones, the deletion test, and
change-locality ("how many files does the next likely change touch"). Synthesis merged
the findings into 18 candidates; the 14 low-risk ones were applied the same day, each
replacement byte-pinned against committed fixtures before its duplicate copy was
deleted.

## Applied (14) — commit `9a15beb`

| # | what | why (one line) |
|---|---|---|
| 2 | export `foldToRoot` from sdk `imt.ts`; delete the 4 consumer copies | the CheckIMTProof fold order (the spec §5.1 bit-order hazard) gets one implementation, co-located with its inverse `merklePath` |
| 3 | one `toWire` in sdk `proving.ts` replaces ~9 producer serializers | the decimal wire encoding lives with the wire types it serves; new circuit fields are handled by construction |
| 4 | `/alarms` becomes one discriminated `disclosure \| envelope` feed | the arbiter's tamper evidence was produced but never consumable over HTTP — a compliance product's alarm was console-only |
| 5 | sdk `indexerApi.ts` owns the read-API shapes + one `buildNotesUrl` | silent wire drift becomes a tsc error; the client half of the /notes auth protocol gets its first test |
| 6 | split `ingest()` into fetch + `applyLogs(logs)` | the correlation ladder tests anvil-free like MirrorTree already does; throw branches become cheap unit cases |
| 7 | NoteLedger gets its own replay seen-set | each stateful module guards its own idempotency instead of borrowing Store's null-return token across the seam |
| 8 | pure amount-aware `selectInputNotes` in wallet `spend.ts` | fixes the amount-blind selection bug (unspent [10, 20, 5000] failed a 4000 transfer) and moves the last untested policy out of `main.ts` |
| 9 | committed `circuits/inputs/*.json` become cross-language conformance fixtures | typed generators + all-four Python round-trips close the proving.ts / schema.py / fixture drift triangle with zero new toolchain |
| 10 | one external-module loader (`loadEthers`/`loadSnarkjs`) replaces 7 copied `createRequire` preambles | the locked GPL-isolation decision implemented once instead of asserted seven times |
| 11 | tail-poll moves into `Indexer.pollOnce()/startTailPolling()`; honest `/health` | "wedged since block N" vs "healthy" becomes machine-visible; the scheduler becomes testable |
| 12 | `calldata.py` pinned by a committed snarkjs-produced differential fixture | the G2 inner-swap knowledge drops from 3 hand-mirrors to one checked implementation vs a byte-level reference artifact |
| 13 | classify witness failures at the `engine.py` subprocess seam | unsatisfiable batch (400) vs prover-box infra fault (500) — the employer app stops being blamed for a broken wasm path; CPU-testable via a stub calculator |
| 14 | `circuits/fixture_lib.ts` owns fixture key material + helpers | "all four fixture proofs share one arbiter key" becomes true by construction; deterministic regeneration + clean `git diff` self-verifies |
| 15 | curve/field concepts consolidated in `babyjub.ts` | `FieldInput` declared once, `SUBGROUP_ORDER` lives with the curve; re-exports preserve every subpath import |

## Deferred (4) — with revival criteria

> **Status 2026-07-25 (same day, supervised session): all four resolved.**
> #1 APPLIED `fed1a22` (byte-pins first, exactly as prescribed — 15 pins incl. the
> circuit ground truth `disclosureChain == committed pub[2]`; both heavy gates
> re-run). #16 APPLIED `052fceb` (equality test written first, mutation-checked
> both directions). #17 DECIDED (b) + APPLIED `3f48ae4` (see its entry).
> #18 APPLIED `dfa2be0` (pure extraction, verified deletion-by-deletion; the
> drivers' false "ECDH values differ" comments were corrected and the scenario's
> scalars made genuinely disjoint). The entries below keep the original deferral
> reasoning as the record of *why* the ordering and safeguards were what they were.

**#1 — sdk envelope codec module (`packages/core/src/envelope.ts`).** The
highest-value candidate: the byte-exact authority-envelope plaintext layout + the
disclosureHash fold exist as 4 encoder sites, an indexer-side decoder that admin-web
imports (the workspace's only app-to-app dependency), and 4 hash-chain copies; three
of the five explorers independently converged on it. **Deferred because** the layout
is consensus-critical — it must byte-match the in-circuit gadgets, and a relocation
slip surfaces only at the heavy gate or as a live-chain mismatch alarm.
**Revive FIRST**, in a supervised session: write committed-fixture disclosureHash
byte-pins *before* the move, run one full heavy-gate pass after. (Leave
`circuits/auditor_decrypt_check.ts` hand-decoded — it is the independent
circuit-parity check; see rejected list.)

**#16 — `network.ts` for the live-pool constants.** Both app configs hand-transcribe
the pool/token/chainId/arbiter-key/H/B/gas-floor facts from
`deploy/addresses.91342.json`. **Deferred because** every constant describes the LIVE
GIWA pool: a transcription slip breaks both apps against the live deployment and
surfaces only at on-chain proof rejection. **Revive** with the
`addresses.91342.json` equality test written FIRST, ideally bundled with the next
redeploy / arbiter-epoch rotation.

**#17 — wallet trial-decrypt fallback dead seam.** `balanceViaTrialDecrypt` has zero
callers (no adapter builds its `leafCommitments` map) while the UI error copy
advertises the fallback — the wallet's only live balance path is the arbiter-mode
`/notes` route, quietly contradicting the spec §7 self-custody story. **Deferred
because** it needs a product decision, not a refactor: (a) expose leaf commitments
from the indexer (`/leaves` or per-slice on `/events`) and wire the fallback —
restores key-only recovery but grows the normative API; or (b) delete the wrapper and
fix the UI copy — a 20-line honesty fix. ~~**Revive** by putting (a)-vs-(b) to the
user; do not pick autonomously.~~ **DECIDED (b) 2026-07-25 + APPLIED.** User
rationale: the current product scenario depends on the indexer ("우리는 지금 indexer에
의존하는 시나리오"), so the key-only fallback is not a path the product needs live.
**Removed:** the unwired `balanceViaTrialDecrypt` wrapper + `FallbackBalanceResult`
(and the now-unused `getEvents`/`getNullifiers` imports) from
`apps/wallet-web/src/lib/balance.ts`; the "falls back to /events trial-decrypt" UI
copy in `main.ts` (the /notes failure path now renders an honest
indexer-required error). **Kept:** the pure `trialDecryptEvents` + `sumUnspent` cores
and their headless tests — the tested SPEC §7/§11-7 discovery primitive (key-only
recoverability of every receiver slice) and the seed for future recovery tooling.
Docs aligned: wallet README balance section + spec §7 wallet bullet (dated
annotations).

**#18 — shared e2e harness for `e2e_orchestrator.ts` / `scenario.ts`.**
`scenario.ts` is a ~250-line fork (actor fixtures, deploy helpers, a second-language
`deployPoolProxy`). **Deferred because** these files ARE the heavy gates: a refactor
slip silently weakens the repo's final verification layer, and each validation costs
two full anvil+proof runs. **Revive LAST**, after #1 (and the applied #3/#10) have
shrunk the duplication to the deploy-and-drive skeleton — or accept the fork
permanently as gate redundancy.

## Rejected (3) — should stay rejected

- **Merging `ImtTree` and `MirrorTree` into one tree module.** This is the repo's one
  genuinely *real* seam with two adapters: ImtTree serves oracle/witness use (all
  leaves known), MirrorTree serves chain-mirror use (opaque batches, replay-idempotent
  event application, arbiter fills). The deletion test passes decisively on both
  sides; a merge would force one interface to carry both global-precondition and
  batch-opaque semantics.
- **Codegen `schema.py` from `proving.ts`** (or a JSON-Schema export). The mirror is 4
  small shapes; fixture-based conformance (applied #9) achieves self-verification with
  zero new toolchain, matching the repo's house style. Codegen infrastructure would
  out-complex the thing it protects.
- **A shared UI package for the byte-identical `dom.ts`** in admin-web/wallet-web. 50
  stable, trivial lines; a third workspace package buys coordination cost for no
  depth. Duplication is the correct state at this scale.

Smaller no's recorded during synthesis, for the same don't-re-suggest purpose:
`engine.py`'s use of rabbitsnark's private `wtns.data._witnesses` is a deliberate,
commented perf choice (the public property int-converts 5.5M elements) — accepted debt;
memoizing `MirrorTree.path()`'s re-fold is unneeded and, being interface-internal, can
land later with zero caller impact; exporting *both* fold flavors from `imt.ts` would
re-create the dual-convention hazard #2 exists to kill; and importing the shared
envelope codec into `auditor_decrypt_check.ts` would collapse checker and checked into
one implementation.
