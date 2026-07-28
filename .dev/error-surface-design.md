# Error surface design

Locked 2026-07-28 (grill session). Implementation follows the V5 wallet swap;
until then this file is the standard any new error handling must match. The
user-facing summary lands in `docs/errors.md` with the implementation commit.

## Classification axis: consequence, not source

Errors are classed by **what the user can do next**, never by which subsystem
raised them. The same indexer failure is blocking during onboarding but mere
degradation during a background refresh — source cannot decide the surface.
Source (indexer / chain / proving / wallet provider) appears only inside the
message text ("Couldn't reach the indexer …").

| class | example | surface |
|---|---|---|
| 1. transient, retryable | manual refresh fails, Load more fails, copy fails | toast (or the flow's existing inline slot when one is nearer, e.g. under the Load-more button) |
| 2. in-flow, user-recoverable | signature rejected, proof failed, insufficient balance, mid-chain leg failure | **inline in the flow, never a toast** — the user is looking at that screen, and the flow slot carries more (retry, leg number, money-state line) |
| 3. session-fatal | 401 token expiry, wrong chain | route change + notice (existing `RECONNECT_NOTICE` pattern) |
| 4. background degradation | auto-refresh loop failing, post-action poll failing | **banner** (the `dataError` slot), no toast — see below |
| 5. unexpected (bug) | invariant violation, unknown exception | toast + "Copy details" |

## Toast = event, banner = state

A toast announces something that *happened* and goes away; a banner names a
condition that *holds* and stays until it clears. Consequences:

- **Background loops never toast.** An indexer outage during auto-refresh flips
  the banner on ("balance may be stale"), each subsequent failure keeps it on,
  the next success clears it. Five minutes of outage = one banner, zero toasts.
  No first-failure toast either: the banner already carries the information.
- On-screen data is never blanked by a failed background read.
- Toasts are reserved for failures of something the user just did (class 1) and
  for class 5.

## In-flow failures (ratified from the U-Z2 chain implementation)

- Inline only. The standard message form for money-touching failures is
  **"specific cause" + "money-state line"** — the `CHAIN_FAILURE_REASSURANCE`
  pattern ("Nothing was sent. Your balance is unchanged, and already-combined
  pieces stay combined.") generalizes to deposit/withdraw flows.
- Mid-chain leg failure: landed merges are not undone (self-sends; always
  spendable); retry replans a shorter chain over the now-fewer notes. A merge
  that landed but timed out waiting for the indexer ends the same way — no
  dedicated recovery UI, the next plan simply picks up the merged note
  (self-healing by construction).
- Single-transaction spends do not carry the reassurance line (it would confuse
  — nothing partial can have landed).

## Code placement

- `packages/core`: the `AppError` taxonomy type (discriminant = the five
  classes) and headless boundary classifiers (indexer HTTP — generalizing
  `classifyReadFailure`; chain/provider rejection; proving worker). Testable
  without React.
- Rendering lives in `packages/ui` (user decision 2026-07-28): the toast host
  and banner are shared components there, alongside the other pieces both apps
  reuse (controls, Modal, ExplorerLink, StagedProgress, money formatting).
  wallet-web adopts first; payroll-web picks the same components up in its
  single-page reshape.
- Message copy stays per-app (U-TEXT: plain words, no note/UTXO jargon).

## Copy standard

- Headline: what happened + what to do next, in plain words. No error codes,
  no jargon, sentence case.
- Money-touching failures always include the money-state line.
- Class 5 shows a generic line plus **Copy details** (message + stack to the
  clipboard, for a bug report).
- **No error telemetry, ever.** This is a privacy product: error details never
  leave the device. Reporting is the user pasting what Copy details gave them.
