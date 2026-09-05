# Error surfaces

How the apps report failure. This is the current-fact contract for contributors:
which surface an error gets is decided by its **consequence class**, never by which
subsystem raised it. Rationale and the decision history live in
[`.dev/error-surface-design.md`](../.dev/error-surface-design.md) (locked 2026-07-28).

## The five classes

Errors are classed by **what the user can do next**. The same indexer failure is
blocking during onboarding but mere degradation during a background refresh — the
source (indexer / chain / proving / wallet provider) appears only inside the message
text, never in the routing.

| class | example | surface |
|---|---|---|
| 1. transient, retryable | manual refresh fails, Load more fails, copy fails | toast — or the flow's existing inline slot when one is nearer (Load more reports under its own button) |
| 2. in-flow, user-recoverable | signature rejected, proof failed, insufficient balance, mid-chain leg failure | **inline in the flow, never a toast** — the flow slot carries more (retry, leg number, money-state line) |
| 3. session-fatal | 401 token expiry, wrong chain | route change + notice (the wallet returns to onboarding carrying the reason) |
| 4. background degradation | auto-refresh loop failing, post-action poll failing | **banner** (the `dataError` slot), never a toast |
| 5. unexpected (bug) | invariant violation, uncaught exception | toast + **Copy details** |

## The two rules

**Toast = event, banner = state.** A toast announces something that *happened* and
goes away; a banner names a condition that *holds* and stays until it clears.
Consequences:

- **Background loops never toast.** An indexer outage during auto-refresh flips the
  banner on, every further failure keeps it on, the next successful read clears it.
  Five minutes of outage = one banner, zero toasts.
- **On-screen data is never blanked by a failed background read.** Stale beats
  blank: the banner says the numbers may be out of date; the numbers stay.

**Money-touching failures carry the money-state line.** An in-flow failure that
could have moved value says where the money stands, in the same message: the spend
chain's "Nothing was sent. Your balance is unchanged, and already-combined pieces
stay combined." (`CHAIN_FAILURE_REASSURANCE`), and the deposit flow's post-approve
"No kKRW left your account. The approval stays in place and is reused when you
retry." (`DEPOSIT_FAILURE_REASSURANCE`). Single-transaction failures carry **no**
line — nothing partial can have landed, and the reassurance would only confuse.

## No telemetry, ever

This is a privacy product: error details never leave the device. Class 5 shows a
generic headline plus **Copy details** (message + stack to the clipboard); reporting
a bug is the user pasting what that button gave them. There is no error-reporting
endpoint, and none may be added.

## Where the code lives

- **`packages/core/src/errors.ts`** — the `AppError` taxonomy (the five classes as
  a discriminated union) and the headless boundary classifiers: indexer HTTP reads
  (`classifyIndexerRead`, parsing the sdk's `"url -> status"` throw contract),
  chain/provider failures (`classifyChainFailure` — EIP-1193 codes, viem's typed
  error names and cause chains), and proving failures (`classifyProvingFailure`).
  Pure functions; their decision tables gate in `packages/core/test/errors.test.ts`.
- **`packages/ui`** — the shared render components: `ToastHost` (stacking, aria-live
  polite, Copy details) over the headless `ToastQueue` (dedup, auto-dismiss, timing —
  gated without a DOM in `packages/ui/test/`), and `Banner` (the stateless state
  slot, warn/info tones). Classname-based on the apps' Tailwind tokens; each app
  compiles its own CSS (wallet-web declares the package as a Tailwind `@source`).
- **Per-app wiring** — apps own their copy (plain words, no jargon) and the routing:
  `@bongtu/client` `refresh.ts` (`runRefresh` — the one refresh path, with the
  never-toast/never-blank rules enforced headlessly), `src/lib/toasts.ts` (the app's
  queue + the class-5 global handlers), and one exhaustive wording table per app over
  core's `FailureCopyTable` — `WALLET_FAILURE_COPY` (`@bongtu/client` `io/connection/edge.ts`,
  beside `chainSwitchMessage`) and `PAYROLL_FAILURE_COPY` (payroll `src/lib/errors.ts`)
  — so a `ChainFailure` kind added to the classifier is a tsc error in every app, never
  a silent fall-through to raw viem text. Surface wiring gates in
  `apps/wallet-web/test/errorSurface.test.ts`; the tables' every-kind coverage gates in
  each app's copy tests.
