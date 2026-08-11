# M2 — Product surface: a real wallet, a durable indexer, container ops

**M2 turns the proven protocol (M0) and M1's live testnet deploy into a usable product surface: a
self-custody wallet that looks like a wallet, an indexer that survives a restart and ships in a container,
and a per-user transaction history.** No circuits, contracts, or the live pool change — this round is the
app/indexer/ops layer only. Ref: [spec-decisions.md](spec-decisions.md) §6b (indexer API), §7 (apps), §8 (layout);
M1 is complete (256 disburse proven live on a testnet). Prior rounds: [milestone-m0.md](milestone-m0.md),
[milestone-m1.md](milestone-m1.md).

## Locked design (grill session 2026-07-25, Q1–Q8)

The round was scoped by a design grill before any code. The decisions that the diff cannot show:

- **Wallet is a demo-showcase self-custody wallet, not a dev panel.** Mobile-first vertical frame,
  **home-centric stack** (no bottom tab bar): onboarding (connect → derive, hidden as one flow) → home
  (big kKRW balance card + Receive/Send/Withdraw + recent activity + network/indexer status chip) →
  receive/send/withdraw screens → settings behind a gear. **React** (chosen over the vanilla original
  because the wallet is meant to grow), hash routing.
- **Proving stays in the browser.** rapidsnark is native-only with no viable browser port, and sending a
  witness to a server would break self-custody — so a public wallet proves its own transfer/withdraw
  on-device. The cost is real (measured, U-W0): a warm transfer proof is **3.5–5.4 s on a 24-thread
  desktop → a 7–20 s laptop budget**, not the 1–3 s first guessed. UX never promises sub-5 s.
- **History is served by the indexer, not a local journal.** The user overrode a localStorage sketch: a
  new `GET /history` is arbiter-mode (the arbiter already decrypts every op's envelope, so it alone knows
  both the sender and receiver of a transfer) and returns a typed received/sent/withdraw/deposit feed with
  counterparty, amount, txHash, and block timestamp.
- **The indexer store becomes durable behind a two-adapter seam.** `StorePort`/`LedgerPort` interfaces with
  an in-memory adapter (default, keeps CI cheap and the conformance suite unchanged) and a Postgres adapter
  (raw `pg` + SQL, no ORM). Postgres persists the derived ledger + a cursor so a restart **resumes** instead
  of replaying the chain; the MirrorTree is boot-reconstructed from the `leaves` table (deterministic
  O(n) derivation, not persisted tree nodes).
- **Ops ships as a 2-service docker-compose** (postgres + indexer). Prover (GPU) and the static apps are
  excluded. Migrations are an idempotent `schema.sql` applied at boot (no Flyway). Hosted CI stays
  **build-only** for the image; the Postgres integration test (boot → ingest → restart → cursor-resume) is a
  local gate, not a hosted one.

## Done condition (ticked at each unit boundary)

1. **A wallet a demo audience reads as a wallet.** `apps/wallet-web` is a home-centric React app (balance
   card, Receive/Send/Withdraw, activity, status chip) that derives the bjj key, reads balance + activity
   from the arbiter `/notes` + `/history`, and proves transfer/withdraw in-browser with the U-W0 numbers
   baked into the UX. Gate: `tsc` + unit tests + `vite build` green; the proving path uses
   `wtns.calculate`+`groth16.prove` on kept buffers (not repeated `fullProve`), Cache-Storage prefetch
   version-keyed by the zkey hash, and a bn128 pre-warm.
2. **The indexer resumes across a restart and runs in a container.** A `GET /history` endpoint (arbiter
   read-auth), a Postgres adapter behind the store seam with crash-safe single-transaction persist +
   cursor-resume, and a multi-stage Dockerfile + docker-compose. Gate: the in-memory conformance suite
   unchanged and green in hosted CI; the Postgres integration test (restart → resume, no double-count) green
   locally; `docker build` green as a hosted build-only job.

## Units (one workflow each — Implement → Verify → repair → Review — commit between)

- [x] **U-W0 — browser-proving benchmark** (no commit; measurement + [[browser-snarkjs-groth16-transfer-proving-measured]]).
      Real headless-Chromium runs measured a warm transfer proof at 3.5–5.4 s on a 24-thread desktop →
      **7–20 s laptop budget**. ★ Refuted a planned optimization: **COOP/COEP headers had zero effect** in
      Chromium (ffjavascript workers don't need SharedArrayBuffer) — dropped. Revised the proving plan to
      kept-buffer proving + Cache-Storage prefetch + bn128 pre-warm + staged progress, all baked into U-W1.
- [x] **U-I1 — `GET /history`** ✅ `069c370`. Arbiter-mode `/history?owner=&ts=&sig=` (bjj EdDSA read-auth,
      public 404s), per-owner received/sent/withdraw/deposit with counterparty + amount + txHash +
      blockTimestamp, newest-first; ingest now captures block timestamps (one `getBlock` per distinct block,
      bounded 16 in-flight). ★ Review major fixed: a 2-output split payment now emits one "sent" per non-self
      output (was merged onto `outputs[0]`).
- [x] **U-I2 — Postgres two-adapter** ✅ `d51d521`. `StorePort`/`LedgerPort` + in-memory (default) + Postgres
      (raw `pg`) adapters over a shared pure `deriveOp`; cursor-resume with the MirrorTree rebuilt from the
      `leaves` table. ★ Review blocker fixed: persistence was three separate transactions (cursor last), so a
      crash between the leaves commit and the cursor advance left leaves ahead of the cursor → boot rebuilds a
      tree past the resume point → head-invariant **wedge**. Fix = `Indexer.persist(head)` writes store rows +
      ledger rows + cursor in **one transaction** on a shared client; in-memory `lastBlock` advances only
      post-COMMIT; a rollback re-ingests idempotently. A deterministic crash-in-persist-window test
      (`BONGTU_CRASH_BEFORE_COMMIT`) proves the DB stops with cursor + leaves together and a fresh boot
      resumes byte-identically, no double-count.
- [x] **U-I3 — Docker** ✅ `5a1498b` (CI run 30160441025). Multi-stage indexer Dockerfile (trimmed `npm ci`,
      external ethers into `/opt/extern` via `BONGTU_NODE_MODULES`, a committed pool ABI so the image needs no
      foundry, slim non-root runtime running raw `.ts` via tsx, `/health` HEALTHCHECK) + a 2-service
      docker-compose (postgres:16-alpine + indexer, `service_healthy` gate, pgdata volume) + `.dockerignore` +
      `.env.compose.example` + a build-only `indexer-image` CI job. ★ Review major fixed: the committed ABI's
      only consumer is the Dockerfile COPY and hosted CI never runs the image, so a pool ABI change would ship
      a broken image silently → added an ABI **drift gate** in indexer-units that regenerates the slice from
      the fresh `forge build` artifact and `git diff --exit-code`s it (mirrors the circuits/verifiers pins).
- [x] **U-W1 — React wallet** ✅ `95cbba0` (CI run 30162524375). The home-centric Zashi/Railgun-style rebuild
      (onboarding → home → receive/send/withdraw → settings, hash routing) with in-browser snarkjs proving
      per U-W0: `wtns.calculate`+`groth16.prove` on kept buffers, Cache-Storage prefetch version-keyed by
      `CIRCUITS_VERSION = sha256(transfer.zkey ‖ withdraw.zkey) = 2fef02a1`, bn128 pre-warm, staged 5–20 s
      progress; consumes `/notes` + `/history`. Review fixes: `dist/` untracked + gitignored, the version key
      hashes **both** zkeys (stale-key footgun), SpendScreen key-remount, a `balance===null` send-guard,
      `ffjavascript` declared, and a StrictMode in-flight promise coalesce.
- [x] **U-W2 — rename `@bongtu/sdk` → `@bongtu/core`** ✅ `3f2266c` (CI run 30163496547). `git mv` (22 renames,
      history preserved) + package name/description + all import specifiers + the three apps' dep keys + CI
      `-w` flags + Dockerfile COPY + tsconfig + README/spec headings + prover refs; lockfile + symlink
      regenerated. The package is private (v0.0.0) with no external consumers and is not an SDK — it is the
      shared protocol + crypto **core** that all three apps and the contract differential tests import; "sdk"
      invited callers to treat it as a stable published surface it never was. Pure rename, logic-zero (all
      gates green). A blanket sweep of the ~90 conceptual "sdk" comment mentions was deliberately **not** done
      — it would touch the tracked `admin-web/dist` build artifact and legal NOTICE text and is not
      logic-zero; the false-fact subset (the Dockerfile symlink comment, the CI step label, this spec's §6
      heading/bullet) was fixed.

## Deliberately out of scope this round

admin-web was not touched (M2 is the wallet + indexer round). ~~The Postgres path is not on the hosted
conformance gate (it is a local docker integration test) — the in-memory adapter keeps CI cheap and is the
conformance oracle.~~ **Superseded by U-I4 (2026-07-26, post-M2): the indexer is Postgres-only — the
in-memory ledger backend is deleted, the conformance gate ingests real Postgres, and the hosted
`indexer-conformance` job runs it against a `postgres:16-alpine` service container.** The wallet's balance
reads the arbiter `/notes` (architecture-review #17); the key-only
trial-decrypt primitive remains as the §11-7 recovery property, not a balance path.

Status legend: [ ] pending · [~] in-progress · [x] done · [!] blocked. Toolchain: [toolchain.md](../docs/toolchain.md).
CI design: [ci.md](ci.md). Layout: [monorepo-layout.md](monorepo-layout.md).
