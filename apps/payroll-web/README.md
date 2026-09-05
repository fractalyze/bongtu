# bongtu payroll (Bongtu Payroll Tool)

A login-gated **single-page TESTNET tool for trying batch transfers** (SPEC §7
employer-mode),
built on the shared **`@bongtu/client`** protocol engine. Same bjj identity as the
public wallet — the wallet connect runs the same EIP-712 → bjj derivation under the ONE
`@bongtu/client/identity KEY_DERIVATION` config, so the console and the wallet derive
the **same key for the same account** by construction. It imports the `@bongtu/*`
workspace **source directly**, so every commitment / nullifier / ciphertext it builds
is byte-identical to what the prover service proves and the contract verifies.

There is no auditor mode here anymore (the arbiter seat is the arbiter indexer's
`/notes`); this app is **login + a generated test worksheet only**. All copy is
English, branded "Bongtu Payroll Tool" with a TESTNET badge on both screens.

## The one page — behind a two-stage login

- **Service login (the login page)** — an ID/password form. The credentials are
  REAL prover-service credentials, not UI theater: submit builds HTTP Basic
  (`base64(id + ":" + password)`), validates it against `GET {proverBase}/auth/check`
  (`src/lib/serviceAuth.ts`; 401 → "Wrong ID or password." inline), and holds the
  Basic value in **sessionStorage** — a refresh keeps the service session, closing
  the browser ends it. The same value rides as the `Authorization` header on
  **every** prover request (`lib/proverClient.ts`); a 401 from any later prover
  call drops the service session back to the login page. Against a dev prover with
  `PROVER_AUTH_SHA256` unset, `/auth/check` answers 200 for anything — sign-in is
  free locally.
- **Wallet session (the status bar)** — a full-width bar under the header:
  `[Connect wallet]` while none exists; connected, it shows the short eth account,
  the short bongtu address, the live kKRW balance (Loading until the first read —
  never a false zero) and `[Deposit]`. The connect chain is unchanged: injected
  wallet → `ensureChain` → EIP-712 sign → the in-memory `KeyCache` hold
  (`src/lib/keyCache.ts`) → indexer **view token** so background balance reads
  never need the key. Nothing persists: a refresh, the 10-min idle wipe, or an
  account switch drops the wallet session (the service session stands).
  `[Sign out]` (header) ends the service session AND locks the key cache
  (`lib/signOut.ts`).
- **Payees (generated, not typed)** — rendered only once the wallet is connected.
  Empty state = one `[Generate random recipients]` button: it fills the sheet
  with **255** rows (B−1, one slot is the employer's change note) of fresh random
  bjj addresses (CSPRNG scalar → `deriveKeypair` → `packPubkey`) and random
  positive integer kKRW amounts summing to **floor(80% of the balance)** — always
  strictly under the balance; a balance too small for 255 rows of ≥1 kKRW makes
  fewer rows (`rowCount = min(255, target)`), and a zero/unknown balance disables
  the button — a known-too-small balance shows a "Deposit first" hint, an unknown
  balance shows the loading treatment (`lib/randomRecipients.ts`). Rows stay
  editable (per-row inline errors: bad address, duplicate, self-pay, bad amount)
  and deletable; `[Regenerate]` replaces the whole list. No CSV paste, no manual
  add-row, no draft persistence — a test sheet is regenerated, not authored.
- **Bottom bar (fixed)** — `Total outgoing: X kKRW (N recipients)` + `[Send]`,
  which opens a confirmation naming the random-recipient framing before running.
  One note covers the total → send; covered but fragmented → the run auto-inserts
  merge legs; insufficient → the **Deposit** panel takes over with the exact
  shortfall. Until the first balance read lands there is a fourth, neutral state:
  Loading, send disabled — an unread balance is never reported as Short.

## What [Send] runs

One click, one progress rail, the whole chain:

1. **Merge legs** — `@bongtu/client runMergeChain`: transfer10x2 self-sends (≤10 notes
   each) until ONE note covers the total. The package owns "merge until covered".
2. **The terminal disburse** — this app's leg (`lib/payRun.ts`): signed `/path` for the
   funding note, `lib/disburse.ts` assembles the 1-in/256-out request — with its
   **CSPRNG-randomized** salts / pad owners / shuffle intact (recipient-count
   privacy) — and `lib/chain.ts` submits `disburseWithCiphertexts`.
3. **Done screen** — per-row check + explorer links. No receipts download.

**All proofs go to the prover service** (`lib/proverClient.ts` → `POST {base}/prove`,
per-circuit pub-length pins `disburse=11 / transfer10x2=68 / deposit=19` — the service
registry's vkey truth). The console never proves in the browser; funding deposits run
the shared `@bongtu/client` `runDeposit` (`ops/deposit.ts`) with the same service adapter injected.

## Run

```sh
export PATH=$HOME/.foundry/bin:$HOME/.nvm/versions/node/v22.17.1/bin:$PATH
cd apps/payroll-web
npm install
npm run dev        # Vite dev server → open the printed URL
```

Gates:

```sh
npm test           # worksheet rules, prover adapter pins, KDF equality, and the
                   #   disburse assembly/randomness gates (no GPU/chain)
npm run typecheck  # tsc --noEmit
npm run build      # vite production build
```

### Prover service (employer's GPU box)

```sh
bash ../../prover/setup.sh   # once — see prover/README.md
bash ../../prover/run.sh     # eager boot, then GET :8700/ready -> 200
```

The base URL is `VITE_PROVER_URL`, else `http://127.0.0.1:8700` in dev and the
same-origin `/prover` path in prod builds (`src/config.ts proverUrlFromEnv`; the prod
rewrite behind `/prover` ships with the prover funnel work, U-P4).

## Deployment

Production: https://payroll.fractalyze.io — the `bongtu-payroll` Vercel project
(`fractalyze` team), git-connected with root directory `apps/payroll-web`. `vercel.json`
carries the `/indexer/:path*` rewrite that keeps the indexer same-origin (prod
counterpart of the dev proxy in `vite.config.ts`).

## Layout

```
src/
  config.ts            app knobs (indexer/prover URLs); chain facts come from
                       @bongtu/core/network, the KDF from @bongtu/client/identity
  main.tsx             React entry
  lib/
    worksheet.ts       PURE: rows, validation, the footer readiness verdict
    randomRecipients.ts PURE: the 255-row random payee generator (80% target)
    statusBar.ts       PURE: the status bar's connected/disconnected selection
    signOut.ts         Sign out = drop service session + lock the key cache
    disburse.ts        PURE: recipients + funding note + membership -> ProvingRequest
                       + the 2054-element ciphertext (CSPRNG pads/salts/shuffle)
    payRun.ts          the whole run: client merge chain, then the disburse leg
    errors.ts          the wording boundary: shared-classifier verdicts in the
                       console's voice + the deposit field's amount errors
    serviceAuth.ts     the service session: Basic value builder, /auth/check
                       sign-in probe, sessionStorage holder (drop on 401)
    proverClient.ts    the ONE service adapter: POST /prove + Authorization
                       header + per-circuit pub pins
    chain.ts           disburseWithCiphertexts submit over the shared Connection
    connect.ts         injected EIP-1193 -> the engine's Connection (no wagmi here)
    keyCache.ts        the one lock instance (shared KDF, live-account read)
    toasts.ts          the one toast queue (@bongtu/ui)
  ui/
    App.tsx            service-login gate (session == the held Basic value)
    Login.tsx          hero + the two-line testnet tagline + [Sign in] form
    Console.tsx        header / status bar / generated payees / fixed send bar /
                       confirm / progress rail / done
    controls.tsx       shared control looks on the wallet token palette
test/
  worksheet.test.ts    rows, validation (self-pay), readiness verdict
  randomRecipients.test.ts generation invariants: 255 distinct valid rows, 80% sum
  statusBar.test.ts    bar state selection (null balance stays loading)
  signOut.test.ts      sign-out drops the service session AND locks the key cache
  proverClient.test.ts adapter + pub-length pins + auth header + base-URL defaults
  serviceAuth.test.ts  the service session: Basic value, sign-in probe, holder
  kdf.test.ts          identity coincidence with treasury-web (shared KEY_DERIVATION)
  assemble.test.ts     the disburse assembly gate (kept from the previous console)
  randomness.test.ts   recipient-count privacy: per-batch CSPRNG draws + shuffle
  payRun.test.ts       batch bounds + terminal-leg failure wording (injected I/O)
  errors.test.ts       the wording boundary's gate
```

## License

Apache-2.0 — see the root [`LICENSE`](../../LICENSE).
