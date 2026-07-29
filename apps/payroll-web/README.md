# bongtu payroll (봉투 페이롤)

A login-gated **single-page pay console** for the employer (SPEC §7 employer-mode),
built on the shared **`@bongtu/client`** protocol engine. Same bjj identity as the
public wallet — MetaMask login runs the same EIP-712 → bjj derivation under the ONE
`@bongtu/client/identity KEY_DERIVATION` config, so the console and the wallet derive
the **same key for the same account** by construction. It imports the `@bongtu/*`
workspace **source directly**, so every commitment / nullifier / ciphertext it builds
is byte-identical to what the prover service proves and the contract verifies.

There is no auditor mode here anymore (the arbiter seat is the arbiter indexer's
`/notes`); this app is **login + worksheet only**.

## The one page

- **Login** — product hero + one button: connect the injected wallet → EIP-712 sign →
  console. The session is the in-memory `KeyCache` hold only (`src/lib/keyCache.ts`):
  nothing persists, a refresh (or the 10-min idle wipe, or an account switch) means
  logging in again. At login the key is traded for an indexer **view token** so
  background balance reads never need it.
- **Worksheet** — full-width rows of `{받는 주소, 금액(kKRW)}`; `[+]` adds a row
  (capped at **255** = B−1, one slot is the employer's change note), CSV paste fills
  the sheet (`lib/csv.ts` — exactly two cells `pubkey,amount` per line, base58check/hex
  both fine; a third cell is rejected by line number rather than truncated, so a
  thousands-comma cannot become a 1000x underpay), per-row inline errors (bad address,
  duplicate, self-pay, bad amount), rows draft-persisted to localStorage
  (`lib/worksheet.ts`, injectable-storage seam).
- **Footer** — one note covers the total → `[전송]`; covered but fragmented → `[전송]`
  and the run auto-inserts merge legs; insufficient → the **입금** (deposit) CTA takes
  over with the exact shortfall (deposit is de-emphasized otherwise). Until the first
  balance read lands there is a fourth, neutral state: 확인 중, send disabled, no
  deposit CTA — an unread balance is never reported as 부족.

## What [전송] runs

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
the shared `@bongtu/client` depositFlow with the same service adapter injected.

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
    worksheet.ts       PURE: rows, validation, draft, the footer readiness verdict
    disburse.ts        PURE: recipients + funding note + membership -> ProvingRequest
                       + the 2054-element ciphertext (CSPRNG pads/salts/shuffle)
    payRun.ts          the whole run: client merge chain, then the disburse leg
    csv.ts             recipient CSV parser (the paste-fill path)
    errors.ts          the Korean boundary: shared-classifier verdicts + amount
                       errors in the console's voice (client/ui stay English)
    proverClient.ts    the ONE service adapter: POST /prove + per-circuit pub pins
    chain.ts           disburseWithCiphertexts submit over the shared Connection
    connect.ts         injected EIP-1193 -> the engine's Connection (no wagmi here)
    keyCache.ts        the one lock instance (shared KDF, live-account read)
    toasts.ts          the one toast queue (@bongtu/ui)
  ui/
    App.tsx            login gate (session == the KeyCache hold)
    Login.tsx          hero + [MetaMask로 로그인]
    Console.tsx        header / worksheet / stat bar / footer / progress rail / done
    controls.tsx       shared control looks on the wallet token palette
test/
  worksheet.test.ts    rows, validation (self-pay), csv fill, draft seam, readiness
  proverClient.test.ts adapter + pub-length pins + base-URL defaults
  kdf.test.ts          identity coincidence with wallet-web (shared KEY_DERIVATION)
  assemble.test.ts     the disburse assembly gate (kept from the previous console)
  randomness.test.ts   recipient-count privacy: per-batch CSPRNG draws + shuffle
  csv.test.ts          CSV normalization, cell-count and header-heuristic gate
  payRun.test.ts       batch bounds + terminal-leg failure wording (injected I/O)
  errors.test.ts       the Korean boundary's wording gate
```

## License

Apache-2.0 — see the root [`LICENSE`](../../LICENSE).
