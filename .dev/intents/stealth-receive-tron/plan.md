# Stealth payment receiving on Tron: plan

Spec: [spec.md](spec.md)

Grounding: every file fact below was read in this worktree at main 4f639ab. No
other feature build is in flight (open PRs are intent captures only), so no
file-overlap negotiation is needed.

## Changes

Ordered work units, one commit each. Every unit names the test that proves it.

### U1: core Tron presentation + shared base58

- `packages/core/src/crypto/base58.ts` (new): the base58check codec lifted out
  of `pubkey.ts` (`b58encode`, `b58decode`, `checksum4`), module-internal to
  core. The repo currently holds two base58 codecs (`crypto/pubkey.ts:111-215`
  checksummed, `chain/solana.ts:129-181` plain); this unit consolidates the
  checksummed one instead of adding a third.
- `packages/core/src/crypto/pubkey.ts`: imports the shared codec; exports and
  behavior unchanged (its existing tests prove neutrality).
- `packages/core/src/notes/stealth.ts`: exports `toTronAddress(body: string)`
  (base58check of `0x41` plus the 20-byte body, checksum = first 4 bytes of
  double sha256) and `tronAddressToHex(base58: string)` for validating
  user-entered move destinations. Derivation, scan, and recovery untouched (R1).
- Proof: `packages/core/test/stealth.test.ts` known-answer vectors: the
  committed determinism vector `0x0787be5a…` plus its base58 form cross-checked
  against independent Tron tooling at authoring time; round-trip encode/decode;
  leading-zero handling; existing pubkey suite stays green.

### U2: wire shapes, announce rail "tron", funding columns

- `packages/core/src/wire/indexerNames.ts`: `PortalIssuance` gains `rail`;
  `PortalPublicRecord`/`PortalRecord` gain the funding fields `funded`,
  `fundedUsdt`, `fundedTrx`, `fundingTxHash`, `anchorTxHash`, `fundedAt`;
  `announcePortal` passes `rail` through (request shape already carries it).
- `apps/indexer/src/api/routes/portal.ts`: `parseAnnounceBody` accepts and
  RETURNS `rail` (`"evm"` default, `"tron"` new; the current validator at :133
  drops it and rejects everything else). `handlePortalAnnounce` branches:
  tron requires Tron config (404 in the `PORTAL_PRIV_FACTORY` gating shape),
  skips the factory recompute in favor of `destination = toTronAddress(stealthAddr)`
  (pure, no chain call), and skips the consumer-pair gate (no note is ever
  minted on this rail; spec Design). The evm branch is byte-identical.
- `apps/indexer/src/portal.ts`: `issue` carries rail-appropriate `factory: ""`;
  new write-behind stamps `markFunded(salt, fields)` / `markAnchored(salt, tx)`
  mirroring `markSwept` (:207) and flushing through the existing
  `flushInto`/`commitFlush` pair; `toPublic` (:44-59, explicit field-by-field)
  carries the funding fields.
- `apps/indexer/src/schema.sql`: `ADD COLUMN IF NOT EXISTS` for the six funding
  columns, the `:162-163` precedent.
- Proof: `apps/indexer/test/portal.test.ts` (fast suite, `test:portal`): tron
  announce happy path (destination is the base58 presentation), tron announce
  404 without Tron config, consumer-pair NOT required on tron, cross-rail
  first-write-wins (evm announce then tron announce of the same `stealthAddr`
  is a 409, and concurrently exactly one wins), funding stamps survive a
  restart via the write-behind path, public feed carries funding fields and
  still no attribution field.

### U3: indexer Tron config + server-side issuance

- `apps/indexer/src/chain.ts`: `tron?: { api, apiKey?, usdt, announcer }`
  grouped subconfig on the solana precedent (:245-250): `TRON_API` is the
  switch; `TRON_USDT` and `TRON_ANNOUNCER` mandatory companions that throw at
  boot if absent; `TRON_API_KEY` optional. Boot line in `src/index.ts` states
  configured/unconfigured; the key is never logged.
- `apps/indexer/src/api/routes/portal.ts`: `handlePayPortal` accepts an
  optional JSON body `{ rail: "tron" }` (route currently reads no body). The
  tron branch derives server-side with the existing injected
  `drawScalar`/discard discipline (:92-95), records the row, and returns the
  `PortalIssuance` with the base58 destination and `rail`. An empty or absent
  body keeps today's behavior byte-for-byte (R5, R13).
- Proof: `apps/indexer/test/portal.test.ts`: tron issuance row is identical in
  shape to a tron announce row (deterministic injected scalar), the scalar
  never appears in any response or log line, default-body behavior is pinned
  unchanged, tron body without Tron config is a 404.

### U4: core Tron chain helpers

- `packages/core/src/chain/tron.ts` (new, exported as `@bongtu/core/tron`):
  DATA plus pure helpers in the `chain/solana.ts` mold, fetch-injected, no new
  dependency:
  - HTTP API request builders/parsers for: account info (TRX balance,
    existence), TRC20 `balanceOf` via `triggerconstantcontract`, announcer
    outgoing transactions, `createtransaction` (TRX transfer with data memo),
    `triggersmartcontract` (TRC20 transfer), `delegateresource` /
    `undelegateresource` / `freezebalancev2`, `broadcasttransaction`.
  - A minimal protobuf READER for `raw_data_hex` sufficient to verify a
    node-built transaction before signing: contract type, owner, to, amount,
    token contract, and the data field (C5: verify-before-sign is mandatory;
    a reader is far smaller than a writer).
  - Local signing: txID = sha256(raw_data bytes), secp256k1 recoverable
    signature via `@noble/curves` (already a core dependency).
- The word "rail" stays out of this module's API: in the client engine "rail"
  already names the chain-SDK seam (`packages/client/src/rail.ts`), a
  different concept from the portal wire's address flavor. Tron helpers are
  `tron*`-named.
- Proof: `packages/core/test/tron.test.ts`: decode-verify accepts a recorded
  real transaction fixture and REJECTS a mutated recipient/amount/contract;
  signature vector against a known Tron tx (fixture recorded at authoring
  time); API builders produce the documented wire shapes.

### U5: indexer funding poller

- `apps/indexer/src/tron.ts` (new): a poll loop over unfunded and un-anchored
  tron rows using `@bongtu/core/tron` with injected fetch: stamps
  `markFunded` from USDT/TRX balance reads, stamps `markAnchored` by walking
  the announcer account's outgoing transfers (which also backfills rows the
  store never saw, the `recordChainAnnouncement` analogue). Cadence via
  `TRON_POLL_MS` (default 10000, 0 = off), structured like
  `host.pollOnce`/`startTailPolling` (:209/:236): coalescing guard, failure
  streak, one loop in flight.
- `apps/indexer/src/host.ts` + `src/index.ts`: optional tron capability wiring
  and startup, matching the optional-capability seam (:76-83).
- Proof: `apps/indexer/test/tron.test.ts` (fast suite): funding stamp from a
  fake API, anchor detection from a fake announcer history, chain-only
  backfill of an unknown row, poller off without config, failure streak does
  not wedge the loop.

### U6: the Tron operator bot

- `apps/tron-operator/` (new workspace app, auto-included by the `apps/*`
  glob; sweeper conventions: `"exports": { "./*": "./src/*.ts" }`, tsx
  scripts, `node --test`). Structure mirrors the sweeper: `src/config.ts`
  (bootError-first, `TRON_OPERATOR_KEY`, `TRON_API`(+key), `INDEXER_URL`,
  `PORTAL_OPERATOR_TOKEN`, `MIN_MOVE` dust threshold, announcer address
  derived from the key), `src/anchor.ts` and `src/delegate.ts` pure over a
  deps seam, `src/server.ts`, `src/index.ts` owning the setTimeout cadence
  (one round in flight, the sweeper rule).
- Duties: (1) anchor-and-activate: on first funding of a row from the
  token-gated attributed feed, send ONE TRX transfer to the destination with
  `data = ephemeralPub ‖ viewTag`, skipping below `MIN_MOVE` (R7, R10);
  (2) delegation: `POST /delegate { stealthAddr }` on the bot server, PUBLIC,
  acting only on rows it verifies as funded and anchored via the feed,
  delegating energy/bandwidth and reclaiming after the observed move or a
  timeout (R9).
- Spec refinement recorded here: the spec's Design sentence gates the
  delegation channel with the operator token, but the wallet is tokenless by
  contract (R8), so the channel is public with act-only-on-verified-rows and
  availability-only trust; the spec paragraph is amended in this unit so the
  PR diff shows the deviation.
- Root `tsconfig.json` include gains the app's src/test; CI `node-fast` gains
  `npm test -w @bongtu/tron-operator` (workflow push needs the gh-token
  procedure, see Risks).
- Proof: `apps/tron-operator/test/`: config bootError table; anchor decision
  table over fakes (funded row anchors with the exact data bytes, below-dust
  never fires, anchored rows skip, unfunded spam costs nothing on-chain);
  delegation refuses unverified rows; verify-before-sign rejects substituted
  node bytes; reclaim fires on observed move and on timeout.

### U7: pay-web Tron tab

- `apps/pay-web/src/lib/pay.ts`: `issuePayment` grows a rail parameter (or a
  sibling `issueTronPayment` if the branch reads badly): derive with the same
  `deriveStealthAddress`, announce `rail: "tron"` BEFORE display, parity-check
  the server destination against the LOCAL `toTronAddress` presentation
  (pure; misconfiguration can only disagree, never redirect).
- `apps/pay-web/src/config.ts` + `src/main.ts`: per-rail tabs (Maroo as
  shipped, Tron new), `VITE_TRON_USDT` and network display facts, Korean copy
  with the R11 tier statement (fresh-address unlinkability, amounts visible,
  never "보호됨"/shielded wording on the Tron tab), QR encodes the base58
  address. Unconfigured Tron reports itself unconfigured; the Maroo tab is
  untouched.
- Proof: `apps/pay-web/test/pay.test.ts`: announce-before-display order on
  tron, the announce carries `rail: "tron"`, parity fail-closed on a
  disagreeing server, unconfigured guard, Maroo path pinned unchanged.

### U8: wallet-web Tron rows + move flow

- `apps/wallet-web/src/lib/payments.ts`: rail-aware fold: tron rows take
  amounts from the funding stamps (never a balance read), status `received`
  terminal, `PaymentRow` gains `rail` and the tron amount fields; unfunded
  tron issuances stay dropped as noise.
- `apps/wallet-web/src/ui/screens/Payments.tsx`: tron rows render base58
  destination, USDT/TRX amounts (not kKRW), a tron `received` pill, and a
  move action anchored in the existing trailing column (:49-79). Move dialog:
  destination validated with `tronAddressToHex`, key via `recoverStealthKey`
  (memory-only, flow-scoped), delegation requested from the bot server, TRC20
  transfer node-built then decode-verified locally then signed locally and
  broadcast (`VITE_TRON_API`, `VITE_TRON_OPERATOR_URL`), consolidation
  warning copy (C6). Full-balance USDT; above-cost TRX movable the same way.
- Proof: `apps/wallet-web/test/payments.test.ts`: tron fold rows (funded,
  unfunded, mixed with evm rows); move-flow logic tests at the lib level
  (verify-before-sign rejection path included); screen copy never says
  shielded on a tron row.

### U9: the Tron gate leg + scratch network record

- `deploy/gates/tron_leg.ts` + `deploy/gates/tron_leg.sh` (standalone heavy
  leg, NOT wired into `e2e_m0.sh`: it needs no anvil, no pool, no per-leg
  Postgres coupling to the EVM legs). Flow per spec R12: dockerized private
  java-tron (throwaway container, random port, the `test/run.sh:56-70`
  pattern), deploy a TRC20 stand-in (ERC20 bytecode reused; TVM accepts it),
  spawn the real indexer with Tron config, register a v2 name, two headless
  pay-page tron issuances, two funding transfers from two distinct sender
  accounts, poller and bot run as libraries, then assert: (a) destinations
  differ; (b) negative grep of both payment txs and the feed body for the
  label and registered keys; (c) no attribution field; (d) both balances
  moved out with derived keys via delegation; (e) both rows rebuilt from the
  announcer account's transactions plus the view key alone.
- The leg writes a scratch `deploy/tron.<network>.json` record (the 31337
  precedent; checked out before commits). The committed artifact this slice
  is the record SHAPE plus a loader in `@bongtu/core/tron`; live Nile/mainnet
  records are post-merge human ops (spec C2 resolution).
- If the java-tron container proves unrunnable on hosted CI, the leg ships as
  a dev-box gate like the GPU legs, stated in `.dev/ci.md` (C4).
- Proof: the leg itself exits 0 end to end on the dev box with all R12
  asserts green; `bash deploy/gates/tron_leg.sh` is the command of record.

### U10: docs

- Per the spec's Docs debt list: `docs/portal.md` Tron section and two-tier
  frame; `docs/security-model.md` who-sees-what Tron rows, the C1 accepted
  residual window, the R11 statement; `docs/indexer.md` routes/env/poller;
  `docs/wallet.md` move flow and consolidation warning; root `README.md`
  layout row; app READMEs (pay-web, indexer, tron-operator, wallet-web,
  deploy). `.dev/ci.md` gains the tron leg's clean-env notes.
- Proof: docs build nothing; the reviewer's diff-vs-plan pass and the
  residual-name grep (no "shielded" on Tron surfaces) are the checks.

## Risks

- **java-tron private network in docker**: image choice, x86 requirement,
  boot time, and TVM acceptance of the ERC20 stand-in are unproven in this
  repo. Mitigation: U9 starts with a container smoke script before the leg is
  written; if hosted CI cannot run it, the leg is a dev-box gate (C4), never
  a silent skip. TVM rejection of the reused bytecode would swap in a
  solc-compiled TRC20 fixture, an artifact change only.
- **Tron protobuf verify subtlety**: a wrong reader accepts what it should
  reject. Mitigation: U4 fixtures are recorded from a real node and include
  mutated-field rejction cases; the signature vector is pinned against a
  known transaction.
- **base58 consolidation touches consumer identity encoding** (`pubkey.ts`).
  Mitigation: exports unchanged, existing pubkey/consumer suites must stay
  green in U1; if anything shifts, the consolidation is dropped and the Tron
  codec restated locally per the `toChecksumAddress` precedent.
- **Cross-rail dedupe semantics**: one derivation body must exist on exactly
  one rail. The U2 concurrent test pins it through the existing
  `portal_stealth_addr_uniq` constraint, which is already rail-agnostic.
- **Maroo regression (R13)**: every touched shared surface (announce route,
  store, pay lib, payments fold) keeps an explicit pinned-unchanged test on
  the evm path, and the final gate run includes the full `e2e_m0.sh` with the
  portal_priv leg.
- **Workflow-file push**: adding the node-fast test entry touches
  `.github/workflows/ci.yml`; the dev PAT lacks the workflow scope, so the
  push uses the gh-CLI-token procedure from CLAUDE.md.
- **Lock file**: no new dependency is planned anywhere (protobuf reader is
  local, `@noble` already in core). Any dep that proves necessary follows the
  CLAUDE.md scratch-dir lock procedure with the adds-only diff check.
- **Ops residue** (surfaced in the PR, not this slice): Nile then mainnet
  deployment ladder, operator key custody and TRX stake funding, live indexer
  Tron env, pay-web/wallet-web Vercel env additions.

## Proving gates

- Per iteration (quick): `packages/core` tests, indexer `npm run test:unit`,
  `npm test -w @bongtu/sweeper -w @bongtu/tron-operator` (once it exists),
  pay-web and wallet-web tests, root `tsc --noEmit`, and
  `npm run typecheck --workspaces --if-present` (the vite-misses rule).
- Final, before PR: the new `deploy/gates/tron_leg.sh` (R12) on the dev box;
  `deploy/gates/e2e_m0.sh` (R13 regression, all three existing legs);
  indexer conformance `cd apps/indexer && npm test`; if the lock was touched,
  the adds-only diff with the 26+25 optional-entry counts intact.
