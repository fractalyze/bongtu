# Stealth payment receiving on Maroo — plan

Spec: [spec.md](spec.md)

Auto-mode run. Overlap check at plan time: no other feature worktree or open feature PR
(the op-module worktree's branch is squash-merged residue; intent-workflow is locked
housekeeping). Note: this worktree's `circuits/out` is empty — gate prep regenerates the
CPU artifact set via `prove_all.sh` (gitignored, deterministic) before heavy gates.

## Changes

Ordered work units; one commit per unit via workflow:commit.

### U1 — receive contracts: consumer-family sweep + on-chain announcement

Files: `chains/evm/src/ReceiveFactory.sol`, `chains/evm/src/ReceiveSweeper.sol` (new),
`chains/evm/test/Receive.t.sol` (new), `packages/core/test/stealth.test.ts` (+ a second
parity vector pinned by the new factory).

- Sibling pair of PortalFactory/PortalSweeper with two deltas: (1) the sweeper's pool
  interface is the CONSUMER path — `IReceiveModule.depositPriv(a, b, c, uint[16] pub,
  bytes[] kemCiphertexts)` hardcoded by the same breaking-by-policy rule, approving the
  POOL for `pub[0]` (DepositPrivModule pulls from its caller via `applyOpWithPull`);
  (2) the factory's `sweep(...)` gains `bytes ephemeralPub, uint8 viewTag` and emits
  `Announced(bytes32 indexed salt, bytes ephemeralPub, uint8 viewTag)` beside `Swept` —
  the chain-only recovery path for every swept payment (spec R5).
- CREATE2/salt/addressOf semantics identical (salt = DKSAP stealth address, TS mirror
  unchanged); the new pair has its own `sweeperInitCodeHash`, so `Receive.t.sol` pins a
  fresh parity vector consumed by the core stealth test beside the existing one.

Proof: forge tests — a real committed depositPriv fixture sweeps and mints consumer
notes; repeat-sweep, non-owner revert, balance guards (Portal.t.sol casts); `Announced`
carries the exact ephemeralPub/viewTag; the parity vector pins initcode hash + addressOf.

### U2 — deploy script and record field

Files: `deploy/forge/DeployReceive.s.sol` (new), `deploy/forge/AddressBook.sol`
(`receiveFactory` optional field, the portalFactory pattern), `deploy/gates/test_deploy_receive.sh`
(new, modeled on test_deploy_portal.sh).

- Env knobs `DEPLOYER_KEY`/`BOT`; rerun guard on `receiveFactory`; requires a recorded
  pool AND `depositPrivModule` (read from `modules.<chainid>.json`). The 450815 run is
  the human step (runbook in U8); the gate proves the script on anvil.

Proof: the drill script passes (fresh record → deploy → read-backs → rerun refused);
default `Deploy.s.sol` untouched.

### U3 — indexer: announce route, attribution split, operator gating

Files: `apps/indexer/src/api/routes/portal.ts`, `src/portal.ts`, `src/api/router.ts`,
`src/chain.ts` (+`RECEIVE_FACTORY` config + combined ABI rows for the new pair's
`Swept`/`Announced`), `src/ingest.ts` (watch + gate on the new factory address),
`src/host.ts` (the `receiveAddressOf` capability), `src/index.ts` (env docs + boot
lines), `src/schema.sql` (factory/rail columns + the unique stealth_addr index),
`packages/core/src/wire/indexerClient.ts` + the portal wire types (+ the
`indexerHttp.ts` header seam for the operator token), `apps/indexer/test/portal.test.ts`,
`apps/sweeper/test/sweep.test.ts` + `packages/core/test/indexerApi.test.ts`
(attributed-shape compat updates).

- `POST /portal/announce` `{ label, ephemeralPub, viewTag, stealthAddr }`: server
  recomputes `destination = receiveAddressOf(portalSalt(stealthAddr))`, resolves the
  label to the owner at write time, rejects a recorded `stealthAddr` (first write wins),
  unauthenticated (recorded PoC posture).
- Public projections of `/portal/announcements` + a new announce-backed feed drop
  `name`/`owner`; the sweeper's attributed `/portal/unswept` moves behind
  `PORTAL_OPERATOR_TOKEN` (shared-secret header; enforced only when the env is set so
  the depositor-facing local flows keep working — spec C3 resolution).
- `Swept` from the receive factory flips records exactly as the portal path does;
  `Announced` ingestion backfills/validates announcement rows from chain data.
- Compat sweep: every existing caller of the attributed shapes (treasury-web Receive
  panel, portal_leg, sweeper client) is updated in the same unit.

Proof: portal.test.ts extensions — announce recompute/dedupe/unknown-label 4xx, public
feeds carry no `name`/`owner` field at all, token-gated unswept (401 without, serves
with), receive-factory `Swept`/`Announced` ingestion; indexer unit suite green.

### U4 — sweeper: receive mode proving depositPriv

Files: `apps/sweeper/src/{sweep,prover,config,index}.ts`, `apps/sweeper/test/*`,
(supporting) the consumer deposit request builder in `packages/client` if
`buildDepositRequest` needs a depositPriv sibling.

- A `RECEIVE_FACTORY` mode: fetches token-authed unswept, builds a depositPriv witness
  for the recipient's PUBLIC consumer triple (owner bjj pubkey, `noteViewPub` receiver
  cts, `kemEk` encapsulation — no private material, mirroring the zero-priv identity
  trick), proves `depositPriv` (16 publics), submits via the receive factory's sweep
  with the announcement args. Enterprise mode stays byte-compatible for the old pair.

Proof: sweeper unit tests — receive-mode args build the exact factory tuple, 16-arity
enforcement, announcement args carried, enterprise-mode tests untouched and green.

### U5 — pay-web: the sender-facing page

Files: `apps/pay-web/*` (new Vite app: package.json, vite.config.ts, vercel.json,
src/, test/), root `package.json` workspaces + `package-lock.json` (QR encoder dep —
CLAUDE.md lock procedure, verify the 26+25 optional-entry counts), root README rows.

- `/p/{label}`: `GET /names/{label}` → validate v2 record → browser-side
  `deriveStealthAddress` + `create2Address` against the receive factory (address +
  initcode hash from build-time config, parity-checked against the server recompute in
  the announce response) → `POST /portal/announce` BEFORE display → address + QR +
  chain/token facts. No wallet code, no proving code, nothing persisted.

Proof: unit tests — derivation parity against the U1 vector, announce-before-display
ordering (fetch mock), record validation failure paths; `vite build` + typecheck green.

### U6 — wallet-web: payments list

Files: `apps/wallet-web/src/ui/hooks.ts` (route union), `App.tsx` (Router case),
`src/ui/screens/Payments.tsx` (new), `src/lib/` scan helper, `apps/wallet-web/test/`;
plus the R1 share surface on the existing Receive screen: `src/config.ts`
(`payBaseUrl` knob) + `src/ui/screens/Receive.tsx` (copy-payment-link).

- Scan the public announce feed with the unlocked stealth view key
  (`scanStealthAnnouncement`), fold in `swept` flips and self-scan note arrival:
  rows `received → swept → shielded`. Public endpoints only (tokenless consumer
  contract preserved).

Proof: wallet-web unit tests — own/foreign announcement filtering, status folding,
route wiring; typecheck green.

### U7 — the receive gate leg

Files: `deploy/gates/receive_leg.ts` (new), `deploy/gates/e2e_orchestrator.ts` (call
it after the consumer leg, same Postgres/env plumbing), `deploy/gates/e2e_m0.sh`
(the leg's own Postgres database), `apps/pay-web/package.json` (exports map so the
leg calls the page's issuance decision headlessly).

- Anvil: deploy pool stack + consumer modules + ReceiveFactory; real indexer with both
  factories configured; register a v2 name; TWO headless pay-page issuances (the U5
  derivation called as a library); two plain transfers from two distinct funded EOAs;
  receive-mode `runOnce`; then the spec R7 assertions — distinct destinations, negative
  grep of both payment txs' calldata/logs and the public feed bodies for the recipient's
  keys/label, `Announced` events match the issuances, both notes discovered by the
  recipient's consumer self-scan, `/portal/unswept` token gate enforced.

Proof: the leg passes inside `e2e_m0.sh`; the pre-existing portal leg stays green
(R11 no-regression).

### U8 — docs and runbook

Files: `docs/portal.md`, `docs/security-model.md` (new portal/receive who-sees-what
subsection incl. the pay-page operator row and the precise amount claim),
`docs/indexer.md` (route table + token gating), `docs/wallet.md`, `deploy/README.md`
(DeployReceive runbook for 450815 as the human step), root `README.md`,
`apps/{pay-web,wallet-web,sweeper,indexer}/README.md`.

Proof: stage-5 review against the spec's Docs debt list.

## Risks

- **package-lock**: the QR dep add follows the CLAUDE.md scratch-dir regen-free
  procedure; diff must be adds-only with optional-entry counts unchanged (26 @esbuild +
  25 @rollup) — checked in U5 and again at verify.
- **Attributed-shape compat**: U3's projection change can break deployed readers; the
  unit updates every in-repo caller, and the review re-greps for stragglers.
- **depositPriv witness from public material only**: if the consumer builder demands
  private recipient state anywhere, that is a stop-and-redesign, not a workaround
  (would violate the sweep trust model).
- **Empty circuits/out in this worktree**: regen `prove_all.sh` targets before heavy
  gates; committed artifacts must show adds-only afterward.
- **Live records untouched**: no edit to `addresses.450815.json`/`modules.450815.json`;
  the receiveFactory field lands there only via the human 450815 run.
- **PATH/log discipline** per CLAUDE.md for every gate run.

## Proving gates

Per iteration (quick): affected workspaces' unit tests (core, client, client-evm,
indexer unit, sweeper, wallet-web, pay-web) + `tsc`/workspace typechecks + `forge test`.

Final (/verify full): `deploy/gates/e2e_m0.sh` including the new receive leg and the
untouched portal leg, indexer conformance (`apps/indexer && npm test`),
`test_deploy_receive.sh`, and the lock-file adds-only check.
