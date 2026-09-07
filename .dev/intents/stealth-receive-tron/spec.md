# Stealth payment receiving on Tron: the fresh-address tier (spec)

Author: spec-drafter (reviewed by JunBeom Lee). Status: accepted.
Intent: [intent.md](intent.md)

Decisions of record (user, 2026-09-07), baked in as requirements rather than flagged:

1. **Tron is priority one.** This intent runs before the name layer; `payment-name`
   is parked and will be redrafted chain-aware after this lands.
2. **Name-gateway forward compat.** The Tron issuance path (fresh-address derivation
   plus announce) must be callable server-side by an indexer-hosted issuer, under the
   same record-before-display contract the Maroo pay page enforces, so the future
   name gateway can mint fresh Tron addresses with no new machinery. The name layer
   itself is not specced here.
3. **Honesty constraint.** No pool, no shielding claims on Tron: docs and UI state
   the tier plainly (fresh-address unlinkability, per-address amounts visible)
   versus Maroo's shielded tier.

## Context: what carries over (load-bearing reuse)

The Maroo receive spine was built rail-extensible on purpose (its R9). What Tron
inherits unchanged:

- **Derivation.** `@bongtu/core/stealth` is rail-neutral up to presentation: Tron
  addresses are the SAME secp256k1 pubkey and the SAME 20-byte keccak body as an
  EVM EOA, wrapped in `0x41` plus base58check. `deriveStealthAddress`,
  `scanStealthAnnouncement`, and `recoverStealthKey` need no change; the recovered
  private key controls the Tron account as-is.
- **Wire shapes.** `PortalRecord`/`PortalPublicRecord` carry `rail` already
  (`packages/core/src/wire/indexerNames.ts`); `POST /portal/announce` validates it
  (today rejecting anything but `"evm"`); rows dedupe first-write-wins on the
  20-byte `stealthAddr`, atomically ([docs/indexer.md](../../../docs/indexer.md)).
- **Product surfaces.** The pay page (`apps/pay-web`, announce-before-display,
  parity-check, fail-closed), the attribution-free public feed, the wallet's
  view-key scan and received-payments list, the registered v2 identity
  ([docs/portal.md](../../../docs/portal.md), [docs/wallet.md](../../../docs/wallet.md)).

What Tron does NOT have: a pool, the CREATE2 factory/sweeper pair, the on-chain
`Announced`/`Swept` events, or any shield tier. The payment destination is the
stealth account itself; funds stay there until the recipient moves them with the
derived key. Two Tron-specific realities drive most of this design: an account
must be ACTIVATED (receive TRX or be created) before it can send anything, and a
TRC20 transfer out needs energy/bandwidth at the sending address.

## Requirements

Traceability: R1 ← Problem (the derivation ports) + Constraints (one code path);
R2-R3 ← Proposed outcome bullet 1; R4 ← bullet 2 + Open question 3; R5 ← bullet 1
issuance machinery + decision of record 2; R6-R8 ← bullet 3; R9-R10 ← bullet 4 +
Constraints (fee reality, no stranded dust); R11 ← Constraints (honest tier) +
decision of record 3; R12 ← bullet 4 (the gate); R13 ← Affected systems (depends
on the Maroo spine, which must keep working).

- **R1 (MUST) One derivation path, presentation flavor.** `@bongtu/core/stealth`
  gains a Tron PRESENTATION of the existing 20-byte stealth address
  (base58check over `0x41` plus the body); derivation, scan, and key recovery
  stay the single existing code path. The canonical wire form of `stealthAddr`
  remains the 0x hex body on every rail; `rail` selects presentation only.
  Presentation is pinned by committed known-answer vectors (address plus its
  base58 form, cross-checked against independent Tron tooling).
- **R2 (MUST) Pay page Tron tab.** `/p/{label}` grows a Tron tab: each load
  derives a FRESH destination in the visitor's browser from the SAME registered
  record (no re-registration, no new keys), announces with `rail: "tron"` BEFORE
  displaying, parity-checks the server's recomputed destination against the local
  presentation, then shows the base58 address, QR, and chain/asset facts with the
  tier copy (R11). No wallet code, no signature, nothing persisted; unconfigured
  reports itself unconfigured.
- **R3 (MUST) Acceptance assets: USDT-TRC20 plus TRX.** USDT-TRC20 is the
  acceptance and gate asset; TRX sent to a destination also belongs to the
  recipient and is surfaced. No other TRC20 is claimed or displayed.
  (Resolves Open question 1: the demand the intent names IS TRC20-USDT; TRX-only
  would miss it. Recommendation, class judgment; see Concerns C3 for the cost
  asymmetry it creates.)
- **R4 (MUST) Zero sender software, zero receive precondition.** The payment is a
  plain TRC20 or TRX transfer from any stock Tron wallet or a CEX withdrawal: no
  contract call by the sender beyond the token transfer itself, no bongtu code,
  and NO pre-activation of the destination (a non-activated address holds TRC20
  fine; activation is deferred to R7 and never blocks receiving).
  (Resolves Open question 3's first half.)
- **R5 (MUST) Server-side issuance (the name-gateway hook).** The indexer can
  itself perform a Tron issuance: draw the ephemeral scalar server-side, discard
  it after derivation (the `POST /pay/{name}` discipline), record the
  announcement row, and only then return the destination. The route is public
  like the existing issuance routes and produces rows identical to the pay-page
  path, so the future name gateway is a caller, not new machinery.
- **R6 (MUST) Discovery unchanged.** Tron issuances land on the existing
  attribution-free public announce feed as `rail: "tron"` rows; the recipient's
  view-key scan is rail-agnostic (same `(ephemeralPub, viewTag)` predicate);
  first-write-wins dedupe on `stealthAddr` stays atomic and is cross-rail (one
  derivation body is recorded once, on one rail).
- **R7 (MUST) Funding detection and the chain anchor.** The operator side detects
  funding of announced Tron destinations and (a) stamps funding on the record
  (amounts, tx, time) so the feed serves status, and (b) sends ONE small TRX
  transfer to the funded address carrying `ephemeralPub ‖ viewTag` in the
  transaction data field. That one transaction both ACTIVATES the account
  (enabling R9's delegation) and ANCHORS the announcement on-chain: every funded
  payment becomes recoverable from the announcer account's outgoing transfers
  plus the view key, with no indexer store. (The Tron analogue of the Maroo
  sweep-time `Announced` event; resolves Open question 3's second half:
  activation is operator-funded, at funding time.)
- **R8 (MUST) Receive view.** The wallet lists funded Tron payments beside Maroo
  ones: rows from its own scan of the public feed, status `received` (terminal on
  this tier; no sweep/shield rungs), amounts from the funding stamp, never
  rendering an unfunded issuance as money. The tokenless/no-arbiter contract
  holds: every read is a public endpoint.
- **R9 (MUST) Move with derived keys, fees solved.** The recipient can move the
  full USDT balance (and above-cost TRX) off any funded destination to an address
  they choose: key recovery via `recoverStealthKey`, transaction built and signed
  LOCALLY (never signing remote-built bytes unverified), energy and bandwidth
  supplied by the operator's delegation (stake once, delegate per move, reclaim
  after), so the recipient needs no TRX of their own at any point.
- **R10 (MUST) No stranded dust.** A stated dust policy: balances below a
  configured move threshold stay `received` with honest copy (uneconomic to
  move yet), everything at or above it is movable end to end under R9. The
  design must leave no funded-above-threshold balance unmovable.
- **R11 (MUST) Honest tier statement.** Docs and UI say exactly: Tron payments
  get per-payment fresh-address UNLINKABILITY; each address's amount and its
  onward movement are public; nothing is shielded. The word "shielded" never
  appears on a Tron row or Tron doc claim. Maroo rows keep their shielded-tier
  wording; the two tiers are presented side by side, not blurred.
- **R12 (MUST) Unlinkability gate.** An automated gate on a private Tron network:
  one recipient, two pay-page-shaped issuances, two payments from two distinct
  sender accounts, then asserts (a) the destinations differ; (b) no on-chain
  datum common to the two payment transactions correlates them with each other
  or with the recipient's registered identity (announcer transactions carry only
  the public announcement tuple); (c) the public feed serves no attribution;
  (d) both balances are moved out with derived keys via delegation; and (e) both
  rows are rebuilt from the announcer account's transactions plus the view key
  alone (chain-only recovery, R7).
- **R13 (SHOULD) No Maroo regression.** The Maroo receive product is untouched in
  behavior: existing routes, feeds, contracts, sweeper, and the
  `portal_priv_leg` gate stay green; `rail: "evm"` rows and flows are unchanged.

## Design

### Derivation: one path, a presentation function

Core stealth adds the presentation only: base58check of `0x41` plus the 20-byte
address (checksum = first 4 bytes of double sha256). Implemented locally in
`@bongtu/core` (sha256 is already in `@noble/hashes`; base58 is ~20 lines), the
`toChecksumAddress` precedent: no new dependency in core. Known-answer vectors
committed per R1. Everything upstream of presentation, including
`randomEphemeralScalar`, the viewTag, and `recoverStealthKey`, is byte-identical
across rails; the recovered key signs Tron transactions directly (Tron signs
secp256k1 over sha256 of the raw transaction).

The stealth identity itself does not change: the meta keys keep coming from the
existing Maroo-bound stealth KDF (`packages/client-evm/src/stealthKeys.ts`, one
EIP-712 popup, memory-only custody). One identity, multiple rails; Tron adds no
signing domain and no new key-persistence surface.

### Wire: `rail: "tron"` on the existing portal surfaces

- **`POST /portal/announce`** accepts `rail: "tron"` when the indexer's Tron
  config is present (the `PORTAL_PRIV_FACTORY` gating pattern). The Tron branch
  has no factory: the server recomputes `destination` as the PURE presentation of
  the client's `stealthAddr` (no chain call; the client-sent destination is
  still never accepted). The consumer-pair gate (`noteViewPub`/`kemEk`) is
  scoped to rails that mint consumer notes; a Tron announce needs only the
  stealth meta halves, since no sweep and no note ever happen.
- **Server-side issuance (R5)**: `POST /pay/{label}` gains an optional body
  `{ rail: "tron" }`. The Tron branch derives server-side (scalar drawn and
  discarded, the existing handler seam), writes the row, returns the
  `PortalIssuance` with the base58 destination and `rail`. Default body keeps
  today's enterprise-portal behavior byte-for-byte (R13). Exact route shape may
  move to a sibling path in plan if overloading `/pay` reads badly; the contract
  (public, record-before-return, rows identical to the announce path) is what
  this spec pins.
- **Tron rows**: `factory` is empty (no CREATE2 leg), `destination` is the
  base58 presentation, `stealthAddr` stays the hex body. `swept` never flips;
  new funding fields (amounts, funding tx, anchored-tx) mirror the swept
  columns' write-behind discipline, with exact columns named in plan. The public
  projection (`toPublic`) carries the funding fields; attribution stays dropped.

### Pay page: the Tron tab

`/p/{label}` renders per-rail tabs (Maroo as shipped; Tron new). The Tron tab
derives with the same `deriveStealthAddress` call, presents locally, announces
`rail: "tron"` before display, and parity-checks the server's destination
against its own presentation (pure, so the check needs no configured factory
or initcode hash: unlike the EVM tab, misconfiguration cannot redirect, only
disagree). Displayed facts: network, USDT-TRC20 as the asset (contract address
shown for verification), TRX accepted, and the R11 tier copy. The QR encodes
the base58 address (what TronLink and exchange withdrawal forms accept).

### Funding status: the indexer's Tron poller

The indexer gains a small poll loop over unfunded `tron` rows: USDT `balanceOf`
plus TRX balance via a configured Tron HTTP API (`TRON_API`, key server-side),
stamping funding fields under the existing write-behind persist discipline. It
also observes the announcer account's transactions to mark rows chain-anchored.
The indexer holds NO Tron keys; reads only. (Resolves Open question 2:
**hosted indexer extension plus a public API endpoint**, TronGrid-class, for
this slice; an own java-tron node is the named follow-up if rate limits or
trust in third-party reads bite. Recommendation, class judgment, C4.)

The wallet consumes the feed only, keeping the tokenless contract; it may
optionally double-check a balance against a user-configured Tron endpoint, but
no such read is on the required path.

### The Tron operator bot: announce-and-activate, then delegation

A new operator service beside `apps/sweeper` (the sweeper's Tron twin; bots hold
keys and act, the indexer reads, the Maroo division of labor). Two duties:

1. **Announce-and-activate (R7).** On first funding of a row (read from the
   token-gated attributed feed), send one TRX transfer (activation-sized) to the
   destination with `data = ephemeralPub ‖ viewTag`. Account activated, TRX
   create fee paid by the operator (~1.1 TRX), announcement anchored on-chain.
   Chain-only recovery: walk the announcer account's outgoing transfers, read
   the data field, `scanStealthAnnouncement` with the view key. Spam economics:
   this spend triggers only on FUNDED addresses, so flooding it costs the
   attacker real transfers; unfunded announce spam costs only polling quota
   (C7).
2. **Fee delegation (R9).** The operator stakes TRX once; per move it delegates
   energy and bandwidth to the (activated) destination, and reclaims after the
   move lands. Marginal cost per move is near zero on top of the activation
   already paid. The request channel (wallet asks the operator to delegate for
   address X) is operator-token-gated like the attributed feed; delegation
   cannot redirect or spend, so the trust added is availability only.

Below the dust threshold (`MIN_MOVE`-class env, token base units) neither the
activation transfer nor delegation fires; the row reads `received` with the
honest uneconomic copy (R10). Threshold value is policy (C3).

### Move flow (wallet)

A funded Tron row gains a move action: recipient enters a destination Tron
address, the wallet recovers the one-time key, requests delegation, builds the
TRC20 transfer locally (raw transaction protobuf assembled and signed in the
client; if a node's build endpoint is used for convenience, the returned bytes
are decoded and verified against the intended transfer before signing, since a
hostile node could otherwise substitute the recipient), broadcasts, and shows
the result. Full-balance USDT; TRX at the address above its own transfer cost
is movable the same way, residue below it is left and stated. The recovered key
lives only for the flow, the existing memory-only custody rule. The move UI
carries the consolidation warning (C6): moving several payments to one
destination links them on-chain, by the recipient's own choice.

### Gate

A new heavy leg beside `deploy/gates/portal_priv_leg.ts`: a dockerized private
java-tron network with a deployed TRC20 stand-in for USDT, a real indexer, and
the operator bot as a library. Flow: register the recipient, two headless
pay-page-shaped issuances, two funding transfers from distinct funded sender
accounts, poller and bot run, then the R12 assertions including the negative
scan (grep both payment transactions and the public feed body for the
recipient's registered keys and label) and the chain-only rebuild (e). Runs in
the heavy tier; if the java-tron container proves unrunnable on hosted CI
runners, it is a dev-box gate like the GPU legs (part of C4, and subject to the
local-pass-is-not-CI-pass rule in `.dev/ci.md`).

### Configuration and records

Indexer: `TRON_API` (+key), `TRON_USDT`, `TRON_ANNOUNCER` (address, read-side).
Bot: Tron operator key(s), `TRON_API`, dust threshold, `PORTAL_OPERATOR_TOKEN`.
Pay page: display facts only. Live values ship in a committed per-network
record (the `deploy/addresses.<chainid>.json` copy-by-field-name discipline;
naming in plan), covering the USDT contract, the announcer address, and the
chosen network, so no surface transcribes an address by pattern.

## Non-goals

- No pool, no shielding, no sweep on Tron; the pool question stays with the
  `tron-rail-spike` intent. Status tops out at `received`.
- No name layer: only the R5 server-side issuance hook ships; resolution UX,
  roots, and gateways are the redrafted `payment-name`'s.
- No sender-side software, sender fee abstraction, or payment-detection webhooks.
- No fee model beyond the operator-pays posture and the dust threshold; no
  recipient-charged fees, no delegation marketplace.
- No assets beyond USDT-TRC20 and TRX; no multi-token registry.
- No own java-tron node operation in this slice (named follow-up under C4).
- No consolidation automation (batch moves, scheduled sweeps of stealth
  balances); moves are per-address, recipient-initiated.
- No changes to Maroo receive behavior, contracts, or the live 450815 pool; no
  transaction of any kind on 450815.

## Concerns

Flagged for the human gate. BLOCKER stops auto-mode per the intent-chain rule;
JUDGMENT needs a call but has a workable recommendation; MINOR is recorded
posture. Triage 2026-09-07: both blockers resolved with the user (resolutions
inline below); judgment and minor items ship with their stated recommendations.

- **C1 (BLOCKER, funds recoverability / security model): the pre-anchor window.**
  Until the announce-and-activate transaction lands, a Tron announcement exists
  ONLY in the indexer store: for unfunded issuances (and funded ones during
  watcher downtime) a lost store means the ephemeral pubkey is gone and the
  one-time key can never be re-derived, which on Tron strands the FUNDS, not
  just the discovery (there is no sweep minting to registered keys as on
  Maroo). Mitigations in-spec: the anchor transaction itself (funded payments
  become chain-recoverable, the Maroo C2 symmetry), durable Postgres plus
  operator backups for the window. The residual window and its size are a
  posture the human must accept and
  [docs/security-model.md](../../../docs/security-model.md) must state (the
  receive-edge table gains Tron rows).
  **Resolved (user, 2026-09-07): accepted.** The window is loss-only, never
  theft (the store holds discovery material, not spend keys), it matches the
  precedent already accepted for the Maroo pay page pre-sweep, and the same
  structural window exists in Curvy's stock-wallet path. Ship with the in-spec
  mitigations and state the residual gap in docs/security-model.md.
- **C2 (BLOCKER, live chain / real money): the first live network.** Everything
  bongtu runs today is testnet; the demand this intent cites lives on Tron
  MAINNET with real USDT, real operator TRX, and real user funds under a PoC
  trust posture. Recommendation: gate on the private network, first hosted
  deployment on Nile testnet, and the mainnet flip is a separate explicit human
  decision (operator key custody, TRX funding, and the security-model caveats
  re-read against real value). Not resolvable inside the spec.
  **Resolved (triage, 2026-09-07): recommendation adopted.** This slice performs
  no live-chain action: the gate runs on the private network only, and the
  Nile-then-mainnet ladder is surfaced in the PR as post-merge human ops steps,
  each its own decision at its own time.
- **C3 (JUDGMENT, economics): operator cost and dust policy.** Operator pays
  ~1.1 TRX activation per funded payment plus a one-time stake sized to move
  throughput; no fee model recoups it (recorded PoC posture, the Maroo C5
  shape). The dust threshold value, and the UX of a below-dust `received`
  forever, are policy calls. USDT-as-acceptance-asset also means every payment
  needs the full TRC20 move machinery where TRX-only would not; that asymmetry
  is accepted by R3's resolution.
- **C4 (JUDGMENT, external dependency): third-party Tron reads.** TronGrid-class
  API in the funding-status and broadcast path: key custody server-side, rate
  limits, terms, and trusting a third party's reads for status (never for
  custody). Own-node follow-up criteria plus the gate's docker-on-CI question
  land here.
- **C5 (JUDGMENT, dependency and signing trust): Tron transaction building.**
  Recommendation: minimal local protobuf build and sign over `@noble` (no
  TronWeb; it is heavy and any lock-touching install must follow the CLAUDE.md
  package-lock regen rule). If plan opts for node-built transactions, the
  local verify-before-sign in the Design is mandatory, not optional. Operator-
  side-only TronWeb (never the browser bundle) is the acceptable fallback.
- **C6 (JUDGMENT, privacy claim / UX policy): recipient-side linkage.** Moving
  several payments to one destination links them on-chain; a second payment to
  an already-displayed address links those two payments (the Maroo flip-once
  note's Tron analogue); an exchange deposit address as move target hands the
  exchange the linkage. The warning wording and where it appears are a policy
  call; the unlinkability CLAIM must stay scoped to the receive leg.
- **C7 (MINOR, abuse surface): announce spam.** Unauthenticated announce now
  also drives the Tron poll loop per row: spam widens API quota use (the
  recorded PoC posture, rate limiting is ops). The operator's on-chain spend is
  spam-resistant by construction (fires on funded addresses only).
- **C8 (MINOR, sender cost honesty): first-transfer premium.** Every payment
  goes to a USDT-fresh address, so senders always pay the higher new-holder
  energy rate for TRC20 (roughly double a warm transfer). CEXs absorb it;
  self-custody senders see a larger fee than for a warm address. Docs note, not
  a design change.
- **C9 (MINOR, claim precision): tier vocabulary.** The precise-statement
  discipline (security-model receive section) extends: Tron rows never borrow
  Maroo's shielded wording, and Maroo docs never imply Tron shares it. The gate
  and docs use the R11 form verbatim.

## Docs debt

- [docs/portal.md](../../../docs/portal.md): a Tron receive section (no-pool
  tier, announce-and-activate, delegation, dust policy) and the two-tier frame.
- [docs/security-model.md](../../../docs/security-model.md): Tron rows in the
  receive-edge who-sees-what table (announcer/fee-station operator, Tron chain
  observer), the C1 recovery posture, the R11 precise tier statement.
- [docs/indexer.md](../../../docs/indexer.md): route deltas (`rail` on announce
  and issuance, funding fields on the feeds), the Tron poller, env.
- [docs/wallet.md](../../../docs/wallet.md): Tron rows in the received-payments
  list, the move flow, the consolidation warning.
- Root `README.md`: layout row for the new operator service; pay-page and
  status wording where Tron appears.
- `apps/pay-web/README.md` (Tron tab, config), `apps/indexer/README.md` (env,
  routes), new operator-service README, `apps/wallet-web/README.md` (move
  flow), `deploy/README.md` (new gate leg, per-network Tron record).

Status: accepted.
