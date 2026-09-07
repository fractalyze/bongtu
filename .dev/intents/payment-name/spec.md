# Payment name: rotating resolver over the stealth meta-address (spec)

Author: spec-drafter (reviewed by JunBeom Lee). Status: accepted.
Intent: [intent.md](intent.md)

Auto-mode note: drafted under `/run-intent`. Four user decisions of record (2026-09-07)
are baked in as requirements, not flagged: the MetaMask live-freshness acceptance check
(R2, R6), announce-before-return (R3), the explicit human ops prerequisites (Design,
"Human ops prerequisites"), and family naming for the new pieces (R11). The intent's
open questions are resolved with recommendations in Design; residual items are in
Concerns with their class.

## Context: what already exists (load-bearing reuse)

The receive product (PR #88) already owns everything below the name layer. The
`/names` directory holds owner-signed records carrying the stealth meta-address plus
the v2 consumer pair; `@bongtu/core/stealth` owns the DKSAP derivation and the
CREATE2 leg (`portalSalt`/`create2Address`, parity-pinned against
`PortalFactoryBase.addressOf`); the pay page (`apps/pay-web`) derives fresh
destinations browser-side and announces BEFORE displaying (`src/lib/pay.ts`, the
four-step contract); the indexer records announcements first-write-wins on the stealth
address (`POST /portal/announce`), serves the attribution-free public feed, and holds
`portalPrivAddressOf`; the `PortalPrivFactory`/`PortalPrivSweeper` pair sweeps funded
destinations into the consumer `depositPriv` family and emits the on-chain `Announced`
recovery event. Owning docs: [docs/portal.md](../../../docs/portal.md),
[docs/indexer.md](../../../docs/indexer.md),
[docs/security-model.md](../../../docs/security-model.md#stealth-receiving-the-portalreceive-edge).

What this spec adds is exactly the name layer the predecessor spec declared a
non-goal: a mainnet ENS name over the same records, resolving to the same
destinations, feeding the same announcement store and sweep spine. No new
cryptography, no new sweep path, no Maroo contract.

## Requirements

Traceability: R1, R5 ← Proposed outcome bullet 1 + Constraints (no ETH); R2 ← bullet 2
+ Problem (a static mapping destroys the privacy) + user decision 1; R3 ← user
decision 2 + Problem; R4 ← bullet 3 + Constraints (availability trust); R6 ← bullet 5
+ Constraints (measure MetaMask) + user decision 1; R7 ← bullet 5 + Affected systems
(same sweep spine); R8 ← bullet 4; R9, R10 ← Constraints; R11 ← user decision 4.

- **R1 (MUST) Wildcard resolution over the directory.** Every `/names` record carrying
  the full v2 shape (stealth meta + consumer pair, non-sentinel) resolves as
  `{label}.{root}` from unmodified ENS-aware wallets, via ENSIP-10 wildcard resolution
  and ERC-3668 CCIP-Read. A missing, v1-only, or sentinel-cleared record does not
  resolve (fail closed, the same gate `POST /portal/announce` applies server-side).
  No per-name on-chain state exists.
- **R2 (MUST) Fresh destination per resolution.** Every resolution derives a fresh
  DKSAP destination from the record's public meta-address: two resolutions of the same
  name yield two different addresses. No layer may present a reusable answer: the
  resolver contract stores no address, gateway HTTP responses are `Cache-Control:
  no-store`, and the signed response's validity window is at most 300 seconds (it
  bounds replay of one response, never authorizes reuse across resolutions).
- **R3 (MUST) Announce before return.** The gateway records the announcement
  (ephemeralPub, viewTag, stealthAddr, attributed to the name) through the existing
  first-write-wins store BEFORE signing and returning the address, mirroring the pay
  page's announce-before-display contract: a MetaMask sender will never announce, so
  the issuer must. If the announce write fails for any reason (including the 409
  duplicate), the resolution aborts with an error and no address is returned. The
  returned address is the `PortalPrivFactory` CREATE2 destination (not the raw stealth
  EOA), so a payment to it sweeps into the shielded balance through the existing,
  unchanged sweep path.
- **R4 (MUST) Verifiable, bounded responses.** Gateway responses are signed and
  expiry-bounded, and the resolver contract verifies signer and expiry on-chain in the
  CCIP callback before the wallet accepts the address. The gateway derives with a
  fresh ephemeral scalar and discards it (it can derive, never spend, the
  `POST /pay/{name}` posture). Every returned destination has a public announcement
  row the recipient's view key verifies via `scanStealthAnnouncement`; a signed
  response whose destination has no honest announcement, or whose announcement does
  not scan to the recipient's meta, is cryptographic evidence of gateway misbehavior.
  The gateway is availability-trust only: it can refuse service, and any redirection
  it attempts is detectable and attributable, never silent.
- **R5 (MUST) Gasless name issuance.** Obtaining a name is exactly the existing
  owner-signed `/names` registration: offchain, no ETH held by the user, no per-name
  transaction on any chain. Wildcard resolution makes every directory label a name
  with zero marginal on-chain cost.
- **R6 (MUST) MetaMask acceptance check.** The demoable test, run live at gate time:
  (a) in MetaMask (current release) with Ethereum mainnet selected, type the full name
  into the send field, note the resolved address, exit the send flow, repeat: the two
  resolved addresses differ; (b) both appear on `GET /portal/announcements` and match
  the recipient's view-key scan; (c) both, funded with kKRW on Maroo, sweep into the
  recipient's shielded balance. Additionally, MEASURE (not assume) MetaMask's behavior
  with Maroo selected: whether the send field resolves at all and which coin type the
  gateway receives; the measured result and the documented sender fallback ship in
  docs (Concern C5).
- **R7 (MUST) One discovery and sweep spine.** Resolver-issued announcements ride the
  same store, feeds, uniqueness index, and attributed operator projection as pay-page
  issuances. The wallet receive view, the recipient's scan, and the sweeper consume
  them with no change; the recipient cannot tell (and never needs to tell) which
  front door issued a payment. This resolves the intent's dedup question: one store,
  one first-write-wins index on the stealth address, fresh scalar per issuance,
  no cross-path reconciliation to build.
- **R8 (MUST) Browser fallback.** Opening the product-branded form of a name in a
  browser lands on that name's pay page (`/p/{label}`), serving senders whose wallet
  or exchange resolves nothing. The mechanism ships in this slice; the domain itself
  is an ops prerequisite.
- **R9 (MUST) No live-pool or Maroo contract change.** Pool `0x3B6238…1aD6` and the
  deployed PortalPriv pair are reused as-is; the only new contract is the mainnet
  resolver. Existing pay-web, portal routes, and sweep behavior are unchanged and
  their gates stay green.
- **R10 (MUST) Honest trust posture in docs.** Shipped docs state: the gateway
  operator sees every resolution query (sender IP, name, timing) BEFORE any payment
  exists; it can censor; redirection is detectable, not preventable; the per-payment
  amount remains public twice; and the wrong-chain hazard (C2) with its guidance.
- **R11 (MUST) Family naming.** The new pieces take PortalPriv family names (the
  portal/PortalPriv precedent): same mechanism, same name family, no divergent
  product codenames in code or records.

## Design

### Name root (resolves intent open question 1)

An owned `.eth` second-level name with ENSIP-10 wildcard subdomains. Rationale
against the DNSSEC-import alternative: a 2LD costs one registration, needs no DNSSEC
maintenance, and its wildcard + one `setResolver` gives every directory label a name
with zero per-name cost, satisfying R5 outright. The concrete label is a branding and
acquisition decision (Concern C1); everything below is parameterized on `{root}.eth`.

The `.frx` rendering is branding on top, exactly as the intent says: no wallet
resolves `.frx`, so the canonical wallet-typed form is `{label}.{root}.eth`, and the
product renders `{label}.frx` in its own UI only. The browser fallback (R8) is a DNS
wildcard on a product-owned DNS domain redirecting `{label}.<domain>` to the pay
page's `/p/{label}`; plain hosting, no ENS machinery.

### Resolver contract: `PortalPrivResolver` (mainnet)

A small ENSIP-10 extended resolver in `chains/evm/src`, following the ENS
offchain-resolver reference pattern:

- `resolve(bytes name, bytes data)` reverts `OffchainLookup` with the gateway URL and
  the request; `supportsInterface` advertises the extended-resolver interface.
- `resolveWithProof` verifies the gateway signature over
  (resolver address, expiry, request hash, result hash) against the owner-set signer,
  rejects expired responses, and returns the result. This is the whole R4 on-chain
  half: signer binding plus bounded validity.
- Owner-settable signer and URL list (rotation without redeploying); no name data,
  no address storage (R2's on-chain half).

It deploys to Ethereum mainnet, a new deployment target for the repo; the address is
recorded in a new mainnet record (`deploy/addresses.1.json`) and set as the root
name's resolver. Deploy and wiring are human runbook steps (below).

### Gateway: indexer routes in the portal family

The gateway is a set of new routes in `apps/indexer` rather than a standalone
service: issuance needs the names store, the portal store's atomic first-write-wins
index, and `portalPrivAddressOf`, all of which the indexer already holds in-process.
Route naming stays in the portal family (R11), e.g. `GET/POST
/portal/resolve/{sender}/{data}.json` in the CCIP-Read wire shape. New env: the
response signer key (never logged, never returned, the `AUTHORITY_KEY` handling
posture) plus the resolver's mainnet address for the signed-payload binding.

Per resolution, the gateway mirrors the pay page's four-step issuance contract with
itself in the visitor's role, against the priv pair server-side (the
`handlePayPortal` shape):

1. decode the ENSIP-10 request: DNS-decode the wildcard name, take the first label,
   apply the directory grammar plus ENSIP-15 normalization (fail closed on
   non-conforming labels); only `addr` profiles are served, ENSIP-9 coinType 60 and
   the ENSIP-11 EVM coinType for chain 450815, both answering the same destination;
   other profiles return the empty answer and never mint an announcement;
2. resolve the label in the names store; fail closed unless the v2 record is complete
   (R1);
3. derive a fresh destination server-side and let the scalar go out of scope; write
   the attributed announcement through the same `portal.issue` first-write-wins path
   the announce route uses, and parity-derive the destination via
   `portalPrivAddressOf` (R3): any failure aborts the resolution;
4. sign (expiry ≤ 300 s) and return, `Cache-Control: no-store` (R2, R4).

### Verification and evidence chain (R4)

Three checks compose the "cannot steal undetected" bound. The resolver's signature
check pins every accepted answer to the gateway signer and a validity window, so a
redirecting answer is non-repudiable evidence in the sender's hands. The
announce-before-return rule means every honest answer has a public announcement row;
the recipient's view key audits the feed continuously for free (its normal scan). A
compromised gateway that skips announcing or derives off-meta produces exactly the
detectable signature: a signed destination absent from the feed, or a row no view key
claims. Docs state plainly that detection is after the fact; prevention is not
claimed (R10).

### What does not change

Sweep, discovery, receive view, feeds, and the pay page are untouched (R7, R9). A
resolver-issued row is a pay-page row with a different writer: same attribution
split, same operator token gate, same `Swept` flip, same on-chain `Announced`
recovery event at sweep time. `POST /pay/{name}` (enterprise pair) and
`POST /portal/announce` (browser derivation) keep their existing contracts.

### Gate

An automated leg proving, without a live wallet: (a) two gateway calls for one name
return two destinations, both parity-correct against the local CREATE2 mapping and
both recorded on the public feed before the response was signed; (b) a forced
announce failure yields no signed response; (c) `resolveWithProof` accepts a fresh
gateway-signed fixture and rejects expired and wrong-signer ones (forge); (d) a
gateway-issued destination, funded on anvil, sweeps to a consumer note via the
existing `portal_priv_leg` machinery. The live MetaMask check (R6) is the human
demo at gate time, per the decision of record.

### Human ops prerequisites (explicit, per the decision of record)

Named here because no PR can perform them:

1. Register the root `.eth` name on Ethereum mainnet (real ETH, owner custody
   decision, C1/C6).
2. Deploy `PortalPrivResolver` to mainnet with the gateway URL and signer; record the
   address in `deploy/addresses.1.json`.
3. `setResolver` on the root name to the deployed resolver (mainnet tx from the name
   owner).
4. Host the gateway publicly: the live indexer reachable at the URL baked into the
   resolver, signer key provisioned in its env.
5. Point the product DNS domain's wildcard at the pay page (R8).

## Non-goals

- No on-chain subdomain issuance, NameWrapper, or per-user ENS records; names are
  offchain directory rows resolved by wildcard.
- No DNSSEC-imported root in this slice (recorded alternative, not re-proposed).
- No ENS contenthash / decentralized-site serving; the browser fallback is a DNS
  redirect.
- No operator blindness: the gateway operator sees queries and the mapping it serves,
  honestly excluded from the claim as before (OMR/TEE class work stays out of scope).
- No sender-side software, wallet plugin, or non-EVM (Tron/Solana) name resolution.
- No fee model, no multi-gateway redundancy, no query-privacy machinery (C3).
- No change to sweep economics, the pay page flow, or any Maroo contract.

## Concerns

Flagged for the human gate; class per the intent-chain rule (blocker = security
model, live deployments, user harm; judgment = policy and product calls).

- **C1 (judgment, branding + ops): the concrete root label and its custody.** Which
  `.eth` 2LD to register, under which key, and how the `.frx` branding maps onto it.
  Pure acquisition/branding; the design is parameterized on the answer.
- **C2 (BLOCKER, user harm): wrong-chain sends can strand funds.** A name resolved on
  mainnet yields a Maroo CREATE2 destination; a sender who completes the send on
  mainnet (or any chain without the factory) pays an address where no sweeper can
  ever deploy, and the funds are unrecoverable by anyone. The demo itself resolves on
  mainnet, so the hazard is on the happy path's doorstep. Ship options: accept and
  document loudly (docs + pay-page guidance), and/or name a rescue follow-up
  (deterministic same-address factory deployment on the stranding chain). Needs an
  explicit posture decision; cite
  [docs/security-model.md](../../../docs/security-model.md#stealth-receiving-the-portalreceive-edge)
  residual-gaps style when recording it.
- **C3 (judgment, recorded posture): query privacy.** The gateway sees sender IP,
  name, and timing at resolution, BEFORE any payment exists, a strictly earlier
  signal than the pay page's. Recommendation: no mitigation ships this slice; the
  posture is stated in docs (R10) and OMR/TEE-class work stays the named exclusion.
- **C4 (judgment, abuse surface): resolution-driven row minting.** Every `addr`
  resolution mints an attributed announcement row through an unauthenticated public
  endpoint, widening the recorded PoC spam surface (rows are hints, the bot sweeps
  only funded addresses, rate limiting is ops). Confirm the posture still holds when
  the minting trigger is a wallet keystroke flow rather than a page visit.
- **C5 (judgment, measured constraint): MetaMask on Maroo may not resolve.** If the
  R6 measurement finds no resolution on the custom network, the live demo remains
  mainnet-resolution plus paste-and-send on Maroo, and custom-network senders are
  documented to the pay page fallback. Confirm that shape satisfies the acceptance
  intent; the measurement result ships in docs either way.
- **C6 (BLOCKER, key custody + live ops): the gateway signer and the name owner
  keys.** A leaked signer key signs redirections (detectable, C2-adjacent, but real
  until rotated by a mainnet `setSigner`); the name-owner key can repoint the
  resolver entirely. Custody, rotation runbook, and env handling (never logged, the
  `AUTHORITY_KEY` rule) need human sign-off before the mainnet steps run.
- **C7 (minor): MetaMask caching granularity.** If MetaMask caches a resolved address
  within one send flow, per-resolution freshness is per gateway query, and the demo
  measures across send-flow entries; record the observed granularity with R6's
  measurement.
- **C8 (minor): label normalization edge.** ENSIP-15 forbids labels the directory
  grammar admits (e.g. hyphens in positions 3 and 4); the gateway normalizes and
  fails closed, leaving such labels pay-page-only. Note in docs.
- **C9 (minor, repo hazard): dependencies.** The resolver needs the small ENS
  interface set (vendor or minimal dep); any lock-touching install follows the
  CLAUDE.md package-lock regen rule.

## Docs debt

- [docs/portal.md](../../../docs/portal.md): a payment-name section (the third front
  door: resolver issuance beside pay-page and depositor flows, announce-before-return,
  the wrong-chain guidance).
- [docs/security-model.md](../../../docs/security-model.md): the gateway operator row
  in the receive who-sees-what table (query visibility, censor-not-steal, the signed
  evidence chain), and the wrong-chain hazard per C2's resolution.
- [docs/indexer.md](../../../docs/indexer.md): the gateway routes in the HTTP API
  table, the signer env, the resolution-minted row posture.
- [docs/deployment.md](../../../docs/deployment.md) + `deploy/README.md`: the mainnet
  target, the new address record, the ENS wiring runbook.
- `chains/evm/README.md`: the resolver contract; `apps/indexer/README.md`: env and
  route deltas; `apps/pay-web/README.md`: the fallback-domain origin note.
- Root `README.md`: system map and What-is-built rows for the name layer.

Status: accepted
