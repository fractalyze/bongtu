# Payment name: rotating resolver over the stealth meta-address (spec)

Author: spec-drafter (reviewed by JunBeom Lee). Status: accepted.
Intent: [intent.md](intent.md)

Redraft note: this replaces the Maroo-centric first draft (local commit 35a50cf).
Eight user decisions of record (2026-09-07) are baked in as requirements, not
flagged, and a research-grounded revision (2026-09-08, MetaMask extension
13.49.0 / mobile 8.12.0 / ens-resolver-snap 1.2.0, source-verified) moved the
demo to Sepolia and added chain-parameterized resolution: the
personally-executed acceptance demo (R6), same-chain resolution and funds
(R9 and the removed-concerns section), the demo consumer stack and its record
discipline (R9), USDC as the demo asset with native ETH out of sweep scope
(R9, R10), the user-registered ENS root (Design, "Human ops"), the carried
resolver/gateway design (R1-R5), ENSIP-11 chain-specific records (R13), key
custody as an env-key-plus-rotation-runbook resolution (Design, "Key
custody"), and the full demo loop as the gate (R6, Design "Gate"). Residual
open questions are resolved with recommendations or listed in Concerns with
their class.

## Context: what already exists (load-bearing reuse)

The receive product already owns everything below the name layer. The `/names`
directory holds owner-signed records carrying the stealth meta-address plus the
v2 consumer pair; `@bongtu/core/stealth` owns the DKSAP derivation and the
CREATE2 leg (`portalSalt`/`create2Address`, parity-pinned against
`PortalFactoryBase.addressOf`); the pay page (`apps/pay-web`) derives fresh
destinations browser-side and announces BEFORE displaying (`src/lib/pay.ts`,
the four-step contract); the indexer records announcements first-write-wins on
the stealth address (`POST /portal/announce`), serves the attribution-free
public feed, and holds `portalPrivAddressOf`; the
`PortalPrivFactory`/`PortalPrivSweeper` pair sweeps funded destinations into
the consumer `depositPriv` family and emits the on-chain `Announced` recovery
event; `apps/sweeper` in `MODE=priv` proves the sweep on CPU snarkjs. Deploy
profiles exist for a no-arbiter stack: `DeployConsumerOnly.s.sol` (pool +
consumer modules, recorded as `deploy/addresses.consumer.<chainid>.json` +
`modules.consumer.<chainid>.json`) and `DeployPortalPriv.s.sol` (the factory
add-on). Owning docs: [docs/portal.md](../../../docs/portal.md),
[docs/indexer.md](../../../docs/indexer.md),
[docs/consumer.md](../../../docs/consumer.md),
[docs/security-model.md](../../../docs/security-model.md#stealth-receiving-the-portalreceive-edge).

What this spec adds is the name layer over that spine: an ENSIP-10 wildcard
resolver, a CCIP-Read gateway inside the indexer, and a demo consumer stack on
Sepolia that the resolved destinations sweep into, with mainnet as the
enumerated promotion step. No new cryptography, no new sweep path, no change
to any Maroo contract.

**Prior art and differentiation.** Fluidkey (`username.fkey.eth`) has run
exactly this resolution pattern (ENS CCIP-Read, fresh stealth address per
query) in production for over two years, at roughly $1B volume and ~28k users,
and an ENSIP standardizing it is in draft; per-query freshness is there
acknowledged as a trusted-gateway property that no protocol layer can enforce,
which is why R2/R4 pin it as gateway MUSTs backed by the evidence chain.
Fluidkey shares a BIP-32 viewing node with its gateway and lands funds in
counterfactual 1/1 Safes; it has NO shielded pool, so its privacy ends at
address unlinkability (amounts, balances, and all onward flow stay public).
bongtu's differentiator is what stands behind the name: the shielded pool
(amounts hidden from the moment of receive onward) and the auditable family.
Wallet reach is uneven and documented rather than assumed: MetaMask resolves
via its built-in ens-resolver-snap on every network, Rabby deliberately blocks
ENS sends (pay-page fallback), and Phantom resolves `.eth` but its CCIP-Read
support is unverified with negative lean (a canary resolution of
`test.offchaindemo.eth` is the cheap check, Human ops step 0).

## What the same-chain reframing removes

The first draft resolved on mainnet but held funds on Maroo, and two of its
concerns existed only because of that split. Review should see why they are
gone, not wonder where they went:

- **Old C2 (wrong-chain stranding) is gone.** The resolution answer and the
  funds now live on the same chain: the gateway derives every answer against
  the factory of the chain the query names (R13), so the resolved address is
  always a destination the sweeper serves on the chain the sender is on. What
  remains is only the generic hazard every EVM address has (a sender manually
  copying an address to some other chain), covered by one docs line.
- **Old C5 (custom-network resolution in MetaMask) is gone, and inverted.**
  Resolution is no longer mainnet-only knowledge: MetaMask's ens-resolver-snap
  resolves on every network, natively against Sepolia's own registry
  (eip155:11155111 is one of the snap's two hardcoded native chains), and
  cross-resolves everything else via mainnet. The demo therefore runs entirely
  on Sepolia for free; Tron stays parked under its own intent.
- **Old C7 (caching, was a measurement concern) is now source-verified fact**
  and moved into R6's wording: the extension holds a 60-second forward cache
  per (domain, chainId), scoped to the UI session (closing the popup clears
  it); mobile has no forward cache. Only a residual confirm-on-the-day note
  remains (Concern C7).

## Requirements

Traceability: R1, R5 come from Proposed outcome bullets 1-2 and the no-ETH
constraint; R2 from the Problem (a static mapping destroys the privacy) plus
decision 1; R3 from decision 1 (a MetaMask sender never announces); R4 from
bullet 3 and the availability-trust constraint; R6 from bullet 5 (falsifiable)
plus decisions 1, 2, and 8; R7 from Affected systems (same sweep spine) and
the intent's dedup question; R8 from bullet 4; R9 from decisions 2, 3, and 4;
R10 from the Constraints plus decisions 3, 4, and 7; R11 from the carried
family naming decision; R12 from decision 8 (the balance must be readable in
wallet-web for the demo to close); R13 from the measured MetaMask constraint
in the intent ("measure MetaMask behavior rather than assuming") plus the
chain-aware growth path the user originally asked for.

- **R1 (MUST) Wildcard resolution over the directory.** Every `/names` record
  carrying the full v2 shape (stealth meta + consumer pair, non-sentinel)
  resolves as `{label}.{root}.eth` from unmodified ENS-aware wallets, via
  ENSIP-10 wildcard resolution and ERC-3668 CCIP-Read, on the demo chain
  (Sepolia's own ENS registry) and later on mainnet at promotion. A missing,
  v1-only, or sentinel-cleared record does not resolve (fail closed, the same
  gate `POST /portal/announce` applies server-side). No per-name on-chain
  state exists.
- **R2 (MUST) Fresh destination per resolution.** Every resolution derives a
  fresh DKSAP destination from the record's public meta-address: two
  resolutions of the same name yield two different addresses, checkable live
  in MetaMask's send field. Freshness is a gateway-trust property no protocol
  layer enforces (the ENSIP draft thread records this), so every layer this
  spec controls refuses to present a reusable answer: the resolver contract
  stores no address, gateway HTTP responses are `Cache-Control: no-store`, and
  the signed response's validity window is at most 300 seconds (it bounds
  replay of one response, never authorizes reuse across resolutions).
  Wallet-side caches outside our control are bounded and documented (R6).
- **R3 (MUST) Announce before return.** The gateway records the announcement
  (ephemeralPub, viewTag, stealthAddr, attributed to the name) through the
  existing first-write-wins store BEFORE signing and returning the address,
  mirroring the pay page's announce-before-display contract: a MetaMask sender
  will never announce, so the issuer must. If the announce write fails for any
  reason (including the 409 duplicate), the resolution aborts and no address
  is returned. The returned address is the queried chain's `PortalPrivFactory`
  CREATE2 destination (not the raw stealth EOA), so a payment to it sweeps
  into the shielded balance through the existing, unchanged sweep path.
- **R4 (MUST) Verifiable, bounded responses.** Gateway responses are signed
  and expiry-bounded, and the resolver contract verifies signer and expiry
  on-chain in the CCIP callback before the wallet accepts the address. The
  gateway derives with a fresh ephemeral scalar and discards it (derive, never
  spend: the `POST /pay/{name}` posture). Every returned destination has a
  public announcement row the recipient's view key verifies via
  `scanStealthAnnouncement`; a signed response whose destination has no honest
  announcement, or whose announcement does not scan to the recipient's meta,
  is cryptographic evidence of gateway misbehavior. The gateway is
  availability-trust only: it can refuse service, and any redirection it
  attempts is detectable and attributable, never silent.
- **R5 (MUST) Gasless name issuance.** Obtaining a name is exactly the
  existing owner-signed `/names` registration: offchain, no ETH held by the
  user, no per-name transaction on any chain. Wildcard resolution makes every
  directory label a name with zero marginal on-chain cost.
- **R6 (MUST) The personally-executed acceptance demo, on Sepolia, free.** The
  gate is the user running the loop themself, per the decision of record
  ("메타마스크에서 ens로 보내고 임시 stealth 주소 나오고 거기에 transfer 하면 우리 봇이
  자동으로 sweep에서 내 private 계좌에 넣어주는거 까지 내가 직접 테스트 하고 싶어"): in
  MetaMask (extension 13.49.0+ with Sepolia selected, resolving natively
  against Sepolia's registry), type the full name into the send field and note
  the resolved address; close the popup or wait 60 seconds (the extension's
  forward cache is 60 s per (domain, chainId), UI-session scoped; mobile
  caches nothing) and resolve again: the two addresses differ. A within-60-s
  repeat serves the same payer the same answer, which is privacy-harmless
  (same sender, one payment). An Etherscan name-page refresh is the secondary
  freshness display (it re-resolves per load). Confirm both addresses appear
  on `GET /portal/announcements` and match the recipient's view-key scan; send
  Sepolia USDC to one; the sweeper bot (MODE=priv, CPU prover) sweeps it into
  the Sepolia demo pool unattended; the shielded balance shows in wallet-web
  pointed at the Sepolia indexer. Every leg that can run without a live chain
  is gated locally on anvil (Design, "Gate"); the Sepolia run itself is the
  human-executed acceptance, at zero cost.
- **R7 (MUST) One discovery and sweep spine.** Resolver-issued announcements
  ride the same store, feeds, uniqueness index, and attributed operator
  projection as pay-page issuances. The wallet receive view, the recipient's
  scan, and the sweeper consume them with no change; the recipient never needs
  to know which front door issued a payment. This resolves the intent's dedup
  question: one store, one first-write-wins index on the stealth address, a
  fresh scalar per issuance, no cross-path reconciliation to build.
- **R8 (MUST) Browser fallback.** Opening the product-branded form of a name
  in a browser lands on that name's pay page (`/p/{label}`), serving senders
  whose wallet or exchange resolves nothing (Rabby blocks ENS sends by
  design; Phantom's CCIP support is unverified), and the route senders use
  when the gateway is down (Concern C5). The mechanism ships in this slice;
  the domain itself is an ops prerequisite.
- **R9 (MUST) The Sepolia demo stack, beside the untouched Maroo pool.** A
  consumer stack deploys to Sepolia (chain 11155111): the `DeployConsumerOnly`
  profile (no arbiter key exists) plus a `PortalPrivFactory`, recorded as
  `deploy/addresses.consumer.11155111.json` +
  `deploy/modules.consumer.11155111.json` per the existing consumer record
  discipline, with the factory, resolver, and signer addresses added to that
  record by field name. The pool token is Circle's Sepolia USDC
  (faucet-funded; the address taken from Circle's published record at deploy
  time, recorded by field name, never transcribed from memory). Native ETH
  sent to a destination is out of sweep scope (R10, Concern C1). The live
  Maroo pool `deploy/addresses.450815.json` stays canonical and untouched;
  existing pay-web, portal routes, and sweep behavior are unchanged and their
  gates stay green. Deploy tooling is extended so the factory add-on works
  against the consumer record pair (Design, "The demo stack"). Mainnet (real
  name, real USDC, a few dollars of deploy gas at the measured ~0.05 gwei) is
  the promotion ladder in Human ops, not part of the demo gate.
- **R10 (MUST) Honest risk and trust posture in docs.** Shipped docs state:
  the contracts are unaudited, the demo runs on testnet funds, promotion to
  mainnet puts real value on unaudited contracts at self-test scale with
  documented demo caps, and an audit precedes anything beyond that; the
  gateway operator sees every resolution query (sender IP, name, timing)
  BEFORE any payment exists; it can censor; redirection is detectable, not
  preventable; the per-payment amount is public twice; only the pool's ERC20
  (USDC) is swept, and ETH sent to a destination is stranded under the
  shipped contracts (Concern C1 wording); wallet support is a documented
  matrix (MetaMask verified, Rabby blocked, Phantom unverified), not a claim.
- **R11 (MUST) Family naming.** The new pieces take PortalPriv family names
  (the portal/PortalPriv precedent): same mechanism, same name family, no
  divergent product codenames in code or records.
- **R12 (MUST) True amounts in the demo UI.** wallet-web (and the pay page
  where it renders amounts) displays the demo pool's token with its own
  symbol and decimals (USDC, 6), configurable rather than hardcoded to the
  18-decimal kKRW edge, so the demo balance reads as the amount actually
  sent. No change to the Maroo-pointed defaults.
- **R13 (MUST) Chain-parameterized resolution via ENSIP-11.** The gateway
  serves chain-specific address records: MetaMask requests the SELECTED
  chain's coinType (`0x80000000 | chainId`) first and accepts a hit with no
  code check (contract addresses allowed), while its mainnet coinType-60
  fallback applies a mainnet EOA guard; the gateway therefore derives every
  answer against the `PortalPrivFactory` of the chain the queried coinType
  names, and never relies on the coinType-60 fallback for a non-mainnet funds
  chain. A coinType with no recorded factory returns the empty answer and
  mints no announcement. This is also the growth path that resolves the
  user's original chain-aware wish: adding a funds rail (mainnet at
  promotion, later Arbitrum or Maroo) is deploying that chain's consumer
  stack + factory and adding its coinType to serving, with no resolver or
  name change.

## Design

### Name root and ENS wiring

An owned ENS second-level name with ENSIP-10 wildcard subdomains, registered
by the user (the concrete label is pending; everything below is parameterized
on `{root}.eth`). The demo registers it on Sepolia's ENS (the ENSv2 Sepolia
beta, free); promotion registers the real `.eth` 2LD on mainnet. ENSv2's L2
plans were cancelled (2026-02), so mainnet L1 stays the resolution anchor and
the first draft's rationale against DNSSEC import stands: one registration,
no DNSSEC maintenance, and wildcard + one `setResolver` gives every directory
label a name at zero per-name cost (R5).

The `.frx` rendering is branding on top: no wallet resolves `.frx`, so the
canonical wallet-typed form is `{label}.{root}.eth` and the product renders
`{label}.frx` in its own UI only. The browser fallback (R8) is a DNS wildcard
on a product-owned DNS domain redirecting `{label}.<domain>` to the pay
page's `/p/{label}`: plain hosting, no ENS machinery.

### Resolver contract: `PortalPrivResolver`

A small ENSIP-10 extended resolver in `chains/evm/src`, following the ENS
offchain-resolver reference pattern (pre-deployed CCIP resolver tooling on
Sepolia, e.g. the ezccip.js TOR line, is prior art to compare against, not a
dependency):

- `resolve(bytes name, bytes data)` reverts `OffchainLookup` with the gateway
  URL and the request; `supportsInterface` advertises the extended-resolver
  interface.
- `resolveWithProof` verifies the gateway signature over (resolver address,
  expiry, request hash, result hash) against the owner-set signer, rejects
  expired responses, and returns the result. This is the whole R4 on-chain
  half: signer binding plus bounded validity.
- Owner-settable signer and URL list (rotation without redeploying); no name
  data, no address storage (R2's on-chain half).

It deploys to Sepolia for the demo (recorded in
`deploy/addresses.consumer.11155111.json` beside the stack it serves; the
root name's resolver on the Sepolia registry is set to it) and to mainnet at
promotion with its own record.

### Gateway: indexer routes in the portal family

The gateway is a set of new routes in `apps/indexer`, not a standalone
service: issuance needs the names store, the portal store's atomic
first-write-wins index, and `portalPrivAddressOf`, all of which the indexer
holds in-process. Route naming stays in the portal family (R11), e.g.
`GET/POST /portal/resolve/{sender}/{data}.json` in the CCIP-Read wire shape.
New env: the response signer key (never logged, never returned, the
`AUTHORITY_KEY` handling posture) plus the resolver address for the
signed-payload binding.

Per resolution, the gateway mirrors the pay page's four-step issuance
contract with itself in the visitor's role, against the priv pair
server-side (the `handlePayPortal` shape):

1. decode the ENSIP-10 request: DNS-decode the wildcard name, take the first
   label, apply the directory grammar plus ENSIP-15 normalization (fail
   closed on non-conforming labels); only `addr` profiles are served, and the
   coinType selects the funds chain (R13): the ENSIP-11 coinType of each
   chain with a recorded factory (Sepolia `0x80000000 | 11155111` for the
   demo), plus legacy `addr(node)`/coinType 60 once mainnet is promoted;
   any other profile or unserved coinType returns the empty answer and never
   mints an announcement;
2. resolve the label in the names store; fail closed unless the v2 record is
   complete (R1);
3. derive a fresh destination server-side and let the scalar go out of
   scope; write the attributed announcement through the same `portal.issue`
   first-write-wins path the announce route uses, and derive the destination
   via `portalPrivAddressOf` against the queried chain's factory (R3, R13):
   any failure aborts the resolution;
4. sign (expiry at most 300 s) and return, `Cache-Control: no-store`
   (R2, R4).

MetaMask's send field debounces input by 500 ms with an AbortController, so
typing does not fan out into per-keystroke resolutions (a measured moderator
of the row-minting surface, Concern C3).

### Verification and evidence chain (R4)

Three checks compose the "cannot steal undetected" bound. The resolver's
signature check pins every accepted answer to the gateway signer and a
validity window, so a redirecting answer is non-repudiable evidence in the
sender's hands. The announce-before-return rule means every honest answer has
a public announcement row; the recipient's view key audits the feed
continuously for free (its normal scan). A compromised gateway that skips
announcing or derives off-meta produces exactly the detectable signature: a
signed destination absent from the feed, or a row no view key claims. Docs
state plainly that detection is after the fact; prevention is not claimed
(R10), matching the ENSIP thread's conclusion that freshness and honesty are
gateway-trust properties.

### The demo stack (R9): Sepolia, free

- **Pool + modules**: `DeployConsumerOnly` with `TOKEN_ADDRESS` set to
  Circle's Sepolia USDC; writes `deploy/addresses.consumer.11155111.json` +
  `modules.consumer.11155111.json` unchanged.
- **Factory add-on, tooling delta**: `DeployPortalPriv.s.sol` today reads the
  enterprise `AddressBook` record (`deploy/addresses.<chainid>.json`) and
  `deploy/modules.<chainid>.json`, neither of which exists on this profile.
  It learns the consumer record pair (or gains a consumer variant, plan's
  call), keeps its rerun guard (a second factory strands every announcement
  issued against the first), and records `portalPrivFactory` into
  `addresses.consumer.11155111.json`.
- **Indexer**: a public HTTPS instance in plain (non-arbiter) mode,
  `CHAIN_ID=11155111`, a Sepolia RPC (`LOG_CHUNK` tuned for rate-capped
  public RPC per its README), `POOL`/`PORTAL_PRIV_FACTORY` from the consumer
  record, the names store, the gateway routes, and the signer key env. No
  `AUTHORITY_KEY` exists in this deployment: the consumer-only pool has no
  arbiter at all.
- **Sweeper**: `MODE=priv`, CPU prover, env-pointed at the Sepolia record
  (`CHAIN_ID`, `POOL`, `FACTORY`, `MODULE`, `TOKEN` explicit; the demo runs
  on explicit env, no default-path change required), `MIN_SWEEP` set to a
  demo dust threshold in USDC base units, and a faucet-funded bot key (its
  `/health` already alarms on a zero gas balance).
- **wallet-web + pay-web**: configuration to point at the demo indexer,
  chain, and factory, plus the token symbol/decimals knob (R12). The
  canonical Maroo pins in `packages/core/src/chain/network.ts` are not
  edited; the demo is a configuration, not a retarget.

USDC notes: 6 decimals (base units flow through pool, proofs, and feeds
unchanged; only display needs R12); the standard `approve`/`transferFrom`
surface the sweeper already drives; each sweep approves exactly `pub[0]` and
the pool pulls exactly that, so the allowance returns to zero and repeat
sweeps hold.

### Key custody (resolved, per decision of record)

Three keys, all held by the user: the gateway signer (env var on the indexer,
handled under the `AUTHORITY_KEY` rules: never logged, never served), the
name-owner key (controls `setResolver` on the root), and the sweeper bot key
(factory owner, gas-funded on the serving chain). A leaked signer signs
redirections (detectable per R4) until rotated; the rotation runbook, a
`setSigner` from the resolver owner plus an env swap, ships in
`deploy/README.md` as part of this slice. This is the resolution of the first
draft's custody concern, not an open item.

### What does not change

Sweep contracts, discovery, the receive view, feeds, and the pay page are
untouched (R7, R9). A resolver-issued row is a pay-page row with a different
writer: same attribution split, same operator token gate, same `Swept` flip,
same on-chain `Announced` recovery event at sweep time. `POST /pay/{name}`
(enterprise pair) and `POST /portal/announce` (browser derivation) keep their
existing contracts. The Maroo deployment serves exactly what it serves today.

### Gate

Automated, on anvil and forge, per iteration: (a) two gateway calls for one
name return two destinations, both parity-correct against the local CREATE2
mapping and both recorded on the public feed before the response was signed;
(b) a forced announce failure yields no signed response; (c)
`resolveWithProof` accepts a fresh gateway-signed fixture and rejects expired
and wrong-signer ones (forge); (d) a gateway-issued destination, funded on
anvil, sweeps to a consumer note via the existing `portal_priv_leg`
machinery; (e) the consumer-record deploy path (`DeployConsumerOnly` + the
factory add-on against the consumer record pair) runs end to end on anvil;
(f) coinType routing: the served chain's ENSIP-11 coinType answers, an
unserved coinType returns empty and mints nothing (R13). The Sepolia loop
itself is the human-executed acceptance (R6), run by the user at zero cost.

### Human ops (explicit, per the decision of record)

Named here because no PR can perform them; all keys are the user's. The demo
rung is free; the promotion rung is where real money starts.

Step 0, before any deploy: canary-resolve `test.offchaindemo.eth` in the
wallets that matter (Phantom especially) to measure CCIP-Read support for
free; record the result in the wallet-support matrix (R10).

Demo (Sepolia, free):

1. Register the root name on Sepolia ENS (ENSv2 Sepolia beta).
2. Deploy the demo stack: `DeployConsumerOnly` (Sepolia USDC), the factory
   add-on, and `PortalPrivResolver`; commit the consumer record pair.
3. `setResolver` on the root name (Sepolia tx from the name owner).
4. Host the indexer/gateway publicly over HTTPS at the URL baked into the
   resolver, signer key provisioned in its env (shape: Concern C6).
5. Fund the sweeper bot key from a Sepolia faucet and run it (MODE=priv).
6. Point the product DNS domain's wildcard at the pay page (R8).
7. Run the R6 demo loop personally.

Promotion (mainnet, the ladder after the demo passes; posture per R10 and
Concerns C1/C4): register the real `.eth` 2LD; deploy the consumer stack +
factory + resolver to mainnet (a few dollars at the measured ~0.05 gwei);
record `deploy/addresses.consumer.1.json`; add mainnet coinType-60 and
ENSIP-11 serving (R13); fund the mainnet sweeper key; re-run the loop with
real USDC at self-test scale.

## Non-goals

- No on-chain subdomain issuance, NameWrapper, or per-user ENS records; names
  are offchain directory rows resolved by wildcard.
- No DNSSEC-imported root (recorded alternative, not re-proposed).
- No ENS contenthash / decentralized-site serving; the browser fallback is a
  DNS redirect.
- No Tron (parked under its own intent) and no non-EVM resolution; the
  multi-rail growth path in R13 is EVM coinType serving only.
- No native-ETH sweep path: the pool wraps one ERC20 and the demo asset is
  USDC (the stranding fact is Concern C1, its docs wording R10).
- No operator blindness: the gateway operator sees queries and the mapping it
  serves, honestly excluded from the claim as before (OMR/TEE class work
  stays out of scope). No Fluidkey-style gateway key sharing either: the
  gateway holds no viewing material, only public meta-addresses.
- No fee model, no multi-gateway redundancy, no query-privacy machinery (C2).
- No promotion beyond self-test scale on mainnet, and no audit in this slice;
  audit precedes anything beyond self-test (R10).
- No change to sweep economics, the pay page flow, or any Maroo contract.

## Concerns

Flagged for the human gate; class per the intent-chain rule (blocker =
security model, live deployments, user harm; judgment = policy and product
calls).

- **C1 (BLOCKER, user harm, binds at mainnet promotion): non-USDC assets sent
  to a destination are permanently stranded, and the "recover later with
  derived keys" assumption is false as stated.** The resolved address is the
  factory's CREATE2 contract address, not the stealth EOA: derived stealth
  keys control the EOA, never the destination. The shipped sweeper family is
  ERC20-only with no payable path (`PortalSweeperBase` /
  `PortalPrivSweeper`), the factory deploys only that initcode, and the
  factory is not upgradeable, so ETH (or any non-pool token) landing at an
  undeployed destination has no recovery path under the shipped contracts;
  after deployment the sweeper at least rejects plain ETH transfers. MetaMask
  makes an accidental ETH send to a resolved name easy. Faucet-scale on the
  Sepolia demo; the posture decision (docs warning wording, whether a future
  factory variant with a native/any-token sweep is named as a follow-up) must
  land before the mainnet rung. Cite the residual-gaps style of
  [docs/security-model.md](../../../docs/security-model.md) when recording
  it.
- **C2 (judgment, recorded posture): query privacy.** The gateway sees sender
  IP, name, and timing at resolution, BEFORE any payment exists: a strictly
  earlier signal than the pay page's. Recommendation: no mitigation ships
  this slice; the posture is stated in docs (R10) and OMR/TEE-class work
  stays the named exclusion.
- **C3 (judgment, abuse surface): resolution-driven row minting.** Every
  served `addr` resolution mints an attributed announcement row through an
  unauthenticated public endpoint. MetaMask's 500 ms debounce moderates
  keystroke volume, but any resolving surface mints rows: an Etherscan
  name-page refresh is a public, scriptable mint trigger. The recorded
  posture (rows are hints, the bot sweeps only funded addresses, rate
  limiting is ops) is recommended to carry unchanged; confirm it holds for
  these triggers.
- **C4 (judgment, exposure posture, scoped to the mainnet rung): the promoted
  stack takes real third-party money.** On Sepolia this dissolves (faucet
  funds). Once the mainnet name resolves publicly, anyone who learns it can
  send real USDC into unaudited contracts, not just the user self-testing.
  Recommendation: keep the mainnet root unadvertised during the self-test
  window, document the demo caps and posture (R10), and treat the audit as
  the gate for anything beyond.
- **C5 (judgment, availability posture): the name fails closed when the
  gateway is down.** CCIP-Read has no offline fallback: a dead gateway makes
  every `{label}.{root}.eth` unresolvable until it returns. Recommendation:
  accept for the demo (single instance), document the pay page as the sender
  fallback (R8), and leave multi-gateway redundancy a named non-goal.
- **C6 (judgment, ops shape): public hosting of the indexer/gateway.** The
  demo needs the indexer publicly reachable over HTTPS (MetaMask's snap
  fetches the gateway URL directly) with Postgres, a Sepolia RPC, and the
  signer key in env; the existing indexer hosting pattern is the natural
  shape, but where it runs, TLS termination, and uptime expectations are ops
  decisions outside the repo. Enumerated in Human ops step 4; needs the
  user's hosting choice before the live steps run.
- **C7 (minor, residual confirm): wallet caching on the day.** The 60 s
  extension cache / no mobile cache facts are source-verified against
  extension 13.49.0 / mobile 8.12.0 / snap 1.2.0; confirm behavior on the
  versions actually installed when running R6, and record any drift with the
  run.
- **C8 (minor): label normalization edge.** ENSIP-15 forbids labels the
  directory grammar admits (e.g. hyphens in positions 3 and 4); the gateway
  normalizes and fails closed, leaving such labels pay-page-only. Note in
  docs.
- **C9 (minor, repo hazard): dependencies.** The resolver needs the small ENS
  interface set (vendor or minimal dep); any lock-touching install follows
  the CLAUDE.md package-lock regen rule.

## Docs debt

- [docs/portal.md](../../../docs/portal.md): a payment-name section (the
  third front door: resolver issuance beside pay-page and depositor flows,
  announce-before-return, the demo stack and the promotion ladder, the
  wallet-support matrix).
- [docs/security-model.md](../../../docs/security-model.md): the gateway
  operator row in the receive who-sees-what table (query visibility,
  censor-not-steal, the signed evidence chain), the unaudited-contracts
  posture per rung, and the stranded-asset warning per C1's resolution.
- [docs/indexer.md](../../../docs/indexer.md): the gateway routes in the HTTP
  API table, the signer env, coinType serving, the resolution-minted row
  posture.
- [docs/deployment.md](../../../docs/deployment.md) + `deploy/README.md`: the
  Sepolia target and consumer record extensions, the ENS wiring runbook, the
  signer rotation runbook, the mainnet promotion runbook.
- `chains/evm/README.md`: the resolver contract. `apps/indexer/README.md`:
  env and route deltas. `apps/sweeper/README.md`: the Sepolia/USDC env
  shape. `apps/pay-web/README.md`: the fallback-domain origin note.
  `apps/wallet-web/README.md`: the token symbol/decimals knob.
- Root `README.md`: system map and What-is-built rows for the name layer and
  the demo stack.

Status: accepted
