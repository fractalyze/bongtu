# Stealth payment receiving on Maroo: pay page to shielded balance — spec

Author: spec-drafter (reviewed by JunBeom Lee). Status: accepted.
Intent: [intent.md](intent.md)

Auto-mode note: concerns triaged with the user 2026-09-06; resolutions are recorded
inline below. The user OVERRODE the drafter's zero-deployment recommendation on the
sweep family: swept funds enter the CONSUMER family (`depositPriv`) via a NEW standalone
receive factory/sweeper pair, which also carries the sweep-time on-chain announcement.
R5/R8 and the Design sections are updated to the decided shape; the pool itself stays
untouched either way.

## Context: what already exists (load-bearing reuse)

The intent's spine is largely built, facing the other direction. `@bongtu/core/stealth`
owns the dual-curve DKSAP derivation (meta-address = bjj `viewPub` + secp256k1
`spendPub`), the announcement predicate, and the portal CREATE2 leg
(`portalSalt`/`create2Address`, parity-pinned against `PortalFactory.addressOf`).
`PortalFactory` + `PortalSweeper` (deployed on 450815: `portalFactory` in
`deploy/addresses.450815.json`, copy by field name) turn a plain kKRW transfer into a
pool deposit; `apps/sweeper` watches `/portal/unswept`, proves the deposit, and sweeps.
The indexer holds the `/names` directory (owner-signed records carrying the stealth
meta plus the optional v2 consumer pair `noteViewPub`/`kemEk`), the issuance route
`POST /pay/{name}` (server-side derivation, announcement recorded at issuance), and the
portal feeds. `apps/wallet-web` (consumer wallet) already has a Receive screen doing v2
registration, and self-scan discovery. `deploy/gates/portal_leg.ts` proves the
pay→sweep→notes loop end to end. Owning docs: [docs/portal.md](../../../docs/portal.md),
[docs/indexer.md](../../../docs/indexer.md), [docs/consumer.md](../../../docs/consumer.md),
[docs/wallet.md](../../../docs/wallet.md).

What is missing, and what this spec covers: a sender-facing hosted pay page
(today issuance is inside the recipient's own wallet — depositor-facing), browser-side
derivation, an attribution-free discovery channel (today's public portal feeds expose
`name`/`owner` per payment), a per-payment receive view with status, rail-extensible
wire shapes, and the unlinkability gate.

## Requirements

Traceability: R1–R2 ← Proposed outcome bullet 1; R3 ← bullet 2 + Constraints; R4–R5 ←
bullet 3; R6 ← bullet 4; R7 ← bullet 5; R8 ← Constraints (live pool); R9 ← Constraints
(third-chain); R10–R11 ← Constraints (trust posture) / Problem (existing machinery is
depositor-facing and must keep working).

- **R1 (MUST) Registration.** A consumer recipient can register a receive identity —
  stealth meta-address plus the v2 consumer pair — from the consumer wallet, and
  obtains a stable per-recipient pay-page URL. All private scalars come from the
  existing wallet-signature KDFs (`client-evm` stealth KDF; the consumer triple's one
  signature) under the existing memory-only custody rule; registration introduces no
  new key-persistence surface.
- **R2 (MUST) Pay page.** A hosted static page at the per-recipient URL. Each load
  derives a FRESH stealth destination **in the visitor's browser** from the record's
  public keys plus a locally drawn ephemeral scalar (`@bongtu/core/stealth` — no
  server-held secret participates in the address computation), records the
  announcement **before** displaying the address, and shows the payment coordinates:
  chain, token, destination address, QR. The page is read-only for the visitor — no
  wallet connection, no signature, nothing persisted.
- **R3 (MUST) Zero sender software.** The payment is a plain kKRW ERC-20 transfer to
  the displayed address, valid from any stock wallet or a CEX withdrawal: no approve,
  no contract call, no bongtu code on the sender's side. (Already the portal property;
  this requirement pins it against regression.)
- **R4 (MUST) Discovery without attribution.** Every issuance is discoverable by the
  recipient's client holding only its view key, via a cursor feed
  (`scanStealthAnnouncement` over `(ephemeralPub, viewTag)`). Publicly served
  announcement records carry **no recipient attribution** (no name, no owner pubkey);
  the owner mapping the sweeper needs is confined to operator-side surfaces. The
  announce write path dedupes on stealth address, first write wins.
- **R5 (MUST) Sweep to shielded, consumer family.** A funded destination is swept into
  the live pool by the operator bot **through the consumer `depositPriv` path**, minting
  no-auditor notes owned by the recipient's registered consumer keys — the operator's
  arbiter cannot open the entry note (decided at the human gate, overriding the
  zero-deployment enterprise-entry recommendation). This requires the NEW receive
  factory/sweeper pair (R8). The sweep transaction also EMITS the announcement on-chain
  (ephemeralPub + viewTag in the event), so every swept payment is recoverable from
  chain data alone. A second payment to the same destination re-sweeps. Balances below
  a configured dust threshold are left unswept and remain visible as
  received-but-unswept.
- **R6 (MUST) Receive view.** The consumer wallet lists per-payment rows — fresh
  address, amount, status `received → swept → shielded` — derived from the recipient's
  own scan of the discovery feed, the `Swept` flip, and its note discovery. No arbiter
  read is on this path.
- **R7 (MUST) Unlinkability gate.** An automated gate: one recipient, two payments from
  two distinct sender EOAs via two pay-page issuances. Asserts (a) the two destinations
  differ; (b) no on-chain datum common to the two payment transactions correlates them
  with each other or with the recipient's registered identity (recipient keys appear in
  no calldata/log in the clear; sweep transactions carry the owner only inside
  ciphertext); (c) the public discovery feed serves no attribution (R4); (d) both
  payments end as shielded notes the recipient's client scan discovers (R6).
- **R8 (MUST) Live-pool reuse; new standalone receive pair.** Pool `0x3B6238…1aD6` on
  450815 is reused as-is: no circuit change, no UUPS upgrade, no pool-touching
  transaction. The receive product ships a NEW standalone `ReceiveFactory`/sweeper pair
  (naming in plan) targeting the live `depositPrivModule`, with the sweep-time
  announcement event; the EXISTING `portalFactory` and its depositor-facing flow are
  untouched (R11). The new pair's 450815 deployment is a one-command HUMAN step
  (runbook + record field shipped in this slice; the gate proves the pair on anvil).
- **R9 (MUST) Rail extensibility.** The registration record and the pay-page wire
  shapes carry an explicit rail/address flavor (or a version field that admits one)
  so `stealth-receive-tron` can reuse them with a different address encoding. No
  non-EVM code ships here.
- **R10 (MUST) Honest trust posture in docs.** The shipped docs state: on-chain
  unlinkability is the claim; the pay-page/indexer operator sees the mapping it serves
  (it issues the URLs and stores the announcements); the sweep's redirection-resistance
  rests on the operator bot key (the recorded portal v1 concession); and the
  per-payment amount is public twice (the plain transfer, and the deposit's public
  `pub[0]`) — what is shielded is note ownership, the aggregate balance, and all
  onward flow.
- **R11 (SHOULD) No regression of the depositor-facing portal.** `POST /pay/{name}`,
  the treasury-web Receive panel, and the existing sweep loop keep working; the e2e
  portal leg stays green.

## Design

### Entry: per-recipient URL over the existing directory

The pay-page URL is keyed by the recipient's `/names` directory record
(`/p/{label}` on the pay host). The directory already exists, is owner-signed, and its
label grammar was deliberately shaped for a later name layer — this slice adds **no**
resolver, ENS/CCIP, or naming UX; the `payment-name` intent builds those on the same
records. A recipient who wants an opaque URL registers an opaque label. (Concern C8.)

### Pay page: a new minimal static app

A fourth static web app (working name `apps/pay-web`; Vite, Vercel, same `/indexer`
rewrite pattern as the other apps). Flow per load: `GET /names/{label}` → validate the
record (meta + consumer pair present) → draw an ephemeral scalar
(`randomEphemeralScalar`) → `portalAddress(factory, initCodeHash, meta, r)` in the
browser → announce (below) → render address + QR + chain/token facts. Factory address
and `sweeperInitCodeHash` come from `@bongtu/core/network` / an `eth_call`, so the page
computes the same destination the factory would. The ephemeral scalar dies with the
page; the page holds no other secret. It ships no wallet code and no proving code
(nothing heavier than `@bongtu/core` + a QR encoder — see Concern C7).

### Announcement channel (recommendation; decision flagged C2)

Three candidate shapes, evaluated:

1. **On-chain ephemeral-pubkey log at issuance** — self-sovereign scan, but someone
   must pay gas per page-visit and the visitor cannot be asked; a bongtu-funded
   announcer reintroduces our infra anyway, plus gas per visit (not per payment —
   issuances that never get paid still cost). Rejected for this slice.
2. **Indexer-served announcements** (extend the existing portal record store) — cheap,
   machinery exists; scan depends on our infra. **Recommended for this slice.**
3. **Derive announcements from the payment tx itself** — impossible under R3: a plain
   ERC-20 transfer carries no ephemeral pubkey and nothing recipient-derived; ruled
   out, recorded here so it is not re-proposed.

The self-sovereign middle path — emit the announcement on-chain **at sweep time** (the
bot already pays sweep gas; `sweep` carries `ephemeralPub`/`viewTag` and the contract
logs them) — IS built in this slice: the human gate resolved the sweep family to a new
factory/sweeper pair anyway (C1), so the announcement event rides the same contracts at
marginal cost. Result: indexer-served announcements are the DISPLAY path (instant, at
issuance), the sweep event is the RECOVERY path (chain-only, for every swept payment).

Concretely for shape 2, the indexer gains one route: `POST /portal/announce` with
`{ label, ephemeralPub, viewTag, stealthAddr }`. The server recomputes
`destination = addressOf(portalSalt(stealthAddr))` itself (never trusts a client
destination), resolves the label to the owner record at write time, and **rejects a
`stealthAddr` already recorded** (first write wins). Because the page announces before
it displays the address, a hijacker who re-announces an observed destination under its
own label always loses the race — the honest record already exists. The route is
unauthenticated like `POST /pay/{name}` (the recorded PoC spam posture; garbage
announcements never match any view key and never get funded). Server-side issuance
(`POST /pay/{name}`) remains for the depositor-facing wallet flow (R11).

### Feed attribution split (R4)

Today `GET /portal/announcements` and `/portal/unswept` publicly serve
`{ name, owner, … }` — acceptable when the only consumer was the recipient's own
wallet, a public identity→payment mapping under the receive framing. Change: the
public projections drop `name`/`owner` (serving
`{ seq, ephemeralPub, viewTag, stealthAddr, destination, createdAt, swept,
sweptTxHash, sweptAmount }`); the owner-attributed projection moves behind an
operator-facing surface for the sweeper (mechanism — shared-token gate vs
operator-internal route — flagged C3). The recipient does not need attribution: its
view key re-derives which records are its own.

### Sweep and note family (DECIDED: consumer entry, new pair)

The human gate chose the consumer path: a new standalone factory/sweeper pair whose
sweep proves a **`depositPriv`** against the live `depositPrivModule`, minting
no-auditor consumer notes to the recipient's registered consumer keys — "no one can
open it, operator included" holds from the entry note onward, matching the product's
privacy posture. The pair also logs the sweep-time announcement (above). The existing
enterprise portal pair keeps serving the depositor-facing flow unchanged (R11); the
two coexist, with the new pair recorded under its own addresses field. Sweeper-bot
deltas: consume the operator-side unswept feed, apply the dust threshold (`MIN_SWEEP`
env; below it, skip), keep full-balance unbatched sweeps and no fee model (recorded
PoC posture, C5). The pair's anvil deployment is gate-proven; 450815 deployment is the
human runbook step (R8).

### Receive view (consumer wallet)

Wallet-web's Receive screen (registration exists) gains the payments list: scan the
public discovery feed with the view key → own issuances; destination token balance or
transfer logs → `received`; the record's `Swept` flip → `swept`; the note surfacing in
the wallet's self-scan → `shielded`. All reads are public endpoints, preserving the
consumer wallet's tokenless/no-arbiter contract.

### Wire-shape extensibility (R9)

The announce/record shapes and the pay-page's record consumption gain an explicit
`rail` (or versioned flavor) field defaulting to the EVM flavor; `StealthMetaAddress`
itself stays curve-typed as-is (secp256k1 spend keys cover Tron too; only the
address/salt encoding is rail-specific, which is exactly what the flavor selects).

### Gate (R7)

A new gate leg beside `portal_leg.ts` (anvil + real indexer + sweeper-as-library, same
harness): register a recipient, two browser-shaped issuances (the pay-page derivation
called headlessly), two plain transfers from two distinct funded EOAs, two sweeps, then
the R7 assertions, including a negative scan: grep the two payment txs' calldata/logs
and the public feed body for the recipient's registered keys and label. Runs in the
heavy tier with the existing e2e.

## Non-goals

- No name layer: no resolution UX, no ENS/CCIP gateway, no name marketing surface
  (`payment-name` intent). The directory is reused, not extended with naming features.
- No Tron/third-rail code (`stealth-receive-tron` intent); only the wire shapes admit it.
- No sender-side software of any kind, including "optional" sender tooling.
- No fee model, sweep batching, or gas-abstraction economics beyond the dust threshold.
- No contract or circuit changes in the recommended shape; no pool transaction of any
  kind on 450815.
- No operator-blindness claim: making the pay-page operator unable to see the mapping
  (OMR/TEE class work) is out of scope and stays honestly excluded from the claim.
- No changes to the enterprise/depositor-facing portal flow beyond the feed
  attribution split.

## Concerns

Flagged for the human gate; blockers per the intent-chain rule (security model, live
pool, live deployments).

- **C1 (BLOCKER — security model + live chain): which deposit family receives swept
  funds.** Recommended: enterprise `deposit` via the deployed sweeper — zero live
  deployments, but the entry note is arbiter-openable, a real delta from the consumer
  family's "no one can open it" posture
  ([docs/security-model.md](../../../docs/security-model.md#the-consumer-family-no-auditor-ops)).
  Alternative: sweep via the live `depositPrivModule` — consumer-family entry notes,
  but the sweeper contract's hardcoded enterprise arity forces a new
  `PortalSweeper`/`PortalFactory` deployment on 450815 (standalone, pool untouched —
  precedented by the original factory deploy, still a live-chain deployment decision).
  The spec recommends enterprise-entry for the tracer bullet with the consumer-entry
  factory as the named follow-up; the human gate picks.
  **RESOLVED (user, 2026-09-06): consumer entry via a NEW standalone factory/sweeper
  pair. The privacy posture ("operator cannot open it") outweighs the deployment cost;
  the 450815 deployment is a human runbook step, the pool is untouched, and the old
  pair keeps the depositor-facing flow. R5/R8/Design updated.**
- **C2 (BLOCKER — trust surface): announcement channel.** Recommended shape 2
  (indexer-served) makes payment discovery depend on operator infrastructure: a dead or
  hostile indexer can hide payments (never redirect them — the sweep still mints to the
  registered owner, and a funded-but-hidden address is recoverable once any honest feed
  serves the record). The sweep-time on-chain announcement restores chain-only recovery
  for swept payments but joins C1's deployment decision. Cite
  [docs/security-model.md](../../../docs/security-model.md) residual-gaps posture when
  recording the choice.
  **RESOLVED (user, 2026-09-06): BOTH — indexer-served announcements for instant
  display, sweep-time on-chain events (riding the C1-decided new pair) as the
  chain-only recovery path for every swept payment. A dead or hostile indexer can
  delay discovery of unswept payments but cannot erase swept ones.**
- **C3 (BLOCKER — security model): un-publishing the attribution.** R4 removes
  `name`/`owner` from public portal feeds — a wire-contract change to surfaces
  documented in [docs/indexer.md](../../../docs/indexer.md) — and needs a mechanism
  for the sweeper's owner-attributed feed (shared operator token vs internal-only
  route). This is the serving surface of the unlinkability claim itself; the mechanism
  needs an explicit human decision. Note the existing deployed treasury-web reads
  `getPortalAnnouncements` shapes (compat check owed in plan).
  **RESOLVED as an obligation: attribution comes off the public projections; the
  sweeper's owner-attributed feed moves behind a shared operator token (the existing
  indexer auth pattern), exact mechanism confirmed in plan with the treasury-web
  compat check.**
- **C4 (MAJOR — abuse surface): client-posted announcements.** Moving derivation into
  the visitor's browser means the indexer records announcements it cannot verify
  against the meta-address (verification needs a secret). Mitigations specced:
  server-recomputed destination, first-write-wins dedupe on `stealthAddr`,
  announce-before-display ordering. Residue: the unauthenticated spam surface widens
  from `POST /pay/{name}` to the announce route (same recorded PoC posture). Confirm
  the posture still holds for a public-facing pay page (rate limiting is ops, not
  spec).
  **RESOLVED: posture confirmed for the tracer bullet with the specced mitigations
  (server-recomputed destination, first-write-wins, announce-before-display); rate
  limiting recorded as ops.**
- **C5 (MAJOR — economics/policy): sweep economics.** The operator bot pays all sweep
  gas (who funds the bot key on Maroo is an ops decision); full-balance unbatched
  sweeps; dust threshold value and its UX (a below-dust payment shows `received`
  indefinitely) need a policy call; no fee model means the operator eats unbounded gas
  for spam-funded portals.
  **RESOLVED: operator-pays with `MIN_SWEEP` dust threshold for the tracer bullet;
  the fee model is a named follow-up, not this slice.**
- **C6 (MAJOR — app topology): where the pay page and registration live.** The spec
  puts registration + receive view in `apps/wallet-web` (its Receive screen already
  registers the v2 triple) and the pay page in a NEW static app. The
  consumer-wallet-split intent is drafted but NOT accepted — this spec must not
  presuppose it; a new Vercel project (env, rewrites, `ignoreCommand`) is also an ops
  surface the human should confirm.
  **RESOLVED (user, 2026-09-06): pay page = new minimal app `apps/pay-web` with its
  own Vercel project (the consumer URL beachhead); registration + receive view stay
  in wallet-web for this slice.**
- **C7 (MINOR — repo hazard): new dependency.** The pay page needs a QR encoder (and
  nothing else new). Any lock-touching install must follow the CLAUDE.md
  package-lock regen rule (Vercel `npm ci` rejects a casually regenerated lock).
- **C8 (MINOR — scope boundary): URL key = directory label.** Reusing `/names` labels
  as the per-recipient URL key builds no name machinery but does make labels
  user-visible in URLs; confirm this does not pre-empt a `payment-name` design choice
  (e.g. label grammar or a separate opaque id space).
- **C9 (MINOR — docs gap, pre-existing):**
  [docs/security-model.md](../../../docs/security-model.md) has no portal/stealth
  section at all today; the portal trust concession lives only in docs/portal.md and
  the contract headers. R10's who-sees-what row for the pay-page operator lands there
  (tracked in Docs debt).
- **C10 (MINOR — claim precision): "amount shielded".** The intent's outcome wording
  ("amount … shielded") must be shipped as the R10 precise form: per-payment amounts
  are public; ownership, balance, and onward flow are shielded, and payments are
  unlinkable to the recipient. The gate and docs use the precise form.
- **C11 (MINOR — ops): live wiring.** The live public indexer instance must run with
  `PORTAL_FACTORY` set (copied by field name from `deploy/addresses.450815.json`) and
  the sweeper bot must run against Maroo; both are ops actions outside the PR, worth
  recording at gate time.

## Docs debt

- [docs/portal.md](../../../docs/portal.md) — receive framing, browser-side issuance,
  the announce route, feed attribution split, dust threshold; the trust section gains
  the pay-page operator.
- [docs/security-model.md](../../../docs/security-model.md) — new portal/receive
  subsection: who-sees-what rows for the pay-page/indexer operator and the sweep bot,
  the on-chain-unlinkability claim and its precise amount statement (R10, C9, C10),
  and — if C1 resolves to enterprise-entry — the arbiter-openable entry note.
- [docs/indexer.md](../../../docs/indexer.md) — route table: `POST /portal/announce`,
  the attribution-free public projections, the operator-facing unswept surface.
- [docs/wallet.md](../../../docs/wallet.md) — consumer wallet Receive: payments list,
  statuses, the scan sources.
- `README.md` (root) — Layout + What-is-built rows for the new pay-page app.
- New `apps/pay-web/README.md`; updates to `apps/wallet-web/README.md`,
  `apps/sweeper/README.md` (dust threshold, feed change),
  `apps/indexer/README.md` (env/route deltas), `deploy/README.md` (new gate leg).
