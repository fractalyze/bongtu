# Portal (stealth deposits and stealth receiving)

How money enters the pool from someone who has nothing but an ordinary
wallet: the payer makes a **plain kKRW transfer** to a one-time address, and
the deposit lands shielded on the recipient's balance with **no action from
either side afterwards**. Adapted from Curvy's front-door structure; the
decision record is `.dev/milestone-stealth.md` slice ⑤.

Two products share this machinery, on separate contract pairs:

- **Portal** (depositor-facing, enterprise family): `PortalFactory` +
  `PortalSweeper`, issuance server-side at `POST /pay/{name}`, sweeps through
  the enterprise `deposit` — the original flow below.
- **Receive** (recipient-facing, consumer family): `PortalPrivFactory` +
  `PortalPrivSweeper`, issuance in the **sender's browser** on the pay page
  (`apps/pay-web`), sweeps through the consumer `depositPriv` module — the
  minted notes are no-auditor notes the operator cannot open. The deltas are
  in [Receiving](#receiving-the-consumer-pay-page) below.

## The three tricks that make a plain transfer enough

1. **The destination is a CREATE2 address with no code.** `PortalFactory`
   precomputes where a `PortalSweeper` *would* deploy; paying that address
   needs no contract call and no approve — which is what admits CEX and
   stock-wallet senders. The salt IS the DKSAP-derived stealth address
   (`portalSalt`, one padding rule on both sides, pinned by a parity vector
   the Solidity side generates), so resolver, bot and recipient all
   recompute the same destination from the same announcement the withdraw
   scan machinery already carries ([circuits.md](circuits.md),
   `@bongtu/core/stealth`).
2. **The announcement is recorded at issuance, not by the payer.** A CEX
   sender can never announce, so `POST /pay/{name}`
   ([indexer.md](indexer.md)) derives the destination server-side —
   discarding the ephemeral scalar immediately; the resolver can derive,
   never spend — and persists the portal record in the same breath.
3. **The bot proves the deposit FOR the recipient.** `pool.deposit` is
   permissionless and the deposit circuit binds no owner secret, so
   `apps/sweeper` can mint notes addressed to the recipient's published bjj
   key holding nothing of theirs. The recipient's balance simply grows
   through the same arbiter `/notes` path every deposit already uses.

## Sweep mechanics

The bot watches `/portal/unswept`, and on funding has the factory deploy the
sweeper (idempotent — a second payment to the same address just sweeps again)
and call `sweep`: approve exactly `pub[0]`, then `pool.deposit`. Guards run
before the pool call (`NothingToSweep`, `SweepExceedsBalance`), and the bot
re-reads the balance between proving and sending — a payment landing
mid-flight can only grow the balance past `pub[0]`, the one direction the
contract permits. The indexer flips `swept` off the on-chain `Swept` event;
the bot keeps no state, so a crash resumes by rescan with nothing to
reconcile.

## The trust concession, stated plainly

`sweep` is **onlyOwner (the bot key)** in v1. An on-chain binding of "these
commitments belong to the announced recipient" is impossible without
exposing note owners, so redirection-resistance rests on the institution
key — the SAME trust domain as the arbiter that already decrypts every note.
A cheated recipient detects it: the address was funded, no note arrived —
the `/notes` mismatch is the alarm surface. Recorded here and in both
contract headers; not a hidden assumption.

## Receiving (the consumer pay page)

The receive product turns the portal around: the **recipient** registers a
v2 payment name once (stealth meta + consumer pair, one owner signature) and
shares a URL; every visit to `/p/{label}` on the pay page derives a **fresh**
destination in the visitor's browser from the record's public keys and a
locally drawn ephemeral scalar — no server secret participates, and the
scalar dies with the page. The page records the announcement at
`POST /portal/announce` **before** displaying the address (first write wins
server-side, so an observer of a displayed address can never front-run the
honest record), parity-checks the server's recomputed destination against
its own CREATE2 mapping, and only then shows address + QR.

Sweeps go through the consumer `depositPriv` module: the bot builds the
proof from the recipient's **public** registered triple alone and the notes
seal to keys only the recipient holds — "no one can open it, operator
included" holds from the entry note onward. The sweep transaction also
emits `Announced(salt, ephemeralPub, viewTag)` on-chain, so every **swept**
payment is recoverable from chain data alone: a dead or hostile indexer can
delay discovery of unswept payments but cannot erase swept ones. Balances
below the bot's `MIN_SWEEP` dust threshold stay unswept (they read
`received` in the wallet indefinitely — a stated policy, not a bug).

Discovery is the recipient's own: the public announce feed serves **no
attribution** (no name, no owner — the wire split is
[indexer.md](indexer.md#http-api)), and the wallet's view key re-derives
which records are its own. The attributed rows the sweep bot needs sit
behind the shared `PORTAL_OPERATOR_TOKEN`.

### The receive trust posture, stated plainly

- **On-chain unlinkability is the claim**: distinct payments to one
  recipient share no on-chain datum with each other or with the recipient's
  registered identity — the gate leg (`deploy/gates/portal_priv_leg.ts`) greps
  for exactly this. The **per-payment amount is public twice** (the plain
  transfer, and the deposit's public `pub[0]`); what is shielded is note
  ownership, the aggregate balance, and all onward flow.
- **The pay-page/indexer operator sees the mapping it serves**: it issues
  the URLs and stores the announcements. Operator-blindness (OMR/TEE class
  work) is out of scope and stays honestly excluded from the claim.
- **Redirection-resistance rests on the bot key** — the portal v1
  concession, unchanged. What the consumer path removes is the arbiter's
  read: a cheated recipient still detects theft (funded address, no note in
  its own scan).

## PoC boundaries

Issuance is unauthenticated on both write routes (anyone may mint records —
a spam surface the route headers state; the bot treats rows as hints and
sweeps only funded addresses); sweeps are full-balance, unbatched, one in
flight; no fee model beyond the dust threshold. Run mechanics:
`apps/sweeper/README.md`; page mechanics: `apps/pay-web/README.md`.
