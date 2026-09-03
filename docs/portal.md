# Portal (stealth deposits)

How money enters the pool from someone who has nothing but an ordinary
wallet: the payer makes a **plain kKRW transfer** to a one-time address, and
the deposit lands shielded on the recipient's balance with **no action from
either side afterwards**. Adapted from Curvy's front-door structure; the
decision record is `.dev/milestone-stealth.md` slice ⑤.

## The three tricks that make a plain transfer enough

1. **The destination is a CREATE2 address with no code.** `PortalFactory`
   precomputes where a `PortalSweeper` *would* deploy; paying that address
   needs no contract call and no approve — which is what admits CEX and
   stock-wallet senders. The salt IS the DKSAP-derived stealth address
   (`portalSalt`, one padding rule on both sides, pinned by a parity vector
   the Solidity side generates), so resolver, bot and recipient all
   recompute the same destination from the same announcement the withdraw
   scan machinery already carries (docs/circuits.md, `@bongtu/core/stealth`).
2. **The announcement is recorded at issuance, not by the payer.** A CEX
   sender can never announce, so `POST /pay/{name}` (docs/indexer.md) derives
   the destination server-side — discarding the ephemeral scalar immediately;
   the resolver can derive, never spend — and persists the portal record in
   the same breath.
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

## PoC boundaries

Issuance is unauthenticated (anyone may mint records — a spam surface the
route header states); sweeps are full-balance, unbatched, one in flight; no
fee model. Run mechanics: `apps/sweeper/README.md`.
