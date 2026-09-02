# Milestone: stealth pool edges (add-on)

Decision record + tracker for the stealth-address add-on. Repo decision: in-repo
add-on, NOT a new repository (the relayer lives with the institution box, the
withdraw change is a UUPS upgrade of the live pool, the crypto reuses the bjj
stack). Priority: withdraw → name directory → portal deposits.

Scheme: dual-curve DKSAP (`packages/core/src/stealth.ts`) — bjj ECDH view half
(circuit-`Ecdh()`-compatible, keeps in-circuit audit binding reachable) +
secp256k1 one-time spend key (the destination must be an EOA). Curvy's
pairing-based ECPDKSAP was deliberately NOT adopted: its pairings buy global
announcement-scan speed, and bongtu serves announcements per-owner from the
arbiter indexer (the arbiter already learns the withdrawer from the authority
envelope, so a per-owner feed adds zero disclosure). Public scan-all stays as
the trustless fallback path.

## Shipped

- [x] `@bongtu/core/stealth` — derivation/scan/recover + determinism pin (`4a050b0`)
- [x] indexer `/names` directory + `@bongtu/core/indexerApi` client half (`eef28b5`)

## Slice ③ — stealth withdraw (anvil-complete first; live upgrade gated)

Withdraw pays `msg.sender` today; the stealth exit pays a proof-bound recipient
instead, submitted by anyone (relayer), announced via (R, viewTag) on the event.

- [x] A. circuit: `withdraw.circom` wrapper template adds public `recipient`
      at pub[26] (uint[27]), constrained `recipient*recipient` so it cannot be
      optimized out (Tornado-style calldata binding). Indices 0..25 unchanged.
- [x] B. inputs: `WithdrawInput.recipient` in core `proving.ts` + prover
      `schema.py` mirror + `fixtures/gen_inputs.ts`; `prove_all.sh withdraw`
      regen (zkey, vkey, committed verifier); `gen_realproofs.ts` regen.
- [x] C. contract: `withdraw(uint[27], …, bytes32 ephemeralPub, uint8 viewTag)`
      pays `address(uint160(pub[26]))` (range/zero-checked); a paired
      `WithdrawAnnouncement` event carries recipient + announcement (Withdrawn
      keeps its historical shape — no dual-ABI freeze needed); `reinitializeV2(IWithdrawVerifier)` —
      `reinitializer(2)` + `onlyOwner` (an unguarded reinitializer is claimable
      by anyone after upgrade). Old uint[26] entry point is REPLACED, not kept.
- [x] D. indexer: refresh `abi/BongtuPool.abi.json` (CI drift gate); ingest attaches each
      `WithdrawAnnouncement` to its withdraw feed entry (payload-persisted, no
      new table); `GET /announcements`
      (public, cursor) + arbiter-mode `?owner=` behind the `/notes` read-auth
      (owner attribution from the envelope the ledger already decrypts).
- [x] E. client + wallet UI (toggle, stealth-funds screen, key export): withdraw request/ABI fragment carries recipient + announcement;
      self-stealth destination derived via `stealth.ts`; wallet UI toggle.
- [x] F. gates: core tests + tsc → forge test → prove_all withdraw leg →
      indexer unit + conformance (scenario drives the new signature) → e2e_m0.
- [x] G. LIVE upgrade — executed 2026-09-01 (user go): `UpgradeV2.s.sol`
      (owner broadcast, one upgradeToAndCall) — WithdrawVerifier
      `0xB9E4b3D65424eff12A06c46eBaAc69eEe198CCBc`, impl
      `0x68f553667d653929e8E795E1EF695279d2aE7086`, reinit version 2, storage
      preserved; `addresses.84532.json` merged (`network.ts` owns none of the
      changed fields — no mirror edit); withdraw re-measured 1,716,736 gas
      (docs/performance.md); zkey upload done, CIRCUITS_VERSION
      f91bd0d2 -> bb0115c4. STILL OPEN (ops, not a dev-session action):
      arbiter indexer ABI redeploy — the live bongtu-deploy checkout must pull
      this branch and rebuild, or post-upgrade withdraws will not ingest.

## Slice ⑤ — portal deposits (design decided 2026-09-02, Curvy-style)

User decisions: Portal-escrow lane REJECTED (payer must call a contract — kills
CEX/plain-wallet senders); adopted the Curvy structure (knowledge:
curvy-architecture-stealth-frontdoor-plus-shielded-pool): CREATE2-precomputed
sweeper addresses + an operator bot.

Flow: resolver issues a fresh address at resolve time (derives ephemeral R,
CREATE2 salt = the DKSAP-derived stealth address — the whole existing
derivation/scan machinery is reused verbatim) and RECORDS the announcement then
(a CEX sender can never announce; issuance-time recording is what makes plain
transfers workable). Payer: plain kKRW transfer from any wallet. Bot: watches
unswept announcements, on funding deploys the sweeper via the factory and calls
sweep — approve(pool) + pool.deposit with a proof the BOT builds minting notes
to the RECIPIENT's bjj key (deposit has no owner binding; no recipient secret
needed). Recipient: does nothing — balance appears via the arbiter /notes path.

Trust note (recorded, not hidden): sweep is onlyBot in v1 — an on-chain
binding of "these commitments belong to the announced recipient" is impossible
without exposing owners, so redirection-resistance rests on the institution
key, the SAME trust domain as the arbiter that already decrypts every note.
A cheated recipient detects it (address funded, no note arrived) — the /notes
mismatch is the alarm surface.

Units: U-P1 contracts (PortalFactory + Sweeper, CREATE2 address parity with
core TS derivation, forge tests incl. only-bot + re-sweep refusal) → U-P2 core
+ indexer (portalAddress derivation in stealth.ts; issuance route + announcement
kind "portal", unswept index) → U-P3 apps/sweeper bot (watch → prove → sweep;
key never logged; separate from the relayer to keep its withdraw-only story) →
U-P4 wallet payer flow + e2e + live wiring (factory deploy is NEW standalone —
the pool is NOT touched, no UUPS this time).

Announcement fields (ephemeralPub, viewTag) ride as calldata/event, NOT in the
proof: tampering them by a relayer can only break discovery (funds still reach
the proof-bound recipient); binding R to the disclosed owner in-circuit is the
follow-up that also gives the auditor a provable exit-owner link.
