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
- [ ] G. LIVE upgrade (separate explicit go): re-measure withdraw gas for
      docs/performance.md on the upgraded pool; deploy new WithdrawVerifier +
      impl, `upgradeToAndCall(reinitializeV2)`, update `addresses.84532.json`
      + `network.ts` mirror, wallet zkey re-upload (`upload_circuits.sh`,
      CIRCUITS_VERSION bump), arbiter indexer ABI redeploy (ops: the live
      bongtu-deploy checkout is not touched from dev sessions).

Announcement fields (ephemeralPub, viewTag) ride as calldata/event, NOT in the
proof: tampering them by a relayer can only break discovery (funds still reach
the proof-bound recipient); binding R to the disclosed owner in-circuit is the
follow-up that also gives the auditor a provable exit-owner link.
