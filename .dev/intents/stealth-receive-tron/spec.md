# Stealth payment receiving on Tron: portal front door, native shielded backend (spec)

Author: spec-drafter (reviewed by JunBeom Lee). Status: accepted.
Intent: [intent.md](intent.md)

This is a full replacement of the first spec (commit `9368bed`, the fresh-address-only
tier), superseded by user decisions of 2026-09-07 made after empirical probing of the
TVM and the bridge routes. The intent capped Tron at the unlinkability tier "unless the
tron-rail-spike leads to a pool"; the probe closed that question both ways: a bongtu
pool ON Tron is measured dead, and a bridge to an off-Tron pool was researched, found
viable, and REJECTED by the user in favor of reusing the chain's own shielded machinery
("tron native 그대로 사용하고 portal만 우리가 만들자"). The shield tier therefore ships
ON Tron, through the chain's native shielded TRC20 (TIP-135/137), with bongtu building
ONLY the portal family around it. Requirements trace to the intent's Problem plus the
decisions of record; the widening beyond the intent's Proposed outcome is the user's
own direction, recorded here so review does not mistake it for drafter scope creep.

Decisions of record (user, 2026-09-07), baked in as requirements, not concerns:

1. Tron is priority one, consumer-only. Sender = stock Tron wallet or CEX withdrawal,
   zero sender software. Receive works on Tron MAINNET.
2. No bongtu zk executes on Tron, ever: the pool question is closed by measurement.
3. Shield backend = the chain's native shielded TRC20 (Sapling precompiles, live on
   mainnet and Nile). bongtu deploys one ShieldedTRC20 wrapper instance bound to
   mainnet USDT; a Nile smoke of the reference contract is a mandatory early
   verification (the feature has near-zero production usage since ~2021).
4. bongtu builds only the portal family: stealth receive plus EIP-1167 clone sweepers
   that approve-and-mint the full balance into the shielded contract, to the
   recipient's registered Sapling payment address.
5. Trust posture, accepted: the sweep is FRAUD-EVIDENT, not theft-proof (a shielded
   output's recipient cannot be verified on-chain). A regression versus the Maroo
   sweep's in-proof binding, stated plainly, with the announce record as the
   accountability anchor.
6. One user-facing identity: the Sapling keyset is derived deterministically from the
   existing one-signature wallet identity and stays internal.
7. Spending and exit use java-tron's shielded RPC family in its `withoutask` variant:
   the spend-authority key never leaves the wallet, which signs locally (a bounded
   RedJubjub signer lands in core). Exit = burn to a transparent address, CEX deposit
   address as the no-gas headline path.
8. An own java-tron full node is the expected infra (TronGrid very likely does not
   serve the shielded RPCs; verify early). Trial-decrypt discovery is the wallet's
   job; the indexer keeps serving the announce/funding store.
9. Tier honesty, family naming with the TVM `0x41` CREATE2 flavor, no live-chain
   action without a human gate, and Maroo untouched all stand from the prior record.

## Measured grounding

The numbers below are MEASURED, not assumed: live probes of Tron mainnet and Nile
chain parameters, a local java-tron 4.8.2 (tronbox/TRE docker) running bongtu's real
verifiers and the real receive flow, and live bridge quotes (2026-09-07, dev box:
Ryzen 9 9950X3D). Apparatus: `tron_probe.ts` (untracked scratch at the worktree root)
and the TVM-flavored factory probe under `chains/evm/test/probe/`; the findings are
what this spec builds on, the scripts themselves are not deliverables.

- **bongtu Groth16 on the TVM blows the mainnet CPU cap.** java-tron's bn128
  precompiles are pure Java; `getMaxCpuTimeOfOneTx` = 80 ms on mainnet (160 ms Nile,
  read live). Bare verifies of bongtu's real circuits: 47-77 ms warm, 123 ms
  JIT-cold. A full `depositPriv` sweep transaction: **3,026,275 energy (~303 TRX,
  roughly $102 at live prices) and 118-141 ms execution** on a top-end CPU. Time
  alone kills mainnet; each failure burns the whole fee_limit, nondeterministically.
  Tron compute pricing measured ~2,000x Base per gas unit: rejected on BOTH axes.
- **The native shielded TRC20 path is fast and live.** TIP-135/137 precompiles
  (`verifyMintProof` 0x1000001 at 150k energy, `verifyTransferProof` 0x1000002 at
  200k, `verifyBurnProof` 0x1000003, `merkleHash` 0x1000004) are JNI calls into
  librustzcash (Sapling, Groth16 over BLS12-381, Tron's MPC parameters), ~10-15 ms,
  enabled on mainnet and Nile since GreatVoyage 4.0. The 80 ms cap is irrelevant to
  them. The circuit is HARDCODED: 1-in/1-out mint, up to 2-in/2-out transfer,
  1-in burn, depth-32 note commitment tree. No visible production usage since ~2021.
- **CREATE2 diverges by one byte.** TVM uses prefix `0x41` where the EVM uses `0xff`
  (TIP-26). Confirmed live: the unpatched factory reverts `SweeperAddressMismatch`;
  patching `addressOf` to `hex"41"` makes prediction == deployment == where the
  payment landed. Every off-chain predictor needs the flavor too.
- **Tron-side costs.** Clone deploy ~9k energy; plain TRC20 move 30-130k energy
  (fresh-holder USDT at the high end); operator energy from staking at a measured
  9.58 energy per TRX per day. Writes go native protobuf only (no
  `eth_sendRawTransaction` on the TVM's JSON-RPC); the probe's build-sign-broadcast
  path is a working PoC of the transaction flow the bots need.
- **USDT-TRC20 realities.** The legacy token's `transfer()` returns nothing
  (SafeERC20-style calls only), 6 decimals, issuer blacklist live
  (`destroyBlackFunds` can zero a balance), fee-on-transfer machinery present but
  set to 0 (measure balance deltas anyway).

## Rejected alternatives (measured reasons; do not relitigate)

- **(a) A bongtu pool on Tron.** Killed on both time and cost by the measurements
  above. Not "hard": the 80 ms cap is a consensus parameter outside our control
  (TIP-397 lets SRs raise it; the native-crypto PRs are unmerged as of v4.8.2.1),
  and a Nile pass is not evidence of a mainnet pass. Closed permanently; this record
  answers the `tron-rail-spike` question.
- **(b) Hub-and-spoke: a new minimal Arbitrum pool fed by a Tron-to-Arbitrum
  bridge.** Researched and viable, and the shape Curvy verifiably runs on its ten
  EVM-class chains (single Arbitrum pool, per-chain stealth receive, bridge with
  on-chain receiver binding; Curvy cannot reach Tron because LI.FI has no Tron).
  Route facts, measured: USDT0 Legacy Mesh live on Tron (UsdtOFT
  `TFG4wBaDQ8sHWWP1ACeSGnoNR6RRzevLPt`, LayerZero EID 30420, 16.5M USDT depth,
  3 bps, Arbitrum hub; composeMsg from Tron unverified); deBridge DLN binds
  destination calldata cryptographically but its compliance screening returned
  `COMPLIANCE_ADDRESS_BLOCKED` on fresh addresses (stealth flows are always fresh);
  Symbiosis cheapest with a thin trust model. REJECTED by the user in favor of
  native reuse: no new pool to audit, no new trusted setup holding real value, no
  bridge trust or in-flight custody, one chain end to end. Recorded as the FALLBACK
  architecture if the native path fails its smoke (R5): the research stands ready,
  nothing else of it ships.
- **(c) Operator peg into the Maroo pool.** Maroo is an appchain third-party bridges
  do not reach; a peg makes the operator a custodian of the corridor. The user
  rejected the custodial peg role outright.

The first spec's own rejection of the native shielded path is superseded knowingly:
its three objections are each answered by a decision of record. Operator-mint
redirect risk is now the ACCEPTED fraud-evident posture (decision 5, R7); the dead
client-proving ecosystem is routed around with node-assisted `withoutask` proving
plus a local signer (decision 7, R9); the per-chain identity fork is prevented by
deriving the Sapling keyset from the one wallet identity (decision 6, R2).

## Context: what carries over (load-bearing reuse)

The Maroo receive spine was built rail-extensible (its R9) and carries over intact:

- **Derivation.** `@bongtu/core/stealth` (DKSAP derivation, `portalSalt`,
  `create2Address`, the announcement predicate) is rail-neutral up to two flavors:
  address presentation (base58check over `0x41` plus the same 20-byte keccak body)
  and the CREATE2 prefix byte. The stealth identity keeps coming from the existing
  one-signature KDF under the memory-only custody rule.
- **Wire and store.** `PortalRecord`/`PortalPublicRecord` already carry `rail`;
  `POST /portal/announce` validates it (today `"evm"` only); first-write-wins
  dedupe on `stealthAddr` is atomic; the public feed is attribution-free and the
  attributed feed sits behind `PORTAL_OPERATOR_TOKEN`
  ([docs/indexer.md](../../../docs/indexer.md)).
- **Product surfaces.** The pay page (`apps/pay-web`: announce-before-display,
  parity-check, fail-closed), the wallet's registration and received-payments list,
  the bot division of labor (bots hold keys and act, the indexer reads), and the
  relayer's "who submits is a free variable" posture
  ([docs/portal.md](../../../docs/portal.md), [docs/relayer.md](../../../docs/relayer.md)).
- **Contracts.** `PortalFactoryBase`'s family shape: the salt IS the stealth
  address, `addressOf` is the pure prediction, deploy-if-absent is idempotent with
  the hard mismatch stop; the family naming rule holds and the Tron pair joins it
  (naming in plan).

What is new: the Tron chain island (contracts compiled with the tronprotocol
solidity fork, native-protobuf writes), the ShieldedTRC20 wrapper deployment, the
clone sweeper that mints shielded, the Sapling keyset derivation and the RedJubjub
signer in core, the own-node infra, and the wallet's shielded scan and exit flows.

## Requirements

Traceability: R1 <- intent Constraint (one derivation path) + decision 9; R2 <-
decision 6; R3-R4 <- intent Proposed outcome bullets 1-2 + decision 1; R5 <-
decision 3; R6 <- decision 4; R7 <- decision 5; R8 <- outcome bullet 3 + decision
8; R9 <- decision 7 + intent Constraint (fee reality); R10 <- decision 8; R11 <-
intent Constraint (honest tier) + decision 9; R12 <- decision 9's economics +
intent Constraint (no stranded dust); R13 <- the no-live-action rule; R14 <-
outcome bullet 4 (the gate); R15 <- the Maroo-untouched rule.

- **R1 (MUST) One derivation path, two TVM flavors.** `@bongtu/core/stealth` gains
  (a) the Tron PRESENTATION of the 20-byte address body (base58check over `0x41`
  plus body; the canonical wire form stays the 0x hex body on every rail) and
  (b) a TVM CREATE2 flavor (`0x41` prefix) used by every off-chain predictor.
  Derivation, scan, and key recovery stay the single existing code path. Both
  flavors are pinned by committed known-answer vectors, the CREATE2 one by a
  parity vector against the TVM factory's `addressOf` (the measured mismatch is
  the regression this pins).
- **R2 (MUST) One identity; the Sapling keyset is internal.** The recipient's
  Sapling keys (spending key and the derived ask/nsk/ovk, ivk, and payment
  address) are derived DETERMINISTICALLY from the existing one-signature wallet
  identity: no new popup, no new signing domain, no new persistence surface, and
  full recovery from the same signature. The registration record gains the Sapling
  payment address as a versioned field beside the consumer pair; registration
  stays one flow.
- **R3 (MUST) Pay page Tron tab.** `/p/{label}` grows a Tron tab: each load derives
  a FRESH destination in the visitor's browser from the same registered record,
  announces with `rail: "tron"` BEFORE displaying, parity-checks the server's
  recomputed destination, then shows the base58 address, QR, network and asset
  facts, and the R11 tier copy. The destination is the TVM-CREATE2-predicted
  address of a not-yet-deployed sweeper clone (the Maroo portal trick, Tron
  flavor). A Tron announce requires the record to carry the Sapling payment
  address (a payment must have somewhere shielded to land).
- **R4 (MUST) Zero sender software; USDT-TRC20 is the acceptance asset.** The
  payment is a plain USDT-TRC20 transfer from any stock Tron wallet or CEX
  withdrawal: no contract call beyond the token transfer, no bongtu code, no
  activation precondition on the destination. USDT-TRC20 is the sole acceptance
  asset; no other TRC20 and no TRX is claimed or displayed.
- **R5 (MUST) Shield backend: one ShieldedTRC20 wrapper on native precompiles.**
  The shield is Tron's native shielded TRC20. bongtu deploys ONE wrapper instance
  bound to mainnet USDT (`scalingFactor` set for the 6-decimal token; exact value
  in plan) unless review of the reference contract's provenance surfaces a
  canonical audited deployment worth reusing (C1; none is currently known, so
  deploy-own is the working assumption). Before any deep build investment, a
  human-gated NILE SMOKE of the reference contract must pass: mint, transfer,
  burn, and scan against a real node, since the feature has near-zero production
  usage since ~2021. If the smoke fails, the recorded fallback is architecture
  (b); this spec does not proceed silently.
- **R6 (MUST) Sweep = approve + shielded mint, value-bound in code.** Funding is
  swept by deploying an EIP-1167 clone at the predicted address whose code does
  exactly: approve the wrapper for the clone's FULL USDT balance, call the
  wrapper's mint with operator-supplied proof parameters whose public value the
  clone requires to equal that balance, and emit
  `Announced(salt, ephemeralPub, viewTag)`. The mint's note is built by the
  operator to the recipient's REGISTERED Sapling payment address. The clone binds
  the token, the wrapper, and the amount on-chain; it cannot bind the shielded
  recipient (R7). Re-sweep after a second payment to the same address is legal
  and idempotent. Per-payment cost target: clone ~9k plus approve plus mint 150k,
  roughly 200-250k energy.
- **R7 (MUST) The fraud-evident posture, stated plainly.** Because a Sapling
  output's recipient is inside the proof's ciphertext and cannot be checked by
  the sweeper contract, a malicious operator could mint to itself. This is a
  REGRESSION versus the Maroo sweep, where the depositPriv proof is built from
  the recipient's public triple and the notes seal to the recipient by
  construction. The accepted posture: theft is possible but FRAUD-EVIDENT, never
  silent. The accountability anchor is the announce-before-display record plus
  the on-chain funding and sweep transactions: an announced, funded, swept
  payment with no note in the recipient's own scan is proof of operator fraud
  (the non-receipt evidence flow, C8). [docs/security-model.md](../../../docs/security-model.md)
  gains this as an explicit receive-edge row; docs and UI never claim the sweep
  is redirect-proof on Tron.
- **R8 (MUST) Discovery and receive view.** Tron issuances ride the existing
  attribution-free announce feed as `rail: "tron"` rows; the view-key scan
  predicate is rail-agnostic. The indexer stamps funding and the sweep/mint
  transaction (reads only, no keys). Shielded-note discovery is the WALLET's job:
  it trial-decrypts the wrapper's note stream with its own viewing material and
  lists Tron payments beside Maroo ones with statuses `received` (funded, not yet
  swept) and `shielded` (mint landed and the note found by the wallet's own
  scan). No arbiter read on any path; Tron and Maroo shielded balances are
  per-rail and never conflated.
- **R9 (MUST) Spend and exit, ask never leaves the wallet.** Spending uses
  java-tron's shielded-contract-parameter RPC in the `withoutask` variant: the
  node builds the proof from viewing-class material and note data, and the wallet
  signs the spend-authority signature LOCALLY with `ask` using a new bounded
  RedJubjub/Jubjub signer in `@bongtu/core` (test-vector-pinned against
  librustzcash, C4). The wallet verifies that what it signs covers the intended
  outputs before signing. Exit = burn to a user-chosen transparent Tron address,
  with a CEX deposit address as the headline no-gas path; the operator submits
  the transaction (authorization is in-proof: spend-authority plus binding
  signatures, so the submitter is a free variable, the relayer precedent), so the
  recipient never needs TRX. Shielded-to-shielded transfer ships only as far as
  the same machinery yields it (2-in/2-out max per transaction; consolidating N
  notes takes a chain of merges, stated in the UX and priced in R12).
- **R10 (MUST) Own-node infra; exposure stated.** The shielded RPC family is
  expected to require an OWN java-tron full node (TronGrid availability verified
  as an early task; this resolves the v1 own-node question the other way). The
  proving node sees the spend's note plaintexts, and scan-by-viewing-key hands
  the node ivk-class material: both are stated in the security model as the same
  class as the existing operator-sees-the-receive-graph posture (our node, our
  operator, never spend authority). The exact material each RPC needs is
  verified against java-tron source before the wire is fixed (C3).
- **R11 (MUST) Honest tier and claim language.** Docs and UI say exactly: a Tron
  payment gets per-payment fresh-address UNLINKABILITY at receive time, and the
  amount is public at the plain transfer and again at the public mint value;
  after the mint, the funds are shielded by Tron's native Sapling pool (amounts,
  recipients, and shielded flow hidden; burn amounts and burn destinations
  public). Three deltas versus Maroo are stated, never blurred: the sweep is
  fraud-evident rather than redirect-proof (R7), the shielded ciphertexts are
  classical (no post-quantum hybrid, unlike bongtu notes), and the shield is
  Tron's trusted setup and circuit, not bongtu's. The word "shielded" on a Tron
  row means the Sapling pool, and the docs say so.
- **R12 (MUST) Economics posture, stated honestly.** Per-payment receive cost is
  roughly 22-25 TRX at burn (~$7-8), falling to $1-2 with the operator's energy
  stake or rental (measured 9.58 energy/TRX/day); a shielded transfer is ~20 TRX
  and an exit burn ~15 TRX at burn, similarly reduced by staking. No bridge
  fees; one chain. Positioning is meaningful-ticket receiving ($100+), not
  micropayments; payments below a configured sweep threshold stay `received`
  with honest copy (C7). A Curvy-style fee is the named cost-recovery option,
  not required in this slice.
- **R13 (MUST) No live-chain action without a human gate.** Automated gates run
  on a local java-tron (TRE) only. The human-gated ladder, each step its own
  decision: (1) the Nile reference-contract smoke (R5, early); (2) TronGrid
  shielded-RPC verification / own-node bring-up; (3) mainnet wrapper deploy and
  record commit; (4) Tron factory deploy and operator energy stake; (5) the
  capped operational demo. Mainnet steps re-read the security-model deltas
  against real value.
- **R14 (MUST) End-to-end gate.** An automated heavy gate on a local java-tron
  with the shielded feature enabled: one recipient, two pay-page-shaped
  issuances, two USDT payments from distinct senders, two sweeps, wallet scan,
  one exit burn. Asserts (a) the destinations differ; (b) no on-chain datum
  common to the two payments correlates them with each other or the recipient's
  registered identity, and the public feed serves no attribution; (c) prediction
  == deployment for the TVM CREATE2 flavor; (d) the clone's value binding holds
  (a mint attempt for less than the balance reverts); (e) both payments become
  notes the recipient's own scan finds, and a deliberately mis-addressed mint is
  DETECTED by the same scan (the fraud-evidence assertion); (f) the exit burn
  lands at the chosen transparent address with the operator as submitter and the
  wallet's local spend-authority signature; (g) rows are rebuildable from chain
  data plus the view key for the stealth leg.
- **R15 (SHOULD) Maroo untouched.** The Maroo receive product is regression-pinned:
  existing routes, feeds, contracts, sweeper, and the `portal_priv_leg` gate stay
  green; `rail: "evm"` rows and flows are byte-unchanged; no transaction of any
  kind on 450815.

## Design

### The shape, end to end

```
sender (stock wallet / CEX)
  | plain USDT-TRC20 transfer                              [Tron mainnet]
  v
fresh CREATE2(0x41) landing pad  --sweep-->  EIP-1167 clone
  |  clone code: approve(wrapper, balance) + mint(balance, operator-built proof)
  |  + emit Announced(salt, ephemeralPub, viewTag)
  v
ShieldedTRC20 wrapper (native Sapling precompiles, Tron's circuit and setup)
  v
note to the recipient's registered Sapling payment address
  |  discovery: wallet trial-decrypt scan (own node, viewing material only)
  v
spend/exit: node-built proof (withoutask) + LOCAL spend-authority signature
  --> burn to CEX deposit address | any transparent Tron address
```

Everything is one chain. bongtu ships no circuit and no verifier for Tron; the zk
is the chain's own, reached through two precompile-backed wrapper calls.

### Derivation and keys

Core stealth adds the base58check presentation (sha256 is in `@noble/hashes`;
base58 is ~20 lines, no new dependency) and the `create2Address` prefix-byte
flavor. New in core: a Sapling key module deriving the keyset (sk, then
ask/nsk/ovk, ivk, diversified payment address) from the existing wallet-signature
KDF output under a new domain tag, plus the RedJubjub signer for spend-authority
signatures. Both are bounded, dependency-light, and pinned by committed test
vectors generated against librustzcash (C4). The registration record carries the
payment address as a versioned addition; old records without it simply have no
Tron tab (the pay page reports it plainly).

### Tron contracts: the portal family, TVM flavor

A Tron chain island (folder naming in plan) compiled with the tronprotocol
solidity fork. The factory carries the family shape with `hex"41"` in `addressOf`
and deploys EIP-1167 clones. The clone's implementation holds one sweep function,
operator-triggered (spam control and energy custody) and parameterized only by
the mint proof material: it reads its own USDT balance, requires the mint's
public value to equal it, approves the wrapper for exactly that, calls mint, and
emits `Announced`. There is no destination parameter anywhere; what the operator
controls is WHEN and WHICH NOTE, and the note is the fraud-evident concession
(R7). USDT moves use SafeERC20-style calls with balance-delta measurement. The
ShieldedTRC20 wrapper itself is the reference contract, deployed by us and bound
to USDT at construction; whether it needs a fork (event surface for scanning,
anything the Nile smoke turns up) is C1, and any fork is kept to the minimum
diff against the reference.

### The wrapper and its trust facts

The wrapper escrows every shielded participant's USDT transparently at one
address (a blacklist or bug on that single address is the whole rail's
concentration risk, C11); the shielded state is Tron's depth-32 note commitment
tree maintained through `merkleHash`; proofs verify in native code well under
every CPU cap. The circuit and its MPC parameters are Tron's, not bongtu's: the
soundness of the shielded pool is inherited, not audited by us, and stated as
such (R11, C9). Mint values, burn values, and burn destinations are public by
the design of TIP-137; shielded transfers hide amounts and parties.

### Operator service

One Tron bot beside `apps/sweeper` (which keeps Maroo unchanged): watch the
token-gated attributed feed, detect funding (via the own node), build mint
parameters against the registered payment address through the node's shielded
RPC, deploy-and-sweep clones above the dust threshold, manage the energy stake,
and submit user exit transactions (the submitter role, holding no user
authority). All writes go through the native protobuf build-sign-broadcast path
the probe validated; transactions are built and signed locally by the bot's own
key, never from remote-built bytes unverified.

### Indexer and wallet

- `POST /portal/announce` accepts `rail: "tron"` when the Tron config is present
  (the existing config-gating pattern); the server recomputes the destination
  with the TVM CREATE2 flavor and never accepts a client-sent one; a Tron
  announce requires the record's Sapling payment address to exist.
- Tron rows gain funding and sweep/mint stamps under the existing write-behind
  persist discipline; the public projection carries status, never attribution.
  The indexer's Tron reader is HTTP reads against the own node; it holds no keys.
- The wallet performs shielded discovery itself: scan the wrapper's note stream
  through the node's viewing-key scan RPC (ivk-class material only; exact fields
  per C3) or, as the named follow-up, a fully client-side trial-decrypt. It
  renders `received`/`shielded` rows, the shielded balance per rail, the merge
  economics of 2-in/2-out consolidation before an exit, and the exit flow with
  its fee/cost statement and destination choice (CEX address or any transparent
  address). The non-receipt evidence view (C8) lists announced+funded+swept
  payments the scan cannot find, which is exactly the fraud alarm.

### Gates

A new heavy leg beside `portal_priv_leg.ts`: dockerized TRE java-tron with the
shielded TRC20 feature enabled in its config (committee parameter; the local
defaults sidestep the CPU cap question entirely), the reference wrapper deployed
against a test TRC20, the real indexer, the bot as a library, and a headless
wallet driving derivation, scan, and the withoutask-plus-local-sign spend.
Assertions per R14, including the negative fraud-evidence case. TRE realities
the harness respects: the local CPU cap is 200 ms (no timing conclusions carry
to mainnet) and heavy broadcasts block the broadcast call, so the harness polls
`gettransactioninfobyid`. If the java-tron container cannot run on hosted CI,
the leg is a dev-box gate under the local-pass-is-not-CI-pass rule
(`.dev/ci.md`). The Maroo `portal_priv_leg` runs unchanged as the R15 pin. The
Nile smoke (R5) is a human-run checklist, not part of the automated tier.

### Records and configuration

Live values ship in a committed Tron network record under the
copy-by-field-name discipline: the USDT contract, the wrapper, the factory, the
clone implementation, the announcer/bot address, the chosen network, and the
node endpoint expectations. No surface transcribes an address by pattern; the
cross-chain CREATE-nonce collision hazard in CLAUDE.md applies. Bot env: node
URL, operator key, dust threshold (`MIN_SWEEP`-class, token base units),
`PORTAL_OPERATOR_TOKEN`. Indexer env: node URL, wrapper, factory, USDT.

## Non-goals

- No bongtu zk on Tron: no pool, no bongtu circuits, no verifier deployments
  (closed by measurement).
- No bridge and no Arbitrum pool: architecture (b) is recorded research and the
  named fallback, nothing of it ships.
- No enterprise family and no arbiter on the Tron rail: the native shielded pool
  has no disclosure mechanism, so the rail is consumer-posture only and the
  compliance story explicitly does not extend to it (C10).
- No name layer; the pay page is the route (Tron wallets resolve no names).
- No sender-side software, sender fee abstraction, or payment webhooks.
- No acceptance assets beyond USDT-TRC20; no TRX handling in the product path.
- No cross-rail note motion: Maroo notes and Tron shielded notes are separate
  balances under one identity; no swap or peg between them.
- No required fee model; the fee option is named, not built.
- No live-chain transaction of any kind in this slice (the R13 ladder instead).
- No general shielded-wallet ambitions: shielded-to-shielded transfer ships only
  as the machinery's natural byproduct; bongtu is the receive-and-exit product.
- No changes to Maroo receive behavior, contracts, or feeds.

## Concerns

Flagged for the human gate. BLOCKER stops auto-mode per the intent-chain rule;
JUDGMENT needs a call but has a workable recommendation; MINOR is recorded
posture.

- **C1 (BLOCKER, resolved by an early gate): the reference ShieldedTRC20's
  provenance and fitness.** The wrapper is third-party reference code with
  unclear audit state and near-zero production usage since ~2021. Unknowns the
  R5 Nile smoke plus a source review must answer before build investment: audit
  trail, whether its event/log surface supports viewing-key scanning as-is or
  needs a minimal fork, upgrade/ownership surface, and `scalingFactor`
  semantics against 6-decimal USDT. Failure path is the recorded architecture
  (b) fallback; proceeding on a fork raises the audit question explicitly for
  the human.
- **C2 (JUDGMENT, infra): shielded RPC availability.** TronGrid very likely does
  not serve the shielded RPC family, making an own java-tron full node required
  infra (disk, sync, ops). Verify early alongside C1; recommendation: plan for
  the own node (it also removes third-party-read trust from the funding path)
  and record node ops as a deployment prerequisite in the R13 ladder.
- **C3 (JUDGMENT, wire correctness): the withoutask contract with the node.**
  The exact input material `createshieldedcontractparameterswithoutask` needs
  (which of ak/nsk/ovk/ivk, and what the returned message-to-sign covers) must
  be verified against java-tron source before the wallet wire is fixed. Two
  stakes: `ask` must provably never be needed by the node, and `nsk` exposure
  (if required) lets the node compute nullifiers and link the user's spends,
  which must then be stated in the R10 posture rather than discovered later.
- **C4 (JUDGMENT, implementation risk): the RedJubjub/Jubjub signer.** A new
  cryptographic module in core, on a curve the repo has never touched. Bounded
  scope (one curve, one scheme, sign-only), committed test vectors generated
  from librustzcash, and the R14 gate exercising the real end-to-end signature
  are the mitigations; a focused review pass on this module alone is
  recommended at feature-PR time.
- **C5 (JUDGMENT, UX/perf): recipient scan cost and latency.** Trial-decrypt
  discovery over the wrapper's note stream grows with total rail usage, and the
  node-side ivk scan RPC has unknown block-range limits. Recommendation: scope
  scans by the announce record's funding timestamps (the indexer store bounds
  the search window per payment), measure in the gate, and name client-side
  full-scan as the follow-up if node limits bite.
- **C6 (JUDGMENT, abuse surface): mint griefing and front-running.** The mint
  parameters transit the mempool; verify during build that a copied or
  replayed parameter set cannot land twice (note-commitment and nullifier
  uniqueness in the wrapper), that a third party calling the wrapper directly
  cannot corrupt a pending sweep, and that a payment landing mid-sweep only
  grows the balance the clone re-reads (the Maroo sweep discipline). Announce
  spam stays the recorded PoC posture (poll quota only; the operator's
  on-chain spend fires on funded rows).
- **C7 (JUDGMENT, policy): dust.** Below `MIN_SWEEP` no sweep fires and the row
  reads `received` with honest uneconomic copy, indefinitely. Threshold value
  is ops policy; with R12's cost profile the floor is meaningfully higher than
  Maroo's, which the pay page should reflect (a stated minimum sensible
  payment; wording at plan time).
- **C8 (JUDGMENT, accountability UX): the fraud-evidence flow.** R7's posture
  needs a concrete non-receipt story: the wallet surfaces announced, funded,
  swept, but unfound payments as a first-class alarm, and the evidence bundle
  (announce record, funding tx, sweep tx, absence of a decryptable note) is
  exportable and producible by the recipient alone. What a recipient DOES with
  it is off-product; wording and placement are policy.
- **C9 (MINOR, inherited trust): Tron's circuit and setup.** The shield's
  soundness rests on Tron's Sapling MPC parameters and librustzcash, not on
  anything bongtu can gate. Recorded honestly in the security model, alongside
  the fact that these are the battle-tested Zcash constructions and that
  bongtu adds no trusted setup of its own on this rail.
- **C10 (MINOR, positioning): no audit story on the Tron rail.** The native
  pool has no disclosure hook, so bongtu's compliance-module positioning does
  not extend to Tron; the rail is consumer-only by construction. Recorded for
  the human's positioning narrative, not a design item.
- **C11 (MINOR, threat model): USDT issuer controls and concentration.** Tether
  can blacklist a landing pad, the bot, or the wrapper itself; the wrapper is
  one transparent address escrowing the whole shielded rail. Accepted-and-
  stated risk of the real-USDT decision, for the security-model docs and the
  demo-phase posture.
- **C12 (MINOR, claim precision): public amounts and timing.** Mint values,
  burn values, and burn destinations are public; a payment's plain transfer
  and its mint are timing-adjacent and equal-valued, so the receive-leg claim
  is payment-to-payment and payment-to-identity unlinkability, never amount
  secrecy at the edges (the R11 wording is the shipped form). The Maroo
  consolidation warning has a Tron analogue at exit: burning several merged
  payments to one transparent address links them by the recipient's own
  choice.
- **C13 (MINOR, carried posture): the pre-anchor store-loss window.** Until a
  payment's sweep emits `Announced`, its announcement exists only in the
  indexer store; a lost store strands discovery of unswept payments
  (loss-only, never theft). The accepted v1 posture carries over unchanged:
  durable store plus operator backups, residual window stated in the security
  model.
- **C14 (MINOR, ops): operator capital and keys.** The energy stake, the bot
  key custody, and the wrapper deployment key are single-operator PoC posture,
  recorded in the R13 ladder for the mainnet steps.

## Docs debt

- [docs/portal.md](../../../docs/portal.md): the Tron receive shape (front door,
  clone approve-and-mint, native shielded backend), the fraud-evident trust
  section beside the Maroo concession, dust and cost posture.
- [docs/security-model.md](../../../docs/security-model.md): Tron rows in the
  receive-edge who-sees-what table (operator/bot, own node with viewing
  material, chain observer), the fraud-evident regression and its evidence
  anchor, the C13 window, the R11 precise claims (public mint/burn amounts,
  classical ciphertexts, inherited Tron setup).
- A new rail doc (working name `docs/tron-rail.md`, the solana-rail.md
  precedent): the wrapper, the Sapling keyset derivation, the withoutask spend
  protocol and local signing, scan mechanics, exit, the 2-in/2-out limits.
- [docs/indexer.md](../../../docs/indexer.md): `rail: "tron"` on announce, the
  funding/mint stamps, the own-node reader, env.
- [docs/wallet.md](../../../docs/wallet.md): Tron rows and statuses, per-rail
  balances, the exit flow and its costs, the non-receipt alarm.
- [docs/deployment.md](../../../docs/deployment.md): the Tron network record,
  the wrapper deploy, the native-protobuf deploy path (no forge), the R13
  ladder.
- Root `README.md`: system map and layout rows (Tron island, the Tron bot),
  status wording where Tron appears.
- Folder READMEs: `apps/pay-web` (Tron tab), `apps/indexer` (env, routes), the
  new Tron bot README, `apps/wallet-web` (scan, exit), `deploy` (gate leg,
  record), the Tron chain-island README, `packages/core` (stealth flavors, the
  Sapling key module, the RedJubjub signer).

Status: accepted.
