// PURE wallet-side witness assembly for the CPU circuits the public app proves in
// the browser: transfer (2-in / 2-out), transfer10x2 (10-in / 2-out) and withdraw
// (2-in / 1-out), SPEC §4 / §7. Framework- and network-free so the exact code runs
// in the browser view AND the headless spend-witness gate. It imports the sdk crypto
// DIRECTLY, so every commitment / nullifier is byte-identical to what snarkjs proves
// and the contract verifies — the witness objects produced here are EXACTLY the
// circom `main` inputs deploy/gates/e2e_orchestrator.ts assembles by hand, in
// ProvingRequest form (@bongtu/core/proving).
//
// What it does NOT do (SPEC §6 boundary): it does not prove (browser snarkjs, see
// prove.ts) and does not send the tx (the wallet, see connection.ts). It stops at "a
// valid transfer/transfer10x2/withdraw ProvingRequest", ready to prove and submit.
//
// ARITY, and who picks it. Every circuit here takes a FIXED number of inputs — 2 for
// transfer/withdraw, 10 for transfer10x2 — so a spend that needs fewer pads the rest
// with {nullifier:0, value:0, enabled:0, path:zeros}: the contract-derived enabled=0
// disables that slot's membership and the §5.2 value-belt forces its value to 0 (no
// mint). The wallet PICKS the circuit from how many notes the payment needs
// (planSpendAction): ≤2 notes stay on the cheap 2×2 transfer, 3–10 go to transfer10x2,
// and a withdraw — which has no arity-10 circuit — stays at 2. All of them emit their
// ciphertext as circuit outputs (public signals), so — unlike disburse — the wallet
// assembles NO separate ciphertext blob; the tx is just (a, b, c, pub, kemCiphertext).
//
// WHEN THE ARITY IS NOT ENOUGH, the wallet does not stop and ask the user to go merge
// their notes first. planSpendChain plans the WHOLE way through: however many
// transfer10x2 self-sends it takes to fold the balance down to something the terminal
// circuit can spend, then the payment or withdrawal itself. One plan, run as one
// flow — see spendFlow.runSpendChain.
//
// TRANSFER10 IS DEPRECATED (user decision 2026-07-28): the 10-in/10-OUT circuit
// stays deployed on chain, but the wallet never routes to it — every >2-input spend
// AND every merge leg proves transfer10x2 (10-in / 2-OUT), because an output is a
// depth-32 IMT append and transfer10 paid for eight zero-value pads every time.
// buildTransfer10Request below survives only for the committed transfer10 e2e
// driver; nothing reachable from the wallet UI produces a "transfer10" request.

// This file stitches the split module back into the ONE stable public subpath
// (@bongtu/client/spend); the implementation lives in the sibling spend* parts.
export * from "./spendPlan.js";
export * from "./spendCrypto.js";
export * from "./spendAssemble.js";
export * from "./spendBuilders.js";
