# M1 — Goal & Done criteria

**M1 scales M0 from the 1×16 dev loop to the real 1×256 disburse on GPU, proves it verifies on-chain under
the gas cap, and deploys to a public testnet.** Ref: [spec-decisions.md](spec-decisions.md) §4/§9/§10b (M1), M0 is complete (all 4 units).

Key reuse (verified 2026-07-24): bongtu `disburse` at nOutputs=256 is **byte-identical** to the existing
`run_nonrep_imt_256` (same base `anon_enc_nullifier_non_repudiation_imt_base`, same public list
`[nullifiers, encryptionNonce, root, enabled, authorityPublicKey]`, nPublic=10). So the existing
`/home/a41/Workspace/research/disclosure-poc/artifacts/{circuit.zkey (1.24GB), vkey.json, Groth16Verifier.sol}`
are reusable — **no fresh 150s groth16 setup needed.** GPU proving via rabbitsnark on GPU0 (RTX 5090):
warm ~0.5s per the old PoC. **GPU hygiene (memory rule): CUDA_VISIBLE_DEVICES=0, NEVER nsys/command-buffers
(leaked 30GB/1h41m once), foreground, track+kill any prover PID.**

> **Later note (2026-07-24, post-M1):** the security overhaul added the §5.2 zero-commitment belt to the
> disburse base, changing its r1cs — the zkey byte-reuse above held for M1 but was then retired (zkey
> regenerated), and the non-proxied pool this milestone deployed was superseded by a UUPS-proxy pool.
> Everything on this page is a record of M1 as it ran; for what is deployed now, read
> [docs/deployment.md](../docs/deployment.md) and `deploy/addresses.84532.json`. Rationale for the
> circuit change: [zeto-derivation.md](../docs/zeto-derivation.md).

## Done condition (tick at each unit boundary)

1. **256 disburse proves on GPU + verifies on-chain + gas under cap.** disburse256 circuit (Zeto(1,256,32));
   the existing 1.24GB zkey reused; a REAL rabbitsnark GPU proof produced now (snarkjs verify OK); the 256
   verifier wired into BongtuPool(batchSize=256); a forge test (i) accepts the real 256 proof, (ii) attaches
   the 256-leaf subtree and asserts `contract.root == ImtTree(H=32,B=256) oracle root`, (iii) measures
   disburse gas and asserts **< 16,777,216** (Karst per-tx cap) and reports per-recipient gas.
   Gate: `forge test` (256 suite) green + the GPU proof's `snarkjs verify` OK.
2. **Deployment pipeline on a local Foundry node (anvil).** A reusable Foundry deploy script
   (`deploy/Deploy.s.sol`, RPC + deployer key from env, defaults to anvil) deploys the full production B=256
   stack — Poseidon-v1 + the 4 verifiers (incl. Disburse256Verifier) + BongtuPool(B=256, token + verifiers as
   constructor args) + mock kKRW — initializes it (arbiter epoch), and a smoke deposit succeeds against the
   DEPLOYED instance. Gate:
   `forge script Deploy --broadcast --rpc-url <anvil>` deploys with recorded addresses + smoke tx OK.
   Parameterized so the testnet deploy is the SAME script + env. **DONE 2026-07-24: deployed LIVE to a
   testnet** (B()==256 verified on-chain, real deposit tx succeeded; measured deposit ≈$0.008, L1 fee
   ~1% of cost). That deployment has since been abandoned and its addresses removed from the repo —
   the project moved chains and the current record is `deploy/addresses.84532.json`.

## Units (one workflow each, commit between)

- [x] **U5 — 256 disburse: GPU prove + on-chain verify + gas-under-cap** (gate = Done#1). Deps: M0.
      Evidence: real rabbitsnark GPU proof of the 1×256 disburse (RTX 5090 GPU0, zkey-compile 116s cold +
      Az/Bz 3.3s + proof 3.6s; snarkjs verify OK; no GPU leak). Reused the existing 1.24GB zkey (disburse-256
      byte-identical to run_nonrep_imt_256) → no fresh setup. Wired Disburse256Verifier into BongtuPool(B=256);
      `forge test` 23/23 green: real GPU proof accepted by the genuine verifier, contract.root == independent
      ImtTree(32,256) oracle, tamper/replay revert, **aligned disburse gas 1,031,245 < Karst 16.7M (4,028/
      recipient)**. **★ U5 review + verify surfaced a scaling blocker: the partial-block padding was O(B)
      individual zero-leaf inserts → ~248M gas at B=256 (deposit-then-disburse UNEXECUTABLE on-chain). Fixed
      to an O(LOG_B) fold ([[imt-batch-attach-partial-block-close-must-be-olog-b]]) → partial-block disburse
      2,016,300 gas (123× cut, under cap); root-identical (differential + M0 e2e re-pass, same final root).**
- [x] **U6 — deployment pipeline on local anvil (Foundry deploy script, B=256 stack)** (gate = Done#2).
      Deps: U5. Evidence: `deploy/deploy_local.sh` EXIT 0 — `forge script Deploy --broadcast --skip-simulation`
      deploys the full B=256 stack to a live anvil (8 real txs, all addresses non-zero code via cast),
      wiring verified (pool.B()==256, arbiter key = disburse256 fixture pub[8..9], owner=deployer, 4 verifiers
      + poseidon + token wired), then `Smoke` does a REAL deposit against the deployed pool (nextLeafIndex
      0→2, custodied 3000 kKRW). 23 forge tests still green (contracts unmodified; only foundry.toml/remappings
      for script fs-access). Env-parameterized (DEPLOYER_KEY/RPC/BATCH_SIZE/ARBITER_KEY/TOKEN_ADDRESS) →
      **a testnet = the same two scripts + that chain's RPC + a funded key + the two arbiter KEM
      vars, which default on anvil only and are required off it** (deploy/README.md).
      Review fixes applied: live cmds use --skip-simulation (Poseidon via assembly create), TOKEN_ADDRESS env
      hook, broadcast/cache gitignored. **Live deploy: DONE 2026-07-24 once the funded key arrived (see
      Done#2 above).**

Status legend: [ ] pending · [~] in-progress · [x] done · [!] blocked. Toolchain: [toolchain.md](../docs/toolchain.md). M0: [milestone-m0.md](milestone-m0.md).
