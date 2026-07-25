# CLAUDE.md

Read `README.md` once at session start; for anything deeper, follow its
`## Docs` index into `docs/`. Do not re-derive what those files own.

## Rules an agent cannot see from code + README

- **PATH**: `forge`/`anvil`/`node` are not on the default PATH. Prefix gate runs with
  `export PATH=$HOME/.foundry/bin:$HOME/.nvm/versions/node/v22.17.1/bin:$PATH`.
- **External node_modules**: `ethers`/`snarkjs` load via `createRequire` from
  `BONGTU_NODE_MODULES` (default `/home/a41/Workspace/zkx-snap/circuits/node_modules`) —
  there is no repo-local install for them. On another machine, set the env var.
- **Commits**: use the `workflow:commit` skill (conventional `type(scope): summary` + why-body).
  **Never append a `Co-Authored-By` trailer** — fractalyze convention, overrides the harness default.
- **Secrets**: the GIWA deployer key lives in `.env` (gitignored; template `.env.example`).
  Never commit it; check `git diff --cached` for key material before any push.
- **GPU (rabbitsnark, M1 proving)**: `CUDA_VISIBLE_DEVICES=0`; never profile with
  nsys/command-buffers (leaked 30 GB once); cold zkey-compile is ~116 s, longer than the
  default 2-min Bash timeout — pass `timeout ≥ 300000`; after a run, confirm GPU memory
  returns to idle (~15 MiB) and kill stray prover PIDs.
- **Live pool is canonical**: the deployed GIWA pool (`deploy/addresses.91342.json`) is
  reused going forward — do not redeploy for new work; UUPS upgrade only if circuits change.
- **Heavy gates**: iterate on `packages/core` tests + `tsc`; run `deploy/e2e_m0.sh` and the indexer
  conformance test (`cd apps/indexer && npm test`) as the final gate, not per iteration (each spins
  an anvil + CPU proofs).
- **Indexer arbiter mode**: `AUTHORITY_KEY` (the arbiter bjj private key) flips the indexer
  to arbiter mode — treat that instance as institution-internal (it holds every owner's
  decrypted notes even with `/notes` read-auth). Never log or return the key. Mode
  mechanics: `apps/indexer/README.md`.
- **Arbiter key at deploy**: every committed proof fixture is bound to ONE arbiter key
  (`realproofs.arbiterKey` == disburse256 `public[8..9]` — the `Deploy.s.sol` default). Only
  override `ARBITER_KEY_X/Y` alongside freshly re-proven fixtures, or the smoke deposit
  reverts `InvalidProof`.
- **Local-pass ≠ CI-pass**: hosted runners lack the dev-box defaults (the `BONGTU_NODE_MODULES`
  fallback path, prebuilt `circuits/out` / `contracts/out`, fast spawns). Check any new CI-run
  test against a clean env before pushing — see `.dev/ci.md`.
- **GPU regen recipe** (disburse-256, after a circuit change): compile → `groth16 setup` (CPU,
  ~2.5min, 1.24GB zkey) → export verifier/vkey → witness → `rabbitsnark circom prove` on GPU0
  (cold zkey-compile ~120s + warm proof ~0.47s). Runner: `jolt-zorch/.venv/bin/python -m
  rabbitsnark.cli circom prove <zkey> <proof> <public> --wtns <wtns>` from `rabbitsnark-py`.
