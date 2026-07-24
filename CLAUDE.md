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
- **Heavy gates**: iterate on `sdk` tests + `tsc`; run `deploy/e2e_m0.sh` and the indexer
  conformance test as the final gate, not per iteration (each spins an anvil + CPU proofs).
- **Indexer modes**: the indexer runs *public* (no key) by default; setting `AUTHORITY_KEY`
  (the arbiter bjj private key) flips it to *arbiter mode* — it then decrypts every op's
  authority envelope, serves `GET /notes?owner=` and within-batch `/path`, and must be treated
  as institution-internal (unauthenticated `/notes` exposes every owner until the deferred
  bjj-sig auth lands). Never log or return the key.
- **GIWA redeploy arbiter key**: deploy with `ARBITER_KEY_X/Y` matching the smoke proof's key
  (the committed deposit proof is bound to the realproofs authority key, not the disburse256
  default) or the smoke deposit reverts `InvalidProof`.
- **GPU regen recipe** (disburse-256, after a circuit change): compile → `groth16 setup` (CPU,
  ~2.5min, 1.24GB zkey) → export verifier/vkey → witness → `rabbitsnark circom prove` on GPU0
  (cold zkey-compile ~120s + warm proof ~0.47s). Runner: `jolt-zorch/.venv/bin/python -m
  rabbitsnark.cli circom prove <zkey> <proof> <public> --wtns <wtns>` from `rabbitsnark-py`.
