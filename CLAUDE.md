# CLAUDE.md

Read `README.md` once at session start, then follow its `## Docs` index. `docs/`
owns system guarantees and inter-component contracts (one file per topic); each
folder's own `README.md` owns how to run and test that folder. Decision history
and milestone trackers live in `.dev/` — including `.dev/spec-decisions.md`, the
retired spec whose section numbers the `SPEC §n` comments in code still cite. Do
not re-derive what those files own.

## Rules an agent cannot see from code + README

- **PATH**: `forge`/`anvil`/`node` are not on the default PATH. Prefix gate runs with
  `export PATH=$HOME/.foundry/bin:$HOME/.nvm/versions/node/v22.17.1/bin:$PATH`.
- **External node_modules**: `snarkjs`/`circomlibjs` load via `createRequire` from
  `BONGTU_NODE_MODULES` (default `/home/a41/Workspace/zkx-snap/circuits/node_modules`) —
  there is no repo-local install for them. On another machine, set the env var. (ethers is
  gone repo-wide: every chain path is now viem, a normal dependency; `loadEthers` was removed.)
- **const-only TypeScript**: `let` is banned in code (comment prose exempt) — express
  loops/accumulation as `for (const … of Array(n).keys())`, `reduce`, or an IIFE
  `const x = (() => { … })()`. Behavior-neutral conversions only; crypto folds keep
  their iteration order.
- **Commits**: use the `workflow:commit` skill (conventional `type(scope): summary` + why-body).
  **Never append a `Co-Authored-By` trailer** — fractalyze convention, overrides the harness default.
- **Secrets**: the deployer key for the live chain lives in `.env` (gitignored; template
  `.env.example`). Never commit it; check `git diff --cached` for key material before any push.
- **GPU (rabbitsnark, M1 proving)**: `CUDA_VISIBLE_DEVICES=0`; never profile with
  nsys/command-buffers (leaked 30 GB once); cold zkey-compile is ~116 s, longer than the
  default 2-min Bash timeout — pass `timeout ≥ 300000`; after a run, confirm GPU memory
  returns to idle (~15 MiB) and kill stray prover PIDs.
- **Live pool is canonical**: the pool recorded in `deploy/addresses.84532.json` — mirrored into
  `packages/core/src/network.ts`, which `packages/core/test/network.test.ts` holds to that file
  field-for-field — is the deployment everything runs against. Reuse it; do not redeploy for new
  work. A circuit change ships as a UUPS `upgradeToAndCall` carrying a fresh `reinitializer(2)`
  payload; there is no initializer ladder, `initialize()` alone produces the production shape.
  **Never transcribe an address by pattern-matching an older value** — the deployer replayed the
  same CREATE nonces on the previous chain, so several addresses collide across the two while
  naming *different* contracts. Copy from the record BY FIELD NAME.
- **Gate runs in background**: never pipe a gate through `| tail` when backgrounding —
  the pipeline rc becomes tail's and a FAILED gate reports exit 0 (this shipped a
  false-green once). Redirect to a log file and `exit $RC`, then read the file.
- **Heavy gates**: iterate on `packages/core` tests + `tsc` + `npm run typecheck --workspaces --if-present`
  (vite build and the root tsc project both MISS per-workspace typecheck errors — one shipped red to CI);
  run `deploy/gates/e2e_m0.sh` and the indexer
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
  test against a clean env before pushing — see `.dev/ci.md`. In particular, refresh
  `apps/indexer/abi/BongtuPool.abi.json` whenever the pool ABI changes (CI drift-gates it).
- **package-lock.json regen**: npm 11.5 on this box reuses the actual node_modules tree and
  silently DROPS the ~49 cross-platform optional entries (@esbuild/*, @rollup/rollup-*) —
  the box tolerates it but Vercel's `npm ci` rejects the lock and every git-integration
  deploy breaks. Never regen the lock casually; to regen, copy package.json + all workspace
  package.jsons (NO node_modules, NO old lock) to a scratch dir, `npm install
  --package-lock-only` there, copy back. Adding a dep with the complete lock as base is safe
  (verified) — after any lock-touching operation, diff against the old lock (a workspace/dep add
  should only ADD lines) and check the optional-entry counts are unchanged: 26 `node_modules/@esbuild/`
  + 25 `node_modules/@rollup/rollup-` (the "~49" above is their sum, not an @esbuild-only count).
- **Pushing workflow-file changes**: the dev checkout's git PAT lacks the `workflow` scope —
  a push touching `.github/workflows/*` is rejected. Push those with the gh CLI token:
  `GHTOKEN=$(gh auth token); git -c credential.helper= -c "http.https://github.com/.extraheader=Authorization: Basic $(printf "x-access-token:%s" "$GHTOKEN" | base64 -w0)" push origin main`.
- **GPU regen recipe** (disburse-256, after a circuit change): compile → `groth16 setup` (CPU,
  ~2.5min, 1.24GB zkey) → export verifier/vkey → witness → `rabbitsnark circom prove` on GPU0
  (cold zkey-compile ~120s + warm proof ~0.47s). Runner: `jolt-zorch/.venv/bin/python -m
  rabbitsnark.cli circom prove <zkey> <proof> <public> --wtns <wtns>` from `rabbitsnark-py`.
  A circuit change ALSO requires rebuilding that circuit's witness `.so` + `w2s`
  (`circuits/build/build_witness_so.sh`) — the prover service fails at boot without a matching pair.

