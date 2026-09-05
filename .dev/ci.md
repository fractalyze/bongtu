# CI design — hosted gates, cache soundness, pins

The authoritative per-job list — which jobs run, which gates are excluded, and the
per-job mechanics — is the header comment of
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml); it is not restated here.
This file owns the design decisions behind that shape.

## Selection rule

One rule decides inclusion: **a job runs iff a GitHub-hosted ubuntu runner can
genuinely pass it** — no soft-fail jobs, no gates that pass by skipping their point.
Three exclusion classes fall out:

- **GPU** — rabbitsnark disburse256 proving and the prover service boot need a local
  CUDA GPU and the local venv bridge.
- **Secrets** — live-chain deploys need the funded deployer key from the gitignored
  `.env`; the workflow is deliberately secret-free (`permissions: contents: read`,
  actions pinned to commit SHAs, `--ignore-scripts` on the scratch installs).
- **Cost without a consumer** — the 1.24GB disburse256 zkey build is multi-minute and
  its only consumer is the excluded GPU path.

Excluded is not ungated: the on-chain half of disburse256 is still verified hosted,
via the committed real-proof fixtures in the forge job.

## Artifact-cache soundness

`snarkjs groth16 setup` is **deterministic given (r1cs, ptau)**. That is evidence, not
assumption: a fresh-clone simulation with the pinned toolchain (circom v2.2.2 release
binary, zeto @ `2c8ce6b7`, circomlib 2.0.5, the sha256-pinned pot22 ptau) reproduced
the committed verifier `.sol` files **byte-identically**. Two consequences:

1. Fresh zkeys produce proofs that verify against the committed on-chain verifiers —
   so a from-scratch CI build genuinely gates the committed contracts.
2. `circuits/out` (~266MB) is cacheable, and a cache hit cannot hide drift: drift can
   only appear when circuit sources or pins change, which is exactly the cache-*miss*
   path — where the `git diff --exit-code circuits/verifiers` drift gate runs on every
   rebuild.

The 4.8GB ptau is touched only on the miss path. (The old Hermez S3 ptau URL now 403s;
the pinned GCS zkevm mirror is used, checksum-verified, with a one-shot re-download on
a corrupt cache entry.)

## Pins are data: `.github/ci-pins.env`

Toolchain pins live in one env file, sourced into `GITHUB_ENV` and **hashed into the
cache keys** — so a pin bump invalidates the circuit-artifact and extdeps caches with
no workflow edit, and a workflow edit does not spuriously invalidate warm artifacts.
Gotcha already paid for (`478c670`): the loader's key grep must be `^[A-Z0-9_]+=` —
the original `^[A-Z_]+=` silently dropped exactly the two keys containing digits
(`CIRCOM_SHA256`, `PTAU_SHA256`), handing the checksum step an empty expected hash.

## Wall time

Budget: warm push ≤ ~3min (stated in the ci.yml header). Measured: **warm ≈170s**
wall — jobs run in parallel and the node job is the long pole; when the ingest test's
extdeps+forge steps crept into it (~177s) the suite moved to its own parallel
`indexer-units` job (`fd4e797`). A circuits/pins change pays a one-time cold rebuild —
**measured ≈6–8min** (the header budgets ~10–12 conservatively) — then re-warms the
cache. `workflow_dispatch` exists so a warm run can be triggered without a push.

## The hosted-gap lesson

Getting the gates green took **three local-pass / CI-fail rounds, all with one root
cause: dev-box default paths mask hosted dependencies.**

- `d69aeac` — the anvil-free ingest test loads ethers through the
  `BONGTU_NODE_MODULES` external-require seam; the dev-box default path exists
  locally, the runner had no extdeps.
- `c61e6f2` — the same test reads the gitignored forge pool-ABI artifact
  (`contracts/out`) that only existed on the dev box.
- `c83dcf0` — a 2s witness-timeout fixture assumed dev-box spawn speed; a cold node
  spawn on a 2-core hosted runner exceeded it on the *success* leg.

Rule going forward: when adding or changing a CI-run test, check it against a clean
environment — no `BONGTU_NODE_MODULES` fallback, no prebuilt `circuits/out` or
`contracts/out`, no generous-timeout assumptions — and re-run the fresh-clone
simulation for circuits-side changes.

## Restored cargo caches can serve stale build ARTIFACTS

The solana cargo cache (`chains/solana/target`) is keyed on Cargo.lock +
rust-toolchain.toml, so a source-only program change restores a target dir
whose `deploy/*.so` was built from ANOTHER commit. Any gate that skips its
build when the artifact file exists will run the stale binary (e2e-solana
failed InvalidDiscriminator this way on PR #69 while solana-mollusk passed,
because mollusk.sh always rebuilds). Rule: gates build unconditionally and
rely on cargo's incremental no-op, never on artifact-file existence.
Second rule from the same incident: the Agave 4.2.2 release tarball ships its
OWN cargo-build-sbf, and it HARD-FAILS on transfer10x2's 4,608-byte frame
(the pinned v3.1.14 toolchain only warns). e2e_s.sh therefore pins its
builder to active_release (AGAVE_BIN) and uses the v1 release bin ONLY for
solana-test-validator. Any toolchain pin bump is blocked on the frame fix
(tracked as a gh issue).
