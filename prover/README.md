# bongtu prover service

The GPU proving half of SPEC §6, as a standalone Python FastAPI service over
rabbitsnark (the GPU Groth16 prover, bridged from a local checkout — see
`setup.sh`) held **resident in-process** — the 1.24GB disburse256 zkey is
parsed and GPU-compiled **once at boot**, so every proof after the warm-up is
sub-second GPU time instead of a ~2min cold shell-out.
It replaces the retired prover-cli npm package + admin-web `prover-helper.ts`
Node shell-out pair.

This is a **top-level directory, not an npm package**: it is Python, runs only
on the employer's GPU box, and is institution-internal (binds `127.0.0.1` by
default). Browser wallets never talk to it — transfer/withdraw prove **in the
wallet's browser** (a self-custody wallet must never send spending-key
witnesses to a server); only the employer admin app and the deploy runners POST
here, and only for `disburse`.

## Wire contract

The request/response types live in **`packages/sdk/src/proving.ts`** (TS source
of truth); `prover_service/schema.py` mirrors them 1:1 and must be kept in sync.

| endpoint | behaviour |
|---|---|
| `GET /healthz` | 200 — process liveness |
| `GET /ready` | 200 `{status:"ready", circuits:["disburse"], boot_seconds:{...}}` once compiled + warm; 503 `{status:"initializing"\|"failed"}` before/on failure |
| `POST /prove` | body = a `ProvingRequest` (`{circuit:"disburse", input:{...}, backend?:"gpu"}`, field elements as decimal strings) → 200 `Calldata` `{a,b,c,pub}` — snarkjs `exportSolidityCallData` form (G2 inner-swap applied), every value a 0x 32-byte hex word, splat straight into `pool.disburseWithCiphertexts` |

Witness handling: the service accepts the **circuit input JSON** (exactly what
`apps/admin-web` assembles and POSTs) and runs circom witness generation
**server-side** (`node circuits/out/disburse256_js/generate_witness.js`, ~5s
CPU for the 2.79M-constraint circuit) before the GPU proof. No `.wtns` upload path exists — no consumer produces
one, and the input JSON is what the employer flow already has in hand.

Errors: 422 = schema violation, **including the §11-8 two-time-pad guard**
(duplicate output owner pubkeys are rejected before any proving work); 400 =
non-disburse circuit / cpu backend / unsatisfiable witness input (circom's
`Assert Failed` — the client's batch is at fault); 500 = witness **infra**
failure (missing/stale wasm, broken node, timeout — the service's environment;
the detail names the config knobs to check); 503 = still compiling. The
400-vs-500 classification happens at the witness subprocess seam
(`engine.py`), pinned CPU-only by `tests/test_witness_seam.py`.

## Run

Prerequisite: the **gitignored** circuit artifacts must exist under
`circuits/out/` — `disburse256.zkey` (1.24GB) plus the `disburse256_js/`
witness-calculator pair. The CPU build pipeline is in `docs/toolchain.md`; the
GPU regen recipe (after any circuit change) is the "GPU regen recipe" bullet in
the repo `CLAUDE.md` (evidence in `docs/milestone-m1.md`).

```sh
bash prover/setup.sh    # once: create .venv (python 3.11 + rabbitsnark bridge)
bash prover/run.sh      # boots eagerly (~2.5min), then GET /ready -> 200

# smoke: prove the committed fixture input
curl -s http://127.0.0.1:8700/ready
node -e 'const i=require("./circuits/inputs/disburse256.json");
  fetch("http://127.0.0.1:8700/prove",{method:"POST",headers:{"content-type":"application/json"},
  body:JSON.stringify({circuit:"disburse",input:i})}).then(r=>r.json()).then(c=>console.log(c.pub))'
```

Consumers: `apps/admin-web` employer-mode (URL in `src/config.ts`, build-time
override `VITE_PROVER_URL`) and `deploy/giwa_disburse256.ts`
(`BONGTU_PROVER_URL`). If `circuits/inputs/disburse256.json` is missing,
regenerate it: `cd circuits && npx tsx gen_disburse256_input.ts`.

## Ops invariants (measured, do not relax)

- **One instance per GPU, single-process uvicorn.** The compiled prover pins
  ~25GB of the 32GB GPU for the life of the process (the zkx PJRT plugin
  ignores `XLA_PYTHON_CLIENT_PREALLOCATE`). run.sh pins `--workers 1`
  explicitly — with the flag absent uvicorn falls back to the `WEB_CONCURRENCY`
  env var, and a workers supervisor both multiplies the GPU footprint (OOM at
  2) and orphans its worker on kill. Never raise it. Proves are serialized by
  an in-process lock.
- **Eager init, never lazy.** Boot = `parse_zkey` (~23s) → `zkey_to_terms`
  (~3s, the coefficient table is cached — `compile_circom` discards it) →
  `compile_circom` (~2min) → one warm-up proof against
  `circuits/inputs/disburse256.json` (~9s incl. witness-gen; JAX JIT). `/ready`
  flips only after the warm-up lands (measured boot-to-ready: 144s). A warm
  `POST /prove` is then ~6s wall: ~5s CPU witness-gen + ~0.5s GPU proof.
- **GPU 0 only** (`CUDA_VISIBLE_DEVICES=0`, set in `config.py` before any jax
  import), never profiled with nsys (CLAUDE.md GPU contract).

## Known limitations (accepted for the PoC, single-employer usage)

- **Sync handlers share one threadpool.** `/prove` blocks a worker thread on
  the prove lock with no queue bound, so ~40 stacked requests would also starve
  `/healthz` `/ready`; a wedged GPU prove holds the lock indefinitely (only
  witness-gen has a timeout). Fine for one employer console; bound the queue
  before any multi-tenant use.
- **A GPU fault mid-prove does not downgrade `/ready`.** The request fails but
  the service still reports ready; restart the process on repeated 5xx.
- **CORS is `*` and `/prove` is unauthenticated** — same posture as the retired
  prover-helper, and the default bind is loopback, but any browser tab ON the
  employer box can fire ~6s prove jobs at it. Scope `allow_origins` to the
  admin-web origin if that box browses the open web.
- Orphaned `bongtu-prove-*` scratch dirs (SIGKILL mid-prove) are swept at the
  next boot (`app.py`); they are mode-0700 and same-user only in the interim.

## Env & files

Env knobs (all optional): `PROVER_HOST`/`PROVER_PORT` (127.0.0.1:8700,
consumed by `run.sh`); the rest default in `prover_service/config.py` —
`BONGTU_CIRCUITS_OUT`,
`BONGTU_DISBURSE_ZKEY`, `BONGTU_DISBURSE_WASM`, `BONGTU_DISBURSE_GEN_WITNESS`,
`BONGTU_WARMUP_INPUT`, `BONGTU_NODE_BIN`, `BONGTU_WITNESS_TIMEOUT` (seconds,
default 300), `PROVER_DETERMINISTIC` (=1 for byte-stable test proofs).

```
setup.sh                 one-time .venv + rabbitsnark/jax bridge (.pth)
run.sh                   foreground uvicorn (GPU0, single-process)
prover_service/
  app.py                 FastAPI app: /healthz /ready /prove, init thread, prove lock
  engine.py              Disburse256Prover: boot compile + per-request prove
  schema.py              pydantic mirror of @bongtu/sdk/proving (keep in sync!)
  calldata.py            snarkjs exportSolidityCallData-compatible formatting
  config.py              env-resolved paths/ports (pins CUDA_VISIBLE_DEVICES=0)
tests/                   CPU-only unit gates: .venv/bin/python -m pytest  (no GPU)
```

The venv bridges to the **read-only** rabbitsnark/jax installs via a `.pth`
file instead of pip-installing them — see `setup.sh` for why and for the
overridable machine paths.
