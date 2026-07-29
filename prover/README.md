# bongtu prover service

The GPU proving half of SPEC §6, as a standalone Python FastAPI service over
rabbitsnark (the GPU Groth16 prover, bridged from a local checkout — see
`setup.sh`) held **resident in-process** — each registered zkey is parsed and
GPU-compiled **once at boot**, so every proof after the warm-up is sub-second
GPU time instead of a ~2min cold shell-out.
It replaces the retired prover-cli npm package + payroll-web `prover-helper.ts`
Node shell-out pair.

The service is a **circuit registry** (`prover_service/config.py CIRCUITS`):
one resident engine per registered circuit, `BONGTU_CIRCUITS` (comma list)
choosing which entries boot. Three circuits are registered:

| registry name | wire tag | zkey | publics | why it is here |
|---|---|---|---|---|
| `disburse256` | `disburse` | 1.24GB | 11 | 1×256, 2.79M constraints — **needs** the GPU |
| `transfer10x2` | `transfer10x2` | 95MB | 68 | 10-in/2-out merge/pay leg — CPU-provable, but the employer console proves its **merge chains** here so a payroll run stays on the warm box |
| `deposit` | `deposit` | 6.8MB | 19 | 0-in/2-out funding mint — tiny, rides along because the payroll console does NO in-browser proving: its deposits prove on the same warm box |

This is a **top-level directory, not an npm package**: it is Python, runs only
on the employer's GPU box, and is institution-internal (binds `127.0.0.1` by
default). Browser wallets never talk to it — transfer/withdraw prove **in the
wallet's browser** (a self-custody wallet must never send spending-key
witnesses to a server). Only the employer admin app and the deploy runners POST
here, for `disburse` and for the employer's own `transfer10x2` merge legs —
those legs carry the **employer's** spending-key witness to the
**employer-owned** box, which is the same trust boundary disburse already
crosses, not a user witness leaving a wallet.

## Wire contract

The request/response types live in **`packages/core/src/proving.ts`** (TS source
of truth); `prover_service/schema.py` mirrors them 1:1 and must be kept in sync.

| endpoint | behaviour |
|---|---|
| `GET /healthz` | 200 — process liveness |
| `GET /ready` | 200 `{status:"ready", circuits:["disburse","transfer10x2","deposit"], num_public:{...}, boot_seconds:{...}}` once **every** registered engine is compiled + warm (`circuits` lists wire tags in boot order); 503 `{status:"initializing"\|"failed"}` before/on failure |
| `POST /prove` | body = a `ProvingRequest` (`{circuit:"disburse"\|"transfer10x2", input:{...}, backend?:"gpu"}`, field elements as decimal strings) → 200 `Calldata` `{a,b,c,pub}` — snarkjs `exportSolidityCallData` form (G2 inner-swap applied), every value a 0x 32-byte hex word, splat straight into the matching `BongtuPool` entrypoint |

Witness handling: the service accepts the **circuit input JSON** (exactly what
`apps/payroll-web` assembles and POSTs) and runs circom witness generation
**server-side** (`node circuits/out/<circuit>_js/generate_witness.js`, ~5s CPU
for the 2.79M-constraint disburse256) before the GPU proof. No `.wtns` upload
path exists — no consumer produces one, and the input JSON is what the
employer flow already has in hand.

Errors: 422 = schema violation, **including the §11-8 two-time-pad guard**
(duplicate DISBURSE output owner pubkeys are rejected before any proving work;
transfer10x2 allows duplicates — a self-merge is its headline use); 400 = a
CPU-side circuit (transfer/withdraw) / a registry circuit missing from
this instance's `BONGTU_CIRCUITS` (the detail names the knob) / cpu backend /
unsatisfiable witness input (circom's `Assert Failed` — the client's batch is
at fault); 403 = Origin gate (below); 500 = witness **infra** failure
(missing/stale wasm, broken node, timeout — the service's environment; the
detail names the config knobs to check); 503 = still compiling. The 400-vs-500
classification happens at the witness subprocess seam (`engine.py`), pinned
CPU-only by `tests/test_witness_seam.py`.

## Origin allowlist

`PROVER_ALLOWED_ORIGINS` (comma-separated origins, e.g.
`https://payroll.fractalyze.io`): when set, a `POST /prove` whose `Origin`
header is absent or not in the list is refused **403** with a one-line reason,
and CORS is scoped to the same list; `/healthz` and `/ready` stay open (probes
don't send Origin). When unset, everything is allowed — unchanged local-dev
behavior behind the default loopback bind. Origins compare exactly
(scheme+host+port, trailing-slash tolerant). This stops drive-by browser/bot
use only: any non-browser client can forge Origin, so production hardening is
a private network or request signing
([docs/security-model.md](../docs/security-model.md)).

## Run

Prerequisite: the **gitignored** circuit artifacts must exist under
`circuits/out/` for every circuit in `BONGTU_CIRCUITS` — the `.zkey`
(disburse256 1.24GB, transfer10x2 95MB) plus the `<circuit>_js/`
witness-calculator pair. The CPU build pipeline is in `docs/toolchain.md`; the
GPU regen recipe (after any circuit change) is the "GPU regen recipe" bullet in
the repo `CLAUDE.md` (evidence in `.dev/milestone-m1.md`).

```sh
bash prover/setup.sh    # once: create .venv (python 3.11 + rabbitsnark bridge)
bash prover/run.sh      # boots eagerly (~3min for both circuits), then GET /ready -> 200

# smoke: prove the committed fixture inputs (either circuit)
curl -s http://127.0.0.1:8700/ready
node -e 'const i=require("./circuits/inputs/disburse256.json");
  fetch("http://127.0.0.1:8700/prove",{method:"POST",headers:{"content-type":"application/json"},
  body:JSON.stringify({circuit:"disburse",input:i})}).then(r=>r.json()).then(c=>console.log(c.pub))'
node -e 'const i=require("./circuits/inputs/transfer10x2.json");
  fetch("http://127.0.0.1:8700/prove",{method:"POST",headers:{"content-type":"application/json"},
  body:JSON.stringify({circuit:"transfer10x2",input:i})}).then(r=>r.json()).then(c=>console.log(c.pub))'
```

Consumers: `apps/payroll-web` employer-mode (URL in `src/config.ts`, build-time
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
- **Eager init, never lazy.** Boot compiles each `BONGTU_CIRCUITS` engine in
  order: per circuit `parse_zkey` → `zkey_to_terms` (coefficient table cached —
  `compile_circom` discards it) → `compile_circom` → one warm-up proof against
  its `circuits/inputs/<circuit>.json` fixture (JAX JIT). For disburse256 that
  is ~23s + ~3s + ~2min + ~9s; transfer10x2 adds a small fraction of that
  (95MB zkey). `/ready` flips only after the LAST warm-up lands (measured
  boot-to-ready, disburse256 alone: 144s). A warm disburse `POST /prove` is
  then ~6s wall: ~5s CPU witness-gen + ~0.5s GPU proof.
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
- **`/prove` is unauthenticated** — same posture as the retired prover-helper,
  and the default bind is loopback. Set `PROVER_ALLOWED_ORIGINS` (above) so a
  browser tab ON the employer box cannot fire ~6s prove jobs at it; that gate
  is not authentication (Origin is forgeable outside a browser).
- Orphaned `bongtu-prove-*` scratch dirs (SIGKILL mid-prove) are swept at the
  next boot (`app.py`); they are mode-0700 and same-user only in the interim.

## Env & files

Env knobs (all optional): `PROVER_HOST`/`PROVER_PORT` (127.0.0.1:8700,
consumed by `run.sh`); the rest default in `prover_service/config.py` —
`BONGTU_CIRCUITS` (comma list of registry names, default
`disburse256,transfer10x2,deposit`), `PROVER_ALLOWED_ORIGINS` (unset = allow all),
`BONGTU_CIRCUITS_OUT`, per-circuit path overrides
(`BONGTU_DISBURSE_ZKEY`/`_WASM`/`_GEN_WITNESS` + the legacy-named
`BONGTU_WARMUP_INPUT`; `BONGTU_TRANSFER10X2_ZKEY`/`_WASM`/`_GEN_WITNESS`/
`_WARMUP_INPUT`; same family under `BONGTU_DEPOSIT_*`), `BONGTU_NODE_BIN`, `BONGTU_WITNESS_TIMEOUT` (seconds,
default 300), `PROVER_DETERMINISTIC` (=1 for byte-stable test proofs).

```
setup.sh                 one-time .venv + rabbitsnark/jax bridge (.pth)
run.sh                   foreground uvicorn (GPU0, single-process)
prover_service/
  app.py                 FastAPI app: /healthz /ready /prove, origin gate,
                         per-circuit engine routing, init thread, prove lock
  engine.py              CircuitProver: boot compile + per-request prove,
                         one per registered circuit
  schema.py              pydantic mirror of @bongtu/core/proving (keep in sync!)
  calldata.py            snarkjs exportSolidityCallData-compatible formatting
                         (+ per-circuit pub-length check from the registry)
  config.py              circuit registry + env-resolved paths/origins
                         (pins CUDA_VISIBLE_DEVICES=0)
tests/                   CPU-only unit gates: .venv/bin/python -m pytest  (no GPU)
```

The venv bridges to the **read-only** rabbitsnark/jax installs via a `.pth`
file instead of pip-installing them — see `setup.sh` for why and for the
overridable machine paths.

## License

Apache-2.0 — see the root [`LICENSE`](../LICENSE).
