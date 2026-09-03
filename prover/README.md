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
| `GET /auth/check` | the payroll console's sign-in probe: 200 `{ok:true}` when the request's Basic credentials pass the auth gate (or `PROVER_AUTH_SHA256` is unset); 401 otherwise. Costs nothing — proves a credential without proving a circuit |
| `POST /prove` | body = a `ProvingRequest` (`{circuit:"disburse"\|"transfer10x2", input:{...}, backend?:"gpu"}`, field elements as decimal strings) → 200 `Calldata` `{a,b,c,pub}` — snarkjs `exportSolidityCallData` form (G2 inner-swap applied), every value a 0x 32-byte hex word, splat straight into the matching `BongtuPool` entrypoint |

Witness handling: the service accepts the **circuit input JSON** (exactly what
`apps/payroll-web` assembles and POSTs) and computes the witness server-side
with the **compiled rabbitsnark witness calculator**
(`circuits/out/lib<circuit>.so` + `<circuit>_w2s.json`, built by
`circuits/build/build_witness_so.sh`): ~1s CPU for the 2.79M-constraint disburse256,
~5x faster than the retired `node generate_witness.js` (WASM) subprocess it
replaced (U-P5), with an elementwise-identical witness vector (gate below). No
`.wtns` upload path exists — no consumer produces one, and the input JSON is
what the employer flow already has in hand.

### Byte-identity gate

Swapping witness calculators is only safe if the new one computes the SAME
vector: a wrong witness does not fail, it proves a different statement, and
Groth16 has no way to tell you so. `circuits/build/wtns_compare.py` (stdlib-only, no
venv needed) is the check — run it after any change to the .so pipeline or the
circuits, against the WASM calculator as the reference:

```sh
# 1. reference: the WASM calculator's own .wtns (~6s for disburse256)
node circuits/out/disburse256_js/generate_witness.js \
  circuits/out/disburse256_js/disburse256.wasm \
  circuits/fixtures/inputs/disburse256.json /tmp/ref.wtns

# 2. candidate: the bytes the service's witness seam actually returns (~1s)
(cd prover && .venv/bin/python -c '
import json
from prover_service import config
from prover_service.witness import WitnessHost
c = config.CIRCUITS["disburse256"]
h = WitnessHost(c); h.start()
open("/tmp/new.bin", "wb").write(h.compute(json.loads(c.warmup_input.read_text())))
h.close()')

# 3. compare element by element (exit 1 names the first differing index)
python3 circuits/build/wtns_compare.py /tmp/ref.wtns /tmp/new.bin
# BYTE-IDENTICAL: 2796497 witness elements (89487904 bytes)
```

Substitute `transfer10x2` / `deposit` (and their `circuits/fixtures/inputs/*.json`) for
the other registry circuits (disbursePriv256 included). Boot enforces the weaker half of this
automatically: `engine.py` refuses to serve a circuit whose .so witness length
disagrees with its zkey's `num_vars`, the drift a stale half of the artifact
pair produces (measured: 2796497 / 212695 / 14132 / 3049668 for the four registry circuits).

**Why the calculator runs in a resident WORKER process, not the service
process** (the U-P5 decision record): a circom constraint failure inside the
compiled .so is a `cf.assert`, which lowers to
`puts("assertion failed at line N"); abort()` — literally in-process, one
unsatisfiable client request would SIGABRT the whole ~25GB resident GPU prover
(a 2.5min reboot = a DoS by bad batch). So each engine holds a small resident
CPU worker (`witness_worker.py`, loads the .so + w2s once, ~1s warm compute
over pipes, no input JSON spooled to disk); on a constraint failure the WORKER
aborts, the parent (`witness.py WitnessHost`) reads the assert line off its
stderr for the 400 detail and respawns it. The node/WASM subprocess path is
**deleted**, not kept as a fallback: the worker's stderr carries the same
class of diagnostic (`assertion failed at line N` vs WASM's
`Assert Failed ... line: N`), so nothing needed the old path.

Errors: 422 = schema violation, **including the §11-8 two-time-pad guard**
(duplicate DISBURSE output owner pubkeys are rejected before any proving work;
transfer10x2 allows duplicates — a self-merge is its headline use); 400 = a
CPU-side circuit (transfer/withdraw) / a registry circuit missing from
this instance's `BONGTU_CIRCUITS` (the detail names the knob) / cpu backend /
unsatisfiable witness input (the calculator's `assertion failed` — the
client's batch is at fault) / input JSON whose keys or element counts don't
fit the circuit; 403 = Origin gate (below); 500 = witness **infra** failure
(missing/stale .so or w2s, a crashed or wedged worker — the service's
environment; the detail names the config knobs to check); 503 = still
compiling. The 400-vs-500 classification happens at the witness worker seam
(`witness.py`), pinned CPU-only by `tests/test_witness_seam.py`.

## Auth (`PROVER_AUTH_SHA256`) and the Origin allowlist

Two request gates, composable — a `POST /prove` must pass BOTH; each is a no-op
while its env knob is unset (unchanged local-dev behavior behind the loopback
bind).

**`PROVER_AUTH_SHA256`** — hex `sha256("id:password")` of the ONE shared
operator credential (single-employer PoC). When set, `POST /prove` and
`GET /auth/check` require a valid HTTP Basic `Authorization` header: the
decoded `id:password` is sha256'd and compared against the env value in
constant time (`hmac.compare_digest`), and a failure is answered **401** after
a ~0.3s pause (a cheap brake on guessing over the funnel). `/healthz` and
`/ready` stay unauthenticated. This is the gate that actually authenticates —
it holds against any client, browser or not. The payroll console's login page
is a client of exactly this: it validates the typed id/password against
`/auth/check` and rides the same Basic value on every `/prove`. Mint the value
without echoing the credential into shell history, e.g.:

```sh
python3 -c 'import getpass,hashlib;print(hashlib.sha256(getpass.getpass("id:password? ").encode()).hexdigest())'
```

The credential itself never appears in the repo or its tests — tests mint
throwaway pairs. The production systemd unit (below) carries the env value.

**`PROVER_ALLOWED_ORIGINS`** (comma-separated origins, e.g.
`https://payroll.fractalyze.io`): when set, a `POST /prove` whose `Origin`
header is absent or not in the list is refused **403** with a one-line reason,
and CORS is scoped to the same list; `/healthz` and `/ready` stay open (probes
don't send Origin). Origins compare exactly (scheme+host+port, trailing-slash
tolerant). This stops drive-by browser/bot use only: any non-browser client
can forge Origin — the Basic auth above is the real gate
([docs/security-model.md](../docs/security-model.md)).

## Run

Prerequisite: the **gitignored** circuit artifacts must exist under
`circuits/out/` for every circuit in `BONGTU_CIRCUITS` — the `.zkey`
(disburse256 1.24GB, transfer10x2 95MB) plus the `lib<circuit>.so` +
`<circuit>_w2s.json` witness-calculator pair
(`cd circuits && bash build/build_witness_so.sh` — toolchain paths and the
patched-fork caveat are documented in that script; ~2min per circuit). The
zkey CPU build pipeline is in `docs/toolchain.md`; the GPU regen recipe (after
any circuit change) is the "GPU regen recipe" bullet in the repo `CLAUDE.md`
(evidence in `.dev/milestone-m1.md`). **After a circuit change, rebuild BOTH
the zkey and the .so pair, and re-derive the registry's `input_order` if the
circuit's input signals changed** (`prover_service/config.py` documents how).

```sh
bash prover/setup.sh    # once: create .venv (python 3.11 + rabbitsnark bridge)
bash prover/run.sh      # boots eagerly (~3min for both circuits), then GET /ready -> 200

# smoke: prove the committed fixture inputs (either circuit)
curl -s http://127.0.0.1:8700/ready
node -e 'const i=require("./circuits/fixtures/inputs/disburse256.json");
  fetch("http://127.0.0.1:8700/prove",{method:"POST",headers:{"content-type":"application/json"},
  body:JSON.stringify({circuit:"disburse",input:i})}).then(r=>r.json()).then(c=>console.log(c.pub))'
node -e 'const i=require("./circuits/fixtures/inputs/transfer10x2.json");
  fetch("http://127.0.0.1:8700/prove",{method:"POST",headers:{"content-type":"application/json"},
  body:JSON.stringify({circuit:"transfer10x2",input:i})}).then(r=>r.json()).then(c=>console.log(c.pub))'
```

Consumers: `apps/payroll-web` employer-mode (URL in `src/config.ts`, build-time
override `VITE_PROVER_URL`) and the `deploy/live/` drivers
(`BONGTU_PROVER_URL`). If `circuits/fixtures/inputs/disburse256.json` is missing,
regenerate it: `npx tsx circuits/fixtures/gen_disburse256_input.ts`.

## Production run on the GPU box (as deployed 2026-07-29)

The live instance is a **systemd user service** so a crash or reboot cannot
silently kill proving (`loginctl` linger is on for this box):

```sh
# unit: ~/.config/systemd/user/bongtu-prover.service
#   run.sh, CUDA_VISIBLE_DEVICES=0, Restart=on-failure (30s backoff),
#   MemoryMax=16G host-side, PROVER_ALLOWED_ORIGINS = the payroll origins,
#   PROVER_AUTH_SHA256 = sha256 of the operator "id:password" (the value is
#   set on the box only — never committed anywhere)
systemctl --user status bongtu-prover    # logs: journalctl --user -u bongtu-prover
```

Exposure is a **path mount on the existing indexer funnel port** (funnel can
only use 443/8443/10000, and all three are taken):

```sh
tailscale funnel --bg --https=10000 --set-path=/prover http://127.0.0.1:8700
```

so `https://gpu-server.tailec11d1.ts.net:10000/prover/*` reaches the service
with the `/prover` prefix STRIPPED, and the payroll `vercel.json` rewrites
`/prover/:path*` to that URL (the browser's Origin header rides through the
rewrite — that is what the allowlist gates). Footgun: removing a path mount
with `tailscale serve ... off` DOWNGRADES port 10000 from Funnel to
tailnet-only and cuts the LIVE indexer off the public internet — after any
mount change, re-check `tailscale serve status` says "Funnel on" and curl the
public indexer /health.

## Ops invariants (measured, do not relax)

- **One instance per GPU, single-process uvicorn.** The compiled prover pins
  ~25GB of the 32GB GPU for the life of the process (the zkx PJRT plugin
  ignores `XLA_PYTHON_CLIENT_PREALLOCATE`). run.sh pins `--workers 1`
  explicitly — with the flag absent uvicorn falls back to the `WEB_CONCURRENCY`
  env var, and a workers supervisor both multiplies the GPU footprint (OOM at
  2) and orphans its worker on kill. Never raise it. Proves are serialized by
  an in-process lock.
- **Eager init, never lazy.** Boot compiles each `BONGTU_CIRCUITS` engine in
  order: per circuit witness-worker spawn (loads the .so + w2s resident) →
  `parse_zkey` → `zkey_to_terms` (coefficient table cached — `compile_circom`
  discards it) → `compile_circom` → one warm-up proof against its
  `circuits/fixtures/inputs/<circuit>.json` fixture (JAX JIT). For disburse256 that
  is ~2s + ~23s + ~3s + ~2min + ~9s; transfer10x2 adds a small fraction of
  that (95MB zkey). `/ready` flips only after the LAST warm-up lands. A warm
  disburse `POST /prove` is then ~2s wall: ~1s in-process CPU witness compute
  + ~0.5s GPU proof (was ~6s on the retired node/WASM witness path).
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
- **Auth is one shared credential** — `PROVER_AUTH_SHA256` gates `/prove`
  behind a single operator id/password (fine for a single-employer PoC; leave
  it unset for loopback-only local dev). Production would use per-user
  SSO/OIDC. Keep `PROVER_ALLOWED_ORIGINS` set alongside it so browser drive-bys
  are refused before they even reach a credential prompt.

## Env & files

Env knobs (all optional): `PROVER_HOST`/`PROVER_PORT` (127.0.0.1:8700,
consumed by `run.sh`); the rest default in `prover_service/config.py` —
`BONGTU_CIRCUITS` (comma list of registry names, default
`disburse256,transfer10x2,deposit`), `PROVER_ALLOWED_ORIGINS` (unset = allow all),
`PROVER_AUTH_SHA256` (hex sha256 of "id:password"; unset = no auth),
`BONGTU_CIRCUITS_OUT`, per-circuit path overrides
(`BONGTU_DISBURSE_ZKEY`/`_SO`/`_W2S`, `BONGTU_DISBURSEPRIV_ZKEY`/`_SO`/`_W2S`/`_WARMUP_INPUT` for the opt-in consumer circuit, + the legacy-named
`BONGTU_WARMUP_INPUT`; `BONGTU_TRANSFER10X2_ZKEY`/`_SO`/`_W2S`/
`_WARMUP_INPUT`; same family under `BONGTU_DEPOSIT_*`),
`BONGTU_WITNESS_TIMEOUT` (seconds, default 300), `PROVER_DETERMINISTIC` (=1
for byte-stable test proofs).

```
setup.sh                 one-time .venv + rabbitsnark/jax bridge (.pth)
run.sh                   foreground uvicorn (GPU0, single-process)
prover_service/
  app.py                 FastAPI app: /healthz /ready /prove, origin gate,
                         per-circuit engine routing, init thread, prove lock
  engine.py              CircuitProver: boot compile + per-request prove,
                         one per registered circuit
  witness.py             WitnessHost: the resident witness-worker seam +
                         the 400-vs-500 fault classification
  witness_worker.py      the CPU worker process: compiled .so calculator,
                         one resident per engine (takes the constraint-abort
                         so the GPU process never does)
  schema.py              pydantic mirror of @bongtu/core/proving (keep in sync!)
  calldata.py            snarkjs exportSolidityCallData-compatible formatting
                         (+ per-circuit pub-length check from the registry)
  config.py              circuit registry (incl. per-circuit input_order) +
                         env-resolved paths/origins (pins CUDA_VISIBLE_DEVICES=0)
tests/                   CPU-only unit gates: .venv/bin/python -m pytest  (no GPU)
```

The venv bridges to the **read-only** rabbitsnark/jax installs via a `.pth`
file instead of pip-installing them — see `setup.sh` for why and for the
overridable machine paths.

## License

Apache-2.0 — see the root [`LICENSE`](../LICENSE).
