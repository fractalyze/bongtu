# The bongtu prover service — FastAPI over resident CircuitProvers.
#
# Serves the shared ProvingRequest wire contract (packages/core/src/proving.ts is
# the TS source of truth; schema.py mirrors it):
#
#   GET  /healthz    -> 200 {"ok": true}                  liveness (process up)
#   GET  /ready      -> 200 {"status": "ready", ...}      every engine compiled + warm
#                       503 {"status": "initializing"|"failed", ...} otherwise
#   GET  /auth/check -> 200 {"ok": true}                  the payroll console's
#                           sign-in probe: valid Basic credentials (or auth
#                           unset) — costs nothing, proves the credential
#                       401 PROVER_AUTH_SHA256 set and the Authorization
#                           header is absent/malformed/wrong
#   POST /prove      -> 200 Calldata {a, b, c, pub}       prove a ProvingRequest
#                       400 CPU-side circuit (deposit/transfer/withdraw — never
#                           served here) / a registry circuit not in
#                           BONGTU_CIRCUITS on this instance / cpu backend /
#                           unsatisfiable witness input (client fault)
#                       401 auth gate (PROVER_AUTH_SHA256 set and the Basic
#                           credentials absent or wrong — served after a short
#                           delay, before the Origin gate or the body)
#                       403 Origin gate (PROVER_ALLOWED_ORIGINS set and the
#                           request's Origin is absent or not allowed)
#                       422 schema violation (incl. the §11-8 two-time-pad guard)
#                       500 witness infra failure (bad .so/w2s, crashed or wedged
#                           witness worker — the service's environment, never the
#                           client's batch)
#                       503 engines not ready yet
#
# Circuits: one resident engine per BONGTU_CIRCUITS registry name
# (config.CIRCUITS — disburse256 + transfer10x2 + deposit by default). disburse
# (1×256, 2.79M constraints) NEEDS the GPU; transfer10x2 and deposit ride along
# so the employer console — which does no in-browser proving at all — runs its
# whole merge-and-fund flow on the same warm box. transfer/withdraw prove in
# the wallet's browser (a self-custody wallet never sends spending-key witnesses
# to a server).
#
# Ops shape (from the measured GPU contract): the compiled disburse256 prover
# pins ~25GB of GPU memory, so run EXACTLY ONE instance per GPU with ONE uvicorn
# worker, and ALL proves — across every engine — are serialized by one
# in-process lock. Init is EAGER: a background thread compiles every registered
# engine at boot, in BONGTU_CIRCUITS order (never lazy on first request);
# /ready flips once the last warm-up proof lands.

from __future__ import annotations

import asyncio
import threading
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import config
from .engine import CircuitProver
from .schema import Calldata, ProvingRequest
from .witness import WitnessGenerationError, WitnessInfraError

engines: dict[str, CircuitProver] = {
    name: CircuitProver(config.CIRCUITS[name]) for name in config.ENABLED_CIRCUITS
}
state = {"status": "initializing", "error": None, "boot_started": None}
_prove_lock = threading.Lock()


def _initialize() -> None:
    state["boot_started"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        for engine in engines.values():  # serial: one GPU, dict preserves BONGTU_CIRCUITS order
            engine.initialize()
        state["status"] = "ready"
    except Exception as e:  # noqa: BLE001 — a failed boot must be visible on /ready
        state["status"] = "failed"
        state["error"] = f"{type(e).__name__}: {e}"


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Eager init in a daemon thread: the server accepts connections immediately
    # (so /ready can answer 503 while compiling) and never lazy-inits.
    threading.Thread(target=_initialize, name="prover-init", daemon=True).start()
    yield


app = FastAPI(title="bongtu prover service", lifespan=lifespan)


@app.middleware("http")
async def request_gates(request: Request, call_next):
    # Both gates compose — a gated request must pass BOTH — and both fire
    # before the body is even parsed. /healthz and /ready stay open (monitors
    # send neither header); each gate is a no-op while its env knob is unset
    # (local dev, loopback bind, unchanged behavior).
    #
    # (1) Auth gate, on /prove AND the sign-in probe /auth/check: when
    #     PROVER_AUTH_SHA256 is set, the request must carry HTTP Basic
    #     credentials whose sha256 matches it (config.auth_rejection —
    #     constant-time compare). This is the real gate: it holds against any
    #     client, browser or not. The 401 is served after a short pause so
    #     credential guessing over the funnel pays for every try.
    is_prove = request.method == "POST" and request.url.path == "/prove"
    if is_prove or (request.method == "GET" and request.url.path == "/auth/check"):
        reason = config.auth_rejection(request.headers.get("authorization"))
        if reason is not None:
            # No WWW-Authenticate header on purpose: this 401 answers a fetch()
            # from the console, and the browser's native Basic dialog must not
            # pop over the app's own login form.
            await asyncio.sleep(config.AUTH_FAILURE_DELAY)
            return JSONResponse(status_code=401, content={"detail": reason})
    # (2) Origin gate, on /prove only: when PROVER_ALLOWED_ORIGINS is set, the
    #     request must carry an allowed Origin. Stops browser/bot drive-bys
    #     only; any non-browser client can forge Origin — the Basic auth above
    #     is what actually authenticates (docs/security-model.md).
    if is_prove:
        reason = config.origin_rejection(request.headers.get("origin"))
        if reason is not None:
            return JSONResponse(status_code=403, content={"detail": reason})
    return await call_next(request)


# The employer browser app (payroll-web, another origin) POSTs directly here.
# With PROVER_ALLOWED_ORIGINS set, CORS reflects only those origins (so allowed
# browsers pass preflight) and the origin gate above 403s everything else.
# Added AFTER the gate middleware ON PURPOSE: Starlette runs later-added
# middleware outermost, and CORS must wrap the gates — a preflight OPTIONS is
# answered before any gate sees it, and a gate's own 401/403 still gets CORS
# headers, without which a cross-origin login page could not read the 401 that
# means "wrong password".
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS if config.ALLOWED_ORIGINS is not None else ["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


@app.get("/auth/check")
def auth_check() -> dict:
    # The console's sign-in probe: reaching here means the middleware accepted
    # the credentials (or PROVER_AUTH_SHA256 is unset — then sign-in is free,
    # exactly like every other endpoint in local dev).
    return {"ok": True}


@app.get("/ready")
def ready() -> dict:
    if state["status"] != "ready":
        raise HTTPException(
            status_code=503,
            detail={
                "status": state["status"],
                "error": state["error"],
                "boot_started": state["boot_started"],
            },
        )
    return {
        "status": "ready",
        # Every circuit-keyed field uses the WIRE tag — what a client may put in
        # ProvingRequest.circuit — never the registry (artifact) name.
        "circuits": [e.circuit.wire_tag for e in engines.values()],
        "num_public": {e.circuit.wire_tag: e.num_public for e in engines.values()},
        "boot_started": state["boot_started"],
        "boot_seconds": {e.circuit.wire_tag: e.boot_seconds for e in engines.values()},
    }


@app.post("/prove")
def prove(request: ProvingRequest) -> Calldata:
    # Sync def on purpose: FastAPI runs it on a worker thread, and the lock
    # serializes GPU proves (one GPU, engines share it).
    circuit_name = config.WIRE_TAG_TO_CIRCUIT.get(request.circuit)
    if circuit_name is None:
        raise HTTPException(
            status_code=400,
            detail=f"'{request.circuit}' proves CPU-side where it is assembled (browser wallet / "
            f"deploy scripts); this service serves {sorted(config.WIRE_TAG_TO_CIRCUIT)} (GPU).",
        )
    engine = engines.get(circuit_name)
    if engine is None:
        raise HTTPException(
            status_code=400,
            detail=f"circuit '{request.circuit}' ({circuit_name}) is not registered on this "
            f"instance: BONGTU_CIRCUITS={','.join(config.ENABLED_CIRCUITS)}. Add "
            f"'{circuit_name}' to BONGTU_CIRCUITS and restart the service.",
        )
    if request.backend == "cpu":
        raise HTTPException(
            status_code=400, detail=f"'{request.circuit}' on this service is GPU-only"
        )
    if state["status"] != "ready":
        raise HTTPException(
            status_code=503, detail={"status": state["status"], "error": state["error"]}
        )
    try:
        with _prove_lock:
            return engine.prove(request.input.model_dump())
    except WitnessGenerationError as e:
        # The request was well-formed but unsatisfiable (bad membership/sums/keys).
        raise HTTPException(status_code=400, detail=str(e)) from e
    except WitnessInfraError as e:
        # The service's own environment failed (.so/w2s/worker) — a 400 here
        # would tell the employer app their batch is unprovable when it isn't.
        raise HTTPException(status_code=500, detail=str(e)) from e
