# The bongtu prover service — FastAPI over resident CircuitProvers.
#
# Serves the shared ProvingRequest wire contract (packages/core/src/proving.ts is
# the TS source of truth; schema.py mirrors it):
#
#   GET  /healthz  -> 200 {"ok": true}                    liveness (process up)
#   GET  /ready    -> 200 {"status": "ready", ...}        every engine compiled + warm
#                     503 {"status": "initializing"|"failed", ...} otherwise
#   POST /prove    -> 200 Calldata {a, b, c, pub}         prove a ProvingRequest
#                     400 CPU-side circuit (deposit/transfer/withdraw — never
#                         served here) / a registry circuit not in
#                         BONGTU_CIRCUITS on this instance / cpu backend /
#                         unsatisfiable witness input (client fault)
#                     403 Origin gate (PROVER_ALLOWED_ORIGINS set and the
#                         request's Origin is absent or not allowed)
#                     422 schema violation (incl. the §11-8 two-time-pad guard)
#                     500 witness infra failure (bad wasm/node/timeout — the
#                         service's environment, never the client's batch)
#                     503 engines not ready yet
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

import shutil
import tempfile
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from . import config
from .engine import CircuitProver, WitnessGenerationError, WitnessInfraError
from .schema import Calldata, ProvingRequest

engines: dict[str, CircuitProver] = {
    name: CircuitProver(config.CIRCUITS[name]) for name in config.ENABLED_CIRCUITS
}
state = {"status": "initializing", "error": None, "boot_started": None}
_prove_lock = threading.Lock()


def _sweep_stale_scratch() -> None:
    # engine.prove spools witness JSON (spending keys) into bongtu-prove-* temp
    # dirs; the context manager cleans them on every normal path, but a SIGKILL
    # or power loss mid-prove orphans one — sweep before serving.
    for d in Path(tempfile.gettempdir()).glob("bongtu-prove-*"):
        shutil.rmtree(d, ignore_errors=True)


def _initialize() -> None:
    state["boot_started"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        _sweep_stale_scratch()
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

# The employer browser app (payroll-web, another origin) POSTs directly here.
# With PROVER_ALLOWED_ORIGINS set, CORS reflects only those origins (so allowed
# browsers pass preflight) and the origin gate below 403s everything else.
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS if config.ALLOWED_ORIGINS is not None else ["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.middleware("http")
async def origin_gate(request: Request, call_next):
    # Drive-by gate on the one work endpoint: when PROVER_ALLOWED_ORIGINS is
    # set, a POST /prove must carry an allowed Origin (403 before the body is
    # even parsed). /healthz and /ready stay open — monitors don't send Origin.
    # Unset = allow everything (local dev, loopback bind, unchanged behavior).
    # This stops browser/bot drive-bys only; any non-browser client can forge
    # Origin (docs/security-model.md — harden with a private network or request
    # signing, not this header).
    if request.method == "POST" and request.url.path == "/prove":
        reason = config.origin_rejection(request.headers.get("origin"))
        if reason is not None:
            return JSONResponse(status_code=403, content={"detail": reason})
    return await call_next(request)


@app.get("/healthz")
def healthz() -> dict:
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
        # The service's own environment failed (wasm/node/timeout) — a 400 here
        # would tell the employer app their batch is unprovable when it isn't.
        raise HTTPException(status_code=500, detail=str(e)) from e
