# The bongtu prover service — FastAPI over the resident Disburse256Prover.
#
# Serves the shared ProvingRequest wire contract (packages/core/src/proving.ts is
# the TS source of truth; schema.py mirrors it):
#
#   GET  /healthz  -> 200 {"ok": true}                    liveness (process up)
#   GET  /ready    -> 200 {"status": "ready", ...}        engine compiled + warm
#                     503 {"status": "initializing"|"failed", ...} otherwise
#   POST /prove    -> 200 Calldata {a, b, c, pub}         prove a ProvingRequest
#                     400 non-disburse circuit / cpu backend (not served here)
#                         / unsatisfiable witness input (client fault)
#                     422 schema violation (incl. the §11-8 two-time-pad guard)
#                     500 witness infra failure (bad wasm/node/timeout — the
#                         service's environment, never the client's batch)
#                     503 engine not ready yet
#
# Only `disburse` is served: it is the one circuit that NEEDS the GPU (1×256,
# 2.79M constraints). transfer/withdraw prove in the wallet's browser (a
# self-custody wallet never sends spending-key witnesses to a server) and
# deposit proves CPU-side wherever it is assembled (deploy scripts, snarkjs).
#
# Ops shape (from the measured GPU contract): the compiled prover pins ~25GB of
# GPU memory, so run EXACTLY ONE instance per GPU with ONE uvicorn worker, and
# proves are serialized by an in-process lock. Init is EAGER: a background
# thread starts compiling at boot (never lazy on first request); /ready flips
# once the warm-up proof lands.

from __future__ import annotations

import shutil
import tempfile
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .engine import Disburse256Prover, WitnessGenerationError, WitnessInfraError
from .schema import Calldata, ProvingRequest

engine = Disburse256Prover()
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
app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["POST", "GET"], allow_headers=["*"]
)


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
        "circuits": ["disburse"],
        "num_public": engine.num_public,
        "boot_started": state["boot_started"],
        "boot_seconds": engine.boot_seconds,
    }


@app.post("/prove")
def prove(request: ProvingRequest) -> Calldata:
    # Sync def on purpose: FastAPI runs it on a worker thread, and the lock
    # serializes GPU proves (one compiled prover, one GPU).
    if request.circuit != "disburse":
        raise HTTPException(
            status_code=400,
            detail=f"this service only proves 'disburse' (GPU); '{request.circuit}' proves "
            "CPU-side where it is assembled (browser wallet / deploy scripts).",
        )
    if request.backend == "cpu":
        raise HTTPException(status_code=400, detail="disburse on this service is GPU-only")
    if state["status"] != "ready":
        raise HTTPException(
            status_code=503, detail={"status": state["status"], "error": state["error"]}
        )
    try:
        with _prove_lock:
            return engine.prove(request.input)
    except WitnessGenerationError as e:
        # The request was well-formed but unsatisfiable (bad membership/sums/keys).
        raise HTTPException(status_code=400, detail=str(e)) from e
    except WitnessInfraError as e:
        # The service's own environment failed (wasm/node/timeout) — a 400 here
        # would tell the employer app their batch is unprovable when it isn't.
        raise HTTPException(status_code=500, detail=str(e)) from e
