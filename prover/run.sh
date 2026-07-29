#!/usr/bin/env bash
# Run the bongtu prover service (foreground).
#
#   bash prover/run.sh
#
# Boot is EAGER: every BONGTU_CIRCUITS zkey (default disburse256,transfer10x2,deposit)
# is parsed + GPU-compiled and one warm-up proof runs per circuit (~3min total)
# before GET /ready flips to 200. The compiled state pins ~25GB of GPU memory
# for the life of the process — run exactly ONE instance per GPU. --workers 1
# is pinned EXPLICITLY: with the flag absent, uvicorn falls back to the
# WEB_CONCURRENCY env var and would silently start a multi-worker supervisor —
# each worker compiling its own ~25GB prover (instant OOM at 2) and the worker
# surviving a kill of the recorded PID. Never raise it.
# Env knobs are documented in prover_service/config.py (BONGTU_CIRCUITS,
# PROVER_ALLOWED_ORIGINS, BONGTU_CIRCUITS_OUT, per-circuit BONGTU_*_ZKEY/_SO/
# _W2S, ...); the bind address/port are owned HERE
# (PROVER_HOST/PROVER_PORT).
set -euo pipefail

cd "$(dirname "$0")"
[ -x .venv/bin/uvicorn ] || { echo "FATAL: prover/.venv missing — run: bash prover/setup.sh"; exit 1; }

# The repo GPU contract (CLAUDE.md): device 0 only, never profiled.
export CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}"

exec .venv/bin/uvicorn prover_service.app:app \
  --workers 1 \
  --host "${PROVER_HOST:-127.0.0.1}" \
  --port "${PROVER_PORT:-8700}"
