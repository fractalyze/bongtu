# The witness-calculator WORKER: a resident CPU child process, one per engine.
#
# It exists because a circom constraint failure inside the compiled calculator
# is a cf.assert, which lowers to `puts("assertion failed at line N"); abort()`
# — running the calculator in the service process would let ONE unsatisfiable
# client request SIGABRT the whole resident ~25GB GPU prover (a 2.5min reboot).
# The worker takes the abort instead: the parent (witness.WitnessHost) sees the
# crash, reads the assert message off stderr, answers 400, and respawns.
#
# Protocol (parent <-> worker), length-delimited over pipes:
#   worker stdout -> parent: one JSON line handshake
#       {"ready": true, "num_inputs": N, "witness_size": M}
#     then per request: one JSON header line
#       {"ok": true, "nbytes": B, "seconds": S}   followed by B raw bytes
#       (the witness vector, standard-form 32-byte LE elements), or
#       {"ok": false, "error": "..."}             (recoverable input fault)
#   parent -> worker stdin: one JSON line per request
#       {"values": ["<decimal>", ...]}            (flattened, circuit order)
#
# The C runtime's assert message is a puts() to fd 1 — which would corrupt the
# protocol stream — so the worker re-points fd 1 at stderr at startup and keeps
# a private dup of the original stdout for the protocol.
#
# Anything unexpected is allowed to CRASH the worker (traceback on stderr):
# the parent classifies a death without the assert signature as an infra
# fault. Only input-shaped problems are answered with ok:false and survived.
#
# Runs under the prover venv but stays GPU-free: numpy + zk_dtypes +
# rabbitsnark.circom.witness_calculator only — no jax import anywhere.

from __future__ import annotations

import ctypes
import json
import os
import sys
import time


def main(so_path: str, w2s_path: str) -> None:
    # Claim the protocol stream, then send C-level stdout (assert puts) to stderr.
    proto = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    # C stdio buffers fd-1 writes when it is a pipe, and abort() never flushes —
    # the assert message would die with the worker. Unbuffer the C stdout stream
    # so cf.assert's puts() reaches the parent before the abort.
    libc = ctypes.CDLL(None)
    libc.setvbuf(ctypes.c_void_p.in_dll(libc, "stdout"), None, 2, 0)  # _IONBF

    import numpy as np

    import rabbitsnark.circom.witness_calculator as wc
    from rabbitsnark.circom.witness_calculator import FIELD_ELEM_SIZE, _make_memref

    calc = wc.CircomWitnessCalculator(so_path)
    w2s = np.asarray(wc.load_w2s(w2s_path), dtype=np.int64)
    if len(w2s) < calc.witness_size:
        raise RuntimeError(
            f"w2s map at {w2s_path} has {len(w2s)} entries < witness_size "
            f"{calc.witness_size} — mismatched .so / w2s pair?"
        )

    proto.write(
        json.dumps(
            {"ready": True, "num_inputs": calc.num_inputs, "witness_size": calc.witness_size}
        ).encode()
        + b"\n"
    )

    stdin = sys.stdin.buffer
    while True:
        line = stdin.readline()
        if not line:
            return  # parent closed stdin: clean shutdown
        values = json.loads(line)["values"]
        if len(values) != calc.num_inputs:
            proto.write(
                json.dumps(
                    {
                        "ok": False,
                        "error": f"flattened input has {len(values)} values but the "
                        f"circuit takes {calc.num_inputs}",
                    }
                ).encode()
                + b"\n"
            )
            continue

        t0 = time.monotonic()
        # The upstream CircomWitnessCalculator.compute_witness has two bugs this
        # inlines around (upstream fix pending): its subcmps buffer is 1 int64
        # per component where the runtime stores 3 (heap-overrun SIGBUS on big
        # circuits — r1cs-solver's circom_witness_test.cc allocates n*3), and
        # its witness extraction is a minutes-slow per-element Python loop
        # (vectorized gather here: ~1s total for disburse256's 2.8M elements).
        signals_buf = np.zeros(calc.total_signals * FIELD_ELEM_SIZE, dtype=np.uint8)
        subcmps_buf = np.zeros(calc.num_components * 3, dtype=np.int64)
        signals_buf[:FIELD_ELEM_SIZE] = np.frombuffer(
            int.to_bytes(1, FIELD_ELEM_SIZE, "little"), dtype=np.uint8
        )
        input_start = 1 + calc.num_outputs
        for i, val in enumerate(values):
            signal_idx = int(w2s[input_start + i])
            off = signal_idx * FIELD_ELEM_SIZE
            signals_buf[off : off + FIELD_ELEM_SIZE] = np.frombuffer(
                int(val).to_bytes(FIELD_ELEM_SIZE, "little"), dtype=np.uint8
            )

        mr_signals = _make_memref(signals_buf)
        calc._lib._mlir_ciface_to_mont_inplace(
            ctypes.byref(mr_signals), ctypes.c_int64(0), ctypes.c_int64(calc.total_signals)
        )
        mr_subcmps = _make_memref(subcmps_buf)
        # An unsatisfiable input aborts INSIDE this call (see module docstring).
        calc._lib._mlir_ciface_circuit_main(ctypes.byref(mr_signals), ctypes.byref(mr_subcmps))
        calc._lib._mlir_ciface_from_mont_inplace(
            ctypes.byref(mr_signals), ctypes.c_int64(0), ctypes.c_int64(calc.total_signals)
        )

        sig_words = signals_buf.view(np.uint64).reshape(calc.total_signals, 4)
        witness = sig_words[w2s[: calc.witness_size]].tobytes()

        proto.write(
            json.dumps(
                {
                    "ok": True,
                    "nbytes": len(witness),
                    "seconds": round(time.monotonic() - t0, 3),
                }
            ).encode()
            + b"\n"
        )
        proto.write(witness)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
