# Stand-in for prover_service/witness_worker.py so test_witness_seam.py can
# drive witness.WitnessHost through a REAL worker subprocess (same pipe
# protocol) without numpy/rabbitsnark or any compiled .so — stdlib only, so the
# CPU-only CI pytest job (pydantic+pytest, no GPU venv bridge) runs it too.
#
#   stub_witness_worker.py <mode> [echo_path]
#
# Well-behaved modes:
#   success    handshake, then answer every request with FAKE_WITNESS
#              (writing the received request line to echo_path first, if given)
#   chatty     handshake, then per request log 8KB to stderr and answer
#              normally — a resident worker that logs, whose cumulative stderr
#              passes the 64KB pipe capacity after ~8 requests
#
# Death modes:
#   assert     handshake, then die like the compiled calculator does on an
#              unsatisfiable input: the cf.assert lowering is
#              `puts("assertion failed at line N"); abort()`
#   assert-noisy  the same death behind 200KB of stderr chatter — the compiled
#              calculator's own C-stdout is routed to stderr, so a verbose
#              circuit reaches the abort with the pipe long since full
#   infra      handshake, then die WITHOUT the assert signature (e.g. SIGBUS,
#              python traceback) — exit code + stderr only
#   hang       handshake, then never answer (wedged worker; host timeout fires)
#   boot-fail  die before the handshake (bad .so simulation)
#
# Lying/broken-protocol modes (the worker is not a trusted narrator: it is a
# separate process running a compiled artifact that can be stale or wrong):
#   garbage-handshake  a handshake line that is not JSON, then stay alive
#   handshake-no-size  a ready handshake missing witness_size, then stay alive
#   short-payload      handshake witness_size=4 (=128 bytes), then answer with
#                      a header claiming 64 bytes and 64 bytes of payload
#   truncated-payload  an HONEST 128-byte header, then only 64 bytes before EOF

import os
import sys
import time

MODE = sys.argv[1]
ECHO_PATH = sys.argv[2] if len(sys.argv) > 2 else None

# 4 fake witness elements, 32 bytes each.
FAKE_WITNESS = b"".join(i.to_bytes(32, "little") for i in (1, 7, 8, 9))

out = sys.stdout.buffer

if MODE == "boot-fail":
    print("dlopen failed: not-a-real.so: cannot open shared object file", file=sys.stderr)
    sys.exit(3)

if MODE == "garbage-handshake":
    out.write(b"Segmentation fault (core dumped)\n")
    out.flush()
    time.sleep(60)  # stays alive: an unkilled child would be a LEAK, not a corpse
    sys.exit(0)

if MODE == "handshake-no-size":
    out.write(b'{"ready": true, "num_inputs": 4}\n')
    out.flush()
    time.sleep(60)
    sys.exit(0)

out.write(b'{"ready": true, "num_inputs": 4, "witness_size": 4}\n')
out.flush()

for line in sys.stdin.buffer:
    if ECHO_PATH:
        with open(ECHO_PATH, "ab") as f:
            f.write(line)
    if MODE == "success":
        out.write(b'{"ok": true, "nbytes": %d, "seconds": 0.001}\n' % len(FAKE_WITNESS))
        out.write(FAKE_WITNESS)
        out.flush()
    elif MODE == "chatty":
        sys.stderr.write("worker log line: computing\n" + "." * 8192 + "\n")
        sys.stderr.flush()
        out.write(b'{"ok": true, "nbytes": %d, "seconds": 0.001}\n' % len(FAKE_WITNESS))
        out.write(FAKE_WITNESS)
        out.flush()
    elif MODE == "short-payload":
        out.write(b'{"ok": true, "nbytes": 64, "seconds": 0.001}\n')
        out.write(FAKE_WITNESS[:64])
        out.flush()
    elif MODE == "truncated-payload":
        out.write(b'{"ok": true, "nbytes": %d, "seconds": 0.001}\n' % len(FAKE_WITNESS))
        out.write(FAKE_WITNESS[:64])
        out.flush()
        sys.exit(0)  # EOF mid-payload: the pipe truncated
    elif MODE == "assert":
        print("assertion failed at line 118", file=sys.stderr)
        sys.stderr.flush()
        os.abort()
    elif MODE == "assert-noisy":
        sys.stderr.write("x" * (200 * 1024) + "\n")
        print("assertion failed at line 118", file=sys.stderr)
        sys.stderr.flush()
        os.abort()
    elif MODE == "infra":
        print("Fatal Python error: Bus error", file=sys.stderr)
        sys.exit(3)
    elif MODE == "hang":
        time.sleep(60)
    else:
        print(f"unknown stub mode: {MODE}", file=sys.stderr)
        sys.exit(2)
