#!/usr/bin/env bash
# One-time setup of prover/.venv for the bongtu prover service.
#
# The rabbitsnark GPU stack is NOT pip-installable: rabbitsnark-py is a source
# checkout, and its jax/jaxlib are custom cp311 wheels living in the jolt-zorch
# venv (READ-ONLY — never pip-install into it). This venv therefore bridges to
# both via a .pth file, and only fastapi/uvicorn/pytest are installed into it.
#
#   bash prover/setup.sh          # creates prover/.venv (idempotent)
#
# Overridables (defaults = the known dev-box locations):
#   PYTHON311        the cp311 interpreter (custom jax wheels are cp311-only)
#   RABBITSNARK_DIR  the rabbitsnark-py source checkout
#   JAX_SITE         site-packages carrying the custom jax + zk_dtypes wheels
set -euo pipefail

cd "$(dirname "$0")"

PYTHON311="${PYTHON311:-/home/a41/.pyenv/versions/3.11.11/bin/python}"
RABBITSNARK_DIR="${RABBITSNARK_DIR:-/home/a41/Workspace/rabbitsnark-py}"
JAX_SITE="${JAX_SITE:-/home/a41/Workspace/jolt-zorch/.venv/lib/python3.11/site-packages}"

[ -x "$PYTHON311" ] || { echo "FATAL: python 3.11 not found at $PYTHON311 (set PYTHON311)"; exit 1; }
[ -d "$RABBITSNARK_DIR/rabbitsnark" ] || { echo "FATAL: rabbitsnark-py not at $RABBITSNARK_DIR (set RABBITSNARK_DIR)"; exit 1; }
[ -d "$JAX_SITE" ] || { echo "FATAL: jax site-packages not at $JAX_SITE (set JAX_SITE)"; exit 1; }

echo "== creating .venv (python 3.11) =="
"$PYTHON311" -m venv .venv

SITE="$(.venv/bin/python -c 'import site; print(site.getsitepackages()[0])')"
echo "== writing the rabbitsnark/jax bridge .pth into $SITE =="
# zz_ prefix: processed after the venv's own packages; two lines = two sys.path
# entries (the rabbitsnark source tree, then the read-only jax site-packages).
printf '%s\n%s\n' "$RABBITSNARK_DIR" "$JAX_SITE" > "$SITE/zz_rabbitsnark_bridge.pth"

echo "== installing the service deps (fastapi/uvicorn + test deps only) =="
# httpx: fastapi.testclient's transport, used only by tests/test_app.py.
.venv/bin/pip install --quiet 'fastapi==0.140.0' 'uvicorn==0.51.0' pytest httpx

echo "== smoke: the bridge resolves rabbitsnark + jax =="
.venv/bin/python - <<'EOF'
import importlib.util as u
for mod in ("rabbitsnark", "jax", "zk_dtypes", "fastapi", "uvicorn", "pytest"):
    assert u.find_spec(mod), f"bridge failed: {mod} not importable"
print("   all imports resolve OK")
EOF

echo "setup complete — run the service with: bash prover/run.sh"
