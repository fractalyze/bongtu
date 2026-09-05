#!/usr/bin/env bash
# Upload the wallet's proving assets (public/circuits wasm+zkey) to the
# bongtu-circuits Vercel Blob store under a CIRCUITS_VERSION-named path.
#
# This is the successor of the deploy-wallet zkey guard: production serves
# /circuits/* through a vercel.json rewrite that carries the SAME version in its
# destination path, so a circuit regen is live only when (1) this script uploaded
# the new assets and (2) the commit bumping CIRCUITS_VERSION also bumps the
# rewrite — one atomic diff. The guard's "identity, not existence" check lives
# here now: the upload refuses assets whose combined zkey hash does not match the
# pin committed in src/config.ts.
#
# Usage: BLOB_READ_WRITE_TOKEN=... deploy/gates/upload_circuits.sh [assets-dir]
#   assets-dir defaults to apps/treasury-web/public/circuits next to this repo.
#   Token: `vercel env pull` in the linked wallet dir, or the store's RW token.
set -euo pipefail

HERE=$(cd "$(dirname "$0")/../.." && pwd)   # deploy/gates -> repo root
ASSETS=${1:-"$HERE/apps/treasury-web/public/circuits"}
# `vercel blob` reads BLOB_READ_WRITE_TOKEN from the env on its own — the
# guard below only fails fast; the token is never passed as a flag, because
# argv is world-readable in /proc for the duration of each upload.
: "${BLOB_READ_WRITE_TOKEN:?set BLOB_READ_WRITE_TOKEN (vercel env pull in the linked wallet dir)}"

# transfer10 is DEPRECATED (2026-07-28): its assets left the served set when
# transfer10x2 (10-in / 2-out) replaced it in every wallet route. Copy
# circuits/out/transfer10x2.zkey and circuits/out/transfer10x2_js/transfer10x2.wasm
# into the assets dir (as transfer10x2.{zkey,wasm}) before uploading.
for f in transfer.wasm transfer.zkey transfer10x2.wasm transfer10x2.zkey withdraw.wasm withdraw.zkey deposit.wasm deposit.zkey; do
  test -s "$ASSETS/$f" || { echo "missing proving asset: $ASSETS/$f" >&2; exit 1; }
done

pinned=$(grep -oE 'CIRCUITS_VERSION = "[0-9a-f]+"' "$HERE/apps/treasury-web/src/config.ts" | grep -oE '[0-9a-f]{8}')
actual=$(cat "$ASSETS/transfer.zkey" "$ASSETS/transfer10x2.zkey" "$ASSETS/withdraw.zkey" "$ASSETS/deposit.zkey" | sha256sum | cut -c1-8)
if [ "$pinned" != "$actual" ]; then
  echo "zkeys do not match CIRCUITS_VERSION: pinned=$pinned actual=$actual" >&2
  echo "regen left src/config.ts and $ASSETS out of sync — fix before uploading" >&2
  exit 1
fi

echo "uploading circuits @$pinned"
for f in transfer.wasm transfer.zkey transfer10x2.wasm transfer10x2.zkey withdraw.wasm withdraw.zkey deposit.wasm deposit.zkey; do
  # Versioned path => immutable; a year of caching is safe.
  vercel blob put "$ASSETS/$f" \
    --pathname "circuits/$pinned/$f" \
    --content-type application/octet-stream \
    --access public \
    --cache-control-max-age 31536000
done
echo "done — point the wallet vercel.json /circuits rewrite at circuits/$pinned/"
