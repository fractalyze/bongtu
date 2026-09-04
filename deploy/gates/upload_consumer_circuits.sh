#!/usr/bin/env bash
# Upload the CONSUMER wallet's proving assets (the four *Priv wasm+zkey pairs) to
# the bongtu-circuits Vercel Blob store under a CIRCUITS_VERSION-named path. The
# consumer sibling of upload_circuits.sh: same store, same 3-part companion rule
# (the pin in apps/consumer-web/src/config.ts, this upload, and the vercel.json
# /circuits rewrite all move in ONE change), its own version bucket. Assets come
# straight from circuits/out: unlike wallet-web there is no public/circuits
# staging copy, so circuits/out is the build the pinned sizes and hash refer to
# and the blob store is the one serve path.
#
# The identity guard: the upload refuses assets whose combined zkey hash does not
# match the pin committed in apps/consumer-web/src/config.ts.
#
# The pin identifies the ARTIFACT, not the source: circuits/out is gitignored
# and `groth16 setup` draws fresh randomness, so a clean rebuild produces
# different zkey bytes and a different hash. The blob bucket is the archival
# copy of the pinned build; this guard fails closed on any other bytes.
#
# Usage: BLOB_READ_WRITE_TOKEN=... deploy/gates/upload_consumer_circuits.sh [circuits-out-dir]
#   Token: `vercel env pull` in a linked app dir, or the store's RW token.
set -euo pipefail

HERE=$(cd "$(dirname "$0")/../.." && pwd)   # deploy/gates -> repo root
OUT=${1:-"$HERE/circuits/out"}
# `vercel blob` reads BLOB_READ_WRITE_TOKEN from the env on its own — the
# guard below only fails fast; the token is never passed as a flag, because
# argv is world-readable in /proc for the duration of each upload.
: "${BLOB_READ_WRITE_TOKEN:?set BLOB_READ_WRITE_TOKEN (vercel env pull in a linked app dir)}"

CIRCUITS=(depositPriv transferPriv transfer10x2Priv withdrawPriv)
for n in "${CIRCUITS[@]}"; do
  test -s "$OUT/$n.zkey" || { echo "missing proving asset: $OUT/$n.zkey" >&2; exit 1; }
  test -s "$OUT/${n}_js/$n.wasm" || { echo "missing proving asset: $OUT/${n}_js/$n.wasm" >&2; exit 1; }
done

pinned=$(grep -oE 'CIRCUITS_VERSION = "[0-9a-f]+"' "$HERE/apps/consumer-web/src/config.ts" | grep -oE '[0-9a-f]{8}')
actual=$(cat "$OUT/depositPriv.zkey" "$OUT/transferPriv.zkey" "$OUT/transfer10x2Priv.zkey" "$OUT/withdrawPriv.zkey" | sha256sum | cut -c1-8)
if [ "$pinned" != "$actual" ]; then
  echo "zkeys do not match consumer CIRCUITS_VERSION: pinned=$pinned actual=$actual" >&2
  echo "regen left apps/consumer-web/src/config.ts and $OUT out of sync: fix before uploading" >&2
  exit 1
fi

# The version hash covers zkeys ONLY, and the versioned bucket is cached for a
# year: a wasm-only regen could not bump the pin and would serve mixed bytes
# under the same path. Refuse any wasm whose size disagrees with the committed
# CIRCUIT_ASSET_BYTES row (sizes, not hashes: that is what the app pins too).
for n in "${CIRCUITS[@]}"; do
  want=$(grep -oE "$n: \{ wasm: [0-9]+" "$HERE/apps/consumer-web/src/config.ts" | grep -oE '[0-9]+$')
  got=$(stat -c %s "$OUT/${n}_js/$n.wasm")
  if [ "$want" != "$got" ]; then
    echo "wasm size mismatch for $n: config.ts pins $want, $OUT has $got" >&2
    echo "a wasm change needs a full re-pin: bump CIRCUITS_VERSION alongside CIRCUIT_ASSET_BYTES" >&2
    exit 1
  fi
done

echo "uploading consumer circuits @$pinned"
for n in "${CIRCUITS[@]}"; do
  # Versioned path => immutable; a year of caching is safe.
  for f in "$OUT/${n}_js/$n.wasm" "$OUT/$n.zkey"; do
    vercel blob put "$f" \
      --pathname "circuits/$pinned/$(basename "$f")" \
      --content-type application/octet-stream \
      --access public \
      --cache-control-max-age 31536000
  done
done
echo "done: the consumer vercel.json /circuits rewrite must point at circuits/$pinned/"
