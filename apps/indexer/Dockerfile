# syntax=docker/dockerfile:1

# bongtu indexer image (U-I3) — read-only BongtuPool event ingest + IMT mirror +
# API, run via `node --import tsx` over the raw workspace .ts (the repo ships no
# build step; NodeNext + tsx resolve @bongtu/core's per-file ./src/*.ts exports).
#
# Multi-stage:
#   deps    trims the npm workspace to root + packages/core + apps/indexer ONLY
#           (a lockfile-pinned `npm ci --workspace ...` — no react/vite from the
#           web apps) and installs ethers into an external node_modules (the
#           BONGTU_NODE_MODULES seam @bongtu/core/extern loads ethers from).
#   runtime slim non-root image: installed trees + raw source + the committed
#           pool ABI + the addresses file; serves GET /health.
#
# The build context MUST be the repo root (the image needs packages/core, the
# deploy/ addresses file, and the committed ABI — not just apps/indexer):
#   docker build -f apps/indexer/Dockerfile -t bongtu-indexer .

ARG NODE_IMAGE=node:22.17.1-slim
# ethers v5, externally loaded at runtime. MUST match .github/ci-pins.env
# ETHERS_VERSION — the repo pins the externally-loaded ethers there, and a
# mismatch would change how the pool ABI is decoded.
ARG ETHERS_VERSION=5.8.0

# ---------------------------------------------------------------------------
# deps — trimmed lockfile-pinned workspace install + external ethers
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS deps
ARG ETHERS_VERSION
WORKDIR /app

# Only the manifests the trimmed workspace needs. The committed root
# package-lock.json pins every transitive version; `npm ci --workspace` installs
# ONLY the indexer + core subtree (pg, poseidon-lite, tsx + esbuild) and creates
# the node_modules/@bongtu/{core,indexer} workspace symlinks. The web workspaces
# are absent from the context, so npm never resolves their react/vite deps.
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/package.json
COPY apps/indexer/package.json apps/indexer/package.json
RUN npm ci \
      --workspace @bongtu/indexer \
      --workspace @bongtu/core \
      --include-workspace-root

# ethers is NOT a repo dependency: @bongtu/core/extern loads it at runtime via
# createRequire from BONGTU_NODE_MODULES. Install it into a dedicated dir the
# runtime stage points BONGTU_NODE_MODULES at. (The indexer never loads snarkjs.)
RUN mkdir -p /opt/extern \
    && cd /opt/extern \
    && printf '{"name":"bongtu-extern","private":true}' > package.json \
    && npm install --no-audit --no-fund --ignore-scripts "ethers@${ETHERS_VERSION}"

# ---------------------------------------------------------------------------
# runtime — slim, non-root, source + installed deps + committed ABI
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS runtime
ENV NODE_ENV=production \
    PORT=8600 \
    BONGTU_NODE_MODULES=/opt/extern/node_modules
WORKDIR /app

# Installed trees from the deps stage.
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /opt/extern /opt/extern

# Workspace manifests + tsconfig so tsx/NodeNext resolution matches the repo and
# the node_modules/@bongtu/* symlinks point at real source.
COPY package.json package-lock.json tsconfig.base.json tsconfig.json ./
COPY packages/core/package.json packages/core/tsconfig.json packages/core/
COPY packages/core/src packages/core/src
COPY apps/indexer/package.json apps/indexer/tsconfig.json apps/indexer/
COPY apps/indexer/src apps/indexer/src

# chain.ts reads the pool ABI from chains/evm/out/BongtuPool.sol/BongtuPool.json at
# runtime (a gitignored forge artifact on a dev box). Ship the committed minimal
# ABI at exactly that path: self-contained (no foundry in the build) + reproducible
# (identical bytes every build). Regenerate: apps/indexer/abi/README.md.
COPY apps/indexer/abi/BongtuPool.abi.json chains/evm/out/BongtuPool.sol/BongtuPool.json

# POOL defaults to deploy/addresses.<CHAIN_ID>.json when the POOL env is unset, so
# the file the container needs is picked at RUNTIME by CHAIN_ID. A glob bakes in
# every recorded deployment: the image then serves any CHAIN_ID the compose file or
# the operator names, and a future chain move touches the deploy record only — a
# single-file COPY silently ships an image that dies at boot with ENOENT the moment
# CHAIN_ID points anywhere else.
COPY deploy/addresses.*.json deploy/

# Drop privileges to the image's built-in non-root user (uid 1000). The service
# only reads /app and opens sockets; it never writes to the image filesystem.
USER node

EXPOSE 8600
WORKDIR /app/apps/indexer

# Liveness: healthy once the API serves GET /health with ok:true (mirror built +
# tail poll not persistently failing). Uses node's global fetch — the slim base
# ships no curl/wget. start-period covers the initial full-chain ingest.
HEALTHCHECK --interval=10s --timeout=5s --start-period=40s --retries=6 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8600)+'/health').then(r=>r.json()).then(j=>process.exit(j.ok?0:1)).catch(()=>process.exit(1))"

# `npm start` is `node --import tsx src/index.ts`; call node directly so SIGTERM
# reaches the indexer's graceful-shutdown handler without an npm wrapper process.
CMD ["node", "--import", "tsx", "src/index.ts"]
