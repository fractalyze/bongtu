# Monorepo layout — the deployed-vs-imported decision

Decision record for the 2026-07-25 workspace refactor (`939fbe8`, layout "A1"). The
as-built tree lives in [`spec-decisions.md`](spec-decisions.md) §8 and the root [`README.md`](../README.md)
`## Layout` — this file owns only *why* it is shaped this way and which alternative
layouts were rejected.

## The axis: `apps/` = runnable, `packages/` = importable

One question decides where npm code lives: is it **deployed/run** (`apps/`) or
**imported** by other workspace code (`packages/`)? So `apps/` holds the indexer (a
deployed service, not a library — it moved out of the top level for exactly that
reason) plus the two web apps, and `packages/` holds the core library (`@bongtu/core`). Renames rode along:
`admin` → `admin-web` and `public` → `wallet-web` (now `treasury-web`), because "public" said nothing about
being the recipient wallet.

At the refactor commit `packages/` also held `prover-cli`; one commit later
(`46c8500`) the resident Python prover service replaced it and the axis held — the
thing deleted was an importable wrapper around what is really a deployed service, and
the service landed as top-level `prover/` (next section), not as a package.

## Every non-npm toolchain is its own top-level root

`circuits/` (circom), `contracts/` (Foundry), `prover/` (Python), and `deploy/`
(forge scripts + runners) deliberately stay outside `apps/` and `packages/`. Putting a
forge/circom/python toolchain under npm workspaces is a category error: "workspace"
means *npm installs, links, and runs scripts here*, and none of these are installed by
npm, export anything through a `package.json`, or want node managing their toolchain.
Nesting them would buy hoisting hazards and imply install relationships that do not
exist, for zero linking benefit. The top level *is* the axis for them: one root per
toolchain.

## Raw-src exports — no build step, by design

Workspace packages export raw TypeScript: `"exports": { "./*": "./src/*.ts" }`. The
load-bearing reason is correctness, not convenience: **the apps must bundle the exact
bytes the prover and indexer execute.** Wallet, indexer, prover witness-gen, and the
contract fixtures all have to agree on every commitment / nullifier / Poseidon-sponge
ciphertext; a compiled `dist/` would be a second artifact that can drift from source
(stale build, different transpile) — drift between what is *proved* and what is
*served*. With raw-src exports, tsc (NodeNext), tsx, and Vite all resolve the very
same `src/*.ts` file.

## Why the Vite `.js`→`.ts` shim survives the refactor

The refactor moved **cross-package** imports from deep-relative `../sdk/src/x.js` to
`@bongtu/core/x`, resolved through the exports map — those no longer need any shim. But
**intra-package** imports still use NodeNext-style `./poseidon.js` specifiers pointing
at sibling `.ts` files, and rollup resolves the literal `.js` first. The
`tsJsResolve()` plugin (byte-identical in both app vite configs — see
[`apps/treasury-web/vite.config.ts`](../apps/treasury-web/vite.config.ts)) rewrites a
relative `.js` import to `.ts` whenever only the `.ts` exists. It stays until the
intra-package specifier convention itself changes, which would be a repo-wide source
migration, not a config tweak.

## Nested lockfiles collapsed

The per-package `package-lock.json` files collapsed into the single root workspace
lock: one dependency truth, one `npm ci`, and CI keys its node_modules cache off one
`hashFiles('package-lock.json')`. npm ignores nested lockfiles under workspaces
anyway — keeping them only misleads readers and tools.

## Rejected alternatives

| option | shape | why rejected |
|---|---|---|
| A2 — `services/` split | separate `services/` (indexer, prover-facing) from the web apps | splits on *what kind of runnable*, not on the axis that governs tooling and imports. Deployment kind changes nothing about how code is installed, linked, or bundled — it adds a third npm root and a taxonomy debate per new app for zero mechanical benefit. |
| B — `web/` rename | group/rename the browser apps under `web/` | same non-load-bearing distinction, and it breaks the single `apps/*` workspace glob. The "web" bit lives in the package names instead (`admin-web`, `wallet-web`), which keeps one glob and still says what each app is. |

**Revival criteria:** revisit A2 only if `apps/` accumulates runnables with genuinely
different deploy pipelines (several daemons *and* several static sites) so that
per-kind CI/deploy globbing becomes real pain. Until then, deployed-vs-imported is the
only split that pays rent.
