// External heavyweight deps (snarkjs, circomlibjs) — the ONE owner of the
// createRequire loader the node-side scripts used to copy-paste per file. (ethers
// is gone: every consumer moved to viem, which ships as a normal repo dependency.)
//
// The repo deliberately ships NO local install of these packages (locked decision,
// docs/toolchain.md / CLAUDE.md): they are large, ship no usable types for this
// setup, and snarkjs is GPL — so they load at RUNTIME from an external
// node_modules (env BONGTU_NODE_MODULES; default = the docs/toolchain.md path).
// They come back as `any`: we type OUR code (notes, keys, tree), not theirs.
//
// NODE-ONLY: this module touches node:module. Browser bundles (treasury-web proves
// in-page with its own bundled snarkjs) must never import it — the sdk's per-file
// "./*" exports mean it is only pulled in by files that ask for `@bongtu/core/extern`.

import { createRequire } from "node:module";
import { join } from "node:path";

const require = createRequire(import.meta.url);

/** The external node_modules directory the loaders resolve from
 *  (override with env BONGTU_NODE_MODULES on another machine). */
export const EXTERN_NODE_MODULES =
  process.env.BONGTU_NODE_MODULES || "/home/a41/Workspace/zkx-snap/circuits/node_modules";

/** Require a module (or a path inside one) from the external node_modules. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function requireExtern(spec: string): any {
  return require(join(EXTERN_NODE_MODULES, spec));
}

/** snarkjs via its CJS build entry — the package's default entry does not resolve
 *  under createRequire here, so the non-obvious build/main.cjs path is pinned. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function loadSnarkjs(): any {
  return requireExtern("snarkjs/build/main.cjs");
}
