import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Plugin } from "vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

// The bongtu sdk / indexer / prover-cli sources use NodeNext ".js" import
// specifiers that actually point at sibling ".ts" files (e.g. `./poseidon.js`).
// Vite/rollup resolves the literal ".js" first and would miss the ".ts", so
// rewrite a relative ".js" import to ".ts" whenever only the ".ts" exists. This
// lets the app import the exact same crypto the prover + indexer run, unbuilt.
function tsJsResolve(): Plugin {
  return {
    name: "bongtu-ts-js-resolve",
    enforce: "pre",
    resolveId(source, importer) {
      if (!importer) return null;
      if (!source.startsWith("./") && !source.startsWith("../")) return null;
      if (!source.endsWith(".js")) return null;
      const tsPath = resolve(dirname(importer), source.slice(0, -3) + ".ts");
      return existsSync(tsPath) ? tsPath : null;
    },
  };
}

export default {
  plugins: [tsJsResolve()],
  server: {
    // The app imports unbuilt @bongtu/* workspace source (packages/sdk, apps/indexer,
    // packages/prover-cli via root node_modules symlinks) — allow
    // the Vite dev server to read the whole monorepo, not just apps/admin-web.
    fs: { allow: [REPO_ROOT] },
  },
  build: {
    target: "es2022",
    // A single-page PoC; a slightly larger bundle (ethers + poseidon constants) is
    // fine — silence the default 500 KiB warning rather than code-split a demo.
    chunkSizeWarningLimit: 4096,
  },
};
