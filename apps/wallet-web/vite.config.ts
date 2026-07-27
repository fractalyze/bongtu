import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Plugin } from "vite";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

// The bongtu sdk / indexer sources use NodeNext ".js" import specifiers that
// actually point at sibling ".ts" files (e.g. `./poseidon.js`) — and, now that the
// wallet view layer is React, the app's own ".js" specifiers point at sibling
// ".tsx" files (e.g. `./App.js` -> `App.tsx`). Vite/rollup resolves the literal
// ".js" first and would miss both, so rewrite a relative ".js" import to the sibling
// ".ts"/".tsx" that actually exists. This lets the wallet import the exact same crypto
// the prover + indexer run, unbuilt, AND lets NodeNext-required ".js" specifiers reach
// the React components. (The ".ts" half is byte-for-byte the plugin payroll-web ships —
// the wallet must agree with the indexer/contract on every commitment/ciphertext.)
function tsJsResolve(): Plugin {
  return {
    name: "bongtu-ts-js-resolve",
    enforce: "pre",
    resolveId(source, importer) {
      if (!importer) return null;
      if (!source.startsWith("./") && !source.startsWith("../")) return null;
      if (!source.endsWith(".js")) return null;
      const stem = resolve(dirname(importer), source.slice(0, -3));
      for (const ext of [".ts", ".tsx"]) {
        if (existsSync(stem + ext)) return stem + ext;
      }
      return null;
    },
  };
}

// Same-origin indexer proxy — a LOCAL-DEVELOPMENT convenience. The wallet's DEFAULT
// indexer base is the relative path `/indexer` (src/config.ts), so the browser only ever
// talks to the Vite origin and Vite forwards to the real indexer server-side — no
// cross-origin CORS wall and no second port to expose. This is what makes remote
// development work: SSH-forward ONLY the wallet port and `/indexer/*` still reaches an
// indexer bound to the dev box's localhost:8600. Target overridable for a non-default
// indexer host/port.
const indexerProxy = {
  "/indexer": {
    target: process.env.VITE_INDEXER_PROXY_TARGET || "http://localhost:8600",
    changeOrigin: true,
    rewrite: (p: string) => p.replace(/^\/indexer/, ""),
  },
};

// The proxy MUST be OFF in production. There the wallet is a static build served behind
// an Nginx/ingress reverse-proxy that owns `/indexer/*`; a live Vite proxy would — in
// `vite preview`, which defaults to production mode — silently forward `/indexer` to a
// localhost:8600 that does not exist in prod, masking a missing infra route. Vite's
// `mode` is `development` for `vite dev` and `production` for `vite build`/`vite
// preview`, so gating on it disables the proxy in production AUTOMATICALLY — no manual
// flag to remember, and the relative `/indexer` default then resolves against the real
// reverse-proxy. `vite dev --mode production` (or `preview --mode development`) follows
// the mode, which is the intended escape hatch.
export function resolveIndexerProxy(mode: string) {
  return mode === "production" ? undefined : indexerProxy;
}

export default defineConfig(({ mode }) => {
  const proxy = resolveIndexerProxy(mode);
  return {
    // react() transpiles JSX + wires Fast Refresh; tsJsResolve is enforce:"pre" so the
    // NodeNext ".js" -> ".ts"/".tsx" rewrite resolves before React's own hooks run.
    plugins: [react(), tailwindcss(), tsJsResolve()],
    server: {
      // The wallet imports unbuilt @bongtu/* workspace source (packages/core, apps/indexer
      // via root node_modules symlinks) — allow
      // the Vite dev server to read the whole monorepo, not just apps/wallet-web.
      fs: { allow: [REPO_ROOT] },
      proxy,
    },
    preview: { proxy },
    build: {
      target: "es2022",
      // A single-page PoC; a larger bundle (ethers + snarkjs + poseidon constants) is
      // fine — silence the default 500 KiB warning rather than code-split a demo.
      chunkSizeWarningLimit: 8192,
    },
  };
});
