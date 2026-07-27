import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

// The bongtu sdk sources use NodeNext ".js" import
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
      // NodeNext ".js" specifiers point at sibling ".ts" — and, now that the
      // view layer is React, at sibling ".tsx" — sources.
      const base = resolve(dirname(importer), source.slice(0, -3));
      for (const ext of [".ts", ".tsx"]) {
        if (existsSync(base + ext)) return base + ext;
      }
      return null;
    },
  };
}

// Same-origin indexer proxy — a LOCAL-DEVELOPMENT convenience, mirroring the wallet.
// The admin's DEFAULT indexer base is the relative path `/indexer` (src/config.ts), so
// the browser only ever talks to the Vite origin and Vite forwards to the real indexer
// server-side. It MUST be OFF in production, where Vercel's rewrite (vercel.json) owns
// `/indexer/*`; Vite's `mode` is `production` for `vite build`/`vite preview`, so gating
// on it disables the proxy automatically. Target overridable for a non-default host/port.
const indexerProxy = {
  "/indexer": {
    target: process.env.VITE_INDEXER_PROXY_TARGET || "http://localhost:8600",
    changeOrigin: true,
    rewrite: (p: string) => p.replace(/^\/indexer/, ""),
  },
};

export default defineConfig(({ mode }) => {
  const proxy = mode === "production" ? undefined : indexerProxy;
  return {
    plugins: [react(), tailwindcss(), tsJsResolve()],
    server: {
      // The app imports unbuilt @bongtu/core source via the root node_modules
      // symlink — allow the Vite dev server to read the whole monorepo, not
      // just apps/payroll-web.
      fs: { allow: [REPO_ROOT] },
      proxy,
    },
    preview: { proxy },
    build: {
      target: "es2022",
      // A single-page PoC; a slightly larger bundle (ethers + poseidon constants) is
      // fine — silence the default 500 KiB warning rather than code-split a demo.
      chunkSizeWarningLimit: 4096,
    },
  };
});
