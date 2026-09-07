import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
// The NodeNext ".js" -> ".ts" resolver and the mode-gated `/indexer` dev proxy are
// owned once at the repo root (vite.shared.ts) and shared with the other browser
// apps — Vite bundles this config with esbuild, so the relative import above the
// app dir resolves at bundle time. Nothing else is wired: the pay page has no
// wallet, no prover, no circuits — its whole server surface is the indexer.
import { resolveIndexerProxy, tsJsResolve } from "../../vite.shared.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

export default defineConfig(({ mode }) => {
  const proxy = resolveIndexerProxy(mode);
  return {
    plugins: [tsJsResolve()],
    // /p/{label} is client-routed off one page; the dev server must serve
    // index.html for it (production has the vercel.json rewrite).
    appType: "spa" as const,
    server: {
      // The page imports unbuilt @bongtu/core workspace source (via root
      // node_modules symlinks) — allow the dev server to read the monorepo.
      fs: { allow: [REPO_ROOT] },
      proxy,
    },
    preview: { proxy },
    // One page; @bongtu/core's crypto (bjj, poseidon constants) lands in a
    // single chunk past Vite's default 500 KiB warning — accepted, not split.
    build: { target: "es2022", chunkSizeWarningLimit: 2048 },
  };
});
