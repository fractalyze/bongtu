import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
// The NodeNext ".js" -> ".ts"/".tsx" resolver and the mode-gated `/indexer` dev proxy
// are owned once at the repo root (vite.shared.ts) and shared with the wallet — Vite
// bundles this config with esbuild, so the relative import above the app dir resolves
// at bundle time. Only app-specific knobs live below.
import { resolveIndexerProxy, tsJsResolve } from "../../vite.shared.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

export default defineConfig(({ mode }) => {
  const proxy = resolveIndexerProxy(mode);
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
