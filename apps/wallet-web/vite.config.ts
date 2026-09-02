import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
// The NodeNext ".js" -> ".ts"/".tsx" resolver and the mode-gated `/indexer` dev proxy
// are owned once at the repo root (vite.shared.ts) and shared with the admin app —
// Vite bundles this config with esbuild, so the relative import above the app dir
// resolves at bundle time. Only wallet-specific knobs live below.
import { resolveIndexerProxy, resolveRelayerProxy, tsJsResolve, type ProxyRule } from "../../vite.shared.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "..", "..");

// WALLET-ONLY: the proving assets have ONE home in every environment — the
// bongtu-circuits blob store, addressed by CIRCUITS_VERSION. Deployments reach it
// through the vercel.json `/circuits` rewrite; local dev reaches it through this proxy
// entry — same path, same bytes, no local asset seed. The version is read from
// src/config.ts so a pin bump re-points dev automatically (vercel.json is the one place
// that needs a manual bump, and the config.ts pin comment says so).
const CIRCUITS_VERSION = /CIRCUITS_VERSION = "([0-9a-f]{8})"/.exec(
  readFileSync(resolve(HERE, "src/config.ts"), "utf8"),
)![1];
const CIRCUITS_BLOB_ORIGIN = "https://hbttd0nloguhlykr.public.blob.vercel-storage.com";

const circuitsProxy: ProxyRule = {
  target: CIRCUITS_BLOB_ORIGIN,
  changeOrigin: true,
  rewrite: (p: string) => p.replace(/^\/circuits/, `/circuits/${CIRCUITS_VERSION}`),
};

/**
 * The wallet's dev proxy: the shared mode-gated `/indexer` rule plus the wallet-only
 * `/circuits` blob rule. Both are development-only for the same reason (see
 * vite.shared.ts) — in production the static build sits behind a reverse proxy that
 * owns those paths, so the whole proxy is dropped when `mode` is production.
 */
export function resolveWalletProxy(mode: string): Record<string, ProxyRule> | undefined {
  const indexer = resolveIndexerProxy(mode);
  return indexer && { ...indexer, ...resolveRelayerProxy(mode), "/circuits": circuitsProxy };
}

export default defineConfig(({ mode }) => {
  const proxy = resolveWalletProxy(mode);
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
