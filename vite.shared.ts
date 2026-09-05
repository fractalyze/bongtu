// The Vite config pieces BOTH browser apps need, owned once at the repo root.
// apps/treasury-web and apps/payroll-web import this relatively (`../../vite.shared.js`):
// Vite bundles its config file with esbuild before running it, so a relative import
// from above the app directory is resolved at bundle time and needs no workspace
// package. Anything only ONE app needs (the wallet's CIRCUITS_VERSION reader and
// /circuits blob proxy, per-app build knobs) stays in that app's config.
//
// These used to be copy-pasted into both configs, which drifted; this file is now the
// single owner, so a fix lands in both apps at once.

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { Plugin } from "vite";

/**
 * Resolve NodeNext ".js" import specifiers to the sibling ".ts"/".tsx" that actually
 * exists. The bongtu sdk / indexer sources use ".js" specifiers pointing at sibling
 * ".ts" files (e.g. `./poseidon.js`), and the React view layers use them pointing at
 * sibling ".tsx" files (e.g. `./App.js` -> `App.tsx`). Vite/rollup resolves the literal
 * ".js" first and would miss both. With this rewrite each app imports the exact same
 * crypto the prover + indexer run, unbuilt, and NodeNext-required ".js" specifiers
 * still reach the React components.
 */
export function tsJsResolve(): Plugin {
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

/** One Vite proxy rule (the subset of Vite's ProxyOptions these apps set). */
export interface ProxyRule {
  target: string;
  changeOrigin: boolean;
  rewrite: (path: string) => string;
}

/**
 * The same-origin `/indexer` proxy — a LOCAL-DEVELOPMENT convenience. Both apps
 * default their indexer base to the relative path `/indexer` (src/config.ts), so the
 * browser only ever talks to the Vite origin and Vite forwards to the real indexer
 * server-side: no cross-origin CORS wall and no second port to expose. This is what
 * makes remote development work — SSH-forward ONLY the app port and `/indexer/*` still
 * reaches an indexer bound to the dev box's localhost:8600.
 *
 * It MUST be OFF in production. There each app is a static build served behind a
 * reverse proxy that owns `/indexer/*` (Vercel's rewrite in vercel.json); a live Vite
 * proxy would — in `vite preview`, which defaults to production mode — silently forward
 * `/indexer` to a localhost:8600 that does not exist in prod, masking a missing infra
 * route. Vite's `mode` is `development` for `vite dev` and `production` for `vite
 * build`/`vite preview`, so gating on it disables the proxy AUTOMATICALLY — no manual
 * flag to remember. `vite dev --mode production` (or `preview --mode development`)
 * follows the mode, which is the intended escape hatch.
 *
 * `proxyTarget` overrides the indexer host/port (env `VITE_INDEXER_PROXY_TARGET`).
 */
export function resolveIndexerProxy(
  mode: string,
  proxyTarget?: string,
): Record<string, ProxyRule> | undefined {
  if (mode === "production") return undefined;
  return {
    "/indexer": {
      target: proxyTarget || process.env.VITE_INDEXER_PROXY_TARGET || "http://localhost:8600",
      changeOrigin: true,
      rewrite: (p: string) => p.replace(/^\/indexer/, ""),
    },
  };
}

/**
 * The same-origin `/relayer` proxy — the `/indexer` rule's twin for the
 * gas-sponsoring withdraw relayer (apps/relayer, default port 8700). Identical
 * mode-gating for the identical reason: dev-only convenience, and in production
 * the reverse proxy must own `/relayer/*` or the path simply does not exist
 * (which the wallet treats as "no relayer configured" — self-submit).
 *
 * `proxyTarget` overrides the relayer host/port (env `VITE_RELAYER_PROXY_TARGET`).
 */
export function resolveRelayerProxy(
  mode: string,
  proxyTarget?: string,
): Record<string, ProxyRule> | undefined {
  if (mode === "production") return undefined;
  return {
    "/relayer": {
      target: proxyTarget || process.env.VITE_RELAYER_PROXY_TARGET || "http://localhost:8700",
      changeOrigin: true,
      rewrite: (p: string) => p.replace(/^\/relayer/, ""),
    },
  };
}
