// The rail-split gate (issue #40): @bongtu/client is the rail-agnostic engine,
// so NO rail SDK (viem, a Solana SDK) may appear anywhere in its dependency
// closure or its sources. Machine-checked here — a dependency added to this
// package (or to anything it depends on) that reaches a rail SDK fails this
// suite, and so does a stray `import ... from "viem"` in src/. The rail io
// lives in @bongtu/client-evm, which depends on this package, never the other
// way around.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PKG_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The rail SDKs the engine must never reach (extend as rails land). */
const RAIL_SDKS = ["viem", "wagmi", "ethers", "@solana/web3.js", "@solana/kit"];

interface PkgJson {
  name?: string;
  dependencies?: Record<string, string>;
}

/** BFS the DECLARED production-dependency closure from this package.json,
 *  resolving each dep's own package.json the way node would (hoisted
 *  workspace installs resolve every workspace package by name). */
function dependencyClosure(startDir: string): Set<string> {
  const seen = new Set<string>();
  const queue: string[] = [startDir];
  for (const dir of queue) {
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as PkgJson;
    for (const dep of Object.keys(pkg.dependencies ?? {})) {
      if (seen.has(dep)) continue;
      seen.add(dep);
      const req = createRequire(join(dir, "package.json"));
      // exports maps hide package.json from require.resolve; resolve the dep
      // DIRECTORY through node's module paths instead.
      const found = req.resolve.paths(dep)?.map((p) => join(p, dep)).find((p) => {
        try {
          return statSync(join(p, "package.json")).isFile();
        } catch {
          return false;
        }
      });
      if (found) queue.push(found);
    }
  }
  return seen;
}

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) return sourceFiles(p);
    return name.endsWith(".ts") ? [p] : [];
  });
}

test("no rail SDK in @bongtu/client's declared dependency closure", () => {
  const closure = dependencyClosure(PKG_DIR);
  for (const sdk of RAIL_SDKS) {
    assert.ok(!closure.has(sdk), `${sdk} reached the engine's dependency closure: ${[...closure].join(", ")}`);
  }
  assert.ok(!closure.has("@bongtu/client-evm"), "the engine must not depend on a rail client package");
});

test("no src module imports a rail SDK or a rail client package", () => {
  const offenders = sourceFiles(join(PKG_DIR, "src")).filter((file) => {
    const text = readFileSync(file, "utf8");
    return (
      RAIL_SDKS.some((sdk) => text.includes(`from "${sdk}`) || text.includes(`require("${sdk}`)) ||
      text.includes('from "@bongtu/client-evm')
    );
  });
  assert.deepEqual(offenders, [], "rail imports found in engine sources");
});
