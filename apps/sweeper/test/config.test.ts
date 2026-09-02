// Boot gates for the sweeper: env resolution (config.ts) and the spawn smokes
// that pin the SWEEPER_KEY contract end to end (the relayer config.test.ts
// posture) —
//
//   (1) REFUSAL — without SWEEPER_KEY (or INDEXER_URL) the process exits
//       nonzero printing one clear line naming the variable;
//   (2) NEVER-LOGS-KEY — booted WITH a (fake) key against dead deps, nothing
//       the process prints and nothing it serves ever contains the key
//       material. The sweeper's one secret has exactly one public trace: the
//       sweeper ADDRESS.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { bootError, resolveConfig } from "../src/config.js";

const SWEEPER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
// A syntactically valid secp256k1 key that is obviously not a real one; distinctive
// hex so a substring scan of logs/responses cannot false-negative.
const FAKE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const FACTORY = "0x00000000000000000000000000000000000fac70";
const POOL = "0x0000000000000000000000000000000000000b0b";

test("bootError: refusal names the FIRST missing required variable, one line each", () => {
  const noKey = bootError({});
  assert.ok(noKey !== null && noKey.includes("SWEEPER_KEY"), "unset env -> error names SWEEPER_KEY");
  assert.ok(!noKey.includes("\n"), "refusal is ONE line");
  const noIndexer = bootError({ SWEEPER_KEY: FAKE_KEY });
  assert.ok(noIndexer !== null && noIndexer.includes("INDEXER_URL"), "key set -> error names INDEXER_URL");
  assert.ok(!noIndexer.includes("\n"), "refusal is ONE line");
  assert.equal(bootError({ SWEEPER_KEY: FAKE_KEY, INDEXER_URL: "http://x" }), null, "both set -> boot proceeds");
  assert.ok(bootError({ SWEEPER_KEY: "", INDEXER_URL: "http://x" }) !== null, "empty string counts as unset");
});

test("resolveConfig: defaults + the deploy-record pool fallback + factory resolution", () => {
  const base = { SWEEPER_KEY: FAKE_KEY, INDEXER_URL: "http://indexer:1234", FACTORY };
  const cfg = resolveConfig(base);
  assert.equal(cfg.rpc, "http://127.0.0.1:8545", "RPC defaults to local anvil");
  assert.equal(cfg.port, 8710);
  assert.equal(cfg.pollMs, 15000);
  assert.match(cfg.circuitsOut, /circuits\/out$/, "CIRCUITS_OUT defaults to <repo>/circuits/out");
  // No POOL env: the pool comes from deploy/addresses.<CHAIN_ID>.json BY FIELD
  // NAME — the canonical record (CLAUDE.md: live pool is canonical).
  assert.match(cfg.pool, /^0x[0-9a-fA-F]{40}$/);
  // No TOKEN env: the sdk TOKEN_ADDRESS (the live wrapped kKRW).
  assert.match(cfg.token, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(cfg.indexerUrl, "http://indexer:1234");

  const explicit = resolveConfig({
    ...base,
    RPC: "http://10.0.0.1:1234",
    POOL,
    TOKEN: "0x000000000000000000000000000000000000700c",
    CHAIN_ID: "31337",
    PORT: "9000",
    POLL_MS: "500",
    CIRCUITS_OUT: "/tmp/circ",
  });
  assert.equal(explicit.rpc, "http://10.0.0.1:1234");
  assert.equal(explicit.pool, POOL);
  assert.equal(explicit.factory, FACTORY);
  assert.equal(explicit.token, "0x000000000000000000000000000000000000700c");
  assert.equal(explicit.chainId, 31337);
  assert.equal(explicit.port, 9000);
  assert.equal(explicit.pollMs, 500);
  assert.equal(explicit.circuitsOut, "/tmp/circ");

  // No FACTORY env and no `portalFactory` field in the record yet (live wiring
  // is U-P4): a sweeper with nowhere to sweep through must fail loudly.
  assert.throws(
    () => resolveConfig({ SWEEPER_KEY: FAKE_KEY, INDEXER_URL: "http://x", POOL, CHAIN_ID: "31337" }),
    /FACTORY|portalFactory/,
  );
});

for (const missing of ["SWEEPER_KEY", "INDEXER_URL"] as const) {
  test(`SPAWN: src/index.ts without ${missing} exits nonzero with the refusal line`, () => {
    const env: Record<string, string | undefined> = {
      ...process.env,
      SWEEPER_KEY: FAKE_KEY,
      INDEXER_URL: "http://127.0.0.1:1",
    };
    delete env[missing];
    const r = spawnSync(process.execPath, ["--import", "tsx", "src/index.ts"], {
      cwd: SWEEPER_DIR,
      env,
      encoding: "utf8",
      timeout: 60_000,
    });
    assert.ok(r.status !== 0 && r.status !== null, `exit status is nonzero (got ${r.status})`);
    assert.ok(r.stderr.includes(missing), `stderr names ${missing} (got: ${r.stderr.trim().slice(0, 200) || "<empty>"})`);
  });
}

test("SPAWN: a booted sweeper never prints or serves the key — logs, /health, and error bodies are all clean", async () => {
  // Boot against dead RPC + dead indexer on an ephemeral port: the first poll
  // round and /health's balance read both FAIL, which is the interesting case —
  // even the failure text must not echo the key.
  const env = {
    ...process.env,
    SWEEPER_KEY: FAKE_KEY,
    INDEXER_URL: "http://127.0.0.1:1", // nothing listens there
    RPC: "http://127.0.0.1:1",
    FACTORY,
    POOL,
    TOKEN: "0x000000000000000000000000000000000000700c",
    PORT: "0",
    POLL_MS: "200",
  };
  const child = spawn(process.execPath, ["--import", "tsx", "src/index.ts"], {
    cwd: SWEEPER_DIR,
    env,
  });
  const output: string[] = [];
  child.stdout.on("data", (d: Buffer) => output.push(d.toString()));
  child.stderr.on("data", (d: Buffer) => output.push(d.toString()));
  try {
    // Wait for the listen line (carries the ephemeral port).
    const port = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`sweeper did not listen; output: ${output.join("")}`)), 30_000);
      const check = (): void => {
        const m = /API listening on :(\d+)/.exec(output.join(""));
        if (m) {
          clearTimeout(timer);
          resolve(Number(m[1]));
        } else {
          setTimeout(check, 100);
        }
      };
      check();
    });
    const base = `http://127.0.0.1:${port}`;
    const health = await fetch(`${base}/health`);
    const healthText = await health.text();
    const missing = await fetch(`${base}/nope`);
    const missingText = await missing.text();
    // Let at least one failed poll round land in the log before scanning.
    await new Promise((r) => setTimeout(r, 500));

    const keyHex = FAKE_KEY.slice(2);
    for (const [what, text] of [
      ["log output", output.join("")],
      ["/health response", healthText],
      ["404 response", missingText],
    ] as const) {
      assert.ok(!text.toLowerCase().includes(keyHex.toLowerCase()),
        `${what} must not contain the sweeper key`);
    }
    // The one public trace of the key: its ADDRESS, logged at boot.
    assert.match(output.join(""), /sweeper=0x[0-9a-fA-F]{40}/);
  } finally {
    child.kill("SIGTERM");
    await new Promise((r) => child.once("exit", r));
  }
});
