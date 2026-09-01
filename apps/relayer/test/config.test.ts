// Boot gates for the relayer: env resolution (config.ts) and the two spawn
// smokes that pin the SUBMITTER_KEY contract end to end —
//
//   (1) REFUSAL — without SUBMITTER_KEY the process exits nonzero printing one
//       clear line naming the variable (the indexer DATABASE_URL posture);
//   (2) NEVER-LOGS-KEY — booted WITH a (fake) key, nothing the process prints
//       and nothing it serves ever contains the key material. The relayer's one
//       secret has exactly one public trace: the submitter ADDRESS.

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveConfig, submitterKeyError } from "../src/config.js";

const RELAYER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");
// A syntactically valid secp256k1 key that is obviously not a real one; distinctive
// hex so a substring scan of logs/responses cannot false-negative.
const FAKE_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

test("submitterKeyError: refusal iff SUBMITTER_KEY is absent, one line, names the variable", () => {
  const err = submitterKeyError({});
  assert.ok(err !== null && err.includes("SUBMITTER_KEY"), "unset env -> error names SUBMITTER_KEY");
  assert.ok(!err.includes("\n"), "refusal is ONE line");
  assert.equal(submitterKeyError({ SUBMITTER_KEY: FAKE_KEY }), null, "set env -> boot proceeds");
  assert.ok(submitterKeyError({ SUBMITTER_KEY: "" }) !== null, "empty string counts as unset");
});

test("resolveConfig: defaults + the deploy-record pool fallback the indexer uses", () => {
  const cfg = resolveConfig({ SUBMITTER_KEY: FAKE_KEY });
  assert.equal(cfg.rpc, "http://127.0.0.1:8545", "RPC defaults to local anvil");
  assert.equal(cfg.port, 8700);
  // No POOL env: the pool comes from deploy/addresses.<CHAIN_ID>.json BY FIELD
  // NAME — the canonical record (CLAUDE.md: live pool is canonical).
  assert.match(cfg.pool, /^0x[0-9a-fA-F]{40}$/);
  const explicit = resolveConfig({
    SUBMITTER_KEY: FAKE_KEY,
    RPC: "http://10.0.0.1:1234",
    POOL: "0x0000000000000000000000000000000000000b0b",
    CHAIN_ID: "31337",
    PORT: "9000",
  });
  assert.equal(explicit.rpc, "http://10.0.0.1:1234");
  assert.equal(explicit.pool, "0x0000000000000000000000000000000000000b0b");
  assert.equal(explicit.chainId, 31337);
  assert.equal(explicit.port, 9000);
});

test("SPAWN: src/index.ts without SUBMITTER_KEY exits nonzero with the refusal line", () => {
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.SUBMITTER_KEY;
  const r = spawnSync(process.execPath, ["--import", "tsx", "src/index.ts"], {
    cwd: RELAYER_DIR,
    env,
    encoding: "utf8",
    timeout: 60_000,
  });
  assert.ok(r.status !== 0 && r.status !== null, `exit status is nonzero (got ${r.status})`);
  assert.ok(r.stderr.includes("SUBMITTER_KEY"), `stderr names SUBMITTER_KEY (got: ${r.stderr.trim().slice(0, 200) || "<empty>"})`);
});

test("SPAWN: a booted relayer never prints or serves the key — logs, /health, and error bodies are all clean", async () => {
  // Boot against an unreachable RPC on an ephemeral port: /health's balance read
  // will FAIL, which is the interesting case — even the failure text must not
  // echo the key. The malformed-/relay 400 path needs no RPC at all.
  const env = {
    ...process.env,
    SUBMITTER_KEY: FAKE_KEY,
    RPC: "http://127.0.0.1:1", // nothing listens there
    POOL: "0x0000000000000000000000000000000000000b0b",
    PORT: "0",
  };
  const child = spawn(process.execPath, ["--import", "tsx", "src/index.ts"], {
    cwd: RELAYER_DIR,
    env,
  });
  const output: string[] = [];
  child.stdout.on("data", (d: Buffer) => output.push(d.toString()));
  child.stderr.on("data", (d: Buffer) => output.push(d.toString()));
  try {
    // Wait for the listen line (carries the ephemeral port).
    const port = await new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`relayer did not listen; output: ${output.join("")}`)), 30_000);
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
    const relay = await fetch(`${base}/relay`, { method: "POST", body: JSON.stringify({}) });
    const relayText = await relay.text();

    const keyHex = FAKE_KEY.slice(2);
    for (const [what, text] of [
      ["log output", output.join("")],
      ["/health response", healthText],
      ["/relay response", relayText],
    ] as const) {
      assert.ok(!text.includes(keyHex) && !text.toLowerCase().includes(keyHex.toLowerCase()),
        `${what} must not contain the submitter key`);
    }
    // The one public trace of the key: its ADDRESS, logged at boot.
    assert.match(output.join(""), /submitter=0x[0-9a-fA-F]{40}/);
  } finally {
    child.kill("SIGTERM");
    await new Promise((r) => child.once("exit", r));
  }
});
