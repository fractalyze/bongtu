// Boot-refusal test (U-I4 Postgres-only): the indexer must REFUSE to start
// without DATABASE_URL — one clear line naming DATABASE_URL + the docker-compose
// recipe, nonzero exit — never a silent in-memory fallback.
//
// Two legs:
//   1. unit: `databaseUrlError` (the factored check index.ts runs first) returns
//      the refusal line iff DATABASE_URL is absent;
//   2. spawn smoke: `node --import tsx src/index.ts` with DATABASE_URL stripped
//      from the env exits nonzero and prints that line to stderr, proving the
//      entrypoint actually wires the check in front of everything else.
//
//   node --import tsx test/config.test.ts       # (== npm run test:config)

import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { databaseUrlError } from "../src/chain.js";

let failures = 0;
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
}
function step(t: string): void {
  console.log(`\n=== ${t} ===`);
}

const INDEXER_DIR = join(dirname(fileURLToPath(import.meta.url)), "..");

step("UNIT: databaseUrlError — refusal iff DATABASE_URL is absent");
{
  const err = databaseUrlError({});
  ok(typeof err === "string" && err.includes("DATABASE_URL"), "unset env → error line names DATABASE_URL");
  ok(!!err && err.includes("docker compose"), "error line points at the docker-compose recipe");
  ok(!err!.includes("\n"), "refusal is ONE line");
  ok(databaseUrlError({ DATABASE_URL: "postgres://x@localhost/db" }) === null, "set env → null (boot proceeds)");
  ok(typeof databaseUrlError({ DATABASE_URL: "" }) === "string", "empty-string DATABASE_URL counts as unset");
}

step("SPAWN: src/index.ts without DATABASE_URL exits nonzero with the refusal line");
{
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.DATABASE_URL;
  const r = spawnSync(process.execPath, ["--import", "tsx", "src/index.ts"], {
    cwd: INDEXER_DIR,
    env,
    encoding: "utf8",
    timeout: 60_000,
  });
  ok(r.status !== 0 && r.status !== null, `exit status is nonzero (got ${r.status})`);
  ok(r.stderr.includes("DATABASE_URL"), `stderr names DATABASE_URL (got: ${r.stderr.trim().slice(0, 200) || "<empty>"})`);
  ok(r.stderr.includes("docker compose"), "stderr points at the docker-compose recipe");
}

console.log(`\n${failures === 0 ? "CONFIG TEST PASS — Postgres-only boot refusal (unit + spawn)" : `CONFIG TEST FAIL — ${failures} assertion(s)`}`);
process.exit(failures === 0 ? 0 : 1);
