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

import { parseAbi } from "viem";

import { databaseUrlError, kemBootGuardError, parseKemGraceSeconds, parseKemKey, staleOpAbiError } from "../src/chain.js";

const failures = { count: 0 };
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures.count++;
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

step("UNIT: kemBootGuardError — refuse a KEM-epoch pool this build cannot honor (design doc §7)");
{
  const ZERO = "0x" + "0".repeat(64);
  const NONZERO = "0x0403c92bcdb56d0369c0981754a6f4af6719395d59eef32370dcfad9bb332314";
  // pre-KEM epoch (or a V1 pool, folded to the zero hash): every build serves.
  for (const arbiterMode of [false, true]) {
    ok(kemBootGuardError({ kemPkHash: ZERO, arbiterMode, hasKemKey: false, abiKnowsKem: true, kemKeyPkHash: null }) === null,
      `zero kemPkHash → serve (arbiterMode=${arbiterMode})`);
  }
  // KEM epoch + V1-only ABI → refuse in BOTH modes (silent envelope under-record).
  for (const arbiterMode of [false, true]) {
    const err = kemBootGuardError({ kemPkHash: NONZERO, arbiterMode, hasKemKey: true, abiKnowsKem: false, kemKeyPkHash: NONZERO });
    ok(typeof err === "string" && /KEM event fields/.test(err) && !err.includes("\n"),
      `nonzero hash + V1 ABI → ONE-line refusal (arbiterMode=${arbiterMode})`);
  }
  // KEM epoch + arbiter mode without AUTHORITY_KEM_KEY → refuse.
  const noKey = kemBootGuardError({ kemPkHash: NONZERO, arbiterMode: true, hasKemKey: false, abiKnowsKem: true, kemKeyPkHash: null });
  ok(typeof noKey === "string" && noKey.includes("AUTHORITY_KEM_KEY") && !noKey.includes("\n"),
    "nonzero hash + keyless arbiter → ONE-line refusal naming AUTHORITY_KEM_KEY");
  // KEM epoch + arbiter key whose embedded ek hashes to a DIFFERENT pk → refuse:
  // implicit rejection would otherwise turn every honest op into a false
  // "kem binding mismatch" tamper alarm.
  const wrongKey = kemBootGuardError({
    kemPkHash: NONZERO, arbiterMode: true, hasKemKey: true, abiKnowsKem: true,
    kemKeyPkHash: "0x" + "11".repeat(32),
  });
  ok(typeof wrongKey === "string" && wrongKey.includes("does not match") && !wrongKey.includes("\n"),
    "nonzero hash + mismatched AUTHORITY_KEM_KEY → ONE-line refusal");
  // KEM epoch, honorable configs → serve: public mode never needs the key;
  // arbiter mode with the MATCHING key serves (hash compare case-blind).
  ok(kemBootGuardError({ kemPkHash: NONZERO, arbiterMode: false, hasKemKey: false, abiKnowsKem: true, kemKeyPkHash: null }) === null,
    "public mode never needs AUTHORITY_KEM_KEY");
  ok(kemBootGuardError({ kemPkHash: NONZERO, arbiterMode: true, hasKemKey: true, abiKnowsKem: true, kemKeyPkHash: NONZERO.toUpperCase().replace("0X", "0x") }) === null,
    "arbiter mode with the matching key serves a KEM epoch");
}

step("UNIT: parseKemKey — exact 2400-byte ML-KEM-768 dk, malformed rejected");
{
  const k = parseKemKey("0x" + "ab".repeat(2400));
  ok(k.length === 2400 && k[0] === 0xab, "2400-byte decapsulation key parses");
  ok(parseKemKey("ab".repeat(2400)).length === 2400, "0x prefix optional");
  for (const [bad, why] of [
    ["0xabc", "odd-length hex"],
    ["beef", "wrong length (decapsulating with a truncated key throws mid-ingest)"],
    ["0x" + "ab".repeat(1184), "pk-sized material is not a decapsulation key"],
  ] as const) {
    const threw = ((): boolean => {
      try {
        parseKemKey(bad);
        return false;
      } catch {
        return true;
      }
    })();
    ok(threw, `${why} rejected`);
  }
}

step("UNIT: parseKemGraceSeconds — one boot-time parse, garbage refuses to boot");
{
  ok(parseKemGraceSeconds(undefined) === 3600, "unset → the 3600s default");
  ok(parseKemGraceSeconds("") === 3600, "empty string counts as unset");
  ok(parseKemGraceSeconds("120") === 120, "numeric value parses");
  ok(parseKemGraceSeconds("-1") === -1, "negative allowed (the tests' everything-is-withheld dial)");
  for (const bad of ["abc", "12s", "NaN"]) {
    const threw = ((): boolean => {
      try {
        parseKemGraceSeconds(bad);
        return false;
      } catch (e) {
        return (e as Error).message.includes("KEM_GRACE_SECONDS");
      }
    })();
    ok(threw, `garbage "${bad}" throws at boot, naming the knob`);
  }
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

step("UNIT: staleOpAbiError — a build missing a dispatched op event fails closed");
{
  // staleOpAbiError now takes the viem ABI ARRAY (parseAbi of human-readable
  // fragments), not an ethers Interface — it checks the event names are present.
  const full = parseAbi([
    "event Transferred10(uint256 indexed epoch)",
    "event Transferred10x2(uint256 indexed epoch)",
    "event WithdrawAnnouncement(uint256 recipient, bytes32 stealthEphemeralPub, uint8 stealthViewTag)",
    "event OpApplied(address indexed module, uint256 startLeafIndex, uint256 nullifierCount, uint256 leafCount, uint256 subtreeRoot, uint256 root)",
    "event ModuleRegistered(address indexed module)",
    "event ModuleRemoved(address indexed module)",
  ]);
  ok(staleOpAbiError(full) === null, "ABI carrying every dispatched op event passes");
  const preV5 = parseAbi(["event Transferred10(uint256 indexed epoch)"]);
  const err = staleOpAbiError(preV5) ?? "";
  ok(err.includes("Transferred10x2"), "a V4-vintage ABI names the missing V5 event");
  const preStealth = parseAbi([
    "event Transferred10(uint256 indexed epoch)",
    "event Transferred10x2(uint256 indexed epoch)",
  ]);
  ok((staleOpAbiError(preStealth) ?? "").includes("WithdrawAnnouncement"),
    "a pre-stealth ABI names the missing announcement event");
  const preV4 = parseAbi(["event Appended(uint256 indexed leafIndex)"]);
  const err4 = staleOpAbiError(preV4) ?? "";
  ok(err4.includes("Transferred10"), "a pre-V4 ABI is refused on its first missing event");
  // A pre-op-module (V2-era) build must be refused too: without the registry
  // events the whole consumer watch-set silently never forms.
  const preV3Pool = parseAbi([
    "event Transferred10(uint256 indexed epoch)",
    "event Transferred10x2(uint256 indexed epoch)",
    "event WithdrawAnnouncement(uint256 recipient, bytes32 stealthEphemeralPub, uint8 stealthViewTag)",
  ]);
  ok((staleOpAbiError(preV3Pool) ?? "").includes("OpApplied"),
    "a pre-op-module ABI names the missing OpApplied event");
}

console.log(`\n${failures.count === 0 ? "CONFIG TEST PASS — Postgres-only boot refusal (unit + spawn)" : `CONFIG TEST FAIL — ${failures.count} assertion(s)`}`);
process.exit(failures.count === 0 ? 0 : 1);
