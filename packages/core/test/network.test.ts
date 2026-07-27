// Equality gate for the deployment-coupled chain facts (src/network.ts).
//
// Every constant in the network module describes the LIVE GIWA pool — a
// transcription slip breaks both apps against the live deployment and surfaces
// only at on-chain proof rejection. This suite convicts any slip in
// milliseconds instead:
//
//   1. Facts the deploy artifact carries (deploy/addresses.91342.json — the
//      canonical record, CLAUDE.md "live pool is canonical") are asserted
//      EQUAL to it field-for-field, so a redeploy that edits the JSON turns
//      this suite red until the module follows.
//   2. Facts the artifact does NOT carry (H, the gas floor, RPC/explorer
//      bases, the POOL_ABI_FRAGMENTS fragment strings) are pinned byte-for-byte to the
//      values previously hand-copied across apps/payroll-web/src/lib/chain.ts,
//      apps/wallet-web/src/lib/metamask.ts, both app config.ts files, and
//      deploy/giwa_disburse256.ts — the copies this module replaced.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ARBITER_KEM_PK,
  ARBITER_KEM_PK_HASH,
  ARBITER_PUBKEY_X,
  ARBITER_PUBKEY_Y,
  B,
  CHAIN_ID,
  EXPLORER_BASE,
  GIWA_GAS_FLOOR_GWEI,
  H,
  POOL_ABI_FRAGMENTS,
  POOL_ADDRESS,
  RPC_URL,
  TOKEN_ADDRESS,
  arbiterKemPkGuardError,
  explorerTxUrl,
  isPreKemProbeError,
} from "../src/network.js";
import { keccak_256 } from "@noble/hashes/sha3";

import { KEM_PUBLIC_KEY_BYTES, kemBytesToHex, kemHexToBytes, ml_kem768 } from "../src/kem.js";

// packages/core/test -> repo root (tests run under tsx/node, not the browser).
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

interface Addresses {
  arbiterKemPk: string;
  arbiterKemPkHash: string;
  arbiterKeyX: string;
  arbiterKeyY: string;
  batchSize: number;
  chainId: number;
  pool: string;
  token: string;
}
const addr = JSON.parse(
  readFileSync(join(REPO_ROOT, "deploy", "addresses.91342.json"), "utf8"),
) as Addresses;

test("module facts equal deploy/addresses.91342.json field-for-field", () => {
  // JSON key -> module value, one row per fact the module owns. A redeploy
  // (new addresses.91342.json) fails here naming the exact stale field.
  const owned: Record<keyof Addresses, string | number> = {
    pool: POOL_ADDRESS,
    token: TOKEN_ADDRESS,
    chainId: CHAIN_ID,
    batchSize: B,
    arbiterKeyX: ARBITER_PUBKEY_X,
    arbiterKeyY: ARBITER_PUBKEY_Y,
    arbiterKemPk: ARBITER_KEM_PK,
    arbiterKemPkHash: ARBITER_KEM_PK_HASH,
  };
  for (const [key, moduleValue] of Object.entries(owned)) {
    assert.deepEqual(
      moduleValue,
      addr[key as keyof Addresses],
      `network.ts disagrees with addresses.91342.json on "${key}"`,
    );
  }
  // The tuple form both app configs consume is the same two scalars.
  assert.deepEqual([ARBITER_PUBKEY_X, ARBITER_PUBKEY_Y], [addr.arbiterKeyX, addr.arbiterKeyY]);
});

test("facts outside the deploy artifact are pinned to the pre-module copies", () => {
  // SPEC §4 IMT height — was re-declared per app config.
  assert.equal(H, 32);
  // GIWA wants ~0.001 gwei; ethers' auto-estimate overpays ~1500x. 0.005 gwei
  // safe floor — was copied in chain.ts / metamask.ts / giwa_disburse256.ts.
  assert.equal(GIWA_GAS_FLOOR_GWEI, "0.005");
  // Chain endpoints — were copied in both app config.ts files.
  assert.equal(RPC_URL, "https://sepolia-rpc.giwa.io");
  assert.equal(EXPLORER_BASE, "https://sepolia-explorer.giwa.io");
});

test("POOL_ABI_FRAGMENTS fragments match the hybrid (V2) BongtuPool signatures", () => {
  // Every op grows +1 public input (kemBinding as the last circuit output shifts
  // the inputs) AND a separate bytes kemCiphertext arg — the exact §4 deltas of
  // .dev/pq-envelope-design.md. These fragments therefore DO NOT match the live
  // pre-KEM V1 pool until the coordinated §7 upgrade lands (deliberate: a
  // lagging client must fail loudly, never send a silent non-PQ op).
  assert.equal(
    POOL_ABI_FRAGMENTS.deposit,
    "function deposit(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[19] pub, bytes kemCiphertext)",
  );
  assert.equal(
    POOL_ABI_FRAGMENTS.transfer,
    "function transfer(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[37] pub, bytes kemCiphertext)",
  );
  assert.equal(
    POOL_ABI_FRAGMENTS.withdraw,
    "function withdraw(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[26] pub, bytes kemCiphertext)",
  );
  // Admin fragment (apps/payroll-web/src/lib/chain.ts): §6b v2 enforced-length
  // disburse — receiverCiphertexts is the separate 2054-element calldata arg.
  assert.equal(
    POOL_ABI_FRAGMENTS.disburseWithCiphertexts,
    "function disburseWithCiphertexts(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[11] pub, uint256[] receiverCiphertexts, bytes kemCiphertext)",
  );
  // Shared view fns.
  assert.equal(POOL_ABI_FRAGMENTS.root, "function root() view returns (uint256)");
  assert.equal(POOL_ABI_FRAGMENTS.nextLeafIndex, "function nextLeafIndex() view returns (uint256)");
  assert.equal(POOL_ABI_FRAGMENTS.B, "function B() view returns (uint256)");
  assert.equal(POOL_ABI_FRAGMENTS.currentEpoch, "function currentEpoch() view returns (uint256)");
  assert.equal(
    POOL_ABI_FRAGMENTS.arbiterKemPkHash,
    "function arbiterKemPkHash(uint256 epoch) view returns (bytes32)",
  );
});

test("ARBITER_KEM_PK is the deploy artifact's 1184-byte key and hashes to ARBITER_KEM_PK_HASH", () => {
  // Also equality-tested field-for-field against addresses.91342.json above;
  // this pins the internal consistency: length, the deploy/arbiter-kem-pk
  // artifact file, keccak256(pk) == the stored hash, and that the bytes ARE a
  // usable ML-KEM-768 encapsulation key (noble accepts them).
  const bytes = kemHexToBytes(ARBITER_KEM_PK);
  assert.equal(bytes.length, KEM_PUBLIC_KEY_BYTES);
  const artifact = readFileSync(join(REPO_ROOT, "deploy", "arbiter-kem-pk.91342.hex"), "utf8").trim();
  assert.equal(ARBITER_KEM_PK, artifact.startsWith("0x") ? artifact : `0x${artifact}`);
  // noble keccak, NOT loadEthers: the extern loader resolves via the dev-box
  // BONGTU_NODE_MODULES fallback, which hosted CI runners do not have.
  assert.equal(kemBytesToHex(keccak_256(bytes)), ARBITER_KEM_PK_HASH);
  const { cipherText, sharedSecret } = ml_kem768.encapsulate(bytes);
  assert.equal(cipherText.length, 1088);
  assert.equal(sharedSecret.length, 32);
});

test("explorerTxUrl builds the live explorer link (trailing slash tolerated)", () => {
  assert.equal(explorerTxUrl("0xabc"), "https://sepolia-explorer.giwa.io/tx/0xabc");
  // metamask.ts trimmed a trailing slash off the base; behavior preserved.
  assert.equal(explorerTxUrl("0xabc", "https://x.example/"), "https://x.example/tx/0xabc");
  assert.equal(explorerTxUrl("0xabc", "https://x.example"), "https://x.example/tx/0xabc");
});

test("arbiterKemPkGuardError: match passes, V1 pool and foreign hash refuse", () => {
  assert.equal(arbiterKemPkGuardError(ARBITER_KEM_PK_HASH), null);
  // ethers returns checksummed/upper hex depending on path; hash compare is case-blind.
  assert.equal(arbiterKemPkGuardError(ARBITER_KEM_PK_HASH.toUpperCase().replace("0X", "0x")), null);
  const v1 = arbiterKemPkGuardError(null);
  assert.ok(v1 !== null && v1.includes("pre-PQ V1 pool"));
  const foreign = arbiterKemPkGuardError("0x" + "11".repeat(32));
  assert.ok(foreign !== null && foreign.includes("does not match"));
});

test("isPreKemProbeError: only CALL_EXCEPTION marks a V1 pool", () => {
  assert.equal(isPreKemProbeError({ code: "CALL_EXCEPTION" }), true);
  // Transient failures must NOT fold to "V1 pool" — that would fail guards open.
  assert.equal(isPreKemProbeError({ code: "NETWORK_ERROR" }), false);
  assert.equal(isPreKemProbeError({ code: "SERVER_ERROR" }), false);
  assert.equal(isPreKemProbeError(new Error("timeout")), false);
  assert.equal(isPreKemProbeError(null), false);
});
