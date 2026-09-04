// Headless gates for the consumer config surface (the S4 contract):
//
//   (1) COMPLETENESS — DEFAULTS carries exactly the consumer key set, every value
//       sourced from @bongtu/core/network's one home (a transcription here would
//       dodge the sdk's deploy-record equality test).
//   (2) ABSENCE — no discovery-mode knob (self-scan IS the product) and no
//       institutional authority key reaches this bundle's config, by name scan
//       over the module's whole export surface.
//   (3) THE CIRCUIT PIN — wallet-web-shaped (8 lowercase hex chars, what the
//       vite.config regex extracts) and a byte table covering exactly the P2P
//       4-op consumer family, so S7 only edits values.

import { test } from "node:test";
import assert from "node:assert/strict";

import * as config from "../src/config.js";
import { CIRCUIT_ASSET_BYTES, CIRCUITS_VERSION, DEFAULTS, testnetFromEnv } from "../src/config.js";
import {
  CHAIN_ID,
  CHAIN_NAME,
  EXPLORER_BASE,
  GAS_FAUCET_URL,
  POOL_ADDRESS,
  RPC_URL,
  TOKEN_ADDRESS,
} from "@bongtu/core/network";

// ============================ (1) COMPLETENESS ===============================

test("DEFAULTS carries exactly the consumer key set", () => {
  assert.deepEqual(
    Object.keys(DEFAULTS).sort(),
    [
      "chainId",
      "chainName",
      "circuitBaseUrl",
      "explorer",
      "gasFaucet",
      "indexerUrl",
      "pool",
      "rpc",
      "testnet",
      "token",
    ],
  );
});

test("every deployment-coupled DEFAULTS value comes from the sdk's one home", () => {
  assert.equal(DEFAULTS.chainId, CHAIN_ID);
  assert.equal(DEFAULTS.chainName, CHAIN_NAME);
  assert.equal(DEFAULTS.rpc, RPC_URL);
  assert.equal(DEFAULTS.explorer, EXPLORER_BASE);
  assert.equal(DEFAULTS.gasFaucet, GAS_FAUCET_URL);
  assert.equal(DEFAULTS.pool, POOL_ADDRESS);
  assert.equal(DEFAULTS.token, TOKEN_ADDRESS);
});

test("the node-runner build (no Vite env) reads the relative same-origin bases", () => {
  assert.equal(DEFAULTS.indexerUrl, "/indexer");
  assert.equal(DEFAULTS.circuitBaseUrl, "/circuits");
});

test("testnetFromEnv: only the literal 'false' flips testnet off", () => {
  assert.equal(testnetFromEnv(undefined), true);
  assert.equal(testnetFromEnv(""), true);
  assert.equal(testnetFromEnv("true"), true);
  assert.equal(testnetFromEnv("FALSE"), true, "case-sensitive: no accidental flips");
  assert.equal(testnetFromEnv("false"), false);
  assert.equal(DEFAULTS.testnet, true, "the node runner has no Vite env: testnet");
});

// ============================ (2) ABSENCE ====================================

test("no discovery knob: self-scan IS the product, so no mode reaches the config", () => {
  assert.ok(!("discovery" in DEFAULTS), "DEFAULTS carries no discovery mode");
  for (const name of Object.keys(config)) {
    assert.ok(!/discovery/i.test(name), `config exports "${name}"`);
  }
});

test("no institutional authority key is exported from this bundle's config", () => {
  assert.ok(!("arbiterPubKey" in DEFAULTS), "DEFAULTS carries no authority pubkey");
  assert.ok(!("relayerUrl" in DEFAULTS), "DEFAULTS carries no sponsored-exit URL");
  for (const name of Object.keys(config)) {
    assert.ok(!/arbiter/i.test(name), `config exports "${name}"`);
  }
});

// ============================ (3) THE CIRCUIT PIN ============================

test("CIRCUITS_VERSION is wallet-web-shaped: 8 lowercase hex chars (the vite regex)", () => {
  assert.match(CIRCUITS_VERSION, /^[0-9a-f]{8}$/);
});

test("the byte table covers exactly the P2P 4-op consumer family, sizes pinned", () => {
  assert.deepEqual(
    Object.keys(CIRCUIT_ASSET_BYTES).sort(),
    ["depositPriv", "transfer10x2Priv", "transferPriv", "withdrawPriv"],
  );
  for (const [name, sizes] of Object.entries(CIRCUIT_ASSET_BYTES)) {
    assert.ok(sizes.wasm > 1_000_000, `${name}.wasm is a real compiled witness generator`);
    assert.ok(sizes.zkey > 1_000_000, `${name}.zkey is a real proving key`);
  }
  // The arity-10 spend key dominates the family — the reason it is fetched only
  // when note selection demands it, never on screen open.
  const biggest = Object.entries(CIRCUIT_ASSET_BYTES).sort(([, a], [, b]) => b.zkey - a.zkey)[0][0];
  assert.equal(biggest, "transfer10x2Priv");
});
