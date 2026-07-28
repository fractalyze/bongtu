// Decision tables for the three boundary classifiers (src/errors.ts) — one block per
// classifier, one assertion row per verdict, per the error-surface standard
// (.dev/error-surface-design.md). These are the headless gates the standard requires
// for "every behavior change": the classes decide surfaces, so a misclassified error
// IS a wrong surface.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  bugError,
  causeChain,
  classifyChainFailure,
  classifyIndexerRead,
  classifyProvingFailure,
  describeThrown,
  errorCode,
  errorTexts,
} from "../src/errors.js";

// ========================= (a) indexer HTTP reads ================================

test("classifyIndexerRead: 401 is unauthorized — the one conclusive verdict", () => {
  const f = classifyIndexerRead(new Error("http://x/notes -> 401: view token invalid or expired"));
  assert.deepEqual(f, { kind: "unauthorized", status: 401 });
});

test("classifyIndexerRead: 403/404 is the wrong-indexer case, not a dead token", () => {
  assert.deepEqual(classifyIndexerRead(new Error("http://x/notes -> 404: not found")), {
    kind: "wrong_endpoint",
    status: 404,
  });
  assert.deepEqual(classifyIndexerRead(new Error("http://x/notes -> 403: nope")), {
    kind: "wrong_endpoint",
    status: 403,
  });
});

test("classifyIndexerRead: other statuses and transport failures are unreachable", () => {
  const server = classifyIndexerRead(new Error("http://x/notes -> 500: boom"));
  assert.equal(server.kind, "unreachable");
  assert.equal(server.kind === "unreachable" && server.status, 500);

  const offline = classifyIndexerRead(new TypeError("Failed to fetch"));
  assert.deepEqual(offline, { kind: "unreachable", status: null, detail: "Failed to fetch" });

  // Non-Error throws must not crash the classifier (total function).
  assert.equal(classifyIndexerRead("boom").kind, "unreachable");
  assert.equal(classifyIndexerRead(undefined).kind, "unreachable");
});

test("classifyIndexerRead parses only the sdk's 'url -> status' contract, not stray digits", () => {
  // A 3-digit number NOT behind the arrow is no status.
  const f = classifyIndexerRead(new Error("block 401 unavailable"));
  assert.equal(f.kind, "unreachable");
});

// ======================== (b) chain / provider errors ============================

test("causeChain walks nested causes, bounded against cycles", () => {
  const leaf = { name: "UserRejectedRequestError", code: 4001 };
  const mid = { name: "TransactionExecutionError", cause: leaf };
  const top = new Error("outer");
  (top as { cause?: unknown }).cause = mid;
  assert.equal(causeChain(top).length, 3);

  const a: Record<string, unknown> = {};
  const b: Record<string, unknown> = { cause: a };
  a.cause = b; // cycle
  assert.equal(causeChain(a).length, 8, "cyclic causes terminate at the bound");
});

test("errorCode/errorTexts dig the conventional fields at any depth", () => {
  const e = { cause: { code: "ACTION_REJECTED", shortMessage: "short", data: { message: "deep" } } };
  assert.equal(errorCode(e), "ACTION_REJECTED");
  assert.ok(errorTexts(e).includes("deep"));
  assert.ok(errorTexts(e).includes("short"));
});

test("classifyChainFailure: user rejection in every shape it arrives as", () => {
  // EIP-1193 ProviderRpcError code
  assert.equal(classifyChainFailure({ code: 4001, message: "User rejected the request." }).kind, "user_rejected");
  // ethers-style string code
  assert.equal(classifyChainFailure({ code: "ACTION_REJECTED", message: "user rejected transaction" }).kind, "user_rejected");
  // viem's typed error, nested two causes deep
  const viem = { name: "TransactionExecutionError", cause: { name: "UserRejectedRequestError", message: "User rejected the request." } };
  assert.equal(classifyChainFailure(viem).kind, "user_rejected");
  // text-only ("user denied")
  assert.equal(classifyChainFailure({ message: "MetaMask Tx Signature: User denied transaction signature." }).kind, "user_rejected");
});

test("classifyChainFailure: insufficient funds is its own verdict", () => {
  const f = classifyChainFailure({ code: -32603, message: "insufficient funds for gas * price + value" });
  assert.equal(f.kind, "insufficient_gas");
});

test("classifyChainFailure: a refused or failed chain switch is chain_switch, with the rejection flagged", () => {
  const refusedSwitch = {
    name: "SwitchChainError",
    message: "An error occurred when attempting to switch chain.",
    cause: { code: 4001, message: "User rejected the request." },
  };
  const f = classifyChainFailure(refusedSwitch);
  assert.equal(f.kind, "chain_switch");
  assert.equal(f.kind === "chain_switch" && f.rejected, true);

  const failedSwitch = { name: "ChainNotConfiguredError", message: "Chain not configured." };
  const g = classifyChainFailure(failedSwitch);
  assert.equal(g.kind, "chain_switch");
  assert.equal(g.kind === "chain_switch" && g.rejected, false);
});

test("classifyChainFailure: timeouts and transport failures", () => {
  assert.equal(classifyChainFailure({ name: "TimeoutError", message: "The request timed out." }).kind, "timeout");
  assert.equal(classifyChainFailure({ message: "request timed out after 10s" }).kind, "timeout");
  assert.equal(
    classifyChainFailure({ name: "HttpRequestError", message: "HTTP request failed.", details: "fetch failed" }).kind,
    "transport",
  );
  assert.equal(classifyChainFailure(new TypeError("Failed to fetch")).kind, "transport");
});

test("classifyChainFailure: everything else keeps viem's own best text (reverts included)", () => {
  const reverted = {
    name: "ContractFunctionExecutionError",
    shortMessage: 'The contract function "transfer" reverted.',
    message: 'The contract function "transfer" reverted.\n\nlong viem dump',
  };
  const f = classifyChainFailure(reverted);
  assert.equal(f.kind, "other");
  assert.equal(f.text, 'The contract function "transfer" reverted.');

  const bare = classifyChainFailure({});
  assert.equal(bare.kind, "other");
  assert.equal(bare.text, null);
});

test("classifyChainFailure: text priority is reason > error.message > data.message > shortMessage", () => {
  const f = classifyChainFailure({ reason: "execution reverted: InvalidProof", shortMessage: "later" });
  assert.equal(f.text, "execution reverted: InvalidProof");
});

// ============================ (c) proving worker =================================

test("classifyProvingFailure: asset downloads, witness asserts, memory, other", () => {
  assert.equal(classifyProvingFailure(new Error("https://blob/x/transfer.zkey -> 404: gone")).kind, "assets");
  assert.equal(classifyProvingFailure(new TypeError("Failed to fetch")).kind, "assets");
  assert.equal(classifyProvingFailure(new Error("Error: Assert Failed. Error in template CheckSum_5")).kind, "witness");
  assert.equal(classifyProvingFailure(new Error("Not all inputs have been set. Only 12 out of 40")).kind, "witness");
  assert.equal(classifyProvingFailure(new Error("RuntimeError: memory access out of bounds")).kind, "memory");
  assert.equal(classifyProvingFailure(new Error("something odd")).kind, "other");
  assert.equal(classifyProvingFailure(42).kind, "other");
});

// ================================ AppError =======================================

test("bugError carries a headline plus copyable details (message + stack + causes)", () => {
  const inner = new Error("inner boom");
  const outer = new Error("outer");
  (outer as { cause?: unknown }).cause = inner;
  const b = bugError("Something unexpected went wrong.", outer);
  assert.equal(b.kind, "bug");
  assert.equal(b.message, "Something unexpected went wrong.");
  assert.match(b.details, /outer/);
  assert.match(b.details, /caused by: Error: inner boom/);
});

test("describeThrown never throws: strings, plain objects, cyclic objects", () => {
  assert.equal(describeThrown("boom"), "boom");
  assert.match(describeThrown({ code: 4001 }), /4001/);
  const cyc: Record<string, unknown> = {};
  cyc.self = cyc;
  assert.equal(typeof describeThrown(cyc), "string"); // JSON fails, String() fallback
});
