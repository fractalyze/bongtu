// Headless gates for the viem wallet edge (@bongtu/client/connection) and the app's
// wagmi config (src/lib/wagmi.ts), driven by
// FAKE EIP-1193 transports — no wallet, no relay, no RPC. What is gated here:
//
//   (1) SUBMIT — every pool/token write goes out as eth_sendTransaction with
//       byte-exact calldata for the right function, and resolves only after the
//       receipt. The browser apps do NOT pin the gas price (they ask the node for
//       eth_gasPrice and take 3x); the GAS_PRICE_PIN_GWEI pin is the live drivers'
//       — see packages/core/src/chain/network.ts. The KEM-ct length pre-check fires
//       BEFORE any RPC.
//   (2) KEM EPOCH GUARD — the pool's arbiterKemPkHash(currentEpoch()) must vouch
//       for the bundled key; a pre-KEM pool (empty eth_call return) fails CLOSED
//       with the readable message, and a transport failure is NOT mistaken for one.
//   (3) CHAIN GUARD — switch, register-then-switch on 4902, and the WalletConnect
//       transport's human-readable refusal (chainSwitchMessage), while the injected
//       path surfaces the raw error.
//   (4) ERRORS — walletErrorMessage classifies viem's layered errors (user
//       rejection, insufficient funds) identically to the plain provider shapes the
//       pre-migration code classified (wallet.test.ts pins those).
//   (5) THE WC BUILD FLAG — no VITE_WC_PROJECT_ID, no WalletConnect connector; the
//       modal then lists only installed (EIP-6963) extensions.
//   (6) IDENTITY — a wagmi connector's self-description reaches the copy through
//       the SAME sanitisation the EIP-6963 announcements always got (walletBrand):
//       name capped, control characters flattened, a remote https icon DROPPED.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  createPublicClient,
  createWalletClient,
  custom,
  defineChain,
  encodeFunctionData,
  parseAbi,
  parseGwei,
  UserRejectedRequestError,
  type PublicClient,
} from "viem";
import {
  ARBITER_KEM_PK_HASH,
  CHAIN_NAME,
  EXPLORER_BASE,
  GAS_TOKEN_PHRASE,
  POOL_ABI_FRAGMENTS,
} from "@bongtu/core/network";
import { liveChain } from "@bongtu/client/chain";
import { buildConnectors } from "../src/lib/wagmi.js";
import {
  assertPoolKemEpoch,
  chainSwitchMessage,
  ensureChain,
  mintTestToken,
  submitTransfer,
  WALLET_FAILURE_COPY,
  walletErrorMessage,
  type Connection,
} from "@bongtu/client/connection";
import type { ChainFailure } from "@bongtu/core/errors";
import { describeWallet, NEUTRAL_WALLET_NAME } from "../src/lib/walletBrand.js";
import type { Calldata } from "@bongtu/core/proving";

const ACCOUNT = "0x00000000000000000000000000000000000000a1";
const POOL = "0x0000000000000000000000000000000000000b0b";
const TX_HASH = ("0x" + "ab".repeat(32)) as `0x${string}`;
const KEM_CT = ("0x" + "cd".repeat(1088)) as `0x${string}`;
const CHAIN_HEX = "0x" + liveChain.id.toString(16);

interface RpcCall {
  method: string;
  params?: unknown[];
}

/** A fake wallet/node: answers the chain id, records every call, and lets a test
 *  script per-method behaviour. The Connection built over it exercises the REAL
 *  viem clients — only the wire is fake. */
function fakeRpc(overrides: Record<string, (params?: unknown[]) => unknown> = {}) {
  const calls: RpcCall[] = [];
  const receipt = {
    blockHash: "0x" + "11".repeat(32),
    blockNumber: "0x1",
    contractAddress: null,
    cumulativeGasUsed: "0x0",
    effectiveGasPrice: "0x0",
    from: ACCOUNT,
    gasUsed: "0x0",
    logs: [],
    logsBloom: "0x" + "0".repeat(512),
    status: "0x1",
    to: POOL,
    transactionHash: TX_HASH,
    transactionIndex: "0x0",
    type: "0x2",
  };
  const provider = {
    async request({ method, params }: { method: string; params?: unknown[] }): Promise<unknown> {
      calls.push({ method, params });
      if (overrides[method]) return overrides[method](params);
      switch (method) {
        case "eth_chainId":
          return CHAIN_HEX;
        case "eth_sendTransaction":
          return TX_HASH;
        case "eth_blockNumber":
          return "0x1";
        case "eth_getTransactionCount":
          return "0x2a"; // pending nonce 42 — asserted on the sent tx below
        case "eth_gasPrice":
          return "0xf4610"; // 1,001,000 wei ≈ the chain's real ~0.001 gwei quote
        case "eth_getTransactionReceipt":
          return receipt;
        default:
          throw new Error(`unexpected RPC ${method}`);
      }
    },
  };
  return { provider, calls };
}

function connectionOver(
  provider: { request: (a: { method: string; params?: unknown[] }) => Promise<unknown> },
  transport: Connection["transport"] = "injected",
): Connection {
  return {
    address: ACCOUNT,
    walletClient: createWalletClient({
      account: ACCOUNT as `0x${string}`,
      chain: liveChain,
      transport: custom(provider),
    }),
    publicClient: createPublicClient({
      chain: liveChain,
      transport: custom(provider),
    }) as PublicClient,
    injected: provider,
    transport,
  };
}

// A transfer's calldata shape: 37 public signals (all zero — encoding is the subject).
const TRANSFER_CALLDATA: Calldata = {
  a: ["1", "2"],
  b: [
    ["3", "4"],
    ["5", "6"],
  ],
  c: ["7", "8"],
  pub: Array.from({ length: 37 }, () => "0"),
};

// ============================ (1) SUBMIT ====================================

test("submitTransfer sends the pinned gas price and byte-exact calldata, then waits for the receipt", async () => {
  const { provider, calls } = fakeRpc();
  const res = await submitTransfer(
    connectionOver(provider),
    POOL,
    TRANSFER_CALLDATA,
    KEM_CT,
    EXPLORER_BASE,
  );

  const sent = calls.find((c) => c.method === "eth_sendTransaction");
  assert.ok(sent, "an eth_sendTransaction went out");
  const tx = (sent.params as [Record<string, string>])[0];
  assert.equal(tx.to?.toLowerCase(), POOL.toLowerCase());
  // The price is the CHAIN's word (eth_gasPrice), never wallet-stack estimation
  // (which once overpaid ~1500x) and no longer a fixed pin that goes stale when
  // the sequencer moves its floor.
  // 3x the node's quote: a tx priced exactly at the floor goes pending the
  // moment the floor drifts up a block later (observed live).
  assert.equal(BigInt(tx.gasPrice), 0xf4610n * 3n, "gas price == 3x the node's eth_gasPrice quote");
  // The nonce comes from the chain's pending count, not the wallet's tracker —
  // MetaMask's cache desyncs after speed-up/cancel surgery ("nonce too low").
  assert.equal(BigInt(tx.nonce), 42n, "nonce == the chain's pending transaction count");

  // Byte-exact calldata: the decimal-string proof encoded exactly as the pool ABI
  // fragment demands (a drift here is a silent on-chain revert).
  const expected = encodeFunctionData({
    abi: parseAbi([POOL_ABI_FRAGMENTS.transfer]),
    functionName: "transfer",
    args: [
      [1n, 2n],
      [
        [3n, 4n],
        [5n, 6n],
      ],
      [7n, 8n],
      TRANSFER_CALLDATA.pub.map(BigInt),
      KEM_CT,
    ] as never,
  });
  assert.equal(tx.data, expected);

  assert.ok(
    calls.some((c) => c.method === "eth_getTransactionReceipt"),
    "resolution waits on the receipt",
  );
  assert.equal(res.txHash, TX_HASH);
  assert.equal(res.explorerUrl, `${EXPLORER_BASE}/tx/${TX_HASH}`);
});

test("a malformed KEM ciphertext is refused before ANY RPC goes out", async () => {
  const { provider, calls } = fakeRpc();
  await assert.rejects(
    submitTransfer(connectionOver(provider), POOL, TRANSFER_CALLDATA, "0x1234", "https://x"),
    /kemCiphertext must be 1088 bytes/,
  );
  assert.equal(calls.length, 0, "the length pre-check is a client-side belt, not a revert");
});

test("mintTestToken (dev faucet) submits at the same pinned gas price", async () => {
  const { provider, calls } = fakeRpc();
  const token = "0x0000000000000000000000000000000000000c0c";
  await mintTestToken(connectionOver(provider), token, ACCOUNT, 5n);
  const sent = calls.find((c) => c.method === "eth_sendTransaction");
  assert.ok(sent);
  const tx = (sent.params as [Record<string, string>])[0];
  assert.equal(tx.to?.toLowerCase(), token);
  assert.equal(BigInt(tx.gasPrice), 0xf4610n * 3n, "mint pays the same 3x chain-quoted price");
});

test("submit signs against the walletClient's OWN chain binding, so a non-live rig (the e2e gate's anvil) submits without a mismatch", async () => {
  // The apps bind their clients to liveChain, so this seam changes nothing for
  // them; the heavy consumer e2e leg binds its rig to anvil and rides the same
  // submitPoolWrite. viem's chain assert must check the client's binding, not a
  // hardcoded liveChain pin.
  const anvil = defineChain({
    id: 31337,
    name: "anvil",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: ["http://127.0.0.1:8545"] } },
  });
  const { provider, calls } = fakeRpc({ eth_chainId: () => "0x7a69" });
  const connection: Connection = {
    address: ACCOUNT,
    walletClient: createWalletClient({
      account: ACCOUNT as `0x${string}`,
      chain: anvil,
      transport: custom(provider),
    }),
    publicClient: createPublicClient({ chain: anvil, transport: custom(provider) }) as PublicClient,
    injected: provider,
    transport: "injected",
  };
  const res = await submitTransfer(connection, POOL, TRANSFER_CALLDATA, KEM_CT, EXPLORER_BASE);
  assert.equal(res.txHash, TX_HASH);
  assert.ok(calls.some((c) => c.method === "eth_sendTransaction"), "the write went out under the anvil binding");
});

// ======================== (2) KEM EPOCH GUARD ===============================

// Per-pool memoisation is part of the contract, so each test uses its own address.
const abiForCalls = parseAbi([POOL_ABI_FRAGMENTS.currentEpoch, POOL_ABI_FRAGMENTS.arbiterKemPkHash]);

test("assertPoolKemEpoch passes when the chain vouches for the bundled KEM key", async () => {
  const pool = "0x0000000000000000000000000000000000000001";
  const { provider } = fakeRpc({
    eth_call: (params) => {
      const data = (params as [{ data: string }])[0].data;
      const epochSelector = encodeFunctionData({ abi: abiForCalls, functionName: "currentEpoch" });
      return data === epochSelector
        ? "0x" + "0".repeat(63) + "1" // currentEpoch() == 1
        : ARBITER_KEM_PK_HASH; // arbiterKemPkHash(1) == the bundled key's hash
    },
  });
  await assert.doesNotReject(assertPoolKemEpoch(connectionOver(provider), pool));
});

test("a pre-KEM pool (empty eth_call return) fails CLOSED with the readable message", async () => {
  const pool = "0x0000000000000000000000000000000000000002";
  const { provider } = fakeRpc({ eth_call: () => "0x" });
  await assert.rejects(
    assertPoolKemEpoch(connectionOver(provider), pool),
    /This wallet version doesn't match the network yet/,
  );
});

test("a transport failure is surfaced, never classified as a pre-KEM pool", async () => {
  const pool = "0x0000000000000000000000000000000000000003";
  const { provider } = fakeRpc({
    eth_call: () => {
      throw new Error("connection refused");
    },
  });
  await assert.rejects(assertPoolKemEpoch(connectionOver(provider), pool), (e: Error) => {
    // folding a network hiccup into "V1 pool" would fail the guard OPEN
    assert.doesNotMatch(e.message, /doesn't match the network/);
    return true;
  });
});

test("a wrong on-chain hash is refused (never encapsulate to an unverified key)", async () => {
  const pool = "0x0000000000000000000000000000000000000004";
  const { provider } = fakeRpc({
    eth_call: (params) => {
      const data = (params as [{ data: string }])[0].data;
      const epochSelector = encodeFunctionData({ abi: abiForCalls, functionName: "currentEpoch" });
      return data === epochSelector ? "0x" + "0".repeat(63) + "1" : "0x" + "ff".repeat(32);
    },
  });
  await assert.rejects(
    assertPoolKemEpoch(connectionOver(provider), pool),
    /This wallet version doesn't match the network yet/,
  );
});

// ========================== (3) CHAIN GUARD =================================

test("ensureChain switches, and registers the chain first when the wallet answers 4902", async () => {
  // Already known: one switch, no add.
  const known = fakeRpc({ wallet_switchEthereumChain: () => null });
  await ensureChain(connectionOver(known.provider));
  assert.deepEqual(
    known.calls.map((c) => c.method),
    ["wallet_switchEthereumChain"],
  );

  // Unknown chain: add, then switch again.
  const switches = { n: 0 };
  const unknown = fakeRpc({
    wallet_switchEthereumChain: () => {
      switches.n += 1;
      if (switches.n === 1) throw { code: 4902, message: "Unrecognized chain ID" };
      return null;
    },
    wallet_addEthereumChain: () => null,
  });
  await ensureChain(connectionOver(unknown.provider));
  const methods = unknown.calls.map((c) => c.method);
  assert.deepEqual(methods, [
    "wallet_switchEthereumChain",
    "wallet_addEthereumChain",
    "wallet_switchEthereumChain",
  ]);
  const added = unknown.calls[1].params as [Record<string, unknown>];
  assert.equal(added[0].chainId, CHAIN_HEX, "the registered chain is the live one, from the one network module");
  assert.equal(added[0].chainName, CHAIN_NAME, "and it is named from that same module");
});

test("a wallet that will not move to the live chain says so in words, over WalletConnect only", async () => {
  const refused = { code: 4001 };
  assert.match(chainSwitchMessage(refused), /You declined the network switch/);
  assert.match(chainSwitchMessage(new Error("relay timeout")), /Add or select that network/);

  const failing = () =>
    fakeRpc({
      wallet_switchEthereumChain: () => {
        throw new Error("method not supported");
      },
    });
  await assert.rejects(
    ensureChain(connectionOver(failing().provider, "walletconnect")),
    /Add or select that network/,
  );
  // The injected path is untouched: its raw error still surfaces for walletErrorMessage.
  await assert.rejects(ensureChain(connectionOver(failing().provider, "injected")), /method not supported/);
});

// ============================ (4) ERRORS ====================================

test("walletErrorMessage classifies viem's layered errors like the plain provider shapes", () => {
  // viem wraps the wallet's 4001 several `cause` levels deep.
  const rejection = new UserRejectedRequestError(new Error("User rejected the request."));
  assert.equal(walletErrorMessage(rejection), "Transaction rejected in your wallet.");
  const wrapped = new Error("Request failed.");
  (wrapped as { cause?: unknown }).cause = rejection;
  assert.equal(walletErrorMessage(wrapped), "Transaction rejected in your wallet.");

  // "insufficient funds" surfacing anywhere in the chain gets the gas-token explainer.
  const outOfGas = new Error("Transaction creation failed.");
  (outOfGas as { cause?: unknown }).cause = {
    name: "InsufficientFundsError",
    details: "insufficient funds for gas * price + value",
  };
  assert.ok(walletErrorMessage(outOfGas).includes(GAS_TOKEN_PHRASE));

  // A viem error's shortMessage wins over its multi-line .message dump.
  const reverted = {
    name: "ContractFunctionExecutionError",
    shortMessage: 'The contract function "transfer" reverted.',
    message: 'The contract function "transfer" reverted.\n\nContract Call:\n  address: 0x...',
  };
  assert.equal(walletErrorMessage(reverted), 'The contract function "transfer" reverted.');
});

test("the wallet copy table covers every ChainFailure kind, each with words", () => {
  assert.deepEqual(
    Object.keys(WALLET_FAILURE_COPY).sort(),
    ["chain_switch", "insufficient_gas", "other", "timeout", "transport", "user_rejected"],
    "a kind added to the classifier must get a wording decision here, not a fall-through",
  );
  for (const [kind, words] of Object.entries(WALLET_FAILURE_COPY)) {
    for (const rejected of [false, true]) {
      const failure = { kind, rejected, text: "engine line" } as unknown as ChainFailure;
      const message = (words as (f: ChainFailure, e: unknown) => string)(failure, new Error("engine line"));
      assert.ok(message.length > 0, `${kind} (rejected=${rejected}) must map to words`);
    }
  }
  // A DECLINED switch is a rejection in the wallet's words — pin the exact line.
  const declined = { kind: "chain_switch", rejected: true, text: null } as unknown as ChainFailure;
  assert.equal(WALLET_FAILURE_COPY.chain_switch(declined as never, declined), "Transaction rejected in your wallet.");
});

// ========================= (5) THE WC BUILD FLAG ============================

test("no project id, no WalletConnect connector — extensions-only modal", () => {
  assert.deepEqual(buildConnectors(null), []);
  // With an id, the WalletConnect wallet joins (RainbowKit contributes the wallet
  // itself plus its own QR-modal connector — both are the WC path).
  const withId = buildConnectors("test-project-id");
  assert.ok(withId.length >= 1, "the WalletConnect connector joins the config");
  for (const c of withId) assert.equal(typeof c, "function");
});

// ============================ (6) IDENTITY ==================================

const DATA_ICON = "data:image/png;base64,iVBORw0KGgo=";

test("a connector's self-description goes through the one sanitisation path", () => {
  // The connector object models wagmi's: EIP-6963 name/icon + the raw provider's flags.
  const described = describeWallet(
    { isMetaMask: true, isRabby: true },
    { name: "A Very Long Wallet Name That Would Reflow The Screen", icon: DATA_ICON },
  );
  assert.equal(described.brand, "rabby", "the vendor's own flag beats the MetaMask compatibility flag");
  assert.equal(described.name.length, 24, "capped, exactly as announced names always were");
  assert.equal(described.iconUrl, DATA_ICON, "a data: icon is safe to draw");
});

test("a remote (https) connector icon is DROPPED, not fetched", () => {
  const described = describeWallet(null, {
    name: "Phone  Wallet",
    icon: "https://wallet.example/icon.png",
  });
  assert.equal(described.iconUrl, null, "fetching it would report every render to the vendor");
  assert.equal(described.name, "Phone Wallet", "and the control character is flattened");
  assert.equal(described.brand, "unknown", "a remote wallet flies no vendor flag — never guess one");
});

test("no connector and no announcement is described in neutral words", () => {
  const described = describeWallet(null, null);
  assert.equal(described.name, NEUTRAL_WALLET_NAME);
  assert.equal(described.named, false);
});
