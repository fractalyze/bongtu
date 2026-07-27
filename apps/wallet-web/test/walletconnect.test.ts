// Headless gates for the WalletConnect path, driven by a FAKE wallet — no relay, no
// project id, no phone. What is gated here, in the order it matters:
//
//   (1) THE SEAM — a WalletConnect provider becomes the same `Connection` every other
//       module already works against, down to signing the derivation struct through it.
//   (2) DETERMINISM — the check that stands between a randomising wallet and a user
//       whose notes quietly stop being theirs (loginGuard.ts). Both halves: the
//       first-login double signature, and the comparison against the key this browser
//       already saw the account derive.
//   (3) NOTHING IS OVERWRITTEN ON REFUSAL — the point of the check. A refused login
//       must leave the stored session and the remembered binding exactly as they were.
//   (4) SILENT RESTORE — a returning visit reopens a live session, and can never pop a
//       QR modal at someone who did not ask for one.
//   (5) IDENTITY — the peer's self-description goes through the SAME sanitisation the
//       EIP-6963 announcements do, so a remote icon URL is dropped rather than fetched.
//   (6) EVENTS + CHAIN GUARD — account switches, the peer hanging up, and a wallet that
//       will not move to GIWA.
//   (7) THE FLAG IS OFF BY DEFAULT — no button, and no path by which the SDK could
//       reach the default bundle.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { CHAIN_ID } from "@bongtu/core/network";
import { deriveIdentityFromSignature } from "../src/lib/derive.js";
import { announcedWallet } from "../src/lib/eip6963.js";
import { deriveLoginIdentity } from "../src/lib/identity.js";
import {
  KEY_CHANGED_MESSAGE,
  NONDETERMINISTIC_WALLET_MESSAGE,
  assertDeterministicSignatures,
  assertKeyUnchanged,
  loginNeedsDeterminismCheck,
} from "../src/lib/loginGuard.js";
import { runLogin, type RunLoginDeps } from "../src/lib/loginFlow.js";
import { chainSwitchMessage, ensureChain, onWalletEvents, signKeyDerivation } from "../src/lib/metamask.js";
import type { Connection } from "../src/lib/metamask.js";
import { keyDerivationTypedData } from "../src/lib/derive.js";
import { describeWallet, NEUTRAL_WALLET_NAME } from "../src/lib/walletBrand.js";
import type { StoredSession } from "../src/lib/session.js";
import {
  WALLETCONNECT_NO_ACCOUNT_MESSAGE,
  WALLETCONNECT_UNCONFIGURED_MESSAGE,
  connectWalletConnect,
  reconnectWalletConnect,
  walletConnectEnabled,
  walletConnectProjectId,
  type WalletConnectDeps,
  type WalletConnectProvider,
} from "../src/lib/walletconnect.js";

const ACCOUNT = "0x00000000000000000000000000000000000000A1";
const OTHER_ACCOUNT = "0x00000000000000000000000000000000000000b2";
const PROJECT_ID = "test-project-id";

const SIG_A = "0x" + "a1".repeat(32) + "b2".repeat(32) + "1c";
const SIG_B = "0x" + "c3".repeat(32) + "d4".repeat(32) + "1b";
const IDENTITY_A = deriveIdentityFromSignature(SIG_A);
const IDENTITY_B = deriveIdentityFromSignature(SIG_B);

const DATA_ICON = "data:image/png;base64,iVBORw0KGgo=";

// ---------------------------------------------------------------------------------
// The fake wallet: an EIP-1193 object with the WalletConnect extras, recording every
// call so a test can assert what did NOT happen (no modal, no second signature).
// ---------------------------------------------------------------------------------

interface FakeOptions {
  accounts?: string[];
  /** Returned in order by successive eth_signTypedData_v4 calls; the last repeats. */
  signatures?: string[];
  peer?: { name?: unknown; icons?: unknown };
  /** Whether a session already exists (the silent-restore condition). */
  connected?: boolean;
  switchChainError?: unknown;
}

class FakeWallet implements WalletConnectProvider {
  accounts: string[];
  session?: { peer?: { metadata?: { name?: unknown; icons?: unknown } } };
  connectCalls = 0;
  disconnectCalls = 0;
  readonly methodCalls: string[] = [];
  private signIndex = 0;
  private readonly listeners = new Map<string, Set<() => void>>();
  private readonly options: FakeOptions;

  constructor(options: FakeOptions = {}) {
    this.options = options;
    this.accounts = options.connected ? (options.accounts ?? [ACCOUNT]) : [];
    if (options.connected) this.session = { peer: { metadata: options.peer ?? { name: "Fake Wallet" } } };
  }

  async connect(): Promise<void> {
    this.connectCalls += 1;
    this.accounts = this.options.accounts ?? [ACCOUNT];
    this.session = { peer: { metadata: this.options.peer ?? { name: "Fake Wallet" } } };
  }

  async disconnect(): Promise<void> {
    this.disconnectCalls += 1;
    this.session = undefined;
    this.accounts = [];
  }

  async request(args: { method: string; params?: unknown[] }): Promise<unknown> {
    this.methodCalls.push(args.method);
    switch (args.method) {
      case "eth_chainId":
        return "0x" + CHAIN_ID.toString(16);
      case "eth_accounts":
        return this.accounts;
      case "eth_signTypedData_v4": {
        const sigs = this.options.signatures ?? [SIG_A];
        return sigs[Math.min(this.signIndex++, sigs.length - 1)];
      }
      case "wallet_switchEthereumChain":
        if (this.options.switchChainError) throw this.options.switchChainError;
        return null;
      default:
        throw new Error(`unexpected RPC ${args.method}`);
    }
  }

  on(event: string, handler: () => void): void {
    const set = this.listeners.get(event) ?? new Set<() => void>();
    set.add(handler);
    this.listeners.set(event, set);
  }

  removeListener(event: string, handler: () => void): void {
    this.listeners.get(event)?.delete(handler);
  }

  /** Fire what the wallet app would fire. */
  emit(event: string): void {
    for (const h of [...(this.listeners.get(event) ?? [])]) h();
  }

  listenerCount(event: string): number {
    return this.listeners.get(event)?.size ?? 0;
  }
}

function wcDeps(wallet: FakeWallet, projectId: string | null = PROJECT_ID): WalletConnectDeps {
  return { projectId: () => projectId, createProvider: async () => wallet };
}

// ============================ (1) THE SEAM ==================================

test("a WalletConnect wallet becomes the same Connection shape the injected path returns", async () => {
  const wallet = new FakeWallet();
  const conn = await connectWalletConnect(wcDeps(wallet));

  assert.equal(conn.address, ACCOUNT);
  assert.equal(conn.transport, "walletconnect");
  assert.equal(wallet.connectCalls, 1, "no live session yet, so the modal opens exactly once");
  // The raw EIP-1193 object sits where every downstream module looks for it — which is
  // why the chain guard and the wallet-identity path needed no WalletConnect branch.
  assert.equal(conn.provider.provider, wallet);
  assert.equal(typeof conn.signer._signTypedData, "function");
});

test("the derivation signature is obtained THROUGH the seam, and derives the same key as any other signature", async () => {
  const wallet = new FakeWallet({ signatures: [SIG_A] });
  const conn = await connectWalletConnect(wcDeps(wallet));

  const typed = keyDerivationTypedData(CHAIN_ID, "0x" + "11".repeat(20), "1");
  const signature = await signKeyDerivation(conn, typed);

  assert.equal(signature, SIG_A);
  assert.ok(wallet.methodCalls.includes("eth_signTypedData_v4"), "the wallet was asked to sign");
  assert.equal(deriveIdentityFromSignature(signature).compressedPubkey, IDENTITY_A.compressedPubkey);
});

test("a wallet that approves the session but shares no account is refused readably", async () => {
  const wallet = new FakeWallet({ accounts: [] });
  await assert.rejects(connectWalletConnect(wcDeps(wallet)), new RegExp(WALLETCONNECT_NO_ACCOUNT_MESSAGE));
});

test("an unconfigured build cannot connect at all", async () => {
  const wallet = new FakeWallet();
  await assert.rejects(
    connectWalletConnect(wcDeps(wallet, null)),
    new RegExp(WALLETCONNECT_UNCONFIGURED_MESSAGE),
  );
  assert.equal(wallet.connectCalls, 0, "and never opens a modal on the way to failing");
});

// ============================ (2) DETERMINISM ===============================

test("only a first WalletConnect login pays the second signature", () => {
  assert.equal(loginNeedsDeterminismCheck("walletconnect", null), true);
  assert.equal(
    loginNeedsDeterminismCheck("walletconnect", IDENTITY_A.compressedPubkey),
    false,
    "a remembered key is the better reference — no second popup",
  );
  assert.equal(loginNeedsDeterminismCheck("injected", null), false);
  assert.equal(loginNeedsDeterminismCheck("injected", IDENTITY_A.compressedPubkey), false);
});

test("two signatures over the same struct must be the same bytes", () => {
  assert.doesNotThrow(() => assertDeterministicSignatures(SIG_A, SIG_A));
  assert.doesNotThrow(
    () => assertDeterministicSignatures(SIG_A, SIG_A.toUpperCase().replace("0X", "0x")),
    "the same bytes written in another case are not a difference — the KDF hashes bytes",
  );
  assert.throws(
    () => assertDeterministicSignatures(SIG_A, SIG_B),
    new RegExp(NONDETERMINISTIC_WALLET_MESSAGE.slice(0, 40)),
  );
});

test("the self-check signs twice, and a randomising wallet is refused by name", async () => {
  const conn = {} as Connection;
  const deterministic: string[] = [];
  const identity = await deriveLoginIdentity(conn, { doubleSign: true }, async () => {
    deterministic.push("sign");
    return SIG_A;
  });
  assert.equal(deterministic.length, 2, "the first WalletConnect login asks twice");
  assert.equal(identity.compressedPubkey, IDENTITY_A.compressedPubkey);

  let nth = 0;
  await assert.rejects(
    deriveLoginIdentity(conn, { doubleSign: true }, async () => (nth++ === 0 ? SIG_A : SIG_B)),
    new RegExp(NONDETERMINISTIC_WALLET_MESSAGE.slice(0, 40)),
  );
});

test("the injected path never double-signs", async () => {
  const conn = {} as Connection;
  let signs = 0;
  const identity = await deriveLoginIdentity(conn, { doubleSign: false }, async () => {
    signs += 1;
    return SIG_A;
  });
  assert.equal(signs, 1, "one popup, exactly as before WalletConnect existed");
  assert.equal(identity.compressedPubkey, IDENTITY_A.compressedPubkey);
});

test("a key that changed since last time is refused with the message that says why", () => {
  assert.doesNotThrow(() => assertKeyUnchanged(IDENTITY_A.compressedPubkey, null), "a first login has nothing to contradict");
  assert.doesNotThrow(() => assertKeyUnchanged(IDENTITY_A.compressedPubkey, IDENTITY_A.compressedPubkey));
  assert.doesNotThrow(
    () => assertKeyUnchanged(IDENTITY_A.compressedPubkey.toUpperCase(), ` ${IDENTITY_A.compressedPubkey} `),
  );
  assert.throws(
    () => assertKeyUnchanged(IDENTITY_B.compressedPubkey, IDENTITY_A.compressedPubkey),
    new RegExp(KEY_CHANGED_MESSAGE.slice(0, 40)),
  );
});

// ============================ (3) REFUSAL WRITES NOTHING ====================

interface LoginTrace {
  plans: boolean[];
  savedSessions: StoredSession[];
  savedBindings: [string, string][];
  connected: ("injected" | "walletconnect")[];
}

function loginDeps(
  trace: LoginTrace,
  opts: { known?: string | null; identity?: typeof IDENTITY_A; tokenFails?: boolean } = {},
): Partial<RunLoginDeps> {
  const identity = opts.identity ?? IDENTITY_A;
  const connection = { address: ACCOUNT } as Connection;
  return {
    connectInjected: async () => {
      trace.connected.push("injected");
      return { ...connection, transport: "injected" } as Connection;
    },
    connectWalletConnect: async () => {
      trace.connected.push("walletconnect");
      return { ...connection, transport: "walletconnect" } as Connection;
    },
    deriveIdentity: async (_c, plan) => {
      trace.plans.push(plan.doubleSign);
      return identity;
    },
    obtainViewToken: async () => {
      if (opts.tokenFails) throw new Error("indexer down");
      return { token: "v1.owner.9999999999.abc", exp: 9_999_999_999 };
    },
    loadKeyBinding: () => opts.known ?? null,
    saveKeyBinding: (eoa, pk) => void trace.savedBindings.push([eoa, pk]),
    saveSession: (s) => void trace.savedSessions.push(s),
  };
}

const newTrace = (): LoginTrace => ({ plans: [], savedSessions: [], savedBindings: [], connected: [] });

test("a login whose key changed writes NOTHING — not the session, not the binding", async () => {
  const trace = newTrace();
  await assert.rejects(
    runLogin(
      { transport: "walletconnect", indexerUrl: "http://indexer" },
      // The account is remembered as IDENTITY_A here, but the wallet derives IDENTITY_B.
      loginDeps(trace, { known: IDENTITY_A.compressedPubkey, identity: IDENTITY_B }),
    ),
    new RegExp(KEY_CHANGED_MESSAGE.slice(0, 40)),
  );
  assert.deepEqual(trace.savedSessions, [], "the stored session must survive a refused login");
  assert.deepEqual(trace.savedBindings, [], "and so must the remembered key");
  assert.deepEqual(trace.plans, [false], "a remembered account never pays a second signature");
});

test("a first WalletConnect login asks the flow for the double signature; injected never does", async () => {
  const wc = newTrace();
  await runLogin({ transport: "walletconnect", indexerUrl: "http://indexer" }, loginDeps(wc));
  assert.deepEqual(wc.plans, [true]);
  assert.deepEqual(wc.connected, ["walletconnect"]);

  const injected = newTrace();
  await runLogin({ transport: "injected", indexerUrl: "http://indexer" }, loginDeps(injected));
  assert.deepEqual(injected.plans, [false]);
  assert.deepEqual(injected.connected, ["injected"]);
});

test("a successful login records the session AND what the account derives", async () => {
  const trace = newTrace();
  const result = await runLogin({ transport: "walletconnect", indexerUrl: "http://indexer" }, loginDeps(trace));

  assert.equal(result.tokenless, false);
  assert.equal(result.session.compressedPubkey, IDENTITY_A.compressedPubkey);
  assert.equal(result.session.transport, "walletconnect", "so the next visit reopens the right transport");
  assert.deepEqual(trace.savedSessions, [result.session]);
  assert.deepEqual(trace.savedBindings, [[ACCOUNT, IDENTITY_A.compressedPubkey]]);
});

test("an indexer that issues no token still records the binding, and says the session is tokenless", async () => {
  const trace = newTrace();
  const result = await runLogin(
    { transport: "walletconnect", indexerUrl: "http://indexer" },
    loginDeps(trace, { tokenFails: true }),
  );
  assert.equal(result.tokenless, true);
  assert.equal(result.session.token, "");
  assert.deepEqual(trace.savedSessions, [], "a tokenless session is never persisted");
  assert.deepEqual(
    trace.savedBindings,
    [[ACCOUNT, IDENTITY_A.compressedPubkey]],
    "which key an account derives has nothing to do with the indexer",
  );
});

// ============================ (4) SILENT RESTORE ============================

test("a live session restores without opening anything", async () => {
  const wallet = new FakeWallet({ connected: true });
  const conn = await reconnectWalletConnect(ACCOUNT.toLowerCase(), wcDeps(wallet));

  assert.ok(conn);
  assert.equal(conn.address, ACCOUNT);
  assert.equal(conn.transport, "walletconnect");
  assert.equal(wallet.connectCalls, 0, "a restore must never pop a QR modal");
});

test("no session, the wrong account, or no project id all fall back to a normal login", async () => {
  const noSession = new FakeWallet({ connected: false });
  assert.equal(await reconnectWalletConnect(ACCOUNT, wcDeps(noSession)), null);
  assert.equal(noSession.connectCalls, 0);

  const otherAccount = new FakeWallet({ connected: true, accounts: [OTHER_ACCOUNT] });
  assert.equal(await reconnectWalletConnect(ACCOUNT, wcDeps(otherAccount)), null);

  const unconfigured = new FakeWallet({ connected: true });
  assert.equal(await reconnectWalletConnect(ACCOUNT, wcDeps(unconfigured, null)), null);
});

test("a provider that cannot be built is a null restore, not a crashed page", async () => {
  const conn = await reconnectWalletConnect(ACCOUNT, {
    projectId: () => PROJECT_ID,
    createProvider: async () => {
      throw new Error("relay unreachable");
    },
  });
  assert.equal(conn, null);
});

// ============================ (5) PEER IDENTITY =============================

test("the peer's name reaches the copy through the SAME sanitisation the announcements get", async () => {
  const wallet = new FakeWallet({
    peer: { name: "A Very Long Wallet Name That Would Reflow The Screen", icons: [DATA_ICON] },
  });
  await connectWalletConnect(wcDeps(wallet));

  const described = describeWallet(wallet, announcedWallet(wallet));
  assert.equal(described.name.length, 24, "capped, exactly as an announced name is");
  assert.equal(described.name, "A Very Long Wallet Name ");
  assert.equal(described.named, true);
  assert.equal(described.iconUrl, DATA_ICON, "a data: icon is safe to draw");
  assert.equal(described.brand, "unknown", "a remote wallet flies no vendor flag — never guess one");
});

test("a remote peer icon URL is DROPPED, not fetched", async () => {
  const wallet = new FakeWallet({
    peer: { name: "Phone  Wallet", icons: ["https://wallet.example/icon.png"] },
  });
  await connectWalletConnect(wcDeps(wallet));

  const described = describeWallet(wallet, announcedWallet(wallet));
  assert.equal(described.iconUrl, null, "fetching it would report every render back to the vendor");
  assert.equal(described.name, "Phone Wallet", "and the control character is flattened");
});

test("a peer that says nothing about itself is described in neutral words", async () => {
  const wallet = new FakeWallet({ peer: {} });
  await connectWalletConnect(wcDeps(wallet));
  const described = describeWallet(wallet, announcedWallet(wallet));
  assert.equal(described.name, NEUTRAL_WALLET_NAME);
  assert.equal(described.named, false);
});

// ============================ (6) EVENTS + CHAIN GUARD ======================

test("account switches and the peer hanging up both reach their handlers, and unsubscribe cleanly", async () => {
  const wallet = new FakeWallet();
  const conn = await connectWalletConnect(wcDeps(wallet));

  let switched = 0;
  let hungUp = 0;
  const stop = onWalletEvents(conn, {
    accountsChanged: () => (switched += 1),
    disconnect: () => (hungUp += 1),
  });

  wallet.emit("accountsChanged");
  wallet.emit("disconnect");
  assert.equal(switched, 1);
  assert.equal(hungUp, 1);

  stop();
  assert.equal(wallet.listenerCount("accountsChanged"), 0);
  assert.equal(wallet.listenerCount("disconnect"), 0);
  wallet.emit("accountsChanged");
  assert.equal(switched, 1, "an unsubscribed handler stops hearing");
});

test("an omitted handler is not wired — an injected wallet's `disconnect` must not sign anyone out", async () => {
  const wallet = new FakeWallet();
  const conn = await connectWalletConnect(wcDeps(wallet));
  const stop = onWalletEvents(conn, { accountsChanged: () => {} });
  assert.equal(wallet.listenerCount("disconnect"), 0);
  stop();
});

test("a wallet that will not move to GIWA says so in words, over WalletConnect only", async () => {
  const refused = { code: 4001 };
  assert.match(chainSwitchMessage(refused), /You declined the network switch/);
  assert.match(chainSwitchMessage(new Error("relay timeout")), /Add or select that network/);

  const wallet = new FakeWallet({ switchChainError: new Error("method not supported") });
  const conn = await connectWalletConnect(wcDeps(wallet));
  await assert.rejects(ensureChain(conn), /Add or select that network/);

  // The injected path is untouched: its raw error still surfaces for walletErrorMessage.
  const injected = { ...conn, transport: "injected" } as Connection;
  await assert.rejects(ensureChain(injected), /method not supported/);
});

// ============================ (7) OFF BY DEFAULT ============================

test("with no VITE_WC_PROJECT_ID this build has no WalletConnect at all", () => {
  assert.equal(walletConnectProjectId(), null);
  assert.equal(walletConnectEnabled(), false);
});

test("the connect button exists ONLY inside the flag's guard", () => {
  const src = readFileSync(new URL("../src/ui/screens/Onboarding.tsx", import.meta.url).pathname, "utf8");
  assert.match(src, /walletConnectEnabled\(\)/, "the screen reads the flag rather than assuming");

  const guardStart = src.indexOf("{remote && (");
  assert.ok(guardStart > 0, "the WalletConnect button is behind a `remote &&` guard");
  const guardEnd = src.indexOf("{!injected && (");
  assert.ok(guardEnd > guardStart);

  // Only what is RENDERED matters; the import that pulls the mark in is not a render.
  const rendered = src.indexOf("export function Onboarding");
  assert.ok(rendered > 0 && rendered < guardStart);

  // Every rendered mention of the option — the mark, the label, the transport — is
  // inside the guard, so an unconfigured build draws none of it.
  for (const token of ["WalletConnectMark", '"WalletConnect"', 'connectWallet("walletconnect")']) {
    let at = src.indexOf(token, rendered);
    assert.ok(at > 0, `${token} is never rendered by the screen`);
    while (at !== -1) {
      assert.ok(
        at > guardStart && at < guardEnd,
        `${token} renders outside the flag guard — it would appear with the flag off`,
      );
      at = src.indexOf(token, at + 1);
    }
  }
});

// The SDK must reach the bundle through `import()` and nothing else, or the default
// chunk grows for every visitor who never touches WalletConnect. Walking the STATIC
// import graph from the entry is the check that actually encodes that: a dynamic
// import is invisible to it by construction, so any hit is a static reference.
test("nothing statically reachable from the entry imports the WalletConnect SDK", () => {
  const SRC = new URL("../src/", import.meta.url).pathname;
  const STATIC_IMPORT = /^\s*(?:import|export)\s[^;]*?\sfrom\s*["']([^"']+)["']/gm;
  const SIDE_EFFECT_IMPORT = /^\s*import\s+["']([^"']+)["']/gm;

  const resolve = (fromFile: string, spec: string): string | null => {
    if (!spec.startsWith(".")) return null; // a package, not a file to walk into
    const base = new URL(spec, `file://${fromFile}`).pathname.replace(/\.js$/, "");
    for (const candidate of [`${base}.ts`, `${base}.tsx`, `${base}/index.ts`]) {
      try {
        readFileSync(candidate, "utf8");
        return candidate;
      } catch {
        // try the next extension
      }
    }
    return null;
  };

  const seen = new Set<string>();
  const packages = new Set<string>();
  const walk = (file: string): void => {
    if (seen.has(file)) return;
    seen.add(file);
    const text = readFileSync(file, "utf8");
    for (const re of [STATIC_IMPORT, SIDE_EFFECT_IMPORT]) {
      re.lastIndex = 0;
      for (const m of text.matchAll(re)) {
        const spec = m[1];
        const resolved = resolve(file, spec);
        if (resolved) walk(resolved);
        else if (!spec.endsWith(".css")) packages.add(spec);
      }
    }
  };
  walk(`${SRC}main.tsx`);

  assert.ok(seen.size > 20, `the walk should reach the whole app, saw ${seen.size} files`);
  assert.ok(
    [...seen].some((f) => f.endsWith("walletconnect.ts")),
    "the WalletConnect module itself IS statically reachable — only the SDK may not be",
  );
  const smuggled = [...packages].filter((p) => /^@(walletconnect|reown)\//.test(p));
  assert.deepEqual(smuggled, [], "the SDK must be reached by import() only");
});
