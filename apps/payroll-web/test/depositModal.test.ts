// Gate for the deposit dialog (lib/depositModal.ts) — the decisions the console's
// view only renders:
//
//   - the state machine: what an OPEN dialog starts as (prefilled from the sheet's
//     shortfall), and what the deposit button says while a deposit runs;
//   - the gas belt: a READ ZERO disables both actions and selects the plain
//     message; an unread/failed gas read must NOT lock a funded operator out;
//   - the mint: fixed ration, to the connected account itself, through a fake
//     wallet edge (no RPC, no chain).
//
// Every I/O edge is injected (DepositModalDeps), so the whole file runs headless.

import { test } from "node:test";
import assert from "node:assert/strict";

import type { Connection } from "@bongtu/client/connection";
import { parseKkrw } from "@bongtu/client/money";
import {
  MINT_AMOUNT,
  NO_GAS_MESSAGE,
  depositModalView,
  mintTestKkrw,
  openDepositModal,
  prefillAmount,
  readDepositAccount,
  readGas,
  type DepositModalDeps,
  type DepositModalState,
} from "../src/lib/depositModal.js";

const KKRW = 10n ** 18n;
const ACCOUNT = "0x00000000000000000000000000000000000000aa";
const TOKEN = "0x00000000000000000000000000000000000000bb";
const POOL = "0x00000000000000000000000000000000000000cc";
const CONNECTION = { address: ACCOUNT } as unknown as Connection;

/** Deps whose every edge is a double; `calls` records what the wallet was asked to do. */
function deps(opts: {
  gas?: bigint | Error;
  balance?: bigint | Error;
  mint?: Error;
}): DepositModalDeps & { calls: { mint: [string, string, bigint][] } } {
  const calls = { mint: [] as [string, string, bigint][] };
  return {
    calls,
    readGasBalance: (async () => {
      if (opts.gas instanceof Error) throw opts.gas;
      return opts.gas ?? 1n;
    }) as DepositModalDeps["readGasBalance"],
    readTokenState: (async () => {
      if (opts.balance instanceof Error) throw opts.balance;
      return { balance: opts.balance ?? 0n, allowance: 0n };
    }) as DepositModalDeps["readTokenState"],
    mintTestToken: (async (_c: Connection, token: string, to: string, amount: bigint) => {
      if (opts.mint) throw opts.mint;
      calls.mint.push([token, to, amount]);
      return { txHash: "0xmint", explorerUrl: "http://explorer.test/0xmint" };
    }) as unknown as DepositModalDeps["mintTestToken"],
  };
}

const state = (patch: Partial<DepositModalState> = {}): DepositModalState => ({
  ...openDepositModal(null),
  ...patch,
});

// ---------------------------- open: the prefill -----------------------------------

test("opening with no shortfall starts empty, with nothing read and nothing running", () => {
  assert.deepEqual(openDepositModal(null), {
    amount: "",
    stage: null,
    minting: false,
    tokenBalance: null,
    gas: "unknown",
    error: null,
  });
});

test("opening from a SHORT sheet prefills the gap, grouped and ready to send", () => {
  const open = openDepositModal(1234567n * KKRW);
  assert.equal(open.amount, "1,234,567");
  const parsed = parseKkrw(open.amount);
  assert.ok(parsed.ok && parsed.wei === 1234567n * KKRW, "the prefill re-parses to the same wei");
});

test("a shortfall below display precision is rounded UP — a prefill must COVER the gap", () => {
  // formatKkrw truncates past 6 decimals: the raw value would prefill an amount
  // SMALLER than the shortfall, and the deposit would leave the sheet still short.
  const dusty = 5n * KKRW + 1n; // 5.000000000000000001 kKRW
  const filled = prefillAmount(dusty);
  const parsed = parseKkrw(filled);
  assert.ok(parsed.ok && parsed.wei >= dusty, `${filled} must cover ${dusty}`);
  assert.equal(filled, "5.000001");
  // Sub-wei-grid dust alone still rounds up to one grid step, never to zero.
  assert.equal(prefillAmount(1n), "0.000001");
  assert.equal(prefillAmount(0n), "");
});

// ---------------------------- the view: labels and gates --------------------------

test("the deposit button carries the running stage, and a stage blocks both actions", () => {
  assert.equal(depositModalView(state({ amount: "100" })).depositLabel, "Deposit");
  const proving = depositModalView(state({ amount: "100", stage: "prove" }));
  assert.match(proving.depositLabel, /zero-knowledge proof/);
  assert.equal(proving.busy, true);
  assert.equal(proving.canDeposit, false, "a second deposit cannot start on top of a running one");
  assert.equal(proving.canMint, false, "and neither can a mint");
});

test("a running mint says so and blocks the deposit under it", () => {
  const minting = depositModalView(state({ amount: "100", minting: true }));
  assert.equal(minting.mintLabel, "Minting…");
  assert.equal(minting.busy, true);
  assert.equal(minting.canDeposit, false);
});

test("the mint button names the fixed ration it will add", () => {
  assert.equal(depositModalView(state()).mintLabel, "Mint 1,000,000 test kKRW");
  assert.equal(MINT_AMOUNT, 1_000_000n * KKRW);
});

test("an empty field opens quiet; a bad one names its cause; a good one unlocks Deposit", () => {
  const empty = depositModalView(state({ amount: "" }));
  assert.equal(empty.amountError, null, "an untouched field must not open shouting");
  assert.equal(empty.canDeposit, false);
  assert.equal(empty.amountWei, null);

  assert.match(depositModalView(state({ amount: "1.5.5" })).amountError ?? "", /valid amount/);
  assert.match(depositModalView(state({ amount: "0" })).amountError ?? "", /above zero/);
  assert.equal(depositModalView(state({ amount: "0" })).canDeposit, false);

  const good = depositModalView(state({ amount: "1,000" }));
  assert.equal(good.amountError, null);
  assert.equal(good.amountWei, 1000n * KKRW);
  assert.equal(good.canDeposit, true);
});

// ---------------------------- the gas belt ----------------------------------------

test("a ZERO-gas account disables both actions and selects the plain message", () => {
  const gasless = depositModalView(state({ amount: "100", gas: "none" }));
  assert.equal(gasless.canDeposit, false);
  assert.equal(gasless.canMint, false);
  assert.equal(gasless.notice, NO_GAS_MESSAGE);
  assert.match(gasless.notice ?? "", /GIWA Sepolia ETH/, "the message the faucet link hangs off");
});

test("an UNREAD (or failed) gas read never locks a funded operator out", () => {
  for (const gas of ["unknown", "funded"] as const) {
    const view = depositModalView(state({ amount: "100", gas }));
    assert.equal(view.canDeposit, true, gas);
    assert.equal(view.canMint, true, gas);
    assert.equal(view.notice, null, gas);
  }
});

test("readGas maps a zero balance to none, anything else to funded, a throw to unknown", async () => {
  assert.equal(await readGas(CONNECTION, deps({ gas: 0n })), "none");
  assert.equal(await readGas(CONNECTION, deps({ gas: 1n })), "funded");
  assert.equal(await readGas(CONNECTION, deps({ gas: new Error("rpc down") })), "unknown");
});

// ---------------------------- the account read ------------------------------------

test("the dialog reads the account's PUBLIC kKRW alongside its gas verdict", async () => {
  const read = await readDepositAccount(CONNECTION, TOKEN, POOL, deps({ balance: 42n * KKRW, gas: 7n }));
  assert.deepEqual(read, { tokenBalance: 42n * KKRW, gas: "funded" });
});

test("the two reads fail SEPARATELY — a dead token read must not erase the gas verdict", async () => {
  const tokenDown = await readDepositAccount(CONNECTION, TOKEN, POOL, deps({ balance: new Error("rpc"), gas: 0n }));
  // null balance renders as a dash, never as a false zero that would push a mint.
  assert.deepEqual(tokenDown, { tokenBalance: null, gas: "none" });

  const gasDown = await readDepositAccount(CONNECTION, TOKEN, POOL, deps({ balance: 9n, gas: new Error("rpc") }));
  assert.deepEqual(gasDown, { tokenBalance: 9n, gas: "unknown" });
});

// ---------------------------- the mint --------------------------------------------

test("the mint sends the fixed ration to the CONNECTED account itself", async () => {
  const d = deps({});
  await mintTestKkrw(CONNECTION, TOKEN, d);
  assert.deepEqual(d.calls.mint, [[TOKEN, ACCOUNT, MINT_AMOUNT]]);
});

test("a rejected mint throws to the caller — the dialog words it, nothing is swallowed", async () => {
  const rejected = Object.assign(new Error("User rejected the request"), { code: 4001 });
  await assert.rejects(mintTestKkrw(CONNECTION, TOKEN, deps({ mint: rejected })), /User rejected/);
});
