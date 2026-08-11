// The viem plumbing the deploy/ drivers share: a chain object, the pinned live
// gas price, and a thin contract "rig" that mirrors the small slice of ethers the
// drivers used (deploy a contract, read a view, send a tx and wait for the
// receipt). It exists so the ONE load-bearing invariant — every live tx pins
// gasPrice instead of letting the client estimate (auto-estimate once overpaid
// ~1500x and drained the faucet grant) — lives in exactly one place: a rig built
// with `gasPrice` bakes it into every write and deploy.
//
// TEST/OPS INFRASTRUCTURE, reached by relative import; not an npm package
// export. Chain-agnostic: the caller passes the chain + rpc + key (+ gasPrice on
// the live chain, omitted on the free anvil gate).
//
// A rig's `at()` handle carries TWO surfaces so both harness consumers keep one
// API: the viem-first `read(fn,args)` / `write(fn,args)` the migrated deploy
// drivers use, AND an ethers-style dynamic dispatch (`pool.deposit(...).wait()`,
// `pool.root()`) that apps/indexer/test/scenario.ts still calls unchanged (its
// viem move is a later unit). The dynamic path coerces snarkjs decimal-string
// args to bigint — viem's encoder takes number/bigint for uint256, not the
// decimal strings ethers used to coerce.

import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  parseGwei,
  type Abi,
  type AbiFunction,
  type Address,
  type Chain,
  type PublicClient,
  type TransactionReceipt,
  type WalletClient,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  CHAIN_ID,
  CHAIN_NAME,
  EXPLORER_BASE,
  GAS_PRICE_PIN_GWEI,
  NATIVE_CURRENCY,
  RPC_URL,
} from "@bongtu/core/network";

/** The live chain as a viem object, derived field-for-field from
 *  @bongtu/core/network (the ONE home of the chain facts) — identical to the
 *  apps' liveChain so a chain move cannot fork a driver's idea of the network
 *  from the sdk's. */
export const liveChain: Chain = defineChain({
  id: CHAIN_ID,
  name: CHAIN_NAME,
  nativeCurrency: NATIVE_CURRENCY,
  rpcUrls: { default: { http: [RPC_URL] } },
  blockExplorers: { default: { name: `${CHAIN_NAME} Explorer`, url: EXPLORER_BASE } },
  testnet: true,
});

/** The pinned per-tx gas price (wei) — a HARD pin, never an estimate: client-side
 *  auto-estimation once overpaid ~1500x. EVERY live write pins this, so it is set
 *  well above the chain's quote (see @bongtu/core GAS_PRICE_PIN_GWEI for the number
 *  and the too-low/too-high asymmetry). */
export const GAS_PRICE = parseGwei(GAS_PRICE_PIN_GWEI);

/** A local anvil chain for the heavy gates (id 31337, the anvil default). The rpc
 *  transport overrides the chain's placeholder url with the gate's actual E2E_RPC. */
export function anvilChain(rpc: string): Chain {
  return defineChain({
    id: 31337,
    name: "anvil",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [rpc] } },
  });
}

/** groth16 `exportSolidityCallData` calldata as decimal strings (snarkjs form). */
export interface ProofCalldata {
  a: string[];
  b: string[][];
  c: string[];
  pub: string[];
}

/** The (a, b, c, pub) tuple as viem wants it — bigints, not the decimal strings
 *  snarkjs emits (viem's abi encoder takes number/bigint for uint256, not decimal
 *  strings; the ethers path relied on ethers coercing the strings). */
export function proofArgs(
  p: ProofCalldata,
): [bigint[], bigint[][], bigint[], bigint[]] {
  return [
    p.a.map((x) => BigInt(x)),
    p.b.map((r) => r.map((x) => BigInt(x))),
    p.c.map((x) => BigInt(x)),
    p.pub.map((x) => BigInt(x)),
  ];
}

/** Coerce an ethers-style dynamic arg to viem's expectation: a decimal-numeric
 *  string (snarkjs uint output) becomes a bigint; a 0x-hex string (address /
 *  bytes / bytes32) is left as-is; arrays recurse; bigints/numbers pass through. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toViemArg(x: any): any {
  if (typeof x === "string") return /^0x/i.test(x) ? x : BigInt(x);
  if (Array.isArray(x)) return x.map(toViemArg);
  return x;
}

/** A contract bound at an address. `read`/`write` are the viem-first surface the
 *  migrated deploy drivers use; the string index signature is the ethers-style
 *  dynamic dispatch scenario.ts still calls (`pool.deposit(...).wait()`). */
export interface Contract {
  address: Address;
  abi: Abi;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  read: (fn: string, args?: readonly unknown[]) => Promise<any>;
  write: (fn: string, args?: readonly unknown[]) => Promise<TransactionReceipt>;
  // ethers-style dynamic methods — any function name resolves to a call/tx.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [method: string]: any;
}

/** A tx handle in flight — the ethers `TransactionResponse` shape scenario.ts
 *  awaits (`(await pool.deposit(...)).wait()`). */
export interface TxResponse {
  hash: `0x${string}`;
  wait: () => Promise<TransactionReceipt>;
}

/** The driver's connection: the two clients, the sender address, plus `at()` to
 *  bind a contract and `deploy()` to publish one. `provider`/`wallet` are the
 *  ethers-shaped aliases scenario.ts destructures (`const { provider, wallet } =
 *  connectAnvil()`) — `wallet` is the rig itself, so `deployStack(wallet, …)`
 *  gets the same object the orchestrator passes. */
export interface Rig {
  account: ReturnType<typeof privateKeyToAccount>;
  address: Address;
  publicClient: PublicClient;
  walletClient: WalletClient;
  at: (address: string, abi: Abi) => Contract;
  deploy: (abi: Abi, bytecode: string, args?: readonly unknown[]) => Promise<Address>;
  provider: { getBlockNumber: () => Promise<number>; request: PublicClient["request"] };
  wallet: Rig;
}

const CONTROL = new Set(["address", "abi", "read", "write", "then"]);

/** Build a rig on `chain` at `rpc`, sending from `privateKey`. When `gasPrice` is
 *  given (the live drivers), every write and deploy pins it — never estimated. */
export function makeRig(opts: {
  chain: Chain;
  rpc: string;
  privateKey: string;
  gasPrice?: bigint;
}): Rig {
  const account = privateKeyToAccount(("0x" + opts.privateKey.replace(/^0x/, "")) as `0x${string}`);
  const transport = http(opts.rpc);
  const publicClient = createPublicClient({ chain: opts.chain, transport });
  const walletClient = createWalletClient({ account, chain: opts.chain, transport });
  const feefields = opts.gasPrice !== undefined ? { gasPrice: opts.gasPrice } : {};

  const sendWrite = async (address: Address, abi: Abi, fn: string, args: readonly unknown[]): Promise<`0x${string}`> =>
    walletClient.writeContract(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      { address, abi, functionName: fn, args, ...feefields } as any,
    );

  const at = (address: string, abi: Abi): Contract => {
    const addr = address as Address;
    const isView = new Map<string, boolean>();
    for (const e of abi) {
      if ((e as AbiFunction).type === "function") {
        const f = e as AbiFunction;
        isView.set(f.name, f.stateMutability === "view" || f.stateMutability === "pure");
      }
    }
    const base: Contract = {
      address: addr,
      abi,
      read: (fn, args = []) =>
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        publicClient.readContract({ address: addr, abi, functionName: fn, args } as any),
      write: async (fn, args = []) => {
        const hash = await sendWrite(addr, abi, fn, args);
        return publicClient.waitForTransactionReceipt({ hash });
      },
    };
    // ethers-style dynamic dispatch for scenario.ts: `pool.<fn>(...args)`.
    return new Proxy(base, {
      get(target, prop, receiver) {
        if (typeof prop !== "string" || CONTROL.has(prop) || prop in target) {
          return Reflect.get(target, prop, receiver);
        }
        const fn = prop;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        return async (...raw: any[]) => {
          const args = raw.map(toViemArg);
          if (isView.get(fn)) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            return publicClient.readContract({ address: addr, abi, functionName: fn, args } as any);
          }
          const hash = await sendWrite(addr, abi, fn, args);
          const resp: TxResponse = { hash, wait: () => publicClient.waitForTransactionReceipt({ hash }) };
          return resp;
        };
      },
    }) as Contract;
  };

  const deploy = async (abi: Abi, bytecode: string, args: readonly unknown[] = []): Promise<Address> => {
    const hash = await walletClient.deployContract(
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      { abi, bytecode: ("0x" + bytecode.replace(/^0x/, "")) as `0x${string}`, args, ...feefields } as any,
    );
    const rcpt = await publicClient.waitForTransactionReceipt({ hash });
    if (!rcpt.contractAddress) throw new Error("deploy: receipt carried no contractAddress");
    return rcpt.contractAddress;
  };

  const rig = {
    account,
    address: account.address,
    publicClient,
    walletClient,
    at,
    deploy,
    provider: {
      getBlockNumber: async () => Number(await publicClient.getBlockNumber()),
      request: publicClient.request,
    },
  } as Rig;
  rig.wallet = rig; // scenario.ts forwards `wallet` to deployStack — it IS the rig.
  return rig;
}
