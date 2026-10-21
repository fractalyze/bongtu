// Measures the consumer receive flow on a LOCAL java-tron (TRE) with real
// contracts and real proofs, producing the per-step energy/bandwidth/TRX
// ledger and wall-clock timings that decide the Tron mainnet posture
// (energy price is protocol-defined, so local energy == mainnet energy).
//
// Scratch probe for .dev/intents/stealth-receive-tron — NOT product code and
// never committed; run: node --import tsx tron_probe.ts
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

import { encodeAbiParameters, encodeFunctionData, type Abi, type Hex } from "viem";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { H } from "@bongtu/core/network";
import { ImtTree } from "@bongtu/core/imt";
import { commitment, nullifier } from "@bongtu/core/note";
import { sealConsumerOutput, type SealedConsumerOutput } from "@bongtu/core/consumer";
import type { PointInput } from "@bongtu/core/babyjub";
import { deriveStealthAddress, portalSalt, stealthKeysFromScalars } from "@bongtu/core/stealth";
import { deriveIdentityFromSignature, type ConsumerWalletIdentity } from "@bongtu/client/derive";
import { buildConsumerDepositRequest, freshConsumerDepositCrypto, selfConsumerRecipient } from "@bongtu/client/consumer";
import { randField } from "@bongtu/client/spend";
import { PRIV_SWEEP_ABI, privSweepArgs } from "@bongtu/sweeper/sweep";
import { makeCircuitProver } from "@bongtu/sweeper/prover";
import type { PortalRecord } from "@bongtu/core/indexerApi";

import { artifact, prove } from "./deploy/live/lib/proof_toolbox.js";
import { proofArgs } from "./deploy/live/lib/viem_client.js";

const API = "http://127.0.0.1:29090";
const PRIV = "33f8955f1fb163dadf84ab8f68de03e95131408ad23a3ef9318d4d103a7e7b52";
const ROOT = process.cwd();
const GATE_B = 16;
const PAY = 800n;

// ---------------------------------------------------------------- tron client
const hexToBytes = (h: string): Uint8Array =>
  Uint8Array.from((h.replace(/^0x/, "").match(/.{2}/g) ?? []).map((b) => parseInt(b, 16)));
const bytesToHex = (b: Uint8Array): string =>
  Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const pubkey = secp256k1.getPublicKey(hexToBytes(PRIV), false);
const OWNER41 = "41" + bytesToHex(keccak_256(pubkey.subarray(1)).subarray(12));
const OWNER20 = ("0x" + OWNER41.slice(2)) as `0x${string}`;
const t20 = (a41: string): `0x${string}` => ("0x" + a41.replace(/^0x/, "").slice(2)) as `0x${string}`;
const t41 = (a20: string): string => "41" + a20.replace(/^0x/, "");

const post = async (path: string, body: unknown, timeoutMs = 60_000): Promise<any> => {
  const r = await fetch(API + path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  return r.json();
};

const signAndBroadcast = async (tx: any): Promise<any> => {
  const digest = sha256(hexToBytes(tx.raw_data_hex));
  const compact = secp256k1.sign(digest, hexToBytes(PRIV), { prehash: false });
  const truePub = bytesToHex(pubkey);
  const recid = [0, 1].find((rid) => {
    try {
      return (
        bytesToHex(
          secp256k1.Signature.fromBytes(compact, "compact").addRecoveryBit(rid).recoverPublicKey(digest).toBytes(false),
        ) === truePub
      );
    } catch {
      return false;
    }
  });
  if (recid === undefined) throw new Error("no recovery id matched");
  // TRE's broadcast can block for minutes on a heavy tx; the txID is known
  // before broadcasting, so a broadcast timeout falls through to info polling.
  return post(
    "/wallet/broadcasttransaction",
    { ...tx, signature: [bytesToHex(compact) + (recid + 27).toString(16).padStart(2, "0")] },
    20_000,
  ).catch((e) => {
    console.log(`  (broadcast response not awaited: ${String(e).slice(0, 60)} — polling txID)`);
    return { result: true };
  });
};

const waitInfo = async (txid: string): Promise<any> => {
  for (const _ of Array(600).keys()) {
    const info = await post("/wallet/gettransactioninfobyid", { value: txid });
    if (info && info.id) return info;
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error("tx info timeout: " + txid);
};

interface LedgerRow {
  step: string;
  energy: number;
  bandwidth: number;
  trx: number;
  note: string;
}
const ledger: LedgerRow[] = [];
const record = (step: string, info: any, note = ""): void => {
  const energy = info.receipt?.energy_usage_total ?? 0;
  const bandwidth = info.receipt?.net_usage ?? (info.receipt?.net_fee ?? 0) / 1000;
  const trx = (energy * 100 + (info.receipt?.net_fee ?? 0)) / 1e6;
  ledger.push({ step, energy, bandwidth, trx, note });
  const result = info.receipt?.result ?? "SUCCESS(create)";
  console.log(`  [${step}] result=${result} energy=${energy} trx=${trx.toFixed(2)} ${note}`);
  if (info.receipt?.result && info.receipt.result !== "SUCCESS") {
    console.log("   FULL INFO:", JSON.stringify(info).slice(0, 600));
    throw new Error(`${step} failed: ${info.receipt.result}`);
  }
};

const deployContract = async (
  step: string,
  bytecode: string,
  ctorArgsHex = "",
): Promise<{ a41: string; a20: `0x${string}` }> => {
  const tx = await post("/wallet/deploycontract", {
    owner_address: OWNER41,
    abi: "[]",
    bytecode: bytecode.replace(/^0x/, ""),
    parameter: ctorArgsHex.replace(/^0x/, ""),
    fee_limit: 1_000_000_000,
    origin_energy_limit: 50_000_000,
    consume_user_resource_percent: 100,
  });
  if (!tx.txID) throw new Error(`${step}: deploy build failed: ` + JSON.stringify(tx).slice(0, 300));
  const b = await signAndBroadcast(tx);
  if (b.result !== true) throw new Error(`${step}: broadcast failed: ` + JSON.stringify(b).slice(0, 300));
  const info = await waitInfo(tx.txID);
  record(step, info);
  return { a41: info.contract_address, a20: t20(info.contract_address) };
};

const write = async (step: string, to41: string, data: Hex): Promise<any> => {
  const trig = await post("/wallet/triggersmartcontract", {
    owner_address: OWNER41,
    contract_address: to41,
    data: data.replace(/^0x/, ""),
    fee_limit: 1_000_000_000,
    call_value: 0,
  });
  if (!trig.transaction?.txID) throw new Error(`${step}: trigger build failed: ` + JSON.stringify(trig).slice(0, 300));
  const b = await signAndBroadcast(trig.transaction);
  if (b.result !== true) throw new Error(`${step}: broadcast failed: ` + JSON.stringify(b).slice(0, 300));
  const info = await waitInfo(trig.transaction.txID);
  record(step, info);
  return info;
};

const read = async (to41: string, data: Hex): Promise<{ out: string; ms: number; energy: number }> => {
  const t0 = process.hrtime.bigint();
  const r = await post("/wallet/triggerconstantcontract", {
    owner_address: OWNER41,
    contract_address: to41,
    data: data.replace(/^0x/, ""),
  });
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  if (r.result?.result !== true) {
    throw new Error(
      "constant call failed: " + (r.result?.message ? Buffer.from(r.result.message, "hex").toString() : JSON.stringify(r).slice(0, 300)),
    );
  }
  return { out: "0x" + (r.constant_result?.[0] ?? ""), ms, energy: r.energy_used ?? 0 };
};

const enc = (abi: Abi, functionName: string, args: unknown[]): Hex =>
  encodeFunctionData({ abi, functionName, args });

// ------------------------------------------------------------------- phase 1
const main = async (): Promise<void> => {
  console.log("owner:", OWNER41);
  console.log("== PHASE 1: consumer-only stack deploy ==");

  const poseidonCode = readFileSync(join(ROOT, "chains", "evm", "test", "fixtures", "poseidon2.hex"), "utf8").trim();
  const poseidon = await deployContract("deploy Poseidon2", poseidonCode);

  const tokenArt = artifact("MockERC20", "MockERC20");
  const token = await deployContract("deploy MockERC20", tokenArt.bytecode);

  const poolArt = artifact("BongtuPool", "BongtuPool");
  const impl = await deployContract("deploy BongtuPool impl", poolArt.bytecode);

  const initData = enc(poolArt.abi as Abi, "initializeConsumerOnly", [poseidon.a20, token.a20, BigInt(GATE_B)]);
  const proxyArt = artifact("ERC1967Proxy", "ERC1967Proxy");
  const proxy = await (async () => {
    try {
      const args = encodeAbiParameters(
        [{ type: "address" }, { type: "bytes" }],
        [impl.a20, initData],
      );
      const p = await deployContract("deploy ERC1967Proxy(+init)", proxyArt.bytecode, args);
      console.log("  (constructor-time delegatecall init WORKED on TVM)");
      return p;
    } catch (e) {
      console.log("  constructor-time init FAILED (the java-tron #5522 shape):", String(e).slice(0, 120));
      const args = encodeAbiParameters([{ type: "address" }, { type: "bytes" }], [impl.a20, "0x"]);
      const p = await deployContract("deploy ERC1967Proxy(empty)", proxyArt.bytecode, args);
      await write("initializeConsumerOnly (separate tx)", p.a41, initData);
      return p;
    }
  })();
  const pool = proxy;

  const b = await read(pool.a41, enc(poolArt.abi as Abi, "B", []));
  const initialized = await read(pool.a41, enc(poolArt.abi as Abi, "initialized", []));
  console.log(`  pool.B=${BigInt(b.out)} initialized=${BigInt(initialized.out) === 1n}`);
  if (BigInt(b.out) !== BigInt(GATE_B)) throw new Error("pool B mismatch");

  const dpvArt = artifact("DepositPrivVerifier", "DepositPrivVerifier");
  const dpv = await deployContract("deploy DepositPrivVerifier", dpvArt.bytecode);
  const wpvArt = artifact("WithdrawPrivVerifier", "WithdrawPrivVerifier");
  const wpv = await deployContract("deploy WithdrawPrivVerifier", wpvArt.bytecode);

  const depModArt = artifact("DepositPrivModule", "DepositPrivModule");
  const depMod = await deployContract(
    "deploy DepositPrivModule",
    depModArt.bytecode,
    encodeAbiParameters([{ type: "address" }, { type: "address" }], [pool.a20, dpv.a20]),
  );
  const wdrModArt = artifact("WithdrawPrivModule", "WithdrawPrivModule");
  const wdrMod = await deployContract(
    "deploy WithdrawPrivModule",
    wdrModArt.bytecode,
    encodeAbiParameters([{ type: "address" }, { type: "address" }], [pool.a20, wpv.a20]),
  );

  await write("registerModule(depositPriv)", pool.a41, enc(poolArt.abi as Abi, "registerModule", [depMod.a20]));
  await write("registerModule(withdrawPriv)", pool.a41, enc(poolArt.abi as Abi, "registerModule", [wdrMod.a20]));

  const facArt = artifact("TvmPortalPrivFactory", "TvmPortalPrivFactory");
  const factory = await deployContract(
    "deploy PortalPrivFactory",
    facArt.bytecode,
    encodeAbiParameters([{ type: "address" }], [OWNER20]),
  );
  const initHash = (await read(factory.a41, enc(facArt.abi as Abi, "sweeperInitCodeHash", []))).out as Hex;
  console.log("  sweeperInitCodeHash:", initHash);

  const subtotal = ledger.reduce((a, r) => a + r.trx, 0);
  console.log(`\n== PHASE 1 done: one-time deploy total ~${subtotal.toFixed(1)} TRX ==\n`);

  // ----------------------------------------------------------------- phase 2
  console.log("== PHASE 2: pay -> sweep(depositPriv) -> withdraw ==");
  const RECIPIENT: ConsumerWalletIdentity = deriveIdentityFromSignature("0x" + "b2".repeat(65));
  const stealth = stealthKeysFromScalars(424242424242424242424n, 535353535353535353535n);
  const derived = deriveStealthAddress(stealth.meta, 910000000000000000001n);
  const salt = portalSalt(derived.address) as Hex;

  // TVM CREATE2: 0x41 where the EVM has 0xff (TIP-26); addressOf on-chain
  // still hashes 0xff, so the two MUST disagree — measured, not assumed.
  const tvmDest20 = ("0x" +
    bytesToHex(
      keccak_256(
        Uint8Array.from([0x41, ...hexToBytes(factory.a20), ...hexToBytes(salt), ...hexToBytes(initHash)]),
      ).subarray(12),
    )) as `0x${string}`;
  const addressOf = (await read(factory.a41, enc(facArt.abi as Abi, "addressOf", [salt]))).out;
  const evmPredicted = ("0x" + addressOf.slice(-40)) as `0x${string}`;
  console.log(`  TVM destination : ${tvmDest20}`);
  console.log(`  addressOf (0xff): ${evmPredicted}  ${evmPredicted.toLowerCase() === tvmDest20.toLowerCase() ? "(MATCHES?!)" : "(diverges as expected — port finding)"}`);

  await write("token.mint(sender)", token.a41, enc(tokenArt.abi as Abi, "mint", [OWNER20, 1_000_000n]));
  await write("PAYMENT: token.transfer -> stealth destination", token.a41, enc(tokenArt.abi as Abi, "transfer", [tvmDest20, PAY]));
  const bal = await read(token.a41, enc(tokenArt.abi as Abi, "balanceOf", [tvmDest20]));
  console.log(`  destination balance: ${BigInt(bal.out)}`);
  if (BigInt(bal.out) !== PAY) throw new Error("payment did not land on the TVM-predicted destination");

  console.log("  building depositPriv proof (CPU)...");
  const crypto = freshConsumerDepositCrypto(randField);
  const recipient = selfConsumerRecipient(RECIPIENT);
  const built = buildConsumerDepositRequest(
    [
      { recipient, value: PAY.toString() },
      { recipient, value: "0" },
    ],
    crypto,
  );
  const depositCalldata = await makeCircuitProver(join(ROOT, "circuits", "out"), "depositPriv")(built.request);
  const rec = {
    stealthAddr: derived.address,
    ephemeralPub: derived.ephemeralPub,
    viewTag: derived.viewTag,
  } as PortalRecord;
  const sweepData = encodeFunctionData({
    abi: PRIV_SWEEP_ABI,
    functionName: "sweep",
    args: privSweepArgs(rec, depMod.a20, depositCalldata, built.meta.kemCiphertexts),
  });
  for (const i of Array(3).keys()) {
    const sim = await read(factory.a41, sweepData);
    console.log(`  sweep constant-sim ${i}: wall=${sim.ms.toFixed(0)}ms energy=${sim.energy}`);
  }
  await write("SWEEP: factory.sweep (depositPriv, real proof)", factory.a41, sweepData);
  const poolBal = await read(token.a41, enc(tokenArt.abi as Abi, "balanceOf", [pool.a20]));
  console.log(`  pool balance after sweep: ${BigInt(poolBal.out)} (expect ${PAY})`);

  const oracle = new ImtTree(H, GATE_B);
  for (const c of built.meta.outputCommitments) oracle.appendLeaf(BigInt(c));
  const chainRoot = await read(pool.a41, enc(poolArt.abi as Abi, "root", []));
  console.log(`  root parity: chain=${BigInt(chainRoot.out)} oracle=${oracle.getRoot()} ${BigInt(chainRoot.out) === oracle.getRoot() ? "MATCH" : "MISMATCH"}`);

  // ---------------------------------------------------------------- withdraw
  console.log("  building withdrawPriv proof (CPU)...");
  const sha = (label: string): Uint8Array => new Uint8Array(createHash("sha256").update(label).digest());
  const sealTo = (
    id: ConsumerWalletIdentity,
    value: bigint,
    noteSalt: bigint,
    ephemeralPriv: bigint,
    encryptionNonce: bigint,
    index: number,
  ): SealedConsumerOutput =>
    sealConsumerOutput({
      value,
      salt: noteSalt,
      ephemeralPriv,
      viewPub: id.viewKeypair.publicKey,
      kemEk: id.kemKeypair.ek,
      encryptionNonce,
      index,
      encapSeed: sha(`bongtu/tron-probe/encap/${index}`),
    });
  const ECDH_WDR = 930000000000000000007n;
  const NONCE_WDR = 777000000003n;
  const changeSalt = 8800001n;
  const padSalt = 8800002n;
  const outs = [
    {
      id: RECIPIENT,
      value: 50n,
      salt: changeSalt,
      seal: sealTo(RECIPIENT, 50n, changeSalt, ECDH_WDR, NONCE_WDR, 0),
      commitment: commitment(50n, changeSalt, RECIPIENT.keypair.publicKey),
    },
  ];
  const zerosPath: bigint[] = new Array(H).fill(0n);
  const { siblings } = oracle.merklePath(0);
  const input = {
    nullifiers: [nullifier(PAY, BigInt(crypto.salt0), RECIPIENT.keypair.formattedPrivateKey), 0n],
    inputCommitments: [BigInt(built.meta.outputCommitments[0]), commitment(0n, padSalt, RECIPIENT.keypair.publicKey)],
    inputValues: [PAY, 0n],
    inputSalts: [BigInt(crypto.salt0), padSalt],
    inputOwnerPrivateKey: RECIPIENT.keypair.formattedPrivateKey,
    ecdhPrivateKey: ECDH_WDR,
    root: oracle.getRoot(),
    pathElements: [siblings, zerosPath],
    leafIndices: [0n, 0n],
    enabled: [1n, 0n],
    outputCommitments: outs.map((o) => o.commitment),
    outputValues: outs.map((o) => o.value),
    outputSalts: outs.map((o) => o.salt),
    outputOwnerPublicKeys: outs.map((o) => o.id.keypair.publicKey) as PointInput[],
    outputViewPublicKeys: outs.map((o) => o.id.viewKeypair.publicKey) as PointInput[],
    kemSs: outs.map((o) => [o.seal.kemSs[0], o.seal.kemSs[1]]),
    encryptionNonce: NONCE_WDR,
    recipient: BigInt(OWNER20),
  };
  const { a, b: bb, c, pub } = await prove("withdrawPriv", input);
  console.log(`  withdrawPriv out (pub[0]) = ${BigInt(pub[0])} (expect ${PAY - 50n})`);
  const kemHexStr = (u: Uint8Array): Hex => ("0x" + Buffer.from(u).toString("hex")) as Hex;
  const ZERO32 = ("0x" + "00".repeat(32)) as Hex;
  const withdrawData = encodeFunctionData({
    abi: wdrModArt.abi as Abi,
    functionName: "withdrawPriv",
    args: [...proofArgs({ a, b: bb, c, pub }), outs.map((o) => kemHexStr(o.seal.kemCiphertext)), ZERO32, 0],
  });
  for (const i of Array(3).keys()) {
    const sim = await read(wdrMod.a41, withdrawData);
    console.log(`  withdraw constant-sim ${i}: wall=${sim.ms.toFixed(0)}ms energy=${sim.energy}`);
  }
  const meBefore = BigInt((await read(token.a41, enc(tokenArt.abi as Abi, "balanceOf", [OWNER20]))).out);
  await write("WITHDRAW: withdrawPriv (real proof)", wdrMod.a41, withdrawData);
  const meAfter = BigInt((await read(token.a41, enc(tokenArt.abi as Abi, "balanceOf", [OWNER20]))).out);
  console.log(`  withdrawn to recipient: ${meAfter - meBefore} (expect ${PAY - 50n})`);

  // ------------------------------------------------------------------ ledger
  console.log("\n==================== FEE LEDGER (energy x 100 sun) ====================");
  console.log(`${"step".padEnd(45)} ${"energy".padStart(10)} ${"TRX".padStart(8)}`);
  for (const r of ledger) console.log(`${r.step.padEnd(45)} ${String(r.energy).padStart(10)} ${r.trx.toFixed(2).padStart(8)}`);
  const deploys = ledger.filter((r) => r.step.startsWith("deploy") || r.step.includes("register") || r.step.includes("initialize"));
  const ops = ledger.filter((r) => !deploys.includes(r));
  console.log(`one-time (deploy+wiring): ${deploys.reduce((a, r) => a + r.trx, 0).toFixed(1)} TRX`);
  console.log(`per-flow ops            : ${ops.reduce((a, r) => a + r.trx, 0).toFixed(2)} TRX`);
};

main().catch((e) => {
  console.error("PROBE FAILED:", e);
  process.exit(1);
});
