// Scenario driver for the indexer test (a trimmed sibling of
// deploy/e2e_orchestrator.ts). Deploys a fresh B=16 pool on a live anvil and
// runs the full cross-circuit cycle the indexer must ingest, then returns the
// secrets the test needs to trial-decrypt + check (recipient keys, amounts,
// salts, subtree root, single-append leaf commitments).
//
// Differences from e2e_orchestrator that matter to the indexer:
//   - the HONEST disburse publishes the FULL ciphertext (receiver ++ authority)
//     so the whole disclosureHash chain recomputes off-chain (→ status pass);
//   - a SECOND disburse (spending the value-0 deposit note) publishes a TAMPERED
//     ciphertext (one element flipped) → the indexer must raise a first-class
//     disclosureHash alarm (status "mismatch");
//   - a THIRD, PLAIN disburse() (spending the payee's transfer note) publishes
//     no ciphertext at all → the indexer must still surface the operation in
//     the feed with disclosure status "withheld" on the alarm channel.
//
// Proving is CPU snarkjs against circuits/out (same as e2e_orchestrator); no
// rabbitsnark / GPU. Runs against E2E_RPC (an anvil the harness started).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

import { ImtTree } from "../../sdk/src/imt.js";
import {
  deriveKeypair, commitment, nullifier,
  poseidonEncrypt, ecdhSharedSecret, assertDistinctOwnerPubkeys,
} from "../../sdk/src/note.js";
import type { Keypair } from "../../sdk/src/note.js";
import type { FieldInput } from "../../sdk/src/babyjub.js";

const require = createRequire(import.meta.url);
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const CIRC_OUT = join(ROOT, "circuits", "out");
const CONTRACTS_OUT = join(ROOT, "contracts", "out");
const POSEIDON_HEX = join(ROOT, "contracts", "test", "fixtures", "poseidon2.hex");

const NODE_MODULES =
  process.env.BONGTU_NODE_MODULES || "/home/a41/Workspace/zkx-snap/circuits/node_modules";
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const snarkjs: any = require(join(NODE_MODULES, "snarkjs/build/main.cjs"));
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const ethers: any = require(join(NODE_MODULES, "ethers"));

const RPC = process.env.E2E_RPC || "http://127.0.0.1:8545";
const PK = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // anvil #0

const H = 32;
const B = 16;

const dec = (x: FieldInput): string => BigInt(x).toString();
function strify(v: unknown): unknown {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(strify);
  if (v && typeof v === "object") {
    const o: Record<string, unknown> = {};
    for (const k of Object.keys(v)) o[k] = strify((v as Record<string, unknown>)[k]);
    return o;
  }
  return v;
}

async function prove(name: string, input: unknown) {
  const wasm = join(CIRC_OUT, `${name}_js`, `${name}.wasm`);
  const zkey = join(CIRC_OUT, `${name}.zkey`);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(strify(input), wasm, zkey);
  const cd = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals);
  const [a, b, c, pub] = JSON.parse("[" + cd + "]");
  return { a, b, c, pub, publicSignals };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function artifact(sol: string, contract: string): { abi: any; bytecode: any } {
  const j = JSON.parse(readFileSync(join(CONTRACTS_OUT, `${sol}.sol`, `${contract}.json`), "utf8"));
  return { abi: j.abi, bytecode: j.bytecode.object };
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function deploy(wallet: any, sol: string, contract: string, args: unknown[] = []): Promise<any> {
  const { abi, bytecode } = artifact(sol, contract);
  const f = new ethers.ContractFactory(abi, bytecode, wallet);
  const inst = await f.deploy(...args);
  await inst.deployed();
  return inst;
}

// Deploy BongtuPool behind a UUPS ERC-1967 proxy (SPEC §5.2), initialized in the
// proxy constructor with the 8-arg initializer. Returns a contract bound to the
// BongtuPool ABI at the PROXY address (the canonical, upgrade-stable pool).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function deployPoolProxy(wallet: any, initArgs: unknown[]): Promise<any> {
  const impl = await deploy(wallet, "BongtuPool", "BongtuPool");
  const { abi: poolAbi } = artifact("BongtuPool", "BongtuPool");
  const initData = new ethers.utils.Interface(poolAbi).encodeFunctionData("initialize", initArgs);
  const proxy = await deploy(wallet, "ERC1967Proxy", "ERC1967Proxy", [impl.address, initData]);
  return new ethers.Contract(proxy.address, poolAbi, wallet);
}

/** The disburse authority (non-repudiation) envelope plaintext (SPEC §4). */
function authorityPlain(
  inPub: readonly [bigint, bigint], inVal: bigint, inSalt: bigint,
  outPubs: [bigint, bigint][], amounts: bigint[], salts: bigint[],
): bigint[] {
  return [
    inPub[0], inPub[1], inVal, inSalt,
    ...outPubs.flatMap((p) => [p[0], p[1]]),
    ...amounts.flatMap((v, i) => [v, salts[i]]),
  ];
}

export interface SingleLeaf {
  leafIndex: number;
  commitment: string; // decimal
}

export interface DisburseInfo {
  startLeafIndex: number;
  recipientPrivs: string[]; // decimal — TEST-ONLY secrets, never held by the indexer
  recipientPubs: [string, string][];
  amounts: string[];
  salts: string[];
  outCommits: string[]; // decimal
  subtreeRoot: string; // decimal
  ecdhPublicKey: [string, string]; // decimal (ephemeral pub emitted on-chain)
  nonce: string; // decimal
}

/** One note the arbiter test tracks through its create -> spend transition. */
export interface ArbiterNote {
  owner: [string, string]; // decimal bjj pubkey
  leafIndex: number;
  value: string; // decimal
  salt: string; // decimal
}

export interface ScenarioResult {
  rpc: string;
  poolAddr: string;
  B: number;
  H: number;
  headRoot: string; // decimal, at end of scenario
  nextLeafIndex: number;
  disburseHonest: DisburseInfo;
  tamperedStartLeafIndex: number; // second (tampered) disburse batch start
  singleLeaves: SingleLeaf[]; // real single-append leaves for the /path test
  // ---- arbiter-mode fixtures (SPEC §6b v2) ---------------------------------
  arbiterPrivateKey: string; // decimal — the AUTHORITY keypair's private scalar
  blockAfterHonestDisburse: number; // block height after disburse#1, BEFORE the transfer
  recipient0Note: ArbiterNote; // recipient #0's disburse-batch note (spent by the transfer)
  recipient0PrivateKey: string; // decimal — TEST-ONLY: recipient #0 signs its own /notes auth
  payeeNote: ArbiterNote; // the payee's transfer output note (created by the transfer)
  payeePrivateKey: string; // decimal — TEST-ONLY: the payee signs its own /notes auth
  spentNullifiers: string[]; // decimal — the real (nonzero) nullifiers this run produces
}

export async function runScenario(): Promise<ScenarioResult> {
  const provider = new ethers.providers.JsonRpcProvider(RPC);
  const wallet = new ethers.Wallet(PK, provider);
  const employerAddr = wallet.address;

  const EMPLOYER = deriveKeypair(111111111111111111111111n);
  const AUTHORITY = deriveKeypair(555555555555555555555555n);
  const PAYEE = deriveKeypair(222222222222222222222222n);
  const recipient = (i: number): Keypair => deriveKeypair(2000000011n + BigInt(i) * 1000003n);
  const RCPTS = Array.from({ length: B }, (_, i) => recipient(i));

  const ECDH_DEP = 600000000000000000007n;
  const ECDH_D1 = 700000000000000000001n;
  const ECDH_TRANSFER = 800000000000000000003n;
  const ECDH_D2 = 900000000000000000009n;
  const ECDH_W = 950000000000000000021n;
  const NONCE_DEP = 555555555555n;
  const NONCE_D1 = 111111111111n;
  const NONCE_TRANSFER = 222222222222n;
  const NONCE_D2 = 333333333333n;
  const NONCE_W = 666666666666n;

  const sD0 = 5000001n, sD1 = 5000002n;
  const sR = (i: number): bigint => 6000000n + BigInt(i);
  const sR2 = (i: number): bigint => 6100000n + BigInt(i);
  const sPay = 7000001n, sChg = 7000002n;
  const sPadT = 7100001n, sPadW = 7100002n, sRes = 7200001n;

  const amounts = Array.from({ length: B }, (_, i) => 100n + BigInt(i) * 3n);
  const V = amounts.reduce((a, x) => a + x, 0n);

  const oracle = new ImtTree(H, B);

  // ---- deploy ----
  const posHex = readFileSync(POSEIDON_HEX, "utf8").trim();
  const posFactory = new ethers.ContractFactory([], posHex, wallet);
  const poseidon = await posFactory.deploy();
  await poseidon.deployed();
  const dv = await deploy(wallet, "DepositVerifier", "DepositVerifier");
  const wv = await deploy(wallet, "WithdrawVerifier", "WithdrawVerifier");
  const dsv = await deploy(wallet, "DisburseVerifier", "DisburseVerifier");
  const tv = await deploy(wallet, "TransferVerifier", "TransferVerifier");
  const token = await deploy(wallet, "MockERC20", "MockERC20");
  const pool = await deployPoolProxy(wallet, [
    poseidon.address, dv.address, wv.address, dsv.address, tv.address, token.address, B,
    [dec(AUTHORITY.publicKey[0]), dec(AUTHORITY.publicKey[1])],
  ]);
  await (await token.mint(employerAddr, dec(V * 1000n))).wait();
  await (await token.approve(pool.address, ethers.constants.MaxUint256)).wait();

  // ---- deposit: note(V)@0, note(0)@1 ----
  const dNoteV = commitment(V, sD0, EMPLOYER.publicKey);
  const dNote0 = commitment(0n, sD1, EMPLOYER.publicKey);
  {
    const { a, b, c, pub } = await prove("deposit", {
      outputCommitments: [dNoteV, dNote0], outputValues: [V, 0n],
      outputSalts: [sD0, sD1], outputOwnerPublicKeys: [EMPLOYER.publicKey, EMPLOYER.publicKey],
      ecdhPrivateKey: ECDH_DEP, encryptionNonce: NONCE_DEP, authorityPublicKey: AUTHORITY.publicKey,
    });
    oracle.appendLeaf(dNoteV);
    oracle.appendLeaf(dNote0);
    await (await pool.deposit(a, b, c, pub)).wait();
  }
  const nfDepositV = nullifier(V, sD0, EMPLOYER.formattedPrivateKey);

  // ---- disburse #1 (HONEST): note(V)@0 -> 16 recipients; emit receiver++authority ----
  const outCommits = amounts.map((v, i) => commitment(v, sR(i), RCPTS[i].publicKey));
  const rcptPubs = RCPTS.map((r) => r.publicKey);
  assertDistinctOwnerPubkeys(rcptPubs);
  const subtreeRoot = oracle.computeSubtreeRoot(outCommits);
  const honestStart = B; // pads 2..15 dead, batch attaches at leaf 16
  {
    const { siblings } = oracle.merklePath(0);
    const { a, b, c, pub } = await prove("disburse", {
      nullifiers: [nfDepositV], inputCommitments: [dNoteV], inputValues: [V], inputSalts: [sD0],
      inputOwnerPrivateKey: EMPLOYER.formattedPrivateKey, ecdhPrivateKey: ECDH_D1,
      root: oracle.getRoot(), pathElements: [siblings], leafIndices: [0n], enabled: [1n],
      outputCommitments: outCommits, outputValues: amounts, outputSalts: amounts.map((_, i) => sR(i)),
      outputOwnerPublicKeys: rcptPubs, encryptionNonce: NONCE_D1, authorityPublicKey: AUTHORITY.publicKey,
    });
    const rcptCts = amounts.map((v, i) =>
      poseidonEncrypt([v, sR(i)], ecdhSharedSecret(ECDH_D1, RCPTS[i].publicKey), NONCE_D1));
    const ctFlat = rcptCts.flat();
    const authCt = poseidonEncrypt(
      authorityPlain(EMPLOYER.publicKey, V, sD0, rcptPubs, amounts, amounts.map((_, i) => sR(i))),
      ecdhSharedSecret(ECDH_D1, AUTHORITY.publicKey), NONCE_D1,
    );
    oracle.attachSubtree(subtreeRoot, outCommits);
    // publish FULL ciphertext (receiver ++ authority) so the whole chain recomputes
    await (await pool.disburseWithCiphertexts(a, b, c, pub, [...ctFlat, ...authCt].map(dec))).wait();
  }
  // Block boundary the arbiter test ingests up to for the spent=false snapshot:
  // anvil mines one block per tx, so this precedes the transfer that spends @16.
  const blockAfterHonestDisburse = await provider.getBlockNumber();

  // recipient #0 note value/salt (also what a wallet recovers by trial-decrypt)
  const recoveredValue0 = amounts[0], recoveredSalt0 = sR(0);

  // ---- transfer: recipient0 spends batch note @16 + padded input -> leaves 32,33 ----
  const nfBatch0 = nullifier(recoveredValue0, recoveredSalt0, RCPTS[0].formattedPrivateKey);
  const payVal = 60n, chgVal = recoveredValue0 - payVal;
  const payCommit = commitment(payVal, sPay, PAYEE.publicKey);
  const chgCommit = commitment(chgVal, sChg, RCPTS[0].publicKey);
  const padCommitT = commitment(0n, sPadT, RCPTS[0].publicKey);
  {
    assertDistinctOwnerPubkeys([PAYEE.publicKey, RCPTS[0].publicKey]);
    const { siblings } = oracle.merklePath(honestStart);
    const zeros: bigint[] = new Array(H).fill(0n);
    const { a, b, c, pub } = await prove("transfer", {
      nullifiers: [nfBatch0, 0n], inputCommitments: [outCommits[0], padCommitT],
      inputValues: [recoveredValue0, 0n], inputSalts: [recoveredSalt0, sPadT],
      inputOwnerPrivateKey: RCPTS[0].formattedPrivateKey, ecdhPrivateKey: ECDH_TRANSFER,
      root: oracle.getRoot(), pathElements: [siblings, zeros], leafIndices: [BigInt(honestStart), 0n],
      enabled: [1n, 0n], outputCommitments: [payCommit, chgCommit], outputValues: [payVal, chgVal],
      outputSalts: [sPay, sChg], outputOwnerPublicKeys: [PAYEE.publicKey, RCPTS[0].publicKey],
      encryptionNonce: NONCE_TRANSFER, authorityPublicKey: AUTHORITY.publicKey,
    });
    oracle.appendLeaf(payCommit);
    oracle.appendLeaf(chgCommit);
    await (await pool.transfer(a, b, c, pub)).wait();
  }
  const payLeaf = honestStart + B; // 32
  const chgLeaf = honestStart + B + 1; // 33

  // ---- withdraw: recipient0 change @33 -> leaf 34, ERC20 out ----
  const nfChange = nullifier(chgVal, sChg, RCPTS[0].formattedPrivateKey);
  const resCommit = commitment(0n, sRes, RCPTS[0].publicKey);
  const padCommitW = commitment(0n, sPadW, RCPTS[0].publicKey);
  {
    const { siblings } = oracle.merklePath(chgLeaf);
    const zeros: bigint[] = new Array(H).fill(0n);
    const { a, b, c, pub } = await prove("withdraw", {
      nullifiers: [nfChange, 0n], inputCommitments: [chgCommit, padCommitW],
      inputValues: [chgVal, 0n], inputSalts: [sChg, sPadW],
      inputOwnerPrivateKey: RCPTS[0].formattedPrivateKey,
      root: oracle.getRoot(), pathElements: [siblings, zeros], leafIndices: [BigInt(chgLeaf), 0n],
      enabled: [1n, 0n], outputCommitments: [resCommit], outputValues: [0n], outputSalts: [sRes],
      outputOwnerPublicKeys: [RCPTS[0].publicKey],
      ecdhPrivateKey: ECDH_W, encryptionNonce: NONCE_W, authorityPublicKey: AUTHORITY.publicKey,
    });
    oracle.appendLeaf(resCommit);
    await (await pool.withdraw(a, b, c, pub)).wait();
  }

  // ---- disburse #2 (TAMPERED): note(0)@1 -> 16 zero-value recipients; emit corrupted ct ----
  const nf0 = nullifier(0n, sD1, EMPLOYER.formattedPrivateKey);
  const amounts2 = new Array(B).fill(0n) as bigint[];
  const outCommits2 = amounts2.map((v, i) => commitment(v, sR2(i), RCPTS[i].publicKey));
  const subtreeRoot2 = oracle.computeSubtreeRoot(outCommits2);
  const tamperedStart = 48; // pad 35..47 dead, attach @48
  {
    const { siblings } = oracle.merklePath(1);
    const { a, b, c, pub } = await prove("disburse", {
      nullifiers: [nf0], inputCommitments: [dNote0], inputValues: [0n], inputSalts: [sD1],
      inputOwnerPrivateKey: EMPLOYER.formattedPrivateKey, ecdhPrivateKey: ECDH_D2,
      root: oracle.getRoot(), pathElements: [siblings], leafIndices: [1n], enabled: [1n],
      outputCommitments: outCommits2, outputValues: amounts2, outputSalts: amounts2.map((_, i) => sR2(i)),
      outputOwnerPublicKeys: rcptPubs, encryptionNonce: NONCE_D2, authorityPublicKey: AUTHORITY.publicKey,
    });
    const rcptCts2 = amounts2.map((v, i) =>
      poseidonEncrypt([v, sR2(i)], ecdhSharedSecret(ECDH_D2, RCPTS[i].publicKey), NONCE_D2));
    const ctFlat2 = rcptCts2.flat();
    const authCt2 = poseidonEncrypt(
      authorityPlain(EMPLOYER.publicKey, 0n, sD1, rcptPubs, amounts2, amounts2.map((_, i) => sR2(i))),
      ecdhSharedSecret(ECDH_D2, AUTHORITY.publicKey), NONCE_D2,
    );
    const full = [...ctFlat2, ...authCt2];
    full[0] = BigInt(full[0]) + 1n; // TAMPER one element → disclosureHash must break
    oracle.attachSubtree(subtreeRoot2, outCommits2);
    await (await pool.disburseWithCiphertexts(a, b, c, pub, full.map(dec))).wait();
  }

  // NOTE: §6b v2 removes the plain disburse() entry point, so a "withheld"
  // (nothing-published) disburse is no longer producible on-chain — publication
  // is enforced. The scenario therefore ends after the honest + tampered
  // batches; the payee note @32 stays an unspent single-append leaf for /path.

  return {
    rpc: RPC,
    poolAddr: pool.address,
    B, H,
    headRoot: (await pool.root()).toString(),
    nextLeafIndex: Number((await pool.nextLeafIndex()).toString()),
    disburseHonest: {
      startLeafIndex: honestStart,
      recipientPrivs: RCPTS.map((r) => dec(r.formattedPrivateKey)),
      recipientPubs: RCPTS.map((r) => [dec(r.publicKey[0]), dec(r.publicKey[1])] as [string, string]),
      amounts: amounts.map(dec),
      salts: amounts.map((_, i) => dec(sR(i))),
      outCommits: outCommits.map(dec),
      subtreeRoot: subtreeRoot.toString(),
      ecdhPublicKey: [dec(deriveKeypair(ECDH_D1).publicKey[0]), dec(deriveKeypair(ECDH_D1).publicKey[1])],
      nonce: dec(NONCE_D1),
    },
    tamperedStartLeafIndex: tamperedStart,
    singleLeaves: [
      { leafIndex: 0, commitment: dec(dNoteV) },
      { leafIndex: payLeaf, commitment: dec(payCommit) },
    ],
    // ---- arbiter-mode fixtures -----------------------------------------------
    // The AUTHORITY keypair IS the arbiter key (the indexer decrypts with its
    // private scalar); the recipient/payee notes + spent nullifiers let the
    // arbiter test assert the note ledger + spent transition from envelopes alone.
    arbiterPrivateKey: dec(AUTHORITY.formattedPrivateKey),
    blockAfterHonestDisburse,
    recipient0Note: {
      owner: [dec(RCPTS[0].publicKey[0]), dec(RCPTS[0].publicKey[1])],
      leafIndex: honestStart, // 16 — recipient #0's batch leaf, spent by the transfer
      value: dec(recoveredValue0),
      salt: dec(recoveredSalt0),
    },
    recipient0PrivateKey: dec(RCPTS[0].formattedPrivateKey),
    payeeNote: {
      owner: [dec(PAYEE.publicKey[0]), dec(PAYEE.publicKey[1])],
      leafIndex: payLeaf, // 32 — created by the transfer
      value: dec(payVal),
      salt: dec(sPay),
    },
    payeePrivateKey: dec(PAYEE.formattedPrivateKey),
    // Real (nonzero) nullifiers, in spend order: deposit note(V)@0 (disburse#1),
    // recipient0 batch note @16 (transfer), change @33 (withdraw), note(0)@1
    // (tampered disburse#2). Transfer/withdraw pad inputs have nullifier 0 (skipped).
    spentNullifiers: [
      dec(nfDepositV),
      dec(nfBatch0),
      dec(nfChange),
      dec(nf0),
    ],
  };
}
