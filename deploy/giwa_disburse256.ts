// Run a REAL 1-in / 256-out private disbursement against the LIVE BongtuPool on
// GIWA Sepolia: reconstruct the on-chain tree, deposit an employer note, then
// spend it to 256 recipients with a rabbitsnark-GPU Groth16 proof, publishing
// the receiver ciphertext on-chain. Measures the real L2 gas + L1 data fee.
//
//   GIWA_RPC (default: the sdk network RPC_URL) + DEPLOYER_KEY (env) required.
//   BONGTU_PROVER_URL (default http://127.0.0.1:8700) must point at a READY
//   bongtu prover service (top-level prover/ — boot it first, see prover/README.md).
//   Reuses the deployed addresses in deploy/addresses.91342.json.
//
// Disburse proving is GPU (rabbitsnark) because the 1x256 circuit is 2.79M
// constraints: this script POSTs the assembled disburse ProvingRequest to the
// prover service and gets back verifier-ready calldata. Deposit is snarkjs CPU,
// in-process. The SDK ImtTree mirror is validated against the live root before
// any tx, so the membership witness is real.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ImtTree } from "@bongtu/core/imt";
import { hybridEnvelopeKey, kemBindingOf, kemSsToLimbs, ml_kem768 } from "@bongtu/core/kem";
import { poseidonN } from "@bongtu/core/poseidon";
import { buildAuthorityPlaintext, disclosureChain } from "@bongtu/core/envelope";
import {
  deriveKeypair, commitment, nullifier,
  poseidonEncrypt, ecdhSharedSecret, assertDistinctOwnerPubkeys,
} from "@bongtu/core/note";
import type { Keypair } from "@bongtu/core/note";
import { toWire } from "@bongtu/core/proving";
import type { Calldata, DisburseInput } from "@bongtu/core/proving";
import { loadEthers } from "@bongtu/core/extern";
import { B, GIWA_GAS_FLOOR_GWEI, H, RPC_URL, explorerTxUrl } from "@bongtu/core/network";

// artifact / prove / dec and the ok()/step() ledger are the chain-agnostic
// toolbox shared with the anvil drivers (deploy/lib/proof_toolbox.ts). This
// script keeps its own connection + address material: it drives the canonical
// LIVE pool, not a stack it deployed.
import { artifact, dec, failureCount, ok, prove, step } from "./lib/proof_toolbox.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
// ethers v5 comes back `any` from the shared external loader.
const ethers = loadEthers();

const RPC = process.env.GIWA_RPC || RPC_URL;
const PK = process.env.DEPLOYER_KEY;
if (!PK) throw new Error("DEPLOYER_KEY env required");

// H=32 / B=256 come from @bongtu/core/network — the live pool's parameters.
// The bongtu prover service (top-level prover/) holds the belted disburse256
// zkey compiled on GPU0 and serves ProvingRequest -> calldata over HTTP. Boot it
// (and wait for GET /ready == 200) before running this script.
const PROVER_URL = (process.env.BONGTU_PROVER_URL || "http://127.0.0.1:8700").replace(/\/$/, "");

const addr = JSON.parse(readFileSync(join(ROOT, "deploy", "addresses.91342.json"), "utf8"));

// Post-PQ the pool only accepts hybrid-envelope proofs, so this script targets
// the UPGRADED pool (UpgradePq.s.sol). The arbiter's full ML-KEM-768 pk is
// distributed off-chain (ARBITER_KEM_PK env, hex; default = the committed
// fixture arbiter KEM pk) and is verified against the on-chain
// arbiterKemPkHash(currentEpoch()) before any encapsulation.
const KEM_PK: Uint8Array = (() => {
  const hex: string = process.env.ARBITER_KEM_PK
    ?? JSON.parse(readFileSync(join(ROOT, "contracts/test/fixtures/realproofs.json"), "utf8")).kemPublicKey;
  return Uint8Array.from(Buffer.from(hex.replace(/^0x/, ""), "hex"));
})();
const kemHex = (b: Uint8Array): string => "0x" + Buffer.from(b).toString("hex");

async function proveDisburse256(input: DisburseInput): Promise<Calldata> {
  // POST the complete disburse ProvingRequest to the prover service; it runs
  // witness-gen + the rabbitsnark GPU proof and returns exportSolidityCallData-form
  // calldata (warm ~seconds; the ~2.5min zkey compile happened at service boot).
  console.log(`   POSTing disburse ProvingRequest to ${PROVER_URL}/prove ...`);
  const t0 = Date.now();
  const res = await fetch(`${PROVER_URL}/prove`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ circuit: "disburse", input: toWire(input), backend: "gpu" }),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`prover service ${res.status}: ${text.slice(0, 400)}`);
  const cd = JSON.parse(text) as Calldata;
  if (!cd.a || !cd.b || !cd.c || !cd.pub) throw new Error("prover service response missing a/b/c/pub");
  console.log(`   proved disburse-256 via the service in ${((Date.now() - t0) / 1000).toFixed(1)}s`);
  return cd;
}
async function main(): Promise<void> {
  const provider = new ethers.providers.JsonRpcProvider(RPC);
  const wallet = new ethers.Wallet(PK, provider);
  const pool = new ethers.Contract(addr.pool, artifact("BongtuPool", "BongtuPool").abi, wallet);
  const token = new ethers.Contract(addr.token, artifact("MockERC20", "MockERC20").abi, wallet);
  const ARBITER: [bigint, bigint] = [BigInt(addr.arbiterKeyX), BigInt(addr.arbiterKeyY)]; // pool's stored authority key
  // Explicit gas price: the GIWA gas floor lives in @bongtu/core/network
  // (ethers' auto-estimate overpays ~1500x and drains the faucet grant).
  const TX = { gasPrice: ethers.utils.parseUnits(GIWA_GAS_FLOOR_GWEI, "gwei") };

  // The pool refuses clients holding the wrong (or a pre-upgrade zero) KEM pk:
  // encapsulating to an unverified key would silently strand the envelope.
  const onchainKemPkHash = await pool.arbiterKemPkHash(await pool.currentEpoch());
  ok(onchainKemPkHash === ethers.utils.keccak256(KEM_PK),
    "keccak256(ARBITER_KEM_PK) == on-chain arbiterKemPkHash(currentEpoch) (pool is PQ-upgraded)");

  const EMPLOYER = deriveKeypair(313131313131313131313131n);
  const recipient = (i: number): Keypair => deriveKeypair(4000000019n + BigInt(i) * 1000003n);
  const RCPTS = Array.from({ length: B }, (_, i) => recipient(i));
  const ECDH = 900000000000000000007n, NONCE = 424242424243n;
  // §4: reusing one tx's ephemeral key + nonce for a second envelope is a two-time pad.
  const ECDH_DEP = 610000000000000000011n, NONCE_DEP = 424242424244n;
  // Fresh ML-KEM encapsulation PER TX (ct reuse collapses the PQ compartment,
  // design doc §6); noble draws real randomness here — live txs need no replay
  // determinism.
  const kemEncap = () => {
    const { cipherText, sharedSecret } = ml_kem768.encapsulate(KEM_PK);
    return { kemSs: kemSsToLimbs(sharedSecret), kemCiphertext: cipherText };
  };
  const KEM_DEP = kemEncap();
  const KEM_DISB = kemEncap();
  const sD0 = 8000001n, sD1 = 8000002n, sR = (i: number): bigint => 9000000n + BigInt(i);
  const amounts = Array.from({ length: B }, (_, i) => 100n + BigInt(i)); // 256 distinct positive
  const V = amounts.reduce((a, x) => a + x, 0n);

  // ---- reconstruct the live tree mirror (leaves 0,1 = the smoke deposit) ----
  step("MIRROR: reconstruct the live GIWA tree and validate against the on-chain root");
  const oracle = new ImtTree(H, B);
  const rp = JSON.parse(readFileSync(join(ROOT, "contracts/test/fixtures/realproofs.json"), "utf8"));
  // deposit publics (18): oc0=pub[13], oc1=pub[14] (the smoke deposit's two leaves).
  oracle.appendLeaf(BigInt(rp.deposit.pub[13]));
  oracle.appendLeaf(BigInt(rp.deposit.pub[14]));
  const liveRoot0 = (await pool.root()).toString();
  ok(oracle.getRoot().toString() === liveRoot0, `mirror root == live pool.root() (nextLeafIndex ${await pool.nextLeafIndex()})`);

  // ---- deposit an employer note(V) + note(0) ----
  step("DEPOSIT (0-in/2-out): employer deposits V -> note(V) + note(0)");
  await (await token.mint(wallet.address, dec(V * 2n), TX)).wait();
  await (await token.approve(addr.pool, ethers.constants.MaxUint256, TX)).wait();
  const dNoteV = commitment(V, sD0, EMPLOYER.publicKey);
  const dNote0 = commitment(0n, sD1, EMPLOYER.publicKey);
  {
    const { a, b, c, pub } = await prove("deposit", {
      outputCommitments: [dNoteV, dNote0], outputValues: [V, 0n],
      outputSalts: [sD0, sD1], outputOwnerPublicKeys: [EMPLOYER.publicKey, EMPLOYER.publicKey],
      ecdhPrivateKey: ECDH_DEP, kemSs: KEM_DEP.kemSs,
      encryptionNonce: NONCE_DEP, authorityPublicKey: ARBITER,
    });
    ok(BigInt(pub[0]) === V, `deposit out == V (${V})`);
    oracle.appendLeaf(dNoteV); oracle.appendLeaf(dNote0);
    await (await pool.deposit(a, b, c, pub, kemHex(KEM_DEP.kemCiphertext), TX)).wait();
    ok((await pool.root()).toString() === oracle.getRoot().toString(), "after deposit: pool.root == mirror");
    ok((await pool.nextLeafIndex()).toString() === "4", "after deposit: nextLeafIndex == 4");
  }
  const leafV = 2; // dNoteV landed at leaf index 2
  const nfV = nullifier(V, sD0, EMPLOYER.formattedPrivateKey);

  // ---- disburse note(V) to 256 recipients (GPU proof) ----
  step("DISBURSE (1-in/256-out): spend note(V) -> 256 private recipient notes");
  const outCommits = amounts.map((v, i) => commitment(v, sR(i), RCPTS[i].publicKey));
  assertDistinctOwnerPubkeys(RCPTS.map((r) => r.publicKey));
  const subtreeRoot = oracle.computeSubtreeRoot(outCommits);
  const { siblings } = oracle.merklePath(leafV);
  const input = {
    nullifiers: [nfV], inputCommitments: [dNoteV], inputValues: [V], inputSalts: [sD0],
    inputOwnerPrivateKey: EMPLOYER.formattedPrivateKey, ecdhPrivateKey: ECDH,
    root: oracle.getRoot(), pathElements: [siblings], leafIndices: [BigInt(leafV)], enabled: [1n],
    outputCommitments: outCommits, outputValues: amounts, outputSalts: amounts.map((_, i) => sR(i)),
    outputOwnerPublicKeys: RCPTS.map((r) => r.publicKey),
    kemSs: KEM_DISB.kemSs,
    encryptionNonce: NONCE, authorityPublicKey: ARBITER,
  };
  const { a, b, c, pub } = await proveDisburse256(input);
  ok(BigInt(pub[3]) === subtreeRoot, "disburse subtreeRoot (pub[3]) == oracle.computeSubtreeRoot");
  ok(BigInt(pub[4]) === kemBindingOf(KEM_DISB.kemSs), "disburse kemBinding (pub[4]) == binding(tx kemSs)");
  ok(BigInt(pub[5]) === nfV, "disburse nullifier (pub[5]) == nullifier(deposit note)");
  ok(BigInt(pub[6]) === oracle.getRoot(), "disburse membership root (pub[6]) == live tree root");
  ok(BigInt(pub[9]) === ARBITER[0] && BigInt(pub[10]) === ARBITER[1], "disburse authority key == pool's stored arbiter key");

  // rebuild + prove the on-chain ciphertext via disclosureHash
  const rcptCts = amounts.map((v, i) => poseidonEncrypt([v, sR(i)], ecdhSharedSecret(ECDH, RCPTS[i].publicKey), NONCE));
  const ctFlat = rcptCts.flat(); // 256*4 = 1024 field elements
  const authPlain = buildAuthorityPlaintext("disburse", {
    inputs: [{ owner: EMPLOYER.publicKey, value: V, salt: sD0 }],
    outputs: amounts.map((v, i) => ({ owner: RCPTS[i].publicKey, value: v, salt: sR(i) })),
  });
  // hybrid envelope key (design doc §2): raw-ECDH would break disclosureHash
  const authCt = poseidonEncrypt(
    authPlain, hybridEnvelopeKey(ecdhSharedSecret(ECDH, ARBITER), KEM_DISB.kemSs), NONCE);
  ok(disclosureChain([...ctFlat, ...authCt]) === BigInt(pub[2]), "recomputed disclosureHash == pub[2] (on-chain ciphertext is the circuit's)");

  oracle.attachSubtree(subtreeRoot, outCommits); // pad leaves 4..255 dead, attach 256..511
  // §6b v2: the enforced-length disburse publishes the FULL ciphertext
  // (256*4 receiver ++ authority = 2054 elements) — the contract reverts otherwise.
  step("SUBMIT disburseWithCiphertexts to GIWA (full ciphertext: receiver ++ authority)");
  const tx = await pool.disburseWithCiphertexts(
    a, b, c, pub, [...ctFlat, ...authCt].map(dec), kemHex(KEM_DISB.kemCiphertext), TX);
  const rcpt = await tx.wait();
  ok((await pool.root()).toString() === oracle.getRoot().toString(), "after disburse: pool.root == mirror (256-subtree attached)");
  ok((await pool.nextLeafIndex()).toString() === "512", "after disburse: nextLeafIndex == 512 (pad 4->256 + 256 batch)");
  ok(await pool.nullifierUsed(dec(nfV)), "disburse marked the deposit-note nullifier");

  // ---- measured cost ----
  const full = await provider.send("eth_getTransactionReceipt", [tx.hash]);
  const gasUsed = BigInt(full.gasUsed), l1Fee = BigInt(full.l1Fee || "0x0"), gp = BigInt(full.effectiveGasPrice);
  const l2 = gasUsed * gp, total = l2 + l1Fee;
  step("RESULT");
  console.log(`   tx           : ${tx.hash}`);
  console.log(`   recipients   : ${B}   V(total) = ${V}`);
  console.log(`   L2 gasUsed   : ${gasUsed}  (< Karst cap 16,777,216: ${gasUsed < 16777216n})`);
  console.log(`   L2 fee       : ${l2} wei`);
  console.log(`   L1 data fee  : ${l1Fee} wei`);
  console.log(`   TOTAL cost   : ${total} wei = ${ethers.utils.formatEther(total.toString())} ETH`);
  console.log(`   per recipient: ${gasUsed / BigInt(B)} gas`);
  console.log(`   explorer     : ${explorerTxUrl(tx.hash)}`);
  const failures = failureCount();
  console.log(`\n${failures === 0 ? "GIWA 256-DISBURSE PASS" : `FAIL ${failures}`}`);
  process.exit(failures === 0 ? 0 : 1);
}
main().catch((e) => { console.error("\nERROR:", e && e.stack ? e.stack : e); process.exit(1); });
