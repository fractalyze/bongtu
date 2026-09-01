// Live per-action gas survey against the CURRENT live pool (withdraw-v2 stealth-exit impl).
// deposit -> transfer(2x2) -> withdraw, one fresh chain with survey-only identities,
// each tx's gasUsed printed for docs/performance.md. Built on @bongtu/core + the
// proof toolbox only — deliberately no wallet-lib imports, so the survey stays
// runnable while the wallet sources are mid-refactor. transfer10 is not re-run here:
// the V4 entrypoint is deprecated (transfer10x2 replaced it in every wallet route),
// and its measurement stays in docs/performance.md.
//
//   LIVE_RPC + DEPLOYER_KEY (env) required.  Run: npx tsx deploy/live/gas_survey.ts
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";

import { deriveKeypair, commitment, nullifier } from "@bongtu/core/note";
import { ml_kem768, kemSsToLimbs, kemHexToBytes } from "@bongtu/core/kem";
import {
  ARBITER_KEM_PK,
  ARBITER_PUBKEY_X,
  ARBITER_PUBKEY_Y,
  CHAIN_ID,
  H,
  RPC_URL,
  explorerTxUrl,
} from "@bongtu/core/network";
import { maxUint256, parseAbi } from "viem";
import { artifact, prove, ok, step, failureCount } from "./lib/proof_toolbox.js";
// The viem rig centralizes the live gas-price pin (auto-estimate once overpaid ~1500x).
import { liveChain, GAS_PRICE, makeRig, proofArgs } from "./lib/viem_client.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const ADDR = JSON.parse(readFileSync(join(HERE, "..", `addresses.${CHAIN_ID}.json`), "utf8"));

const C = deriveKeypair(770000000000000000000077n);
const D = deriveKeypair(880000000000000000000088n);
const AUTHORITY_PUB: [bigint, bigint] = [BigInt(ARBITER_PUBKEY_X), BigInt(ARBITER_PUBKEY_Y)];

const DEP = 200n * 10n ** 18n;
const PAY = 120n * 10n ** 18n;
const CHG = DEP - PAY;

function randField(): bigint {
  const b = new Uint8Array(31);
  webcrypto.getRandomValues(b);
  const x = b.reduce<bigint>((acc, byte) => (acc << 8n) | BigInt(byte), 0n);
  return x === 0n ? 1n : x;
}
// nonce must fit the Poseidon-sponge nonce bound the circuits enforce (< 2^128)
const randNonce = (): bigint => randField() & ((1n << 120n) - 1n);

function drawKem(): { kemSs: [bigint, bigint]; ctHex: string } {
  const enc = ml_kem768.encapsulate(kemHexToBytes(ARBITER_KEM_PK));
  const ss = kemSsToLimbs(enc.sharedSecret) as [bigint, bigint];
  return { kemSs: ss, ctHex: "0x" + Buffer.from(enc.cipherText).toString("hex") };
}

async function livePath(idx: number): Promise<bigint[]> {
  const IDXER = process.env.INDEXER_URL || "https://bongtu.fractalyze.io/indexer";
  const p = (await (await fetch(`${IDXER}/path/${idx}`)).json()) as { siblings: string[] };
  return p.siblings.map(BigInt);
}

async function liveHeadCaughtUp(wantLeaf: number): Promise<bigint> {
  const IDXER = process.env.INDEXER_URL || "https://bongtu.fractalyze.io/indexer";
  const attempt = async (triesLeft: number): Promise<bigint> => {
    if (triesLeft <= 0) throw new Error("indexer did not catch up");
    const h = (await (await fetch(`${IDXER}/head`)).json()) as { root: string; nextLeafIndex: number };
    if (h.nextLeafIndex >= wantLeaf) return BigInt(h.root);
    await new Promise((r) => setTimeout(r, 3000));
    return attempt(triesLeft - 1);
  };
  return attempt(40);
}

async function main(): Promise<void> {
  // The viem rig pins gasPrice on every write — never estimated.
  const rig = makeRig({
    chain: liveChain,
    rpc: process.env.LIVE_RPC || RPC_URL,
    privateKey: process.env.DEPLOYER_KEY!,
    gasPrice: GAS_PRICE,
  });
  const pool = rig.at(
    ADDR.pool,
    parseAbi([
      "function deposit(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[19] pub, bytes kemCiphertext)",
      "function transfer(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[37] pub, bytes kemCiphertext)",
      "function withdraw(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[27] pub, bytes kemCiphertext, bytes32 stealthEphemeralPub, uint8 stealthViewTag)",
      "function nextLeafIndex() view returns (uint256)",
    ]),
  );
  const token = rig.at(ADDR.token, artifact("MockERC20", "MockERC20").abi);
  const gas: Record<string, { used: string; tx: string }> = {};
  const zeros: bigint[] = new Array(H).fill(0n);

  step("DEPOSIT 200 for C (measured)");
  await token.write("mint", [rig.address, DEP]);
  await token.write("approve", [ADDR.pool, maxUint256]);
  const sDep = randField();
  const sDep0 = randField();
  const leafDep = Number(await pool.read("nextLeafIndex"));
  const cDep = commitment(DEP, sDep, C.publicKey);
  const kemD = drawKem();
  {
    const { a, b, c, pub } = await prove("deposit", {
      outputCommitments: [cDep, commitment(0n, sDep0, C.publicKey)],
      outputValues: [DEP, 0n],
      outputSalts: [sDep, sDep0],
      outputOwnerPublicKeys: [C.publicKey, C.publicKey],
      ecdhPrivateKey: randField(),
      kemSs: kemD.kemSs,
      encryptionNonce: randNonce(),
      authorityPublicKey: AUTHORITY_PUB,
    });
    const r = await pool.write("deposit", [...proofArgs({ a, b, c, pub }), kemD.ctHex]);
    gas.deposit = { used: r.gasUsed.toString(), tx: r.transactionHash };
  }

  step("TRANSFER 2x2 C->D 120 (measured)");
  const root1 = await liveHeadCaughtUp(leafDep + 2);
  const sPay = randField();
  const sChg = randField();
  const sPadIn = randField();
  const cPay = commitment(PAY, sPay, D.publicKey);
  const cChg = commitment(CHG, sChg, C.publicKey);
  const kemT = drawKem();
  {
    const { a, b, c, pub } = await prove("transfer", {
      nullifiers: [nullifier(DEP, sDep, C.formattedPrivateKey), 0n],
      inputCommitments: [cDep, commitment(0n, sPadIn, C.publicKey)],
      inputValues: [DEP, 0n],
      inputSalts: [sDep, sPadIn],
      inputOwnerPrivateKey: C.formattedPrivateKey,
      ecdhPrivateKey: randField(),
      root: root1,
      pathElements: [await livePath(leafDep), zeros],
      leafIndices: [BigInt(leafDep), 0n],
      enabled: [1n, 0n],
      outputCommitments: [cPay, cChg],
      outputValues: [PAY, CHG],
      outputSalts: [sPay, sChg],
      outputOwnerPublicKeys: [D.publicKey, C.publicKey],
      kemSs: kemT.kemSs,
      encryptionNonce: randNonce(),
      authorityPublicKey: AUTHORITY_PUB,
    });
    const leafPay = Number(await pool.read("nextLeafIndex"));
    const r = await pool.write("transfer", [...proofArgs({ a, b, c, pub }), kemT.ctHex]);
    gas.transfer = { used: r.gasUsed.toString(), tx: r.transactionHash };
    gas.transfer.tx += ` (pay leaf ${leafPay})`;
  }

  step("WITHDRAW 120 by D (measured)");
  const leafPay = Number(gas.transfer.tx.match(/pay leaf (\d+)/)![1]);
  const root2 = await liveHeadCaughtUp(leafPay + 2);
  const sRes = randField();
  const sPadW = randField();
  const kemW = drawKem();
  {
    const { a, b, c, pub } = await prove("withdraw", {
      nullifiers: [nullifier(PAY, sPay, D.formattedPrivateKey), 0n],
      inputCommitments: [cPay, commitment(0n, sPadW, D.publicKey)],
      inputValues: [PAY, 0n],
      inputSalts: [sPay, sPadW],
      inputOwnerPrivateKey: D.formattedPrivateKey,
      root: root2,
      pathElements: [await livePath(leafPay), zeros],
      leafIndices: [BigInt(leafPay), 0n],
      enabled: [1n, 0n],
      outputCommitments: [commitment(0n, sRes, D.publicKey)],
      outputValues: [0n],
      outputSalts: [sRes],
      outputOwnerPublicKeys: [D.publicKey],
      ecdhPrivateKey: randField(),
      kemSs: kemW.kemSs,
      encryptionNonce: randNonce(),
      authorityPublicKey: AUTHORITY_PUB,
      // proof-bound payout (withdraw-v2, pub[26]): same target the old
      // msg.sender path paid, so the survey's economics are unchanged.
      recipient: BigInt(rig.address),
    });
    ok(BigInt(pub[0]) === PAY, `withdraw pub[0] == ${PAY}`);
    ok(BigInt(pub[26]) === BigInt(rig.address), "withdraw recipient proof-bound (pub[26])");
    // plain (non-stealth) withdraw: the announcement pair rides as the zero sentinel.
    const r = await pool.write("withdraw", [...proofArgs({ a, b, c, pub }), kemW.ctHex, "0x" + "00".repeat(32), 0]);
    gas.withdraw = { used: r.gasUsed.toString(), tx: r.transactionHash };
  }

  step("GAS SURVEY (withdraw-v2 stealth-exit impl)");
  for (const [op, g] of Object.entries(gas)) {
    console.log(`  ${op.padEnd(9)} ${g.used.padStart(10)}  ${explorerTxUrl(g.tx.split(" ")[0])}`);
  }
  if (failureCount() > 0) process.exit(1);
  console.log("\nGAS SURVEY: DONE");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
