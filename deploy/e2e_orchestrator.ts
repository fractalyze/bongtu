// bongtu M0 Unit U4 — cross-circuit spend cycle e2e on a live anvil.
//
// THE CAPSTONE (M0 DoD, docs/milestone-m0.md Done#4 / spec §5, §10b): drive a REAL EVM
// (anvil) through the full cycle with REAL Groth16 proofs (snarkjs CPU) and a
// GENUINE recipient trial-decrypt, asserting tree/value invariants at every
// step:
//
//   DEPLOY  Poseidon-v1 + 4 Groth16 verifiers + BongtuPool(B=16) + mock kKRW
//   DEPOSIT   0-in / 2-out : employer deposits V -> {note(V), note(0)} it owns
//   DISBURSE  1-in/16-out: employer spends note(V) -> 16 recipient notes (sum V),
//                          publishing the receiver ciphertext on-chain
//   DECRYPT   recipient #0, given ONLY its bjj privkey + the on-chain event
//                          (ecdhPublicKey, nonce, ciphertext), recovers (value,
//                          salt), rebuilds the commitment and confirms it is the
//                          batch leaf at its expected index (recovered, not read
//                          from generator memory)
//   TRANSFER  2-in/2-out : recipient #0 spends the batch note (enabled=1) + a
//                          PADDED input (enabled=0, value=0) -> payment + change
//   WITHDRAW  2-in/1-out : recipient #0 withdraws the change note -> ERC20 out
//   CONSERVE  ERC20 deposited == ERC20 withdrawn + value still shielded; every
//                          emitted disburse ciphertext decrypts to a real leaf
//
// The orchestrator maintains an ImtTree oracle in lockstep with the contract:
// every witness is generated against the oracle's CURRENT root (which, because
// the tree logic is byte-identical — U3 differential test — equals the live
// contract root), so proving is genuinely tied to live state. After every
// insert we assert `contract.root() === ImtTree.getRoot()`.
//
// Reuses the committed zkeys in circuits/out (whose verification keys match the
// committed verifiers, checked in the shell wrapper) so new proofs verify
// against the on-chain verifiers.

import { ImtTree, foldToRoot } from "@bongtu/sdk/imt";
import { poseidon2, poseidonN } from "@bongtu/sdk/poseidon";
import { buildAuthorityPlaintext, disclosureChain } from "@bongtu/sdk/envelope";
import {
  commitment,
  nullifier,
  poseidonEncrypt,
  poseidonDecrypt,
  ecdhSharedSecret,
  assertDistinctOwnerPubkeys,
} from "@bongtu/sdk/note";
import { loadEthers } from "@bongtu/sdk/extern";

// The deploy-and-drive skeleton (anvil connection, forge-artifact deploys, the
// UUPS pool proxy, the CPU prove() wrapper, shared actor/salt/amount fixtures)
// lives in the harness shared with apps/indexer/test/scenario.ts.
import {
  H, GATE_B as B, dec, connectAnvil, deployStack, prove as harnessProve,
  EMPLOYER, AUTHORITY, PAYEE, RCPTS,
  sD0, sD1, sR, sPay, sChg, sPadT, sPadW, sRes,
  amounts, V,
} from "./lib/e2e_harness.js";

// ethers v5 comes back `any` from the shared external loader — we type OUR
// code (notes, keys, tree), not theirs.
const ethers = loadEthers();

// ---------------------------------------------------------------------------
// tiny assert / logging harness
// ---------------------------------------------------------------------------
let failures = 0;
const checks: { step: string; pass: boolean }[] = [];
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures++;
  checks.push({ step: msg, pass });
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
  if (!pass) throw new Error(`assertion failed: ${msg}`);
}
function step(title: string): void {
  console.log(`\n=== ${title} ===`);
}
// verbose: the human-watched DoD gate keeps its per-circuit timing log (the
// scenario sibling runs the same harness prove() silent).
const prove = (name: string, input: unknown) => harnessProve(name, input, { verbose: true });

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  const { wallet } = connectAnvil();
  const employerAddr = wallet.address;

  // Actors (EMPLOYER/AUTHORITY/PAYEE/RCPTS), salts, and amounts/V are the
  // harness fixture material shared with the scenario sibling.

  // fresh ephemeral ECDH key + nonce PER TRANSACTION (SPEC U2->U4 note: never
  // reuse a (key, nonce) pair across txs — that would be a two-time pad).
  // Driver-local; the scenario sibling keeps its scalars disjoint from these.
  const ECDH_DEPOSIT = 600000000000000000007n;
  const ECDH_DISBURSE = 700000000000000000001n;
  const ECDH_TRANSFER = 800000000000000000003n;
  const ECDH_WITHDRAW = 900000000000000000009n;
  const NONCE_DEPOSIT = 333333333333n;
  const NONCE_DISBURSE = 111111111111n;
  const NONCE_TRANSFER = 222222222222n;
  const NONCE_WITHDRAW = 444444444444n;

  const oracle = new ImtTree(H, B);

  // ============================ DEPLOY ====================================
  step("DEPLOY (anvil): Poseidon-v1, 4 verifiers, BongtuPool(B=16), mock kKRW");
  // deployStack also funds + approves the employer (deposit pulls from
  // msg.sender via SafeERC20).
  const { poseidon, token, pool } = await deployStack(wallet, {
    batchSize: B,
    authorityPublicKey: AUTHORITY.publicKey,
    mintAmount: V * 1000n,
  });
  // sanity: on-chain Poseidon([1,2]) == the SDK / circuit parity constant
  const posAbi = ["function poseidon(uint256[2]) pure returns (uint256)"];
  const posC = new ethers.Contract(poseidon.address, posAbi, wallet);
  const posRef = (await posC.poseidon([1, 2])).toString();
  ok(posRef === poseidon2(1n, 2n).toString(), "on-chain Poseidon-v1 parity == SDK poseidon2(1,2)");
  console.log(`   pool=${pool.address} token=${token.address} poseidon=${poseidon.address}`);

  ok((await pool.root()).toString() === oracle.getRoot().toString(),
    "empty-tree root: contract == ImtTree oracle");

  const poolBal0 = await token.balanceOf(pool.address);

  const matchRoot = async (label: string): Promise<void> => {
    const cr = (await pool.root()).toString();
    ok(cr === oracle.getRoot().toString(), `${label}: contract.root == ImtTree oracle root`);
    ok((await pool.nextLeafIndex()).toString() === String(oracle.getNextLeafIndex()),
      `${label}: contract.nextLeafIndex == oracle (${oracle.getNextLeafIndex()})`);
  };

  // ============================ DEPOSIT ===================================
  step("DEPOSIT (0-in/2-out): employer deposits V -> note(V) + note(0)");
  const dNote0 = commitment(V, sD0, EMPLOYER.publicKey); // the value-V note (spent by disburse)
  const dNote1 = commitment(0n, sD1, EMPLOYER.publicKey); // a value-0 note
  {
    const input = {
      outputCommitments: [dNote0, dNote1],
      outputValues: [V, 0n],
      outputSalts: [sD0, sD1],
      // deposit has no per-recipient ciphertext (single authority envelope over all
      // outputs), so dup owner pubkeys are fine (no two-time pad).
      outputOwnerPublicKeys: [EMPLOYER.publicKey, EMPLOYER.publicKey],
      // §6b v2 auditor envelope — fresh ephemeral key + nonce for THIS tx.
      ecdhPrivateKey: ECDH_DEPOSIT,
      encryptionNonce: NONCE_DEPOSIT,
      authorityPublicKey: AUTHORITY.publicKey,
    };
    const { a, b, c, pub } = await prove("deposit", input);
    ok(BigInt(pub[0]) === V, `deposit out (pub[0]) == V (${V})`);
    oracle.appendLeaf(dNote0);
    oracle.appendLeaf(dNote1);
    await (await pool.deposit(a, b, c, pub)).wait();
    await matchRoot("after deposit(2 leaves)");
    const pulled = (await token.balanceOf(pool.address)).sub(poolBal0);
    ok(pulled.toString() === V.toString(), `deposit pulled V=${V} ERC20 into the pool`);
  }
  const nfDepositV = nullifier(V, sD0, EMPLOYER.formattedPrivateKey);

  // ============================ DISBURSE ==================================
  step("DISBURSE (1-in/16-out): employer spends note(V) -> 16 recipient notes");
  const outCommits = amounts.map((v, i) => commitment(v, sR(i), RCPTS[i].publicKey));
  const rcptPubs = RCPTS.map((r) => r.publicKey);
  assertDistinctOwnerPubkeys(rcptPubs); // §4 two-time-pad guard (shared ephemeral key)
  const subtreeRoot = oracle.computeSubtreeRoot(outCommits);
  let disbEcdhPub: [bigint, bigint] = [0n, 0n];
  let disbNonce = 0n;
  let disbCtFlat: bigint[] = [];
  {
    // membership of the deposit note (leaf 0) against the LIVE post-deposit root
    const { siblings } = oracle.merklePath(0);
    const membershipRoot = oracle.getRoot();
    const input = {
      nullifiers: [nfDepositV],
      inputCommitments: [dNote0],
      inputValues: [V],
      inputSalts: [sD0],
      inputOwnerPrivateKey: EMPLOYER.formattedPrivateKey,
      ecdhPrivateKey: ECDH_DISBURSE,
      root: membershipRoot,
      pathElements: [siblings],
      leafIndices: [0n],
      enabled: [1n],
      outputCommitments: outCommits,
      outputValues: amounts,
      outputSalts: amounts.map((_, i) => sR(i)),
      outputOwnerPublicKeys: rcptPubs,
      encryptionNonce: NONCE_DISBURSE,
      authorityPublicKey: AUTHORITY.publicKey,
    };
    const { a, b, c, pub } = await prove("disburse", input);
    // pub layout (decl order): [0,1]=ecdhPub [2]=disclosureHash [3]=subtreeRoot [4]=nf [5]=root [7]=nonce
    ok(BigInt(pub[3]) === subtreeRoot, "disburse subtreeRoot (pub[3]) == oracle.computeSubtreeRoot");
    ok(BigInt(pub[4]) === nfDepositV, "disburse nullifier (pub[4]) == nullifier(deposit note)");

    // reproduce the ciphertext the circuit committed to, and PROVE it via disclosureHash
    const rcptCts = amounts.map((v, i) => {
      const ss = ecdhSharedSecret(ECDH_DISBURSE, RCPTS[i].publicKey);
      return poseidonEncrypt([v, sR(i)], ss, NONCE_DISBURSE); // 4 elements each
    });
    const ctFlat = rcptCts.flat();
    // authority (non-repudiation) envelope, laid out by the owning codec
    const authPlain = buildAuthorityPlaintext("disburse", {
      inputs: [{ owner: EMPLOYER.publicKey, value: V, salt: sD0 }],
      outputs: amounts.map((v, i) => ({ owner: RCPTS[i].publicKey, value: v, salt: sR(i) })),
    });
    const authSs = ecdhSharedSecret(ECDH_DISBURSE, AUTHORITY.publicKey);
    const authCt = poseidonEncrypt(authPlain, authSs, NONCE_DISBURSE);
    ok(disclosureChain([...ctFlat, ...authCt]) === BigInt(pub[2]),
      "recomputed disclosureHash == proof pub[2] (published ciphertext is the circuit's)");

    oracle.attachSubtree(subtreeRoot, outCommits); // pad 2->16 (dead 2..15) + attach 16..31
    // §6b v2: the ONLY disburse path publishes the FULL ciphertext (receiver ++
    // authority) — the contract enforces receiverCiphertexts.length == 4*B + authLen.
    const rcpt = await (await pool.disburseWithCiphertexts(a, b, c, pub, [...ctFlat, ...authCt].map(dec))).wait();
    await matchRoot("after disburse(pad+attach 16)");
    ok(await pool.nullifierUsed(dec(nfDepositV)), "disburse marked the deposit-note nullifier");

    // pull ecdhPublicKey + nonce + ciphertext straight off the ON-CHAIN events
    let sawCt = false, sawDisb = false;
    for (const log of rcpt.logs) {
      let ev: any;
      try { ev = pool.interface.parseLog(log); } catch { continue; }
      if (ev.name === "DisburseCiphertexts") { disbCtFlat = ev.args.receiverCiphertexts.map((x: any) => x.toBigInt()); sawCt = true; }
      if (ev.name === "Disbursed") { disbEcdhPub = [ev.args.ecdhPublicKey[0].toBigInt(), ev.args.ecdhPublicKey[1].toBigInt()]; disbNonce = ev.args.encryptionNonce.toBigInt(); sawDisb = true; }
    }
    ok(sawCt && sawDisb, "disburse emitted DisburseCiphertexts + Disbursed events");
    ok(disbCtFlat.length === B * 4 + authCt.length,
      `event carries ${B}*4 receiver + ${authCt.length} authority ciphertext elements`);
  }

  // ==================== TRIAL-DECRYPT (recipient #0, genuine) ==============
  step("TRIAL-DECRYPT: recipient #0 recovers its note from the on-chain event ONLY");
  const R0 = RCPTS[0];
  let recoveredValue0: bigint;
  let recoveredSalt0: bigint;
  {
    // recipient uses ONLY: its bjj private key + (ecdhPublicKey, nonce, ct) from chain.
    const ct0 = disbCtFlat.slice(0, 4);
    const shared = ecdhSharedSecret(R0.formattedPrivateKey, disbEcdhPub); // ECDH(myPriv, ephemeralPub)
    const [value0, salt0] = poseidonDecrypt(ct0, shared, disbNonce, 2);
    recoveredValue0 = value0; recoveredSalt0 = salt0;
    // rebuild the commitment from the RECOVERED (value,salt) + own pubkey
    const rebuilt = poseidonN([value0, salt0, R0.publicKey[0], R0.publicKey[1]]);
    ok(rebuilt === outCommits[0], "recovered commitment == batch leaf value (from ciphertext, not memory)");
    // confirm it is the leaf at the expected batch index (16) and folds to the live root
    const idx0 = B; // batch block starts at leaf 16 (after 2 real + 14 dead pads)
    ok(oracle.leaves[idx0] === rebuilt, `rebuilt commitment sits at expected tree index ${idx0}`);
    const { siblings } = oracle.merklePath(idx0);
    ok(foldToRoot(rebuilt, siblings, idx0).toString() === (await pool.root()).toString(),
      "recovered note's merkle path folds to the LIVE contract root");
    ok(value0 === amounts[0], `recovered value (${value0}) == recipient #0 disbursed amount`);
  }

  // ============================ TRANSFER ==================================
  step("TRANSFER (2-in/2-out): recipient #0 spends batch note + PADDED input(enabled=0)");
  const nfBatch0 = nullifier(recoveredValue0, recoveredSalt0, R0.formattedPrivateKey);
  const payVal = 60n, chgVal = recoveredValue0 - payVal; // payment + change == value_0
  const payCommit = commitment(payVal, sPay, PAYEE.publicKey);
  const chgCommit = commitment(chgVal, sChg, R0.publicKey);
  const padCommitT = commitment(0n, sPadT, R0.publicKey); // padded input note (value 0)
  {
    ok(chgVal > 0n, `transfer split: payment ${payVal} + change ${chgVal} == value_0 ${recoveredValue0}`);
    assertDistinctOwnerPubkeys([PAYEE.publicKey, R0.publicKey]);
    const idx0 = B;
    const { siblings } = oracle.merklePath(idx0);
    const zeros: bigint[] = new Array(H).fill(0n);
    const input = {
      nullifiers: [nfBatch0, 0n], // input[1] padded => nullifier 0
      inputCommitments: [outCommits[0], padCommitT],
      inputValues: [recoveredValue0, 0n],
      inputSalts: [recoveredSalt0, sPadT],
      inputOwnerPrivateKey: R0.formattedPrivateKey,
      ecdhPrivateKey: ECDH_TRANSFER,
      root: oracle.getRoot(),
      pathElements: [siblings, zeros],
      leafIndices: [BigInt(idx0), 0n],
      enabled: [1n, 0n], // input[1] disabled: exercises the value-belt disabled path
      outputCommitments: [payCommit, chgCommit],
      outputValues: [payVal, chgVal],
      outputSalts: [sPay, sChg],
      outputOwnerPublicKeys: [PAYEE.publicKey, R0.publicKey],
      encryptionNonce: NONCE_TRANSFER,
      authorityPublicKey: AUTHORITY.publicKey,
    };
    const { a, b, c, pub } = await prove("transfer", input);
    oracle.appendLeaf(payCommit); // leaf 32
    oracle.appendLeaf(chgCommit); // leaf 33
    await (await pool.transfer(a, b, c, pub)).wait();
    await matchRoot("after transfer(2 outputs)");
    ok(await pool.nullifierUsed(dec(nfBatch0)), "transfer marked the batch-note nullifier");
    ok(!(await pool.nullifierUsed(0)), "zero (padded) nullifier never marked");

    // replay must revert on nullifier reuse
    let reverted = false;
    try { await (await pool.transfer(a, b, c, pub)).wait(); } catch { reverted = true; }
    ok(reverted, "replaying the transfer proof reverts (nullifier already used)");
  }

  // ============================ WITHDRAW ==================================
  step("WITHDRAW (2-in/1-out): recipient #0 withdraws the change note -> ERC20 out");
  const nfChange = nullifier(chgVal, sChg, R0.formattedPrivateKey);
  const resCommit = commitment(0n, sRes, R0.publicKey); // residual note (value 0)
  const padCommitW = commitment(0n, sPadW, R0.publicKey);
  let withdrawnAmount: bigint;
  {
    const idxChg = 33;
    const { siblings } = oracle.merklePath(idxChg);
    const zeros: bigint[] = new Array(H).fill(0n);
    const input = {
      nullifiers: [nfChange, 0n],
      inputCommitments: [chgCommit, padCommitW],
      inputValues: [chgVal, 0n],
      inputSalts: [sChg, sPadW],
      inputOwnerPrivateKey: R0.formattedPrivateKey,
      root: oracle.getRoot(),
      pathElements: [siblings, zeros],
      leafIndices: [BigInt(idxChg), 0n],
      enabled: [1n, 0n],
      outputCommitments: [resCommit],
      outputValues: [0n], // withdraw the FULL change value
      outputSalts: [sRes],
      outputOwnerPublicKeys: [R0.publicKey],
      // §6b v2 auditor envelope — fresh ephemeral key + nonce for THIS tx.
      ecdhPrivateKey: ECDH_WITHDRAW,
      encryptionNonce: NONCE_WITHDRAW,
      authorityPublicKey: AUTHORITY.publicKey,
    };
    const { a, b, c, pub } = await prove("withdraw", input);
    withdrawnAmount = BigInt(pub[0]);
    ok(withdrawnAmount === chgVal, `withdraw out (pub[0]) == change value ${chgVal}`);
    oracle.appendLeaf(resCommit); // leaf 34
    const balBefore = await token.balanceOf(employerAddr);
    await (await pool.withdraw(a, b, c, pub)).wait();
    await matchRoot("after withdraw(1 change output)");
    const got = (await token.balanceOf(employerAddr)).sub(balBefore);
    ok(got.toString() === chgVal.toString(), `withdraw pushed ${chgVal} ERC20 out of the pool`);
    ok(await pool.nullifierUsed(dec(nfChange)), "withdraw marked the change-note nullifier");
  }

  // ===================== VALUE CONSERVATION (end to end) ==================
  step("VALUE CONSERVATION: deposited == withdrawn + still-shielded; all ciphertexts spendable");
  {
    // every note the cycle created, with its nullifier; shielded = unspent (per chain)
    const notes = [
      { v: V, nf: nfDepositV },                                  // deposit note(V) - spent (disburse)
      { v: 0n, nf: nullifier(0n, sD1, EMPLOYER.formattedPrivateKey) }, // deposit note(0) - unspent
      ...amounts.map((v, i) => ({ v, nf: nullifier(v, sR(i), RCPTS[i].formattedPrivateKey) })), // batch
      { v: payVal, nf: nullifier(payVal, sPay, PAYEE.formattedPrivateKey) },       // payment - unspent
      { v: chgVal, nf: nfChange },                               // change - spent (withdraw)
      { v: 0n, nf: nullifier(0n, sRes, R0.formattedPrivateKey) }, // residual - unspent
    ];
    let shielded = 0n;
    for (const n of notes) {
      const spent = await pool.nullifierUsed(dec(n.nf)); // unspent-ness read from the CHAIN
      if (!spent) shielded += n.v;
    }
    console.log(`   deposited V=${V}  withdrawn=${withdrawnAmount}  shielded(unspent)=${shielded}`);
    ok(V === withdrawnAmount + shielded, `V (${V}) == withdrawn (${withdrawnAmount}) + shielded (${shielded})`);

    // every emitted disburse ciphertext trial-decrypts to a note that is a real leaf
    const liveRoot = (await pool.root()).toString();
    let allDecrypt = true;
    for (let i = 0; i < B; i++) {
      const ct = disbCtFlat.slice(i * 4, i * 4 + 4);
      const ss = ecdhSharedSecret(RCPTS[i].formattedPrivateKey, disbEcdhPub);
      const [v, s] = poseidonDecrypt(ct, ss, disbNonce, 2);
      const c = poseidonN([v, s, RCPTS[i].publicKey[0], RCPTS[i].publicKey[1]]);
      const { siblings } = oracle.merklePath(B + i);
      if (c !== outCommits[i] || foldToRoot(c, siblings, B + i).toString() !== liveRoot || v !== amounts[i]) {
        allDecrypt = false;
      }
    }
    ok(allDecrypt, `all ${B} disburse ciphertexts decrypt to notes that are real tree leaves`);

    console.log(`\n   FINAL ROOT = ${liveRoot}`);
    console.log(`   CONSERVED  = V(${V}) == withdrawn(${withdrawnAmount}) + shielded(${shielded})`);
  }

  console.log(`\n${failures === 0 ? "E2E PASS — full cross-circuit spend cycle verified on live anvil" : `E2E FAIL — ${failures} assertion(s) failed`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nE2E ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
