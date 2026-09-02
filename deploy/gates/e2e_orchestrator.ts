// bongtu M0 Unit U4 — cross-circuit spend cycle e2e on a live anvil.
//
// THE CAPSTONE (M0 DoD, .dev/milestone-m0.md Done#4 / spec §5, §10b): drive a REAL EVM
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
//   SELF-SEND 2-in/2-out : the payee transfers its payment note TO ITSELF —
//                          both outputs one owner; each on-chain receiver ct_i
//                          decrypts with nonce + i (§11-8 v1.1, U-X3)
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

import { ImtTree, foldToRoot } from "@bongtu/core/imt";
import { poseidon2, poseidonN } from "@bongtu/core/poseidon";
import { buildAuthorityPlaintext, disclosureChain } from "@bongtu/core/envelope";
import {
  commitment,
  nullifier,
  poseidonEncrypt,
  poseidonDecrypt,
  ecdhSharedSecret,
  assertDistinctOwnerPubkeys,
} from "@bongtu/core/note";
import { hybridEnvelopeKey, kemBindingOf } from "@bongtu/core/kem";

import { parseAbi, parseEventLogs } from "viem";

// The deploy-and-drive skeleton (anvil connection, forge-artifact deploys, the
// UUPS pool proxy, the CPU prove() wrapper, shared actor/salt/amount fixtures)
// lives in the harness shared with apps/indexer/test/scenario.ts.
import {
  H, GATE_B as B, connectAnvil, deployStack, prove as harnessProve,
  ok, step, failureCount,
  EMPLOYER, AUTHORITY, PAYEE, RCPTS, kemDraw, kemCtHex,
  sD0, sD1, sR, sPay, sChg, sPadT, sPadW, sRes,
  amounts, V,
} from "../live/lib/e2e_harness.js";
import { proofArgs } from "../live/lib/viem_client.js";
import { runPortalLeg } from "./portal_leg.js";

// ok() / step() and the failure count are the toolbox's (deploy/live/lib/proof_toolbox.ts),
// shared with the live driver (deploy/live/payroll_e2e.ts).
//
// verbose: the human-watched DoD gate keeps its per-circuit timing log (the
// scenario sibling runs the same harness prove() silent).
const prove = (name: string, input: unknown) => harnessProve(name, input, { verbose: true });

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  const rig = connectAnvil();
  const employerAddr = rig.address;

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

  // fresh ML-KEM encapsulation PER TRANSACTION (design doc §6: ct reuse
  // collapses the PQ compartment); labels are disjoint from the scenario
  // sibling's, like the ECDH scalars above.
  const KEM_DEPOSIT = kemDraw("m0/deposit");
  const KEM_DISBURSE = kemDraw("m0/disburse");
  const KEM_TRANSFER = kemDraw("m0/transfer");
  const KEM_WITHDRAW = kemDraw("m0/withdraw");

  const oracle = new ImtTree(H, B);

  // ============================ DEPLOY ====================================
  step("DEPLOY (anvil): Poseidon-v1, 4 verifiers, BongtuPool(B=16), mock kKRW");
  // deployStack also funds + approves the employer (deposit pulls from
  // msg.sender via SafeERC20).
  const { poseidon, token, pool } = await deployStack(rig, {
    batchSize: B,
    authorityPublicKey: AUTHORITY.publicKey,
    mintAmount: V * 1000n,
  });
  // sanity: on-chain Poseidon([1,2]) == the SDK / circuit parity constant
  const posC = rig.at(poseidon.address, parseAbi(["function poseidon(uint256[2]) pure returns (uint256)"]));
  const posRef = (await posC.read("poseidon", [[1n, 2n]])).toString();
  ok(posRef === poseidon2(1n, 2n).toString(), "on-chain Poseidon-v1 parity == SDK poseidon2(1,2)");
  console.log(`   pool=${pool.address} token=${token.address} poseidon=${poseidon.address}`);

  ok((await pool.read("root")).toString() === oracle.getRoot().toString(),
    "empty-tree root: contract == ImtTree oracle");

  const poolBal0: bigint = await token.read("balanceOf", [pool.address]);

  const matchRoot = async (label: string): Promise<void> => {
    const cr = (await pool.read("root")).toString();
    ok(cr === oracle.getRoot().toString(), `${label}: contract.root == ImtTree oracle root`);
    ok((await pool.read("nextLeafIndex")).toString() === String(oracle.getNextLeafIndex()),
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
      kemSs: KEM_DEPOSIT.kemSs,
      encryptionNonce: NONCE_DEPOSIT,
      authorityPublicKey: AUTHORITY.publicKey,
    };
    const { a, b, c, pub } = await prove("deposit", input);
    ok(BigInt(pub[0]) === V, `deposit out (pub[0]) == V (${V})`);
    ok(BigInt(pub[13]) === kemBindingOf(KEM_DEPOSIT.kemSs),
      "deposit kemBinding (pub[13]) == Poseidon(3)(TAG_BIND, kemSs) of the tx's encapsulation");
    oracle.appendLeaf(dNote0);
    oracle.appendLeaf(dNote1);
    await pool.write("deposit", [...proofArgs({ a, b, c, pub }), kemCtHex(KEM_DEPOSIT.kemCiphertext)]);
    await matchRoot("after deposit(2 leaves)");
    const pulled = (await token.read("balanceOf", [pool.address])) - poolBal0;
    ok(pulled.toString() === V.toString(), `deposit pulled V=${V} ERC20 into the pool`);
  }
  const nfDepositV = nullifier(V, sD0, EMPLOYER.formattedPrivateKey);

  // ============================ DISBURSE ==================================
  step("DISBURSE (1-in/16-out): employer spends note(V) -> 16 recipient notes");
  const outCommits = amounts.map((v, i) => commitment(v, sR(i), RCPTS[i].publicKey));
  const rcptPubs = RCPTS.map((r) => r.publicKey);
  assertDistinctOwnerPubkeys(rcptPubs); // §4 two-time-pad guard (shared ephemeral key)
  const subtreeRoot = oracle.computeSubtreeRoot(outCommits);
  const { disbEcdhPub, disbNonce, disbCtFlat } = await (async (): Promise<{
    disbEcdhPub: [bigint, bigint];
    disbNonce: bigint;
    disbCtFlat: bigint[];
  }> => {
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
      kemSs: KEM_DISBURSE.kemSs,
      encryptionNonce: NONCE_DISBURSE,
      authorityPublicKey: AUTHORITY.publicKey,
    };
    const { a, b, c, pub } = await prove("disburse", input);
    // pub layout (decl order): [0,1]=ecdhPub [2]=disclosureHash [3]=subtreeRoot
    // [4]=kemBinding [5]=nf [6]=root [8]=nonce
    ok(BigInt(pub[3]) === subtreeRoot, "disburse subtreeRoot (pub[3]) == oracle.computeSubtreeRoot");
    ok(BigInt(pub[5]) === nfDepositV, "disburse nullifier (pub[5]) == nullifier(deposit note)");
    ok(BigInt(pub[4]) === kemBindingOf(KEM_DISBURSE.kemSs),
      "disburse kemBinding (pub[4]) == Poseidon(3)(TAG_BIND, kemSs) of the tx's encapsulation");

    // reproduce the ciphertext the circuit committed to, and PROVE it via disclosureHash
    const rcptCts = amounts.map((v, i) => {
      const ss = ecdhSharedSecret(ECDH_DISBURSE, RCPTS[i].publicKey);
      return poseidonEncrypt([v, sR(i)], ss, NONCE_DISBURSE); // 4 elements each
    });
    const ctFlat = rcptCts.flat();
    // authority (non-repudiation) envelope, laid out by the owning codec.
    // Post-PQ the envelope key is the tagged HYBRID fold (ECDH point + ML-KEM
    // limbs, design doc §2) — a raw-ECDH encrypt would break disclosureHash.
    const authPlain = buildAuthorityPlaintext("disburse", {
      inputs: [{ owner: EMPLOYER.publicKey, value: V, salt: sD0 }],
      outputs: amounts.map((v, i) => ({ owner: RCPTS[i].publicKey, value: v, salt: sR(i) })),
    });
    const authKey = hybridEnvelopeKey(
      ecdhSharedSecret(ECDH_DISBURSE, AUTHORITY.publicKey), KEM_DISBURSE.kemSs);
    const authCt = poseidonEncrypt(authPlain, authKey, NONCE_DISBURSE);
    ok(disclosureChain([...ctFlat, ...authCt]) === BigInt(pub[2]),
      "recomputed disclosureHash (hybrid envelope key) == proof pub[2] (published ciphertext is the circuit's)");

    oracle.attachSubtree(subtreeRoot, outCommits); // pad 2->16 (dead 2..15) + attach 16..31
    // §6b v2: the ONLY disburse path publishes the FULL ciphertext (receiver ++
    // authority) — the contract enforces receiverCiphertexts.length == 4*B + authLen.
    const rcpt = await pool.write("disburseWithCiphertexts", [
      ...proofArgs({ a, b, c, pub }), [...ctFlat, ...authCt], kemCtHex(KEM_DISBURSE.kemCiphertext),
    ]);
    await matchRoot("after disburse(pad+attach 16)");
    ok(await pool.read("nullifierUsed", [nfDepositV]), "disburse marked the deposit-note nullifier");

    // pull ecdhPublicKey + nonce + ciphertext straight off the ON-CHAIN events
    // (viem's parseEventLogs decodes uint256 to bigint directly — no .toBigInt()).
    const ctEvs = parseEventLogs({ abi: pool.abi, logs: rcpt.logs, eventName: "DisburseCiphertexts" });
    const disbEvs = parseEventLogs({ abi: pool.abi, logs: rcpt.logs, eventName: "Disbursed" });
    const sawCt = ctEvs.length > 0, sawDisb = disbEvs.length > 0;
    const ctFlatEv: bigint[] = sawCt ? [...((ctEvs[0].args as any).receiverCiphertexts as bigint[])] : [];
    const da = sawDisb ? (disbEvs[0].args as any) : null;
    const ecdhPubEv: [bigint, bigint] = sawDisb ? [da.ecdhPublicKey[0], da.ecdhPublicKey[1]] : [0n, 0n];
    const nonceEv: bigint = sawDisb ? da.encryptionNonce : 0n;
    ok(sawCt && sawDisb, "disburse emitted DisburseCiphertexts + Disbursed events");
    ok(ctFlatEv.length === B * 4 + authCt.length,
      `event carries ${B}*4 receiver + ${authCt.length} authority ciphertext elements`);
    return { disbEcdhPub: ecdhPubEv, disbNonce: nonceEv, disbCtFlat: ctFlatEv };
  })();

  // ==================== TRIAL-DECRYPT (recipient #0, genuine) ==============
  step("TRIAL-DECRYPT: recipient #0 recovers its note from the on-chain event ONLY");
  const R0 = RCPTS[0];
  const { recoveredValue0, recoveredSalt0 } = await (async (): Promise<{
    recoveredValue0: bigint;
    recoveredSalt0: bigint;
  }> => {
    // recipient uses ONLY: its bjj private key + (ecdhPublicKey, nonce, ct) from chain.
    const ct0 = disbCtFlat.slice(0, 4);
    const shared = ecdhSharedSecret(R0.formattedPrivateKey, disbEcdhPub); // ECDH(myPriv, ephemeralPub)
    const [value0, salt0] = poseidonDecrypt(ct0, shared, disbNonce, 2);
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
    return { recoveredValue0: value0, recoveredSalt0: salt0 };
  })();

  // ============================ TRANSFER ==================================
  step("TRANSFER (2-in/2-out): recipient #0 spends batch note + PADDED input(enabled=0)");
  const nfBatch0 = nullifier(recoveredValue0, recoveredSalt0, R0.formattedPrivateKey);
  const payVal = 60n, chgVal = recoveredValue0 - payVal; // payment + change == value_0
  const payCommit = commitment(payVal, sPay, PAYEE.publicKey);
  const chgCommit = commitment(chgVal, sChg, R0.publicKey);
  const padCommitT = commitment(0n, sPadT, R0.publicKey); // padded input note (value 0)
  {
    ok(chgVal > 0n, `transfer split: payment ${payVal} + change ${chgVal} == value_0 ${recoveredValue0}`);
    // no distinct-owner guard: transfer's per-output nonce (§11-8 v1.1) made
    // duplicate owners safe — the SELF-SEND leg below exercises exactly that
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
      kemSs: KEM_TRANSFER.kemSs,
      encryptionNonce: NONCE_TRANSFER,
      authorityPublicKey: AUTHORITY.publicKey,
    };
    const { a, b, c, pub } = await prove("transfer", input);
    oracle.appendLeaf(payCommit); // leaf 32
    oracle.appendLeaf(chgCommit); // leaf 33
    await pool.write("transfer", [...proofArgs({ a, b, c, pub }), kemCtHex(KEM_TRANSFER.kemCiphertext)]);
    await matchRoot("after transfer(2 outputs)");
    ok(await pool.read("nullifierUsed", [nfBatch0]), "transfer marked the batch-note nullifier");
    ok(!(await pool.read("nullifierUsed", [0n])), "zero (padded) nullifier never marked");

    // replay must revert on nullifier reuse — viem estimates gas on the (un-pinned
    // anvil) write, so a reverting call throws before it is ever sent.
    const reverted = await (async (): Promise<boolean> => {
      try { await pool.write("transfer", [...proofArgs({ a, b, c, pub }), kemCtHex(KEM_TRANSFER.kemCiphertext)]); return false; } catch { return true; }
    })();
    ok(reverted, "replaying the transfer proof reverts (nullifier already used)");
  }

  // ============================ WITHDRAW ==================================
  step("WITHDRAW (2-in/1-out): recipient #0 withdraws the change note -> ERC20 out");
  const nfChange = nullifier(chgVal, sChg, R0.formattedPrivateKey);
  const resCommit = commitment(0n, sRes, R0.publicKey); // residual note (value 0)
  const padCommitW = commitment(0n, sPadW, R0.publicKey);
  const withdrawnAmount = await (async (): Promise<bigint> => {
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
      kemSs: KEM_WITHDRAW.kemSs,
      encryptionNonce: NONCE_WITHDRAW,
      authorityPublicKey: AUTHORITY.publicKey,
      recipient: BigInt(employerAddr), // proof-bound payout: same target the old msg.sender path paid
    };
    const { a, b, c, pub } = await prove("withdraw", input);
    const withdrawnAmount = BigInt(pub[0]);
    ok(withdrawnAmount === chgVal, `withdraw out (pub[0]) == change value ${chgVal}`);
    oracle.appendLeaf(resCommit); // leaf 34
    const balBefore: bigint = await token.read("balanceOf", [employerAddr]);
    await pool.write("withdraw", [...proofArgs({ a, b, c, pub }), kemCtHex(KEM_WITHDRAW.kemCiphertext), "0x" + "00".repeat(32), 0]);
    await matchRoot("after withdraw(1 change output)");
    const got = (await token.read("balanceOf", [employerAddr])) - balBefore;
    ok(got.toString() === chgVal.toString(), `withdraw pushed ${chgVal} ERC20 out of the pool`);
    ok(await pool.read("nullifierUsed", [nfChange]), "withdraw marked the change-note nullifier");
    return withdrawnAmount;
  })();

  // ================= TRANSFER TO SELF (U-X3, §11-8 v1.1) ==================
  step("SELF-SEND (2-in/2-out): PAYEE pays PAYEE — per-output receiver nonce");
  // fresh per-tx crypto, scalars/labels disjoint from every leg above
  const ECDH_SELF = 850000000000000000011n;
  const NONCE_SELF = 555555555555n;
  const KEM_SELF = kemDraw("m0/transfer-self");
  const sSelfPay = 987000001n;
  const sSelfChg = 987000002n;
  const sSelfPad = 987000003n;
  const nfPayment = nullifier(payVal, sPay, PAYEE.formattedPrivateKey);
  const selfPayVal = 25n;
  const selfChgVal = payVal - selfPayVal;
  const selfPayCommit = commitment(selfPayVal, sSelfPay, PAYEE.publicKey);
  const selfChgCommit = commitment(selfChgVal, sSelfChg, PAYEE.publicKey);
  {
    ok(selfChgVal > 0n, `self-send split: ${selfPayVal} + ${selfChgVal} == payment note ${payVal}`);
    // BOTH outputs owned by PAYEE — the witness the shared-nonce circuit banned
    // as a two-time pad; per-output nonces (ct_i under nonce+i) make it safe.
    const idxPay = 32; // the transfer leg's payment output leaf
    const { siblings } = oracle.merklePath(idxPay);
    const zeros: bigint[] = new Array(H).fill(0n);
    const input = {
      nullifiers: [nfPayment, 0n],
      inputCommitments: [payCommit, commitment(0n, sSelfPad, PAYEE.publicKey)],
      inputValues: [payVal, 0n],
      inputSalts: [sPay, sSelfPad],
      inputOwnerPrivateKey: PAYEE.formattedPrivateKey,
      ecdhPrivateKey: ECDH_SELF,
      root: oracle.getRoot(),
      pathElements: [siblings, zeros],
      leafIndices: [BigInt(idxPay), 0n],
      enabled: [1n, 0n],
      outputCommitments: [selfPayCommit, selfChgCommit],
      outputValues: [selfPayVal, selfChgVal],
      outputSalts: [sSelfPay, sSelfChg],
      outputOwnerPublicKeys: [PAYEE.publicKey, PAYEE.publicKey],
      kemSs: KEM_SELF.kemSs,
      encryptionNonce: NONCE_SELF,
      authorityPublicKey: AUTHORITY.publicKey,
    };
    const { a, b, c, pub } = await prove("transfer", input);
    oracle.appendLeaf(selfPayCommit); // leaf 35
    oracle.appendLeaf(selfChgCommit); // leaf 36
    const rcpt = await pool.write("transfer", [...proofArgs({ a, b, c, pub }), kemCtHex(KEM_SELF.kemCiphertext)]);
    await matchRoot("after self-send(2 outputs, one owner)");
    ok(await pool.read("nullifierUsed", [nfPayment]), "self-send marked the payment-note nullifier");

    // recover BOTH notes from the ON-CHAIN Transferred event only: ct_i + nonce+i
    // (viem decodes the uint256[] event args to bigint[] directly).
    const tevs = parseEventLogs({ abi: pool.abi, logs: rcpt.logs, eventName: "Transferred" });
    ok(tevs.length > 0, "self-send emitted Transferred");
    const tev = tevs[0].args as any;
    const ephPub: [bigint, bigint] = [tev.ecdhPublicKey[0], tev.ecdhPublicKey[1]];
    const evNonce: bigint = tev.encryptionNonce;
    const evCts: bigint[][] = [
      [...(tev.encryptedValuesForReceiver0 as bigint[])],
      [...(tev.encryptedValuesForReceiver1 as bigint[])],
    ];
    const sharedSelf = ecdhSharedSecret(PAYEE.formattedPrivateKey, ephPub);
    const wantVals = [selfPayVal, selfChgVal];
    const wantCommits = [selfPayCommit, selfChgCommit];
    for (const i of Array(2).keys()) {
      const [v, s] = poseidonDecrypt(evCts[i], sharedSelf, evNonce + BigInt(i), 2);
      ok(v === wantVals[i], `self-send ct_${i} (nonce+${i}) decrypts to value ${wantVals[i]}`);
      ok(
        poseidonN([v, s, PAYEE.publicKey[0], PAYEE.publicKey[1]]) === wantCommits[i],
        `self-send ct_${i} rebuilds output commitment ${i} (both notes recovered by ONE owner)`,
      );
    }
    // the pre-v1.1 shared nonce must NOT open ct_1 (distinct keystreams)
    const [vBad, sBad] = poseidonDecrypt(evCts[1], sharedSelf, evNonce, 2);
    ok(
      poseidonN([vBad, sBad, PAYEE.publicKey[0], PAYEE.publicKey[1]]) !== selfChgCommit,
      "shared (un-offset) nonce yields garbage on ct_1 — keystreams are distinct",
    );
  }

  // ===================== VALUE CONSERVATION (end to end) ==================
  step("VALUE CONSERVATION: deposited == withdrawn + still-shielded; all ciphertexts spendable");
  {
    // every note the cycle created, with its nullifier; shielded = unspent (per chain)
    const notes = [
      { v: V, nf: nfDepositV },                                  // deposit note(V) - spent (disburse)
      { v: 0n, nf: nullifier(0n, sD1, EMPLOYER.formattedPrivateKey) }, // deposit note(0) - unspent
      ...amounts.map((v, i) => ({ v, nf: nullifier(v, sR(i), RCPTS[i].formattedPrivateKey) })), // batch
      { v: payVal, nf: nullifier(payVal, sPay, PAYEE.formattedPrivateKey) },       // payment - spent (self-send)
      { v: chgVal, nf: nfChange },                               // change - spent (withdraw)
      { v: 0n, nf: nullifier(0n, sRes, R0.formattedPrivateKey) }, // residual - unspent
      { v: selfPayVal, nf: nullifier(selfPayVal, sSelfPay, PAYEE.formattedPrivateKey) }, // self-send out0 - unspent
      { v: selfChgVal, nf: nullifier(selfChgVal, sSelfChg, PAYEE.formattedPrivateKey) }, // self-send out1 - unspent
    ];
    const unspentVals: bigint[] = [];
    for (const n of notes) {
      const spent = await pool.read("nullifierUsed", [n.nf]); // unspent-ness read from the CHAIN
      if (!spent) unspentVals.push(n.v);
    }
    const shielded = unspentVals.reduce((a, b) => a + b, 0n);
    console.log(`   deposited V=${V}  withdrawn=${withdrawnAmount}  shielded(unspent)=${shielded}`);
    ok(V === withdrawnAmount + shielded, `V (${V}) == withdrawn (${withdrawnAmount}) + shielded (${shielded})`);

    // every emitted disburse ciphertext trial-decrypts to a note that is a real leaf
    const liveRoot = (await pool.root()).toString();
    const allDecrypt = Array.from({ length: B }, (_, i) => i).reduce<boolean>((acc, i) => {
      const ct = disbCtFlat.slice(i * 4, i * 4 + 4);
      const ss = ecdhSharedSecret(RCPTS[i].formattedPrivateKey, disbEcdhPub);
      const [v, s] = poseidonDecrypt(ct, ss, disbNonce, 2);
      const c = poseidonN([v, s, RCPTS[i].publicKey[0], RCPTS[i].publicKey[1]]);
      const { siblings } = oracle.merklePath(B + i);
      return c !== outCommits[i] || foldToRoot(c, siblings, B + i).toString() !== liveRoot || v !== amounts[i]
        ? false
        : acc;
    }, true);
    ok(allDecrypt, `all ${B} disburse ciphertexts decrypt to notes that are real tree leaves`);

    console.log(`\n   FINAL ROOT = ${liveRoot}`);
    console.log(`   CONSERVED  = V(${V}) == withdrawn(${withdrawnAmount}) + shielded(${shielded})`);
  }

  // ========================== PORTAL DEPOSITS =============================
  // portal_leg throws when E2E_DATABASE_URL is unset, so the gate cannot go
  // green without the portal loop having actually run.
  await runPortalLeg(rig, pool, token);

  const failures = failureCount();
  console.log(`\n${failures === 0 ? "E2E PASS — full cross-circuit spend cycle verified on live anvil" : `E2E FAIL — ${failures} assertion(s) failed`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nE2E ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
