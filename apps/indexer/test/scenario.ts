// Scenario driver for the indexer test (a trimmed sibling of
// deploy/gates/e2e_orchestrator.ts; both share the deploy-and-drive skeleton in
// deploy/live/lib/e2e_harness.ts). Deploys a fresh B=16 pool on a live anvil and
// runs the full cross-circuit cycle the indexer must ingest, then returns the
// secrets the test needs to trial-decrypt + check (recipient keys, amounts,
// salts, subtree root, single-append leaf commitments).
//
// Differences from e2e_orchestrator that matter to the indexer:
//   - the HONEST disburse publishes the FULL ciphertext (receiver ++ authority)
//     so the whole disclosureHash chain recomputes off-chain (→ status pass);
//   - a SECOND disburse (spending the value-0 deposit note) publishes a
//     ciphertext with one RECEIVER element flipped → the indexer must raise a
//     first-class disclosureHash alarm (status "mismatch"); its authority tail
//     is intact, so the arbiter ledger still opens that batch;
//   - a THIRD disburse (spending the value-0 withdraw-residue note) publishes a
//     ciphertext with one AUTHORITY-TAIL element flipped → the disclosureHash
//     alarm (status "mismatch") AND, in arbiter mode, the envelope cross-check
//     alarm (the recovered leaves no longer fold to the on-chain subtreeRoot);
//     the batch stays unopened.
//   - a FINAL deposit submits a consistent-but-junk kemCiphertext (a different
//     encapsulation than the proof's kemSs) → the arbiter's decapsulated
//     binding mismatches the on-chain kemBinding → kem envelope alarm, op
//     withheld (no notes), per pq-envelope-design.md §2/§5.
// (§6b v2 removed the plain disburse() entry point, so a "withheld"
// nothing-published disburse is not producible on-chain.)
//
// Proving is CPU snarkjs against circuits/out (same as e2e_orchestrator); no
// rabbitsnark / GPU. Runs against E2E_RPC (an anvil the harness started).

import { ImtTree } from "@bongtu/core/imt";
import { buildAuthorityPlaintext } from "@bongtu/core/envelope";
import { hybridEnvelopeKey } from "@bongtu/core/kem";
import {
  deriveKeypair, commitment, nullifier,
  poseidonEncrypt, ecdhSharedSecret, assertDistinctOwnerPubkeys,
} from "@bongtu/core/note";

// The deploy-and-drive skeleton (anvil connection, forge-artifact deploys, the
// UUPS pool proxy, the CPU prove() wrapper, shared actor/salt/amount fixtures)
// is the harness shared with deploy/gates/e2e_orchestrator.ts — repo test/ops
// infrastructure, not an npm package export, hence the relative path out of
// apps/indexer.
import {
  RPC, H, GATE_B as B, dec, connectAnvil, deployStack, prove,
  EMPLOYER, AUTHORITY, AUTHORITY_KEM, PAYEE, RCPTS, kemDraw, kemCtHex,
  sD0, sD1, sR, sPay, sChg, sPadT, sPadW, sRes,
  amounts, V,
} from "../../../deploy/live/lib/e2e_harness.js";

/** The disburse authority (non-repudiation) envelope plaintext (SPEC §4),
 *  laid out by the owning codec (@bongtu/core/envelope). */
function authorityPlain(
  inPub: readonly [bigint, bigint], inVal: bigint, inSalt: bigint,
  outPubs: [bigint, bigint][], amounts: bigint[], salts: bigint[],
): bigint[] {
  return buildAuthorityPlaintext("disburse", {
    inputs: [{ owner: [inPub[0], inPub[1]], value: inVal, salt: inSalt }],
    outputs: outPubs.map((p, i) => ({ owner: p, value: amounts[i], salt: salts[i] })),
  });
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
  tamperedStartLeafIndex: number; // receiver-element flip: disclosure alarm only
  tamperedAuthorityStartLeafIndex: number; // authority-tail flip: + arbiter envelope alarm
  kemMismatchTxHash: string; // deposit whose tx ct != the proof's encapsulation: arbiter kem-binding alarm
  singleLeaves: SingleLeaf[]; // real single-append leaves for the /path test
  // ---- arbiter-mode fixtures (SPEC §6b v2) ---------------------------------
  arbiterPrivateKey: string; // decimal — the AUTHORITY keypair's private scalar
  arbiterKemSecretKey: string; // 0x-hex — the fixture ML-KEM decaps key (AUTHORITY_KEM_KEY)
  blockAfterHonestDisburse: number; // block height after disburse#1, BEFORE the transfer
  // Expected /history amounts + counterparty for recipient#0 (decimal strings):
  // the arbiter leg checks received(from employer) / sent / withdraw against these.
  employerPub: [string, string];
  employerPrivateKey: string; // decimal — the employer signs its own /notes auth (never held by the indexer)
  transferPayAmount: string;
  withdrawnAmount: string;
  recipient0Note: ArbiterNote; // recipient #0's disburse-batch note (spent by the transfer)
  recipient0PrivateKey: string; // decimal — TEST-ONLY: recipient #0 signs its own /notes auth
  payeeNote: ArbiterNote; // the payee's transfer output note (created by the transfer)
  payeePrivateKey: string; // decimal — TEST-ONLY: the payee signs its own /notes auth
  transfer10: Transfer10Info; // the V4 arity-10 leg (own owner, so no count above moves)
  spentNullifiers: string[]; // decimal — the real (nonzero) nullifiers this run produces
}

/** The transfer10 leg's secrets: one owner holds every note it touches, which is
 *  what lets the arbiter assertions be exact counts rather than "contains". */
export interface Transfer10Info {
  ownerPub: [string, string];
  ownerPrivateKey: string; // decimal — TEST-ONLY, signs its own /notes auth
  startLeafIndex: number;
  arity: number;
  outCommits: string[]; // decimal
  outValues: string[]; // decimal
  spentLeafIndices: [number, number]; // the deposit notes the op spends
}

export async function runScenario(): Promise<ScenarioResult> {
  const { provider, wallet } = connectAnvil();

  // Per-tx ECDH ephemeral keys + nonces: driver-local, and every (key, nonce)
  // pair is unique across BOTH gate drivers — the §11-8 two-time-pad rule
  // stated literally. The scenario's scalars are deliberately disjoint from
  // e2e_orchestrator's (6/7/8/9-prefixed) so the claim stays greppable-true.
  const ECDH_DEP = 650000000000000000007n;
  const ECDH_D1 = 750000000000000000001n;
  const ECDH_TRANSFER = 850000000000000000003n;
  const ECDH_D2 = 900000000000000000019n;
  const ECDH_W = 950000000000000000021n;
  const ECDH_D3 = 970000000000000000011n;
  const NONCE_DEP = 555555555555n;
  // fresh ML-KEM encapsulation per tx (design doc §6); labels disjoint from the
  // orchestrator sibling's "m0/..." family, like the ECDH scalars above.
  const KEM_DEP = kemDraw("scen/deposit");
  const KEM_D1 = kemDraw("scen/disburse1");
  const KEM_TRANSFER = kemDraw("scen/transfer");
  const KEM_D2 = kemDraw("scen/disburse2");
  const KEM_W = kemDraw("scen/withdraw");
  const KEM_D3 = kemDraw("scen/disburse3");
  const NONCE_D1 = 111111111111n;
  const NONCE_TRANSFER = 222222222222n;
  const NONCE_D2 = 333333333333n;
  const NONCE_W = 666666666666n;
  const NONCE_D3 = 777777777777n;

  // scenario-only salt families for the two TAMPERED disburse batches (the
  // honest legs use the shared harness salts)
  const sR2 = (i: number): bigint => 6100000n + BigInt(i);
  const sR3 = (i: number): bigint => 6200000n + BigInt(i);

  const oracle = new ImtTree(H, B);

  // ---- deploy (harness stack: Poseidon-v1, 4 verifiers, pool proxy, fund) ----
  const { pool } = await deployStack(wallet, {
    batchSize: B,
    authorityPublicKey: AUTHORITY.publicKey,
    mintAmount: V * 1000n,
  });

  // ---- deposit: note(V)@0, note(0)@1 ----
  const dNoteV = commitment(V, sD0, EMPLOYER.publicKey);
  const dNote0 = commitment(0n, sD1, EMPLOYER.publicKey);
  {
    const { a, b, c, pub } = await prove("deposit", {
      outputCommitments: [dNoteV, dNote0], outputValues: [V, 0n],
      outputSalts: [sD0, sD1], outputOwnerPublicKeys: [EMPLOYER.publicKey, EMPLOYER.publicKey],
      ecdhPrivateKey: ECDH_DEP, kemSs: KEM_DEP.kemSs,
      encryptionNonce: NONCE_DEP, authorityPublicKey: AUTHORITY.publicKey,
    });
    oracle.appendLeaf(dNoteV);
    oracle.appendLeaf(dNote0);
    await (await pool.deposit(a, b, c, pub, kemCtHex(KEM_DEP.kemCiphertext))).wait();
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
      outputOwnerPublicKeys: rcptPubs, kemSs: KEM_D1.kemSs,
      encryptionNonce: NONCE_D1, authorityPublicKey: AUTHORITY.publicKey,
    });
    const rcptCts = amounts.map((v, i) =>
      poseidonEncrypt([v, sR(i)], ecdhSharedSecret(ECDH_D1, RCPTS[i].publicKey), NONCE_D1));
    const ctFlat = rcptCts.flat();
    // hybrid envelope key (design doc §2): raw-ECDH would break disclosureHash
    const authCt = poseidonEncrypt(
      authorityPlain(EMPLOYER.publicKey, V, sD0, rcptPubs, amounts, amounts.map((_, i) => sR(i))),
      hybridEnvelopeKey(ecdhSharedSecret(ECDH_D1, AUTHORITY.publicKey), KEM_D1.kemSs), NONCE_D1,
    );
    oracle.attachSubtree(subtreeRoot, outCommits);
    // publish FULL ciphertext (receiver ++ authority) so the whole chain recomputes
    await (await pool.disburseWithCiphertexts(
      a, b, c, pub, [...ctFlat, ...authCt].map(dec), kemCtHex(KEM_D1.kemCiphertext))).wait();
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
    // no distinct-owner guard: transfer's per-output nonce (§11-8 v1.1, U-X3)
    // made duplicate output owners safe; the guard remains disburse-only
    const { siblings } = oracle.merklePath(honestStart);
    const zeros: bigint[] = new Array(H).fill(0n);
    const { a, b, c, pub } = await prove("transfer", {
      nullifiers: [nfBatch0, 0n], inputCommitments: [outCommits[0], padCommitT],
      inputValues: [recoveredValue0, 0n], inputSalts: [recoveredSalt0, sPadT],
      inputOwnerPrivateKey: RCPTS[0].formattedPrivateKey, ecdhPrivateKey: ECDH_TRANSFER,
      root: oracle.getRoot(), pathElements: [siblings, zeros], leafIndices: [BigInt(honestStart), 0n],
      enabled: [1n, 0n], outputCommitments: [payCommit, chgCommit], outputValues: [payVal, chgVal],
      outputSalts: [sPay, sChg], outputOwnerPublicKeys: [PAYEE.publicKey, RCPTS[0].publicKey],
      kemSs: KEM_TRANSFER.kemSs,
      encryptionNonce: NONCE_TRANSFER, authorityPublicKey: AUTHORITY.publicKey,
    });
    oracle.appendLeaf(payCommit);
    oracle.appendLeaf(chgCommit);
    await (await pool.transfer(a, b, c, pub, kemCtHex(KEM_TRANSFER.kemCiphertext))).wait();
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
      ecdhPrivateKey: ECDH_W, kemSs: KEM_W.kemSs,
      encryptionNonce: NONCE_W, authorityPublicKey: AUTHORITY.publicKey,
    });
    oracle.appendLeaf(resCommit);
    await (await pool.withdraw(a, b, c, pub, kemCtHex(KEM_W.kemCiphertext))).wait();
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
      outputOwnerPublicKeys: rcptPubs, kemSs: KEM_D2.kemSs,
      encryptionNonce: NONCE_D2, authorityPublicKey: AUTHORITY.publicKey,
    });
    const rcptCts2 = amounts2.map((v, i) =>
      poseidonEncrypt([v, sR2(i)], ecdhSharedSecret(ECDH_D2, RCPTS[i].publicKey), NONCE_D2));
    const ctFlat2 = rcptCts2.flat();
    const authCt2 = poseidonEncrypt(
      authorityPlain(EMPLOYER.publicKey, 0n, sD1, rcptPubs, amounts2, amounts2.map((_, i) => sR2(i))),
      hybridEnvelopeKey(ecdhSharedSecret(ECDH_D2, AUTHORITY.publicKey), KEM_D2.kemSs), NONCE_D2,
    );
    const full = [...ctFlat2, ...authCt2];
    // Flip a RECEIVER element: disclosureHash must break, but the authority
    // tail stays intact so the arbiter ledger can still open this batch.
    full[0] = BigInt(full[0]) + 1n;
    oracle.attachSubtree(subtreeRoot2, outCommits2);
    await (await pool.disburseWithCiphertexts(
      a, b, c, pub, full.map(dec), kemCtHex(KEM_D2.kemCiphertext))).wait();
  }

  // ---- disburse #3 (AUTHORITY-TAMPERED): residue note(0)@34 -> 16 zero-value
  // recipients; emit receiver ++ authority with one AUTHORITY-TAIL element
  // flipped. poseidonDecrypt reseeds its sponge from the ciphertext itself, so
  // the flip garbles every recovered note from that chunk on — the arbiter's
  // fold of the recovered leaves cannot match the on-chain subtreeRoot, which
  // must surface as the envelope cross-check ALARM (and the batch stays
  // unopened). The disclosureHash chain covers the tail too, so the public
  // "mismatch" alarm fires as well.
  const resLeaf = chgLeaf + 1; // 34
  const nfRes = nullifier(0n, sRes, RCPTS[0].formattedPrivateKey);
  const amounts3 = new Array(B).fill(0n) as bigint[];
  const outCommits3 = amounts3.map((v, i) => commitment(v, sR3(i), RCPTS[i].publicKey));
  const subtreeRoot3 = oracle.computeSubtreeRoot(outCommits3);
  const tamperedAuthorityStart = 64; // nextLeafIndex is 64 after batch #2 (aligned, no pad)
  {
    const { siblings } = oracle.merklePath(resLeaf);
    const { a, b, c, pub } = await prove("disburse", {
      nullifiers: [nfRes], inputCommitments: [resCommit], inputValues: [0n], inputSalts: [sRes],
      inputOwnerPrivateKey: RCPTS[0].formattedPrivateKey, ecdhPrivateKey: ECDH_D3,
      root: oracle.getRoot(), pathElements: [siblings], leafIndices: [BigInt(resLeaf)], enabled: [1n],
      outputCommitments: outCommits3, outputValues: amounts3, outputSalts: amounts3.map((_, i) => sR3(i)),
      outputOwnerPublicKeys: rcptPubs, kemSs: KEM_D3.kemSs,
      encryptionNonce: NONCE_D3, authorityPublicKey: AUTHORITY.publicKey,
    });
    const rcptCts3 = amounts3.map((v, i) =>
      poseidonEncrypt([v, sR3(i)], ecdhSharedSecret(ECDH_D3, RCPTS[i].publicKey), NONCE_D3));
    const ctFlat3 = rcptCts3.flat();
    const authCt3 = poseidonEncrypt(
      authorityPlain(RCPTS[0].publicKey, 0n, sRes, rcptPubs, amounts3, amounts3.map((_, i) => sR3(i))),
      hybridEnvelopeKey(ecdhSharedSecret(ECDH_D3, AUTHORITY.publicKey), KEM_D3.kemSs), NONCE_D3,
    );
    const full3 = [...ctFlat3, ...authCt3];
    full3[ctFlat3.length] = BigInt(full3[ctFlat3.length]) + 1n; // flip the FIRST AUTHORITY element
    oracle.attachSubtree(subtreeRoot3, outCommits3);
    await (await pool.disburseWithCiphertexts(
      a, b, c, pub, full3.map(dec), kemCtHex(KEM_D3.kemCiphertext))).wait();
  }

  // NOTE: §6b v2 removes the plain disburse() entry point, so a "withheld"
  // (nothing-published) disburse is no longer producible on-chain — publication
  // is enforced. The payee note @32 stays an unspent single-append leaf for /path.

  // ---- deposit #2 (KEM-MISMATCH): a consistent-but-junk kemCiphertext -------
  // The proof (and its kemBinding public signal + envelope key) commits to ONE
  // encapsulation; the tx submits a DIFFERENT, well-formed 1088-byte ct. The
  // chain accepts it (length is the only on-chain check, design doc §2
  // trade-off); the arbiter decapsulates the tx's ct, recomputes the binding,
  // mismatches -> first-class kem alarm + envelope withheld: NO notes recorded
  // for this op. Appended past every pinned leaf index so it cannot shift one.
  const sK0 = 8800001n, sK1 = 8800002n;
  const ECDH_DEP2 = 990000000000000000023n;
  const NONCE_DEP2 = 888888888888n;
  const KEM_DEP2_WITNESS = kemDraw("scen/deposit-mismatch/witness");
  const KEM_DEP2_JUNK = kemDraw("scen/deposit-mismatch/junk-ct");
  const kNoteV = commitment(7n, sK0, EMPLOYER.publicKey);
  const kNote0 = commitment(0n, sK1, EMPLOYER.publicKey);
  let kemMismatchTxHash: string;
  {
    const { a, b, c, pub } = await prove("deposit", {
      outputCommitments: [kNoteV, kNote0], outputValues: [7n, 0n],
      outputSalts: [sK0, sK1], outputOwnerPublicKeys: [EMPLOYER.publicKey, EMPLOYER.publicKey],
      ecdhPrivateKey: ECDH_DEP2, kemSs: KEM_DEP2_WITNESS.kemSs,
      encryptionNonce: NONCE_DEP2, authorityPublicKey: AUTHORITY.publicKey,
    });
    oracle.appendLeaf(kNoteV);
    oracle.appendLeaf(kNote0);
    const tx = await pool.deposit(a, b, c, pub, kemCtHex(KEM_DEP2_JUNK.kemCiphertext));
    await tx.wait();
    kemMismatchTxHash = tx.hash;
  }

  // ---- transfer10 (arity 10, ALL ten outputs to one owner) -------------------
  // The V4 entry point, driven on-chain rather than from a synthetic log: a
  // fresh owner deposits, then spends BOTH deposit notes through transfer10
  // with the other eight slots padded. Every output goes to that one owner, so
  // the per-output nonce (§11-8 v1.1) is under its maximum load — ten
  // ciphertexts under one ephemeral key that must each open independently.
  //
  // A NEW owner rather than an existing actor, and appended after every leg
  // above: the arbiter assertions upstream pin exact per-owner note and history
  // counts, and reusing recipient#0 or the employer would move them.
  // ingest.test.ts already exercises this decode path against synthetic logs;
  // what only a live leg can show is that the indexer's mirror still equals the
  // contract root once a single op appends TEN leaves at once.
  const T10 = deriveKeypair(333333333333333333333333n);
  const ECDH_DEP3 = 975000000000000000013n;
  const ECDH_T10 = 985000000000000000017n;
  const NONCE_DEP3 = 444444444444n;
  const NONCE_T10 = 999999999999n;
  const KEM_DEP3 = kemDraw("scen/deposit-t10");
  const KEM_T10 = kemDraw("scen/transfer10");
  const T10_ARITY = 10;
  const t10InValue = 90n;
  const sT10In = (i: number): bigint => 8900001n + BigInt(i);
  const sT10Pad = (i: number): bigint => 8910001n + BigInt(i);
  const sT10Out = (i: number): bigint => 8920001n + BigInt(i);
  const t10InCommits = [
    commitment(t10InValue, sT10In(0), T10.publicKey),
    commitment(0n, sT10In(1), T10.publicKey),
  ];
  const t10OutValues = Array.from({ length: T10_ARITY }, () => t10InValue / BigInt(T10_ARITY));
  const t10OutCommits = t10OutValues.map((v, i) => commitment(v, sT10Out(i), T10.publicKey));
  const t10DepositLeaf = 80 + 2; // 82 — after the kem-mismatch deposit's 80/81
  const t10StartLeaf = t10DepositLeaf + 2; // 84 — the ten outputs land here
  const t10Nullifiers = [
    nullifier(t10InValue, sT10In(0), T10.formattedPrivateKey),
    nullifier(0n, sT10In(1), T10.formattedPrivateKey),
  ];
  {
    const { a, b, c, pub } = await prove("deposit", {
      outputCommitments: t10InCommits, outputValues: [t10InValue, 0n],
      outputSalts: [sT10In(0), sT10In(1)], outputOwnerPublicKeys: [T10.publicKey, T10.publicKey],
      ecdhPrivateKey: ECDH_DEP3, kemSs: KEM_DEP3.kemSs,
      encryptionNonce: NONCE_DEP3, authorityPublicKey: AUTHORITY.publicKey,
    });
    oracle.appendLeaf(t10InCommits[0]);
    oracle.appendLeaf(t10InCommits[1]);
    await (await pool.deposit(a, b, c, pub, kemCtHex(KEM_DEP3.kemCiphertext))).wait();
  }
  {
    const zeros: bigint[] = new Array(H).fill(0n);
    const padCommit = commitment(0n, sT10Pad(0), T10.publicKey);
    const paths = [oracle.merklePath(t10DepositLeaf).siblings, oracle.merklePath(t10DepositLeaf + 1).siblings];
    const idx = (i: number): bigint => (i < 2 ? BigInt(t10DepositLeaf + i) : 0n);
    const { a, b, c, pub } = await prove("transfer10", {
      nullifiers: Array.from({ length: T10_ARITY }, (_, i) => (i < 2 ? t10Nullifiers[i] : 0n)),
      inputCommitments: Array.from({ length: T10_ARITY }, (_, i) => (i < 2 ? t10InCommits[i] : padCommit)),
      inputValues: Array.from({ length: T10_ARITY }, (_, i) => (i === 0 ? t10InValue : 0n)),
      inputSalts: Array.from({ length: T10_ARITY }, (_, i) => (i < 2 ? sT10In(i) : sT10Pad(0))),
      inputOwnerPrivateKey: T10.formattedPrivateKey, ecdhPrivateKey: ECDH_T10,
      root: oracle.getRoot(),
      pathElements: Array.from({ length: T10_ARITY }, (_, i) => (i < 2 ? paths[i] : zeros)),
      leafIndices: Array.from({ length: T10_ARITY }, (_, i) => idx(i)),
      enabled: Array.from({ length: T10_ARITY }, (_, i) => (i < 2 ? 1n : 0n)),
      outputCommitments: t10OutCommits, outputValues: t10OutValues,
      outputSalts: Array.from({ length: T10_ARITY }, (_, i) => sT10Out(i)),
      outputOwnerPublicKeys: Array.from({ length: T10_ARITY }, () => T10.publicKey),
      kemSs: KEM_T10.kemSs,
      encryptionNonce: NONCE_T10, authorityPublicKey: AUTHORITY.publicKey,
    });
    for (const oc of t10OutCommits) oracle.appendLeaf(oc);
    await (await pool.transfer10(a, b, c, pub, kemCtHex(KEM_T10.kemCiphertext))).wait();
  }

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
    tamperedAuthorityStartLeafIndex: tamperedAuthorityStart,
    kemMismatchTxHash,
    singleLeaves: [
      { leafIndex: 0, commitment: dec(dNoteV) },
      { leafIndex: payLeaf, commitment: dec(payCommit) },
      // transfer10 appends its ten outputs one at a time, exactly like transfer,
      // so a /path into the first of them is servable in PUBLIC mode too.
      { leafIndex: t10StartLeaf, commitment: dec(t10OutCommits[0]) },
    ],
    // ---- arbiter-mode fixtures -----------------------------------------------
    // The AUTHORITY keypair IS the arbiter key (the indexer decrypts with its
    // private scalar); the recipient/payee notes + spent nullifiers let the
    // arbiter test assert the note ledger + spent transition from envelopes alone.
    arbiterPrivateKey: dec(AUTHORITY.formattedPrivateKey),
    arbiterKemSecretKey: kemCtHex(AUTHORITY_KEM.secretKey),
    blockAfterHonestDisburse,
    employerPub: [dec(EMPLOYER.publicKey[0]), dec(EMPLOYER.publicKey[1])],
    employerPrivateKey: dec(EMPLOYER.formattedPrivateKey),
    transferPayAmount: dec(payVal),
    withdrawnAmount: dec(chgVal),
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
    transfer10: {
      ownerPub: [dec(T10.publicKey[0]), dec(T10.publicKey[1])],
      ownerPrivateKey: dec(T10.formattedPrivateKey),
      startLeafIndex: t10StartLeaf, // 84 — the first of the ten appended outputs
      arity: T10_ARITY,
      outCommits: t10OutCommits.map(dec),
      outValues: t10OutValues.map(dec),
      spentLeafIndices: [t10DepositLeaf, t10DepositLeaf + 1], // both deposit notes
    },
    // Real (nonzero) nullifiers, in spend order: deposit note(V)@0 (disburse#1),
    // recipient0 batch note @16 (transfer), change @33 (withdraw), note(0)@1
    // (disburse#2), residue note(0)@34 (disburse#3), then the transfer10's two
    // real inputs @82/@83. Transfer/withdraw/transfer10 pad inputs have
    // nullifier 0 (skipped).
    spentNullifiers: [
      dec(nfDepositV),
      dec(nfBatch0),
      dec(nfChange),
      dec(nf0),
      dec(nfRes),
      ...t10Nullifiers.map(dec),
    ],
  };
}
