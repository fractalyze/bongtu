// Indexer conformance test (SPEC §6b DoD-4). Runs the full scenario on a live
// anvil (deposit → disburse(16) → transfer → withdraw → tampered disburse),
// ingests it, and asserts every indexer invariant:
//
//   1. mirror root == contract root AND nextLeafIndex match at head
//   2. GET /path/:i for a real (single-append) leaf folds to the head root
//   3. GET /events carries the disburse ciphertext feed with correct leafIndex
//      annotations; a recipient key trial-decrypts a slice → commitment == the
//      tree leaf, and all B recovered commitments fold to the batch subtreeRoot
//   4. disclosureHash passes for the honest disburse; the receiver-tampered and
//      authority-tampered ones ALARM ("mismatch") on the single discriminated
//      /alarms feed ({ type: "disclosure" } entries). §6b v2 removes the plain
//      disburse() path, so a "withheld" (nothing-published) disburse is no
//      longer producible on-chain.
//   5. GET /path/:i for a disburse-batch leaf is refused (siblings not
//      chain-recoverable, SPEC §11-7); bad /events params are refused (400)
//   6. PUBLIC mode: /nullifiers is served (key-free) and carries the spent set;
//      /notes 404s (arbiter-only route).
//   7. ARBITER mode (SPEC §6b v2, second indexer holding the arbiter private key):
//      a recipient's GET /notes lists its disburse-batch note (value/salt/leaf,
//      spent=false); after the transfer spends it, the note reads spent=true (from
//      the input envelope alone) and the payee's new note is present; GET /path for
//      that batch leaf now folds to root() (the ledger filled the batch); the
//      arbiter /nullifiers carries the spent set; bad /notes params 400; the
//      authority-tampered disburse surfaces a { type: "envelope" } cross-check
//      alarm on /alarms (the recovered leaves cannot fold to the on-chain
//      subtreeRoot) and its batch stays unopened.
//
// Anvil is started + trap-killed by run.sh; this file only talks to E2E_RPC.
//
// Postgres-only (U-I4): the indexer has no in-memory backend, so this gate runs
// against REAL Postgres. run.sh provides TEST_DATABASE_URL (an admin connection
// string — CI's postgres service container, or a throwaway docker container
// locally); this file drops + recreates one fresh database per indexer instance
// (public / arbiter) so runs are hermetic and the two instances never share a
// cursor.

import { Pool } from "pg";
import { poseidon2, poseidonN } from "@bongtu/core/poseidon";
import { ecdhSharedSecret, poseidonDecrypt } from "@bongtu/core/note";
import { packPubkey } from "@bongtu/core/pubkey";
import { signNotesAuth, notesAuthMessage, packSignature } from "@bongtu/core/eddsa";
import { obtainViewToken } from "@bongtu/core/indexerApi";
import { ImtTree } from "@bongtu/core/imt";
import { Indexer } from "../src/ingest.js";
import { parseKemKey } from "../src/chain.js";
import { startApi } from "../src/api/router.js";
import { runScenario } from "./scenario.js";

let failures = 0;
function ok(cond: unknown, msg: string): void {
  const pass = !!cond;
  if (!pass) failures++;
  console.log(`   ${pass ? "PASS" : "FAIL"}  ${msg}`);
  if (!pass) throw new Error(`assertion failed: ${msg}`);
}
function step(t: string): void {
  console.log(`\n=== ${t} ===`);
}

// Admin Postgres URL (run.sh guarantees it, spinning a throwaway container when
// the caller did not export one). A missing URL is a hard FAIL here — the skip
// decision (docker genuinely unavailable) lives in run.sh, loudly.
const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL;
if (!TEST_DATABASE_URL) {
  console.error("FATAL: TEST_DATABASE_URL is not set — the conformance gate is Postgres-backed (run via test/run.sh, which provisions a throwaway postgres, or export TEST_DATABASE_URL yourself).");
  process.exit(1);
}

/** Drop + recreate `name` on the admin connection; return its connection URL. */
async function freshDatabase(name: string): Promise<string> {
  const admin = new Pool({ connectionString: TEST_DATABASE_URL });
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${name}`);
    await admin.query(`CREATE DATABASE ${name}`);
  } finally {
    await admin.end();
  }
  const u = new URL(TEST_DATABASE_URL!);
  u.pathname = `/${name}`;
  return u.toString();
}

function foldToRoot(leaf: bigint, siblings: bigint[], pathIndices: number[]): bigint {
  let cur = leaf;
  for (let j = 0; j < siblings.length; j++) {
    cur = pathIndices[j] === 1 ? poseidon2(siblings[j], cur) : poseidon2(cur, siblings[j]);
  }
  return cur;
}

async function get(base: string, path: string): Promise<{ status: number; body: unknown }> {
  const r = await fetch(base + path);
  return { status: r.status, body: await r.json() };
}

// Arbiter-mode conformance (SPEC §6b v2): a second indexer holding the arbiter
// private key ingests the SAME pool in two phases to exercise the note ledger's
// create -> spend transition, within-batch paths, and the arbiter /nullifiers.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function runArbiter(sc: any): Promise<void> {
  const r0 = sc.recipient0Note;
  const pay = sc.payeeNote;
  // A /notes request is now AUTHENTICATED (SPEC §6b v2): owner is the COMPRESSED
  // pubkey, plus a fresh unix ts and a bjj EdDSA-Poseidon sig over
  // Poseidon(ownerPub.x, ownerPub.y, ts). `signPriv` is decoupled from `owner` so a
  // test can sign the owner-bound message with a DIFFERENT key (the wrong-key attack).
  const authedQ = (
    owner: [string, string],
    signPriv: string,
    ts: number = Math.floor(Date.now() / 1000),
  ): string => {
    const pub: [bigint, bigint] = [BigInt(owner[0]), BigInt(owner[1])];
    const compressed = packPubkey(pub);
    const sig = packSignature(signNotesAuth(BigInt(signPriv), notesAuthMessage(pub, ts)));
    return `/notes?owner=${compressed}&ts=${ts}&sig=${sig}`;
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const noteAt = (list: any[], leafIndex: number) => list.find((n) => n.leafIndex === leafIndex);

  const aix = new Indexer({
    rpc: sc.rpc,
    pool: sc.poolAddr,
    startBlock: 0,
    authorityKey: BigInt(sc.arbiterPrivateKey),
    authorityKemKey: parseKemKey(sc.arbiterKemSecretKey),
    databaseUrl: await freshDatabase("bongtu_conf_arbiter"),
  });
  ok(aix.arbiterMode === true, "second indexer is in ARBITER mode (AUTHORITY key set)");

  // KEM boot guard against the LIVE pool (nonzero arbiterKemPkHash on epoch 0):
  // this build (V2 ABI + AUTHORITY_KEM_KEY) serves; the same arbiter WITHOUT the
  // decapsulation key must be refused with the one-line fatal (design doc §7).
  step("ARBITER kem boot guard — keyed build serves, keyless arbiter refused");
  ok((await aix.kemBootGuard()) === null, "V2 build + AUTHORITY_KEM_KEY → boot guard passes");
  const keyless = new Indexer({
    rpc: sc.rpc,
    pool: sc.poolAddr,
    startBlock: 0,
    authorityKey: BigInt(sc.arbiterPrivateKey),
  });
  const refusal = await keyless.kemBootGuard();
  ok(typeof refusal === "string" && refusal.includes("AUTHORITY_KEM_KEY"),
    "arbiter without AUTHORITY_KEM_KEY on a KEM-epoch pool → one-line refusal");
  const publicBuild = new Indexer({ rpc: sc.rpc, pool: sc.poolAddr, startBlock: 0 });
  ok((await publicBuild.kemBootGuard()) === null, "public mode never needs the KEM key");

  step("ARBITER phase 1: ingest deposit + honest disburse ONLY (up to the pre-transfer block)");
  await aix.ingest(0, sc.blockAfterHonestDisburse);
  const aapi = await startApi(aix, Number(process.env.INDEXER_TEST_PORT || 0));
  const abase = `http://127.0.0.1:${aapi.port}`;
  try {
    // recipient #0's disburse-batch note is present, unspent, decrypted from the
    // authority envelope alone (right value/salt/leafIndex). The request is signed
    // by recipient #0 (compressed owner + fresh ts + valid sig).
    const n1 = await get(abase, authedQ(r0.owner, sc.recipient0PrivateKey));
    ok(n1.status === 200, "GET /notes (recipient#0, signed) 200 (arbiter)");
    const note1 = noteAt(n1.body as unknown[], r0.leafIndex);
    ok(!!note1, `recipient#0 /notes lists its batch note @${r0.leafIndex}`);
    ok(note1.value === r0.value, `note value == disbursed amount (${r0.value})`);
    ok(note1.salt === r0.salt, "note salt == the disbursed salt");
    ok(note1.commitment === sc.disburseHonest.outCommits[0], "note commitment == the on-chain batch leaf");
    ok(note1.spent === false, "recipient#0 batch note spent == false (pre-transfer)");

    step("ARBITER phase 2: ingest the rest (transfer spends @16, withdraw, tampered disburse)");
    await aix.ingest(sc.blockAfterHonestDisburse + 1);

    // Same note now reads spent=true — from the transfer's INPUT envelope, no key.
    const n2 = await get(abase, authedQ(r0.owner, sc.recipient0PrivateKey));
    const note2 = noteAt(n2.body as unknown[], r0.leafIndex);
    ok(!!note2 && note2.spent === true, `recipient#0 batch note @${r0.leafIndex} now spent == true (after transfer)`);

    // The payee's transfer output note is present + unspent (signed by the payee).
    const np = await get(abase, authedQ(pay.owner, sc.payeePrivateKey));
    ok(np.status === 200, "GET /notes (payee, signed) 200");
    const notep = noteAt(np.body as unknown[], pay.leafIndex);
    ok(!!notep, `payee /notes lists its transfer note @${pay.leafIndex}`);
    ok(notep.value === pay.value && notep.spent === false, `payee note value == ${pay.value}, spent == false`);

    // /notes header documents that auth is now ENFORCED.
    const rawNotes = await fetch(abase + authedQ(r0.owner, sc.recipient0PrivateKey));
    const authHdr = rawNotes.headers.get("x-bongtu-auth");
    ok(!!authHdr && /ENFORCED/.test(authHdr), "/notes response carries the ENFORCED-auth header");

    // ---- AUTH GATES (SPEC §6b v2): compressed owner + bjj-sig + ts window ----
    step("ARBITER /notes AUTH — valid 200, wrong-key 401, expired-ts 401, malformed owner 400");
    const now = Math.floor(Date.now() / 1000);
    // (a) a correctly-signed, fresh request returns the owner's notes.
    const authOk = await get(abase, authedQ(r0.owner, sc.recipient0PrivateKey, now));
    ok(authOk.status === 200, "signed /notes (recipient#0, fresh ts) → 200");
    ok(!!noteAt(authOk.body as unknown[], r0.leafIndex), "authenticated response contains recipient#0's note");
    // (b) a signature by the WRONG key over the recipient#0-bound message → 401.
    const wrongKey = await get(abase, authedQ(r0.owner, sc.payeePrivateKey, now));
    ok(wrongKey.status === 401, "wrong-key signature over recipient#0's owner → 401");
    // (c) a valid signature but an EXPIRED ts (outside the 300s window) → 401.
    const expired = await get(abase, authedQ(r0.owner, sc.recipient0PrivateKey, now - 400));
    ok(expired.status === 401, "valid sig but ts 400s in the past → 401 (replay window)");
    // (d) a malformed compressed owner → 400 (before any auth check).
    const malformed = await get(abase, `/notes?owner=abc&ts=${now}&sig=0x00`);
    ok(malformed.status === 400, "malformed compressed owner → 400");

    // ---- GET /history (SPEC §6b): per-owner activity from the decrypted envelopes.
    // recipient#0 received a disburse note (from the employer), then transferred to
    // the payee, then withdrew — so its feed carries received + sent + withdraw,
    // newest-first. Same bjj read-auth as /notes (wrong key 401, missing ts/sig 400).
    step("ARBITER /history — received(from employer) + sent(to payee) + withdraw, sorted desc");
    const employerCompressed = packPubkey([BigInt(sc.employerPub[0]), BigInt(sc.employerPub[1])]);
    const payeeCompressed = packPubkey([BigInt(pay.owner[0]), BigInt(pay.owner[1])]);
    const histQ = (
      owner: [string, string],
      signPriv: string,
      ts: number = Math.floor(Date.now() / 1000),
    ): string => {
      const pub: [bigint, bigint] = [BigInt(owner[0]), BigInt(owner[1])];
      const sig = packSignature(signNotesAuth(BigInt(signPriv), notesAuthMessage(pub, ts)));
      return `/history?owner=${packPubkey(pub)}&ts=${ts}&sig=${sig}`;
    };
    const hh = await get(abase, histQ(r0.owner, sc.recipient0PrivateKey));
    ok(hh.status === 200, "GET /history (recipient#0, signed) 200 (arbiter)");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const items = hh.body as any[];
    ok(items.length === 3, `recipient#0 /history has exactly 3 items (got ${items.length})`);
    ok(items.every((x, i) => i === 0 || items[i - 1].seq > x.seq), "/history sorted by seq desc (newest-first)");
    ok(items.every((x) => typeof x.blockTimestamp === "number" && x.blockTimestamp > 0), "every /history item carries a block timestamp");

    const recv = items.find((x) => x.kind === "received");
    ok(!!recv, "recipient#0 /history has a received item (the disburse)");
    ok(recv.amount === r0.value, `received amount == the disbursed amount (${r0.value})`);
    ok(recv.counterparty === employerCompressed, "received counterparty == the employer (disburse input owner)");

    const sent = items.find((x) => x.kind === "sent");
    ok(!!sent, "recipient#0 /history has a sent item (the transfer)");
    ok(sent.amount === sc.transferPayAmount, `sent amount == what left recipient#0 (${sc.transferPayAmount})`);
    ok(sent.counterparty === payeeCompressed, "sent counterparty == the payee");

    const wd = items.find((x) => x.kind === "withdraw");
    ok(!!wd, "recipient#0 /history has a withdraw item");
    ok(wd.amount === sc.withdrawnAmount && wd.counterparty === null,
      `withdraw amount == ${sc.withdrawnAmount}, counterparty null`);

    // AUTH parity with /notes: a wrong-key sig → 401, owner without ts/sig → 400.
    const histWrong = await get(abase, histQ(r0.owner, sc.payeePrivateKey));
    ok(histWrong.status === 401, "wrong-key signature over recipient#0's /history → 401");
    const histNoAuth = await get(abase, `/history?owner=${packPubkey([BigInt(r0.owner[0]), BigInt(r0.owner[1])])}`);
    ok(histNoAuth.status === 400, "GET /history with owner but no ts/sig → 400");

    // ---- View tokens (SPEC §6b + api/viewtoken.ts): the challenge → sign → token
    // handshake over REAL HTTP, then the token authorising both reads WITHOUT the
    // key — the wallet's login-persistence path. The signed-query assertions above
    // already proved backward compat holds alongside.
    step("ARBITER /auth — view token round-trip authorises /notes + /history; tampered token 401");
    const r0Compressed = packPubkey([BigInt(r0.owner[0]), BigInt(r0.owner[1])]);
    const vt = await obtainViewToken(abase, r0Compressed, BigInt(sc.recipient0PrivateKey));
    ok(vt.token.length > 0 && vt.exp > Math.floor(Date.now() / 1000), "POST /auth issued a token with a future exp");
    const tn = await get(abase, `/notes?owner=${r0Compressed}&token=${encodeURIComponent(vt.token)}`);
    ok(tn.status === 200 && !!noteAt(tn.body as unknown[], r0.leafIndex), "token-authed /notes 200 with recipient#0's note (no sig/ts)");
    const th = await get(abase, `/history?owner=${r0Compressed}&token=${encodeURIComponent(vt.token)}`);
    ok(th.status === 200 && (th.body as unknown[]).length === 3, "token-authed /history 200 with the same 3 items");
    const tampered = vt.token.slice(0, -1) + (vt.token.endsWith("0") ? "1" : "0");
    const tBad = await get(abase, `/notes?owner=${r0Compressed}&token=${encodeURIComponent(tampered)}`);
    ok(tBad.status === 401, "tampered token → 401");
    const tWrongOwner = await get(
      abase,
      `/notes?owner=${packPubkey([BigInt(pay.owner[0]), BigInt(pay.owner[1])])}&token=${encodeURIComponent(vt.token)}`,
    );
    ok(tWrongOwner.status === 401, "recipient#0's token on the payee's owner → 401");

    // ARBITER /path into the disburse batch now serves a REAL path folding to root.
    step("ARBITER /path — within-batch leaf now servable (ledger filled the batch)");
    const bp = await get(abase, `/path/${r0.leafIndex}`);
    ok(bp.status === 200, `GET /path/${r0.leafIndex} → 200 in arbiter mode (was 422 public)`);
    const p = bp.body as { siblings: string[]; pathIndices: number[]; root: string };
    const folded = foldToRoot(BigInt(sc.disburseHonest.outCommits[0]), p.siblings.map(BigInt), p.pathIndices);
    ok(folded.toString() === sc.headRoot, `batch leaf ${r0.leafIndex} path folds to head root`);
    ok(p.root === sc.headRoot, `/path/${r0.leafIndex} reports head root`);

    // /nullifiers (also served in arbiter mode) carries every spent nullifier.
    step("ARBITER /nullifiers — spent nullifier set");
    const nf = await get(abase, "/nullifiers");
    ok(nf.status === 200, "GET /nullifiers 200 (arbiter)");
    const nfSet = new Set(nf.body as string[]);
    for (const x of sc.spentNullifiers as string[]) ok(nfSet.has(x), `/nullifiers contains ${x.slice(0, 12)}…`);

    // The envelope cross-check is the arbiter's independent tamper proof: the
    // authority-tampered disburse decrypts to garbage notes whose fold cannot
    // reproduce the on-chain subtreeRoot, so it must surface as a first-class
    // { type: "envelope" } alarm on the SAME /alarms feed the auditor console
    // already reads — and its batch must stay unopened (no /path into it).
    step("ARBITER /alarms — discriminated feed carries the envelope cross-check alarm");
    const aal = await get(abase, "/alarms");
    ok(aal.status === 200, "GET /alarms 200 (arbiter)");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const afeed = aal.body as any[];
    ok(afeed.filter((a) => a.type === "disclosure").length === 2, "both tampered disburses alarm disclosure-mismatch");
    const envAlarms = afeed.filter((a) => a.type === "envelope");
    ok(envAlarms.length === 2, "exactly two envelope alarms (authority-tampered disburse + kem-mismatch deposit)");
    const subAlarm = envAlarms.find((a) => a.kind === "disburse");
    ok(!!subAlarm && subAlarm.detail.includes(`@${sc.tamperedAuthorityStartLeafIndex}`),
      "envelope alarm pinpoints the authority-tampered batch");
    const unopened = await get(abase, `/path/${sc.tamperedAuthorityStartLeafIndex}`);
    ok(unopened.status === 422, "authority-tampered batch stays unopened (/path 422 even in arbiter mode)");

    // KEM-binding cross-check (pq-envelope-design.md §2/§5): the deposit whose
    // tx ct is a DIFFERENT (consistent-but-junk) encapsulation than the proof's
    // must surface on the SAME "envelope" alarm branch — txHash + on-chain
    // (expected) vs decapsulated (recomputed) binding — and be fully withheld.
    step("ARBITER kem alarm — junk-wrapped kemCiphertext alarms + envelope withheld");
    const kemAlarm = envAlarms.find((a) => a.kind === "deposit");
    ok(!!kemAlarm, "the kem-mismatch deposit raised an envelope alarm");
    ok(kemAlarm.txHash === sc.kemMismatchTxHash, "kem alarm carries the offending txHash");
    ok(/kem binding mismatch/.test(kemAlarm.detail), "kem alarm detail == 'kem binding mismatch — envelope withheld'");
    ok(/^\d+$/.test(kemAlarm.expected) && /^\d+$/.test(kemAlarm.recomputed) && kemAlarm.expected !== kemAlarm.recomputed,
      "kem alarm carries expected (on-chain) vs recomputed (decapsulated) bindings");
    // withheld == STOPPED: the employer's ledger still holds ONLY the two
    // deposit#1 notes — the mismatch deposit recorded nothing.
    const empQ = (
      ts: number = Math.floor(Date.now() / 1000),
    ): string => {
      const pub: [bigint, bigint] = [BigInt(sc.employerPub[0]), BigInt(sc.employerPub[1])];
      const sig = packSignature(signNotesAuth(BigInt(sc.employerPrivateKey), notesAuthMessage(pub, ts)));
      return `/notes?owner=${packPubkey(pub)}&ts=${ts}&sig=${sig}`;
    };
    const empNotes = await get(abase, empQ());
    ok(empNotes.status === 200, "GET /notes (employer, signed) 200");
    ok((empNotes.body as unknown[]).length === 2,
      `employer holds ONLY the deposit#1 notes (kem-mismatch deposit withheld; got ${(empNotes.body as unknown[]).length})`);

    // Distinct 400 branch from the malformed-owner case: auth params are mandatory.
    const noAuth = await get(abase, `/notes?owner=${packPubkey([BigInt(r0.owner[0]), BigInt(r0.owner[1])])}`);
    ok(noAuth.status === 400, "GET /notes with owner but no ts/sig → 400 (auth params required)");
  } finally {
    await aapi.stop();
  }
}

async function main(): Promise<void> {
  step("SCENARIO: deploy B=16 pool + run deposit/disburse16/transfer/withdraw/tampered-disburse on anvil");
  const sc = await runScenario();
  console.log(`   pool=${sc.poolAddr} headRoot=${sc.headRoot} nextLeafIndex=${sc.nextLeafIndex}`);

  step("INGEST: replay pool events from genesis into the SDK ImtTree mirror (postgres-backed)");
  const ix = new Indexer({ rpc: sc.rpc, pool: sc.poolAddr, startBlock: 0, databaseUrl: await freshDatabase("bongtu_conf_public") });
  await ix.ingest(); // throws internally if any per-insert root diverges

  // (1) mirror == contract at head
  const hd = await ix.head();
  ok(ix.tree.root().toString() === sc.headRoot, "mirror root == contract root at head");
  ok(ix.tree.root() === hd.root, "mirror root == live pool.root()");
  ok(ix.tree.nextLeafIndex() === sc.nextLeafIndex, `mirror nextLeafIndex == contract (${sc.nextLeafIndex})`);
  ok(hd.nextLeafIndex === sc.nextLeafIndex, "head() nextLeafIndex == contract");

  const api = await startApi(ix, Number(process.env.INDEXER_TEST_PORT || 0));
  const base = `http://127.0.0.1:${api.port}`;
  try {
    // /head
    step("API /head");
    const headRes = await get(base, "/head");
    ok(headRes.status === 200, "GET /head 200");
    ok((headRes.body as { root: string }).root === sc.headRoot, "/head root == contract root");
    ok((headRes.body as { nextLeafIndex: number }).nextLeafIndex === sc.nextLeafIndex, "/head nextLeafIndex == contract");

    // (2) /path for a real single-append leaf folds to head root
    step("API /path/:i — real leaf folds to head root");
    for (const sl of sc.singleLeaves) {
      const pr = await get(base, `/path/${sl.leafIndex}`);
      ok(pr.status === 200, `GET /path/${sl.leafIndex} 200`);
      const p = pr.body as { siblings: string[]; pathIndices: number[]; root: string };
      const folded = foldToRoot(BigInt(sl.commitment), p.siblings.map(BigInt), p.pathIndices);
      ok(folded.toString() === sc.headRoot, `leaf ${sl.leafIndex} merkle path folds to head root`);
      ok(p.root === sc.headRoot, `/path/${sl.leafIndex} reports head root`);
    }

    // (3) /events ciphertext feed + trial-decrypt
    step("API /events — disburse ciphertext feed + recipient trial-decrypt");
    const evRes = await get(base, "/events");
    ok(evRes.status === 200, "GET /events 200");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const feed = evRes.body as any[];
    const kinds = feed.map((e) => e.kind).join(",");
    ok(kinds === "deposit,disburse,transfer,withdraw,disburse,disburse,deposit", `feed kinds in chain order: ${kinds}`);

    const honest = feed.find((e) => e.kind === "disburse" && e.slices[0]?.leafIndex === sc.disburseHonest.startLeafIndex);
    ok(!!honest, "honest disburse present in feed");
    ok(honest.ecdhPublicKey[0] === sc.disburseHonest.ecdhPublicKey[0]
      && honest.ecdhPublicKey[1] === sc.disburseHonest.ecdhPublicKey[1], "feed ecdhPublicKey == on-chain ephemeral pub");
    ok(honest.encryptionNonce === sc.disburseHonest.nonce, "feed encryptionNonce == on-chain nonce");
    ok(honest.slices.length === sc.B + 1, `disburse has ${sc.B} receiver slices + 1 authority tail`);
    for (let i = 0; i < sc.B; i++) {
      ok(honest.slices[i].leafIndex === sc.disburseHonest.startLeafIndex + i,
        `slice ${i} leafIndex annotation == ${sc.disburseHonest.startLeafIndex + i}`);
    }
    ok(honest.slices[sc.B].leafIndex === null, "authority tail slice has no leafIndex");

    // trial-decrypt every receiver slice with its recipient key; recover the note
    const nonce = BigInt(honest.encryptionNonce);
    const ephemeralPub: [bigint, bigint] = [BigInt(honest.ecdhPublicKey[0]), BigInt(honest.ecdhPublicKey[1])];
    const recovered: bigint[] = [];
    for (let i = 0; i < sc.B; i++) {
      const s = honest.slices[i];
      const ct = (honest.ciphertext as string[]).slice(s.offset, s.offset + s.elts).map(BigInt);
      const priv = BigInt(sc.disburseHonest.recipientPrivs[i]);
      const shared = ecdhSharedSecret(priv, ephemeralPub);
      const [value, salt] = poseidonDecrypt(ct, shared, nonce, 2);
      const pub = sc.disburseHonest.recipientPubs[i];
      const c = poseidonN([value, salt, BigInt(pub[0]), BigInt(pub[1])]);
      recovered.push(c);
      if (i === 0) {
        ok(c.toString() === sc.disburseHonest.outCommits[0], "trial-decrypt slice 0 → commitment == the tree leaf");
        ok(value.toString() === sc.disburseHonest.amounts[0], "recovered value == recipient #0 disbursed amount");
      }
    }
    // all B recovered commitments fold to the batch subtree root the indexer ingested
    const subRoot = new ImtTree(sc.H, sc.B).computeSubtreeRoot(recovered);
    ok(subRoot.toString() === sc.disburseHonest.subtreeRoot, `all ${sc.B} recovered commitments fold to the batch subtreeRoot`);

    // (4) disclosure: honest passes; both tampered disburses alarm "mismatch" on
    // the single discriminated /alarms feed. §6b v2 removes the plain disburse()
    // path, so "withheld" is no longer producible on-chain.
    step("disclosure: honest PASS + tampered MISMATCH alarms (enforced disclosure)");
    ok(honest.disclosure === "verified", "honest disburse disclosureHash status == verified");
    const tampered = feed.find((e) => e.kind === "disburse" && e.slices[0]?.leafIndex === sc.tamperedStartLeafIndex);
    ok(!!tampered, "receiver-tampered disburse present in feed");
    ok(tampered.disclosure === "mismatch", "receiver-tampered disburse disclosureHash status == mismatch (ALARM)");
    const alarmRes = await get(base, "/alarms");
    ok(alarmRes.status === 200, "GET /alarms 200");
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const alarms = alarmRes.body as any[];
    ok(alarms.length === 2, "two alarms surfaced (receiver-tampered + authority-tampered)");
    ok(alarms.every((a) => a.type === "disclosure"), "public /alarms carries only disclosure entries (no ledger)");
    const recvAlarm = alarms.find((a) => a.startLeafIndex === sc.tamperedStartLeafIndex);
    ok(!!recvAlarm && recvAlarm.status === "mismatch", "receiver-tampered batch alarm == mismatch");
    const authAlarm = alarms.find((a) => a.startLeafIndex === sc.tamperedAuthorityStartLeafIndex);
    ok(!!authAlarm && authAlarm.status === "mismatch", "authority-tampered batch alarm == mismatch");

    // (5) /path into a disburse batch leaf is refused; bad /events params are 400
    step("API /path — disburse-batch leaf refused (siblings not chain-recoverable)");
    const batchPath = await get(base, `/path/${sc.disburseHonest.startLeafIndex}`);
    ok(batchPath.status === 422, `GET /path/${sc.disburseHonest.startLeafIndex} (batch leaf) → 422`);
    ok((batchPath.body as { reason: string }).reason === "batch-leaf", "422 reason == batch-leaf");
    const tamperedPath = await get(base, `/path/${sc.tamperedStartLeafIndex}`);
    ok(tamperedPath.status === 422, `GET /path/${sc.tamperedStartLeafIndex} (tampered-batch leaf) → 422`);
    const badCursor = await get(base, "/events?cursor=abc");
    ok(badCursor.status === 400, "GET /events?cursor=abc → 400");
    const badLimit = await get(base, "/events?limit=0");
    ok(badLimit.status === 400, "GET /events?limit=0 → 400");

    step("PUBLIC mode: /nullifiers served (key-free), /notes 404 (arbiter-only)");
    const nfRes = await get(base, "/nullifiers");
    ok(nfRes.status === 200, "GET /nullifiers 200 (public)");
    const nfSet = new Set(nfRes.body as string[]);
    for (const nf of sc.spentNullifiers) ok(nfSet.has(nf), `/nullifiers contains spent nullifier ${nf.slice(0, 12)}…`);
    const notesPublic = await get(base, `/notes?owner=${sc.recipient0Note.owner[0]},${sc.recipient0Note.owner[1]}`);
    ok(notesPublic.status === 404, "GET /notes → 404 in public mode (route not registered)");
    const historyPublic = await get(base, `/history?owner=${sc.recipient0Note.owner[0]},${sc.recipient0Note.owner[1]}`);
    ok(historyPublic.status === 404, "GET /history → 404 in public mode (route not registered)");
  } finally {
    await api.stop();
  }

  // ======================= ARBITER MODE (SPEC §6b v2) =======================
  // A SECOND indexer built WITH the arbiter private key, ingesting the SAME pool.
  // It decrypts every op's authority envelope → a note ledger + within-batch paths,
  // with spent status derived from envelopes ALONE (no user key, no nullifier link).
  await runArbiter(sc);

  console.log(`\n${failures === 0 ? "INDEXER TEST PASS — mirror==contract, /path folds, feed trial-decrypts, disclosureHash pass + tamper alarm, arbiter note-ledger spent-transition + batch paths + /nullifiers" : `INDEXER TEST FAIL — ${failures} assertion(s)`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("\nINDEXER TEST ERROR:", e && e.stack ? e.stack : e);
  process.exit(1);
});
