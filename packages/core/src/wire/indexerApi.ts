// The ONE owner of the spec-normative indexer read-API (SPEC §6b): the wire
// shapes every endpoint serves plus a thin typed fetch client.
//
// Adapter pattern (the same seam discipline §6 locks for ProvingRequest in
// proving.ts): the indexer's routes type their RESPONSE BODIES against these
// shapes (server adapter), and payroll-web / treasury-web import the client instead
// of hand-copied types (consumer adapters). Adding a field to /events is a
// one-type change here that tsc propagates to the route and both apps; silent
// wire drift becomes a type error instead of a runtime surprise.
//
// Wire conventions: JSON, every field element as a DECIMAL string (bigints do
// not survive JSON), leaf indices as numbers, tx hashes as 0x-hex.
//
// `buildNotesUrl` is the client half of the /notes signed-query protocol
// (param names, unix-seconds ts, the 300s replay window on the server side,
// EdDSA-Poseidon sig over Poseidon(ownerPub.x, ownerPub.y, ts)). It is written
// ONCE here and tested headlessly against the sdk's own `verifyNotesAuth` — the
// exact function the indexer route checks with — closing the auth loop inside
// one repo (test/indexerApi.test.ts).
//
// How the wallets use these endpoints (SPEC §6b): this subpath IS the import
// home for every consumer — the cross-package re-export barrel that used to
// front it from the client package was removed by user decision 2026-09-04
// (issue #15). The wallets use:
//   - signed `GET /notes` (arbiter mode) for the balance path — the
//     sdk `buildNotesUrl` signs with the wallet's OWN key (byte-identical to the
//     indexer's verifier, tested headlessly in the sdk suite), so only the owner
//     can read its own notes even though the arbiter indexer holds everyone's;
//   - `GET /events` + `GET /nullifiers` for the key-only trial-decrypt discovery
//     primitive (`trialDecryptEvents` — tested, not a wallet balance path) and —
//     with the cursor-paged `getEventsFrom`, the auth-free `getPath`, and `getHead`
//     — for the selfscan-mode balance path (selfscan.ts, OPMOD §3.6);
//   - `GET /head` + signed `GET /path/{leafIndex}` to build a spend's membership
//     witness — signed because a disbursed note sits inside a batch, and the
//     arbiter indexer only opens a batch slot to its proven owner;
//   - paged `GET /history` (`fetchHistoryPage`) for the activity feed — the app
//     holds one page at a time and asks for the next by cursor, so a long-lived
//     account does not download its entire history to render four Home rows;
//   - the `/names` directory (`resolveName` + the shared `normalizeName` grammar)
//     for pay-by-name: the Send form turns a registered name into the owner's
//     canonical address before the user confirms (`registerName` /
//     `buildNameRegistration` cover the wallet's own registration side);
//   - `POST /pay/{name}` (`payPortal`) for the Receive panel's one-time deposit
//     address: the indexer derives a fresh CREATE2 portal destination for the
//     session's registered name and records the announcement at issuance time
//     (Slice ⑤ — the payer then needs nothing but a plain kKRW transfer).
//
// This file stitches the split wire module back into the ONE stable public
// subpath (@bongtu/core/indexerApi); the implementation lives in the sibling
// indexer* parts.
export * from "./indexerDto.js";
export * from "./indexerHttp.js";
export * from "./indexerReads.js";
export * from "./indexerNames.js";
export * from "./indexerClient.js";

