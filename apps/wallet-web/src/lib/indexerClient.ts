// Consumer adapter over the indexer read API (SPEC §6b): the wire shapes AND the
// fetch wrappers are owned by @bongtu/sdk/indexerApi — one owner for both apps,
// server-adapter-typed on the indexer side. This file only keeps the wallet's
// import path stable. The wallet uses:
//   - signed `GET /notes` (arbiter mode) for the balance path — the
//     sdk `buildNotesUrl` signs with the wallet's OWN key (byte-identical to the
//     indexer's verifier, tested headlessly in the sdk suite), so only the owner
//     can read its own notes even though the arbiter indexer holds everyone's;
//   - `GET /events` + `GET /nullifiers` for the key-only trial-decrypt discovery
//     primitive (`trialDecryptEvents` — tested, not a wallet balance path);
//   - `GET /head` + `GET /path/{leafIndex}` to build a spend's membership witness.

export {
  getHead,
  getPath,
  getEvents,
  getNullifiers,
  buildNotesUrl,
  fetchNotes,
  buildHistoryUrl,
  fetchHistory,
  fetchHealth,
  type OwnerNote,
  type FeedEvent,
  type Head,
  type PathResult,
  type HistoryItem,
  type HistoryKind,
  type Health,
} from "@bongtu/sdk/indexerApi";
