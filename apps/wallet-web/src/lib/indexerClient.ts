// The ONE indexer import home for the wallet (SPEC §6b). Every read of the indexer —
// the fetch wrappers AND the wire types — enters the app through this file; nothing
// else in apps/wallet-web imports @bongtu/core/indexerApi directly. The wire shapes and
// the fetch wrappers themselves are owned by @bongtu/core/indexerApi — one owner for
// both apps, server-adapter-typed on the indexer side — so this barrel adds no logic.
// The wallet uses:
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
  buildNotesUrl,
  fetchNotes,
  buildHistoryUrl,
  fetchHistory,
  fetchHealth,
  obtainViewToken,
  buildNotesTokenUrl,
  buildHistoryTokenUrl,
  type OwnerNote,
  type FeedEvent,
  type Head,
  type PathResult,
  type HistoryItem,
  type HistoryKind,
  type Health,
  type ViewToken,
} from "@bongtu/core/indexerApi";
