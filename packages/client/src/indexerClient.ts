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

export {
  getHead,
  getSignedPath,
  getEvents,
  buildNotesUrl,
  fetchNotes,
  buildHistoryUrl,
  fetchHistory,
  fetchHistoryPage,
  HISTORY_PAGE_LIMIT,
  fetchHealth,
  getAnnouncements,
  buildAnnouncementsUrl,
  fetchAnnouncements,
  obtainViewToken,
  buildNotesTokenUrl,
  buildHistoryTokenUrl,
  resolveName,
  registerName,
  buildNameRegistration,
  normalizeName,
  payPortal,
  type OwnerNote,
  type FeedEvent,
  type WithdrawAnnouncementRecord,
  type Head,
  type PathResult,
  type HistoryItem,
  type HistoryKind,
  type HistoryPage,
  type Health,
  type ViewToken,
  type NameRecord,
  type NameRegistration,
  type PortalIssuance,
} from "@bongtu/core/indexerApi";
