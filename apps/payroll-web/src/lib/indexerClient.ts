// The ONE indexer import home for the admin app. Every read of the indexer — the
// fetch wrappers AND the wire types — enters the app through this file; nothing
// else in apps/payroll-web imports @bongtu/core/indexerApi directly. The wire
// shapes and the fetch wrappers themselves are owned by @bongtu/core/indexerApi
// (one owner for both apps, server-adapter-typed on the indexer side), so this
// barrel adds no logic — it keeps the app's import path stable and gives the
// indexer surface a single place to be audited from.
//
// Employer-mode uses /head + /path to build the input-note membership witness from
// chain state; auditor-mode uses /events + /alarms (the Alarm union gives the auditor
// console the DisclosureStatus vocabulary).
//
// `buildNotesUrl` / `fetchNotes` are the signed GET /notes read-auth path (SPEC §6b
// v2), tested headlessly against the sdk `verifyNotesAuth` the indexer route checks
// with. That auth binds to the OWNER key: the signature must verify against the
// queried pubkey, so the caller must hold that owner's private scalar. In auditor-mode
// this is a helper for a recipient checking their own holdings via the arbiter indexer
// (or an auditor with a cooperating recipient's key) — the auditor's general "who
// received what" view comes from the /events decrypt (ledger.ts), which needs only the
// arbiter key.

export {
  getHead,
  getPath,
  getEvents,
  getAlarms,
  buildNotesUrl,
  fetchNotes,
  type Head,
  type PathResult,
  type FeedEvent,
  type Alarm,
} from "@bongtu/core/indexerApi";
