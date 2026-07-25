// Signed GET /notes URL construction (SPEC §6b v2 read-auth). The ONE
// implementation lives in @bongtu/core/indexerApi (`buildNotesUrl`), tested
// headlessly against the sdk `verifyNotesAuth` the indexer route checks with;
// this file only keeps the admin app's import path stable.
//
// The /notes auth binds to the OWNER key: the signature must verify against the
// queried pubkey, so the caller must hold that owner's private scalar. In
// auditor-mode this is offered as a helper for a recipient checking their
// holdings via the arbiter indexer (or an auditor with a cooperating recipient's
// key). The auditor's general "who received what" view comes from the /events
// decrypt (ledger.ts), which needs only the arbiter key.

export { buildNotesUrl, fetchNotes } from "@bongtu/core/indexerApi";
