// Consumer adapter over the indexer read API (SPEC §6b): the wire shapes AND the
// fetch wrappers are owned by @bongtu/sdk/indexerApi — one owner for both apps,
// server-adapter-typed on the indexer side. This file only keeps the admin app's
// import path stable. Employer-mode uses /head + /path to build the input-note
// membership witness from chain state; auditor-mode uses /events + /alarms (the
// Alarm union gives the auditor console the DisclosureStatus vocabulary).

export {
  getHead,
  getPath,
  getEvents,
  getAlarms,
  type Head,
  type PathResult,
  type FeedEvent,
  type Alarm,
} from "@bongtu/sdk/indexerApi";
