// wire/indexerClient.ts — the bound IndexerClient class (split from indexerApi.ts).
import type { FieldInput } from "@bongtu/core/babyjub";
import type {
  Alarm,
  FeedEvent,
  Head,
  Health,
  HistoryItem,
  HistoryPage,
  HistoryPageQuery,
  OwnerNote,
  PathResult,
  WithdrawAnnouncementRecord,
} from "./indexerDto.js";
import {
  buildHistoryUrl,
  buildNotesTokenUrl,
  buildNotesUrl,
  fetchHealth,
  fetchHistory,
  fetchHistoryPage,
  fetchNotes,
  getAlarms,
  getEventsFrom,
  getHead,
  getNullifiers,
  getPath,
  getSignedPath,
  obtainViewToken,
  type ViewToken,
} from "./indexerReads.js";
import {
  buildAnnouncementsUrl,
  fetchAnnouncements,
  fetchUnswept,
  getAnnouncements,
  getPortalAnnouncements,
  registerName,
  payPortal,
  resolveName,
  type NameRecord,
  type NameRegistration,
  type PortalIssuance,
  type PortalRecord,
} from "./indexerNames.js";
// --- the bound client (issue #15 C1) ----------------------------------------------
//
// One IndexerClient binds the base URL (and the injected fetchFn) ONCE, so the
// ~25 call sites stop re-threading `indexerUrl` through every read. The class is
// a pure delegation layer: every method body is a one-line call into the free
// functions above — they REMAIN the exported primitive/protocol layer (raw
// builder use, `typeof`-typed dependency seams, the headless auth-loop tests),
// and delegation is what makes URL/auth/error drift between the two impossible.
// Methods are readonly ARROW properties so a tear-off (handing `indexer.unswept`
// to a deps bag) keeps its instance — the ToastQueue precedent.

/** Constructor options: `fetchFn` is the ONE test seam — every read and POST a
 *  client instance performs goes through it. */
export interface IndexerClientOptions {
  fetchFn?: typeof fetch;
}

/** The trailing option of the polling-consumed reads (head/health/events/path):
 *  cancellation for consumers that unmount or supersede a scan mid-flight. */
export interface ReadAbort {
  signal?: AbortSignal;
}

/** What a session holding only a VIEW TOKEN can read. Paged /history is
 *  token-only: paging spans requests, and only the token survives between them. */
export interface OwnerTokenReads {
  notes(): Promise<OwnerNote[]>;
  /** ONE page; `limit` is always sent (it selects the { items, nextBefore }
   *  envelope over the legacy bare array). */
  historyPage(page?: HistoryPageQuery): Promise<HistoryPage>;
}

/** What the owner's PRIVATE KEY can read: the signed one-shot feeds plus the
 *  signed /path a within-batch leaf needs. Unpaged /history on purpose — a
 *  key-mode binding is transient, so there is nothing to page a second request
 *  with. */
export interface OwnerKeyReads {
  notes(): Promise<OwnerNote[]>;
  history(): Promise<HistoryItem[]>;
  announcements(): Promise<WithdrawAnnouncementRecord[]>;
  signedPath(leafIndex: number): Promise<PathResult>;
}

/** The key a key-mode binding signs with — a value, or a thunk so every read
 *  pulls the key through the caller's lock at call time instead of capturing it. */
export type OwnerKeySource = FieldInput | (() => FieldInput);

/** asOwner's overload pair — the server's real capability matrix as a type:
 *  token ⇒ { notes, paged history }, key ⇒ { notes, unpaged history,
 *  announcements, signed path }. The illegal combination (a token asking for a
 *  signed /path, a transient key paging) is a compile error, not a 401. */
export interface AsOwner {
  (owner: string, auth: { token: string }): OwnerTokenReads;
  (owner: string, auth: { key: OwnerKeySource }): OwnerKeyReads;
}

export class IndexerClient {
  private readonly base: string;
  private readonly fetchFn: typeof fetch;

  constructor(indexerUrl: string, opts: IndexerClientOptions = {}) {
    // Trimmed ONCE here; the delegated free functions re-trim idempotently. The
    // base stays a plain string prefix — the deployed wallet's base is RELATIVE
    // ("/indexer"), which `new URL` cannot parse, so no URL object ever exists.
    this.base = indexerUrl.replace(/\/$/, "");
    this.fetchFn = opts.fetchFn ?? fetch;
  }

  readonly head = (opts: ReadAbort = {}): Promise<Head> =>
    getHead(this.base, { fetchFn: this.fetchFn, signal: opts.signal });

  readonly health = (opts: ReadAbort = {}): Promise<Health> =>
    fetchHealth(this.base, { fetchFn: this.fetchFn, signal: opts.signal });

  readonly path = (leafIndex: number, opts: ReadAbort = {}): Promise<PathResult> =>
    getPath(this.base, leafIndex, { fetchFn: this.fetchFn, signal: opts.signal });

  /** Cursor-paged `GET /events` (getEventsFrom) — the incremental read the
   *  self-scan resumes on, so this (not the legacy limit-only read) is the
   *  method shape. */
  readonly events = (cursor: number, limit?: number, opts: ReadAbort = {}): Promise<FeedEvent[]> =>
    getEventsFrom(this.base, cursor, limit, { fetchFn: this.fetchFn, signal: opts.signal });

  readonly nullifiers = (): Promise<string[]> => getNullifiers(this.base, { fetchFn: this.fetchFn });

  readonly alarms = (): Promise<Alarm[]> => getAlarms(this.base, { fetchFn: this.fetchFn });

  readonly announcements = (cursor?: number, limit?: number): Promise<WithdrawAnnouncementRecord[]> =>
    getAnnouncements(this.base, cursor, limit, this.fetchFn);

  readonly resolveName = (name: string): Promise<NameRecord | null> => resolveName(this.base, name, this.fetchFn);

  readonly registerName = (reg: NameRegistration): Promise<NameRecord> => registerName(this.base, reg, this.fetchFn);

  readonly payPortal = (name: string): Promise<PortalIssuance> => payPortal(this.base, name, this.fetchFn);

  readonly unswept = (cursor?: number, limit?: number): Promise<PortalRecord[]> =>
    fetchUnswept(this.base, cursor, limit, this.fetchFn);

  readonly portalAnnouncements = (cursor?: number, limit?: number): Promise<PortalRecord[]> =>
    getPortalAnnouncements(this.base, cursor, limit, this.fetchFn);

  readonly obtainViewToken = (ownerCompressed: string, ownerPrivateKey: FieldInput): Promise<ViewToken> =>
    obtainViewToken(this.base, ownerCompressed, ownerPrivateKey, this.fetchFn);

  /**
   * Bind an owner for the authed reads. CUSTODY INVARIANT: a TOKEN-mode binding
   * may live for a session (the token is the auth, no key material is held); a
   * KEY-mode binding must be constructed TRANSIENTLY inside a read — the
   * caller's key cache stays the one cross-call key holder — and the key may be
   * a thunk so each read pulls through the lock at call time. Either way every
   * signed URL is built FRESH per call (a signed URL embeds its ts, and a cached
   * one would expire out of the server's replay window mid-session).
   */
  readonly asOwner: AsOwner = ((owner: string, auth: { token: string } | { key: OwnerKeySource }) =>
    // The cast is the standard overload-implementation widening a function
    // DECLARATION would get for free; an arrow property has to say it.
    "token" in auth ? this.tokenReads(owner, auth.token) : this.keyReads(owner, auth.key)) as AsOwner;

  private readonly tokenReads = (owner: string, token: string): OwnerTokenReads => ({
    notes: () => fetchNotes(buildNotesTokenUrl(this.base, owner, token), { fetchFn: this.fetchFn }),
    historyPage: (page: HistoryPageQuery = {}) => fetchHistoryPage(this.base, owner, token, page, this.fetchFn),
  });

  private readonly keyReads = (owner: string, key: OwnerKeySource): OwnerKeyReads => {
    // Normalized to a thunk so every read below re-draws the key — nothing here
    // outlives the call when the caller handed a lock-backed thunk.
    const keyOf = typeof key === "function" ? key : (): FieldInput => key;
    return {
      notes: () => fetchNotes(buildNotesUrl(this.base, owner, keyOf()), { fetchFn: this.fetchFn }),
      history: () => fetchHistory(buildHistoryUrl(this.base, owner, keyOf()), { fetchFn: this.fetchFn }),
      announcements: () =>
        fetchAnnouncements(buildAnnouncementsUrl(this.base, owner, keyOf()), { fetchFn: this.fetchFn }),
      signedPath: (leafIndex: number) =>
        getSignedPath(this.base, leafIndex, owner, keyOf(), { fetchFn: this.fetchFn }),
    };
  };
}
