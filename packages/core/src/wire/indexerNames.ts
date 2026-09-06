// wire/indexerNames.ts — the /names directory, withdraw announcements and the
// portal deposit endpoints (split from indexerApi.ts).
import type { FieldInput } from "@bongtu/core/babyjub";
import { getJson, postJson, getJsonOr404, trim, type IndexerFetchOpts } from "./indexerHttp.js";
import { signedOwnerProof, signedReadUrl } from "./indexerReads.js";
import type { WithdrawAnnouncementRecord } from "./indexerDto.js";
// --- name directory (public /names endpoints) ------------------------------------
//
// The stealth/payment directory: a human name resolving to the owner's bjj
// pubkey (the in-pool receive identity) and stealth meta-address (the pool-edge
// one). Server half: apps/indexer src/names.ts + api/routes/names.ts.

import {
  nameAuthMessage,
  nameBindingField,
  nameAuthMessageV2,
  nameBindingFieldV2,
  NOTE_VIEW_PUB_ZERO,
  KEM_EK_ZERO,
} from "@bongtu/core/eddsa";
import type { StealthMetaAddress } from "@bongtu/core/stealth";

// The v2 zero-sentinels, re-exported so a client clearing its consumer pair
// keeps one import path with the fetch builders below.
export { NOTE_VIEW_PUB_ZERO, KEM_EK_ZERO } from "@bongtu/core/eddsa";

// Lowercase label, 3–32 chars, alnum with interior hyphens — a deliberately
// DNS-label-shaped grammar so a name can later become an ENS/CCIP subname
// without a migration. The grammar lives HERE, beside the wire shapes, so the
// server's registry and the wallet's pay-by-name form judge input with the ONE
// function — a form that accepted what the registry rejects (or vice versa)
// would be wire drift by another name.
const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$/;

/** Canonical form of a requested name, or null when no canonical form exists. */
export function normalizeName(raw: string): string | null {
  const name = raw.trim().toLowerCase();
  return NAME_PATTERN.test(name) ? name : null;
}

/** One directory record, as served by GET /names/:name. */
export interface NameRecord {
  name: string;
  /** compressed bjj pubkey — the owner's in-pool receive address. */
  owner: string;
  /** compressed bjj stealth VIEW pubkey (see stealth.ts). */
  viewPub: string;
  /** compressed secp256k1 stealth SPEND pubkey (see stealth.ts). */
  spendPub: string;
  /** compressed bjj NOTE-LAYER view pubkey (consumer triple, OPMOD §6.1) —
   *  absent on records registered before the consumer extension. */
  noteViewPub?: string;
  /** ML-KEM-768 encapsulation key, 0x + 1184-byte hex (consumer triple) —
   *  required together with `noteViewPub`, absent on legacy records. */
  kemEk?: string;
  /** unix seconds of the last accepted registration (server clock). */
  updatedAt: number;
}

/** The signed POST /names body. OPMOD §6.4 form selection is by payload shape:
 *  `noteViewPub`/`kemEk` present (required together) selects the v2 signature
 *  form exclusively; neither present selects v1 exclusively — no dual-try. */
export interface NameRegistration {
  name: string;
  owner: string;
  viewPub: string;
  spendPub: string;
  noteViewPub?: string;
  kemEk?: string;
  ts: number;
  sig: string;
}

/**
 * Build a registration the indexer will accept: the owner key signs the
 * payload-binding tuple (eddsa.ts nameAuthMessage), so the signature authorises
 * exactly this (name -> meta) mapping and nothing else. `nowSeconds` is
 * injectable for deterministic tests; the server allows |now - ts| <= 300s.
 */
export function buildNameRegistration(
  name: string,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
  meta: StealthMetaAddress,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): NameRegistration {
  const { owner, ts, sig } = signedOwnerProof(
    ownerCompressed,
    ownerPrivateKey,
    (pub, at) => nameAuthMessage(pub, nameBindingField(name, meta.viewPub, meta.spendPub), at),
    nowSeconds,
  );
  return { name, owner, viewPub: meta.viewPub, spendPub: meta.spendPub, ts, sig };
}

/** The note-layer consumer identity a v2 registration binds beside the stealth
 *  meta (OPMOD §6.1): the bjj note-view pubkey + the ML-KEM-768 encapsulation
 *  key — an unusable half-identity alone, so always required together. */
export interface ConsumerNameIdentity {
  noteViewPub: string; // compressed bjj pubkey, 0x + 32-byte hex
  kemEk: string; // 0x + 1184-byte hex
}

/**
 * Build a v2 registration carrying (or clearing) the consumer triple. The owner
 * signs the FIVE-segment v2 binding under the v2 domain tag (OPMOD §6.4): pass
 * the identity to set/rotate it, or `"clear"` to sign the zero-sentinels —
 * clearing is a signed statement, never an omission. Legacy v1 payloads keep
 * using `buildNameRegistration` unchanged.
 */
export function buildNameRegistrationV2(
  name: string,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
  meta: StealthMetaAddress,
  consumer: ConsumerNameIdentity | "clear",
  nowSeconds: number = Math.floor(Date.now() / 1000),
): NameRegistration {
  const pair = consumer === "clear" ? { noteViewPub: NOTE_VIEW_PUB_ZERO, kemEk: KEM_EK_ZERO } : consumer;
  const { owner, ts, sig } = signedOwnerProof(
    ownerCompressed,
    ownerPrivateKey,
    (pub, at) =>
      nameAuthMessageV2(
        pub,
        nameBindingFieldV2(name, meta.viewPub, meta.spendPub, pair.noteViewPub, pair.kemEk),
        at,
      ),
    nowSeconds,
  );
  return {
    name,
    owner,
    viewPub: meta.viewPub,
    spendPub: meta.spendPub,
    noteViewPub: pair.noteViewPub,
    kemEk: pair.kemEk,
    ts,
    sig,
  };
}

/** POST a registration; resolves to the accepted record, throws on any error
 *  status (the server's error body text is included). */
export function registerName(
  indexerUrl: string,
  reg: NameRegistration,
  fetchFn: typeof fetch = fetch,
): Promise<NameRecord> {
  return postJson<NameRecord>(`${trim(indexerUrl)}/names`, reg, fetchFn);
}

/** Resolve a name to its directory record; null when it is not registered. */
export function resolveName(
  indexerUrl: string,
  name: string,
  fetchFn: typeof fetch = fetch,
): Promise<NameRecord | null> {
  return getJsonOr404<NameRecord>(`${trim(indexerUrl)}/names/${encodeURIComponent(name)}`, fetchFn);
}

/** The public announcement feed (seq > cursor, capped). The trustless scan-all
 *  path — pair each record with scanStealthAnnouncement to find your own. */
export function getAnnouncements(
  indexerUrl: string,
  cursor = -1,
  limit = 5000,
  fetchFn: typeof fetch = fetch,
): Promise<WithdrawAnnouncementRecord[]> {
  return getJson<WithdrawAnnouncementRecord[]>(
    `${trim(indexerUrl)}/announcements?cursor=${cursor}&limit=${limit}`,
    fetchFn,
  );
}

/** The signed arbiter-mode `GET /announcements?owner=` URL — only the caller's
 *  own announcements, no scanning (same read-auth as /notes). */
export function buildAnnouncementsUrl(
  indexerUrl: string,
  ownerCompressed: string,
  ownerPrivateKey: FieldInput,
): string {
  return signedReadUrl(indexerUrl, "announcements", ownerCompressed, ownerPrivateKey);
}

/** Fetch a signed /announcements URL (from `buildAnnouncementsUrl`). */
export function fetchAnnouncements(url: string, opts: IndexerFetchOpts = {}): Promise<WithdrawAnnouncementRecord[]> {
  return getJson<WithdrawAnnouncementRecord[]>(url, opts.fetchFn, opts.signal);
}

// --- portal deposits (public /pay + /portal endpoints) ----------------------------
//
// The Curvy-style stealth front door (Slice ⑤): POST /pay/{name} makes the
// INDEXER derive a fresh stealth address for the name's meta-address and record
// the announcement at issuance time (a CEX sender can never announce), returning
// the CREATE2 sweeper `destination` the payer funds with a plain transfer.
// Server half: apps/indexer src/portal.ts + api/routes/portal.ts.

/** What POST /pay/{name} returns: everything the payer (and a paranoid
 *  recipient re-deriving it) needs. `destination` is the CREATE2 sweeper
 *  address to fund; `stealthAddr` is the underlying DKSAP one-time EOA whose
 *  bytes32 left-pad is the CREATE2 salt (stealth.ts portalSalt — the one rule);
 *  `factory` names the PortalFactory the wrap was computed against. */
export interface PortalIssuance {
  /** the CREATE2 sweeper address the payer actually funds (EIP-55). */
  destination: string;
  /** "0x" + 32-byte hex — the packed bjj ephemeral pubkey R (the announcement). */
  ephemeralPub: string;
  viewTag: number;
  /** "0x" + 20-byte hex — the DKSAP-derived one-time EOA (the CREATE2 salt's address). */
  stealthAddr: string;
  /** the PortalFactory address the destination was derived against. */
  factory: string;
}

/** One portal/receive announcement as PUBLICLY served (/portal/announcements):
 *  the announcement half mirrors WithdrawAnnouncementRecord (ephemeralPub,
 *  viewTag, seq cursor) plus the payment coordinates. Deliberately carries NO
 *  recipient attribution (no name, no owner) — the receive product's
 *  unlinkability claim is served here, and the recipient does not need
 *  attribution: its view key re-derives which records are its own
 *  (scanStealthAnnouncement). `swept` flips when a factory Swept event lands. */
export interface PortalPublicRecord {
  kind: "portal";
  /** issuance-order cursor key (the portal feed's own seq space, NOT the
   *  chain-event feed's — issuance has no tx to sequence by). */
  seq: number;
  /** address-encoding flavor of `stealthAddr`/`destination` — "evm" today; a
   *  non-EVM rail reuses these shapes with a different flavor. */
  rail: string;
  /** the factory address the destination was derived against (portal or
   *  receive pair) — public, since the destination itself implies it. */
  factory: string;
  ephemeralPub: string;
  viewTag: number;
  stealthAddr: string;
  destination: string;
  /** unix seconds of issuance (server clock). */
  createdAt: number;
  swept: boolean;
  sweptTxHash: string | null;
  /** decimal; the swept deposit amount (the proof's public amount). */
  sweptAmount: string | null;
}

/** The OPERATOR-side record (/portal/unswept behind the operator token): the
 *  public shape plus the attribution the sweep bot needs to build the deposit
 *  for the right recipient. Never served on a public projection. A row
 *  backfilled from a chain `Announced` event carries empty name/owner (chain
 *  data has no attribution — such rows are already swept). */
export interface PortalRecord extends PortalPublicRecord {
  name: string;
  /** compressed bjj pubkey of the name's owner (the recipient's in-pool identity). */
  owner: string;
}

/** What the pay page POSTs to /portal/announce: the browser-side derivation's
 *  public half, keyed by the recipient's directory label. The server NEVER
 *  trusts a client destination — it recomputes addressOf(portalSalt(
 *  stealthAddr)) itself and returns the public record carrying it, which the
 *  page parity-checks before display. */
export interface PortalAnnounceRequest {
  label: string;
  /** "0x" + 32-byte hex — the packed bjj ephemeral pubkey R. */
  ephemeralPub: string;
  viewTag: number;
  /** "0x" + 20-byte hex — the DKSAP-derived one-time EOA. */
  stealthAddr: string;
  /** address-encoding flavor; omitted means "evm". */
  rail?: string;
}

/** Record a browser-side issuance (the pay page calls this BEFORE displaying
 *  the address). 404: unknown label or receive deposits unconfigured; 409: the
 *  stealth address is already recorded (first write wins — a hijacker
 *  re-announcing an observed destination under its own label always loses the
 *  race to the honest record). */
export function announcePortal(
  indexerUrl: string,
  req: PortalAnnounceRequest,
  fetchFn: typeof fetch = fetch,
): Promise<PortalPublicRecord> {
  return postJson<PortalPublicRecord>(`${trim(indexerUrl)}/portal/announce`, req, fetchFn);
}

/** Resolve `name` into a fresh portal destination (the pay-by-name front door).
 *  Every call mints a NEW record server-side — call once per intended payment.
 *  404: unknown name, or portal deposits not configured on this indexer. */
export function payPortal(
  indexerUrl: string,
  name: string,
  fetchFn: typeof fetch = fetch,
): Promise<PortalIssuance> {
  return postJson<PortalIssuance>(`${trim(indexerUrl)}/pay/${encodeURIComponent(name)}`, {}, fetchFn);
}

/** The sweeper bot's work feed: unswept ATTRIBUTED records (seq > cursor,
 *  capped). Operator-facing: when the indexer is started with
 *  PORTAL_OPERATOR_TOKEN, the same value must ride the x-operator-token
 *  header or the read is 401 (the attribution split — the public projection
 *  never carries name/owner). */
export function fetchUnswept(
  indexerUrl: string,
  cursor = -1,
  limit = 5000,
  fetchFn: typeof fetch = fetch,
  operatorToken?: string,
): Promise<PortalRecord[]> {
  return getJson<PortalRecord[]>(
    `${trim(indexerUrl)}/portal/unswept?cursor=${cursor}&limit=${limit}`,
    fetchFn,
    undefined,
    operatorToken ? { "x-operator-token": operatorToken } : undefined,
  );
}

/** The full public announcement feed (swept and not) — the recipient's
 *  scan-all path: pair each record with scanStealthAnnouncement, then map the
 *  matched address through portalSalt/create2Address to confirm `destination`.
 *  Attribution-free by design (PortalPublicRecord). */
export function getPortalAnnouncements(
  indexerUrl: string,
  cursor = -1,
  limit = 5000,
  fetchFn: typeof fetch = fetch,
): Promise<PortalPublicRecord[]> {
  return getJson<PortalPublicRecord[]>(
    `${trim(indexerUrl)}/portal/announcements?cursor=${cursor}&limit=${limit}`,
    fetchFn,
  );
}
