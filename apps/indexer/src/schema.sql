-- bongtu indexer Postgres schema (U-I2). Stores the DERIVED read state so a
-- restart RESUMES from the block cursor instead of replaying the whole chain.
-- Idempotent (CREATE ... IF NOT EXISTS): applied on every boot with DATABASE_URL.
--
-- What is persisted, and how it is used on boot:
--   events      the ciphertext feed — replayed through the in-memory read model
--               to rebuild /events + the disclosure /alarms + the seq counter.
--   nullifiers  the spent-nullifier set (/nullifiers).
--   leaves      one row per single-append leaf (its commitment) or per disburse
--               block (its subtree root) — MirrorTree.rebuildFromLeaves folds the
--               frontier back to the on-chain root without an event re-scan.
--   ingest_cursor  the single last-fully-ingested block; ingest resumes at +1.
--   notes / history / envelope_alarms / applied_ops  the arbiter note ledger
--               (only written when the indexer holds the arbiter key).
--
-- The chain stays the source of truth (SPEC §6b: the indexer is a convenience /
-- availability layer, not trust-critical for funds); Postgres is a durable cache.

CREATE TABLE IF NOT EXISTS events (
  seq          BIGINT PRIMARY KEY,
  tx_hash      TEXT   NOT NULL,
  log_index    INTEGER NOT NULL,
  block_number BIGINT NOT NULL,
  kind         TEXT   NOT NULL,
  disclosure   TEXT,            -- the disclosure status string, or NULL
  payload      JSONB  NOT NULL, -- the full FeedEntry (feed is rebuilt from this)
  UNIQUE (tx_hash, log_index)   -- the (txHash, logIndex) first-sight dedup key
);

CREATE TABLE IF NOT EXISTS nullifiers (
  nf TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS leaves (
  leaf_index  BIGINT PRIMARY KEY,
  commitment  TEXT,   -- decimal; a single-append leaf value (NULL for a batch row)
  batch_root  TEXT    -- decimal; a disburse subtree root (NULL for a single leaf)
);

CREATE TABLE IF NOT EXISTS ingest_cursor (
  id         INTEGER PRIMARY KEY,  -- always 1 (single-row table)
  last_block BIGINT  NOT NULL
);

CREATE TABLE IF NOT EXISTS notes (
  leaf_index BIGINT PRIMARY KEY,   -- each note sits at a distinct tree leaf
  owner_key  TEXT    NOT NULL,     -- "x,y" decimal bjj pubkey
  value      TEXT    NOT NULL,     -- decimal
  salt       TEXT    NOT NULL,     -- decimal
  commitment TEXT    NOT NULL,     -- decimal
  tx_hash    TEXT    NOT NULL,
  spent      BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS notes_owner_idx ON notes (owner_key);
CREATE INDEX IF NOT EXISTS notes_commitment_idx ON notes (commitment);

CREATE TABLE IF NOT EXISTS history (
  seq             BIGINT PRIMARY KEY,  -- global chain-apply order (sorted desc on read)
  owner_key       TEXT   NOT NULL,     -- "x,y" decimal bjj pubkey
  kind            TEXT   NOT NULL,     -- received | sent | withdraw | deposit
  counterparty    TEXT,                -- compressed bjj pubkey hex, or NULL
  amount          TEXT   NOT NULL,     -- decimal
  tx_hash         TEXT   NOT NULL,
  block_timestamp BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS history_owner_idx ON history (owner_key);

CREATE TABLE IF NOT EXISTS envelope_alarms (
  id         BIGSERIAL PRIMARY KEY,
  kind       TEXT NOT NULL,
  tx_hash    TEXT NOT NULL,
  detail     TEXT NOT NULL,
  recomputed TEXT NOT NULL,  -- decimal
  expected   TEXT NOT NULL,  -- decimal
  -- (tx_hash, detail) is the natural key: detail pins the leaf/batch position, so
  -- a re-derived alarm is ON CONFLICT DO NOTHING'd like every sibling table (no
  -- duplicate on re-ingest), instead of the BIGSERIAL id silently multiplying it.
  UNIQUE (tx_hash, detail)
);

CREATE TABLE IF NOT EXISTS applied_ops (
  tx_hash   TEXT    NOT NULL,
  log_index INTEGER NOT NULL,
  PRIMARY KEY (tx_hash, log_index)
);

-- The name directory (src/names.ts): the ONE indexer-owned mutable table — not
-- chain-derived, populated by signed POST /names registrations.
CREATE TABLE IF NOT EXISTS names (
  name       TEXT   PRIMARY KEY,
  owner      TEXT   NOT NULL,  -- compressed bjj pubkey hex
  view_pub   TEXT   NOT NULL,  -- compressed bjj stealth view pubkey hex
  spend_pub  TEXT   NOT NULL,  -- compressed secp256k1 stealth spend pubkey hex
  updated_at BIGINT NOT NULL   -- unix seconds, server clock at acceptance
);
CREATE INDEX IF NOT EXISTS names_owner_idx ON names (owner);
-- Consumer registry triple (OPMOD §6.1): the note-layer view pubkey + ML-KEM ek,
-- set only by v2-signed writes (v1 writes leave them untouched; NULL = unset).
ALTER TABLE names ADD COLUMN IF NOT EXISTS note_view_pub TEXT;
ALTER TABLE names ADD COLUMN IF NOT EXISTS kem_ek TEXT;

-- The op-module registry mirror (src/modules.ts, OPMOD §1.4): derived from the
-- pool's balanced ModuleRegistered/ModuleRemoved stream. Removed modules keep
-- their row (registered = FALSE) — the chunk watch-set may still need them.
CREATE TABLE IF NOT EXISTS modules (
  address    TEXT    PRIMARY KEY,  -- lowercase 0x-hex
  registered BOOLEAN NOT NULL
);

-- Consumer-disburse kem chunk transport (src/kemchunks.ts, OPMOD §5): one row
-- per batch (its K keccak commitments) + one per ACCEPTED chunk (data NULL when
-- the submission tx's calldata was not directly decodable).
CREATE TABLE IF NOT EXISTS kem_batches (
  batch_id        BIGINT PRIMARY KEY,  -- == startLeafIndex (unique forever)
  module          TEXT   NOT NULL,     -- lowercase module address
  tx_hash         TEXT   NOT NULL,
  chunk_hashes    TEXT   NOT NULL,     -- JSON array of 0x-hex keccak256
  batch_timestamp BIGINT NOT NULL,     -- unix seconds (the kem-withheld grace anchor)
  outputs         INTEGER NOT NULL     -- B: per-output kem cts the chunks carry
);
CREATE TABLE IF NOT EXISTS kem_chunks (
  batch_id    BIGINT  NOT NULL,
  chunk_index INTEGER NOT NULL,
  data        TEXT,                    -- 0x-hex chunk bytes, or NULL (undecodable)
  tx_hash     TEXT,                    -- the accepting submit tx — what boot re-fetches
                                       -- when data is NULL (accepted-unassembled)
  PRIMARY KEY (batch_id, chunk_index)
);
ALTER TABLE kem_chunks ADD COLUMN IF NOT EXISTS tx_hash TEXT;

-- Portal-deposit issuance records (src/portal.ts): announcements the resolver
-- writes at POST /pay/{name} time (indexer-owned like names — issuance has no
-- chain footprint) whose swept state IS chain-derived: the factory's Swept
-- event flips it inside the same ingest transaction as the block cursor.
CREATE TABLE IF NOT EXISTS portal_announcements (
  seq           BIGINT  PRIMARY KEY,  -- issuance order (the feed's cursor key)
  name          TEXT    NOT NULL,     -- the resolved payment name
  owner         TEXT    NOT NULL,     -- compressed bjj pubkey of the name's owner
  ephemeral_pub TEXT    NOT NULL,     -- packed bjj ephemeral pubkey R (0x-hex)
  view_tag      INTEGER NOT NULL,
  stealth_addr  TEXT    NOT NULL,     -- lowercase 0x-hex; portalSalt(this) == the Swept salt
  destination   TEXT    NOT NULL,     -- the CREATE2 sweeper address the payer funds
  created_at    BIGINT  NOT NULL,     -- unix seconds, server clock at issuance
  swept         BOOLEAN NOT NULL,
  swept_tx_hash TEXT,
  swept_amount  TEXT                  -- decimal
);
CREATE INDEX IF NOT EXISTS portal_stealth_addr_idx ON portal_announcements (stealth_addr);
CREATE INDEX IF NOT EXISTS portal_owner_idx ON portal_announcements (owner);
