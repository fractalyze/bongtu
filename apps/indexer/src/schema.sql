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
  kind            TEXT   NOT NULL,     -- received | sent | withdraw | deposit | self
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
