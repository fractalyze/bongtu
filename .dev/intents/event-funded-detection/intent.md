# Event-driven funded detection for issued destinations

Author: JunBeom Lee. Status: accepted.
Origin: conversation

## Problem

The sweeper bot finds money by polling: every issued destination row is a
candidate forever, and the bot reads its token balance until something
appears. Measured on the live Sepolia demo: rows are minted on every
resolution and page visit, so never-funded rows accumulate (two throwaway
"ping" rows already sit in the feed) and each one costs RPC reads on every
cycle; the rate-capped public RPC's load balancer lags, making fresh balance
reads flap to zero (the bot needed retry loops to trust its own reads); and
sweep latency is bounded by the poll interval, not by the payment. Because
issuance is unauthenticated (PoC posture: rows are hints), the candidate set
is attacker-growable while the polling cost is ours.

## Proposed outcome

The system knows a destination is funded the moment the token Transfer
lands, without per-row balance polling: an indexer-side tail over the funds
chain's Transfer logs marks the destination's row funded, and the bot's
sweep trigger consumes that mark. Falsifiable: on the demo stack, a USDC
transfer to an issued destination flips its row to funded within the
indexer's ingest lag; the bot sweeps it having issued zero balance reads
against never-funded rows; stopping the tail stalls detection, proving the
polling path is gone.

## Affected users and systems

Recipient (sweep latency) and operator (RPC load), on the consumer receive
product. Components: indexer (ingest tail, store, portal routes), sweeper
bot. No circuits, contracts, or wallet changes.

## Constraints

The live Sepolia demo stack keeps working (record pair consumed by field
name). The public RPC is rate-capped: the tail must fetch logs in
LOG_CHUNK-sized windows like the existing ingest. Funded-ness is public
on-chain data, so serving it is not a privacy regression. Reorg safety on
the funds chain: a flag set on a reorged-out Transfer must not trigger a
doomed sweep loop.

## Open questions

Confirmation depth before flagging funded. Whether the flag is served on
the public announcement routes or stays operator-internal (the
receive-arrival-notice intent wants it client-visible). Pool-token-only
detection vs also native-asset transfers (which the sweeper cannot sweep
today - is a stranded-ETH warning worth surfacing). Backfill semantics when
the tail restarts (missed-window rescan). Whether the bot keeps a slow
reconciliation poll as a safety net against tail bugs.
