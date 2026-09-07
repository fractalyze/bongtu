# @bongtu/sweeper

The portal-deposit operator bot (PoC; the portal design is
[`docs/portal.md`](../../docs/portal.md)). A portal payer can only do
a plain kKRW transfer to the CREATE2 destination the resolver issued; this bot —
holding the PortalFactory owner key, `sweep` being `onlyOwner` per the portal
design's recorded v1 trust concession — watches the indexer's `/portal/unswept` feed and, for
each **funded** destination, builds a deposit minting the full balance to the
announced recipient's bjj key, proves it on CPU snarkjs, and calls
`factory.sweep`. The indexer flips `swept` from the factory's `Swept` event; the
bot never marks state itself.

PoC boundaries (stated, not hidden): no batching, no fee, full-balance sweeps
only, retries by rescan. Unswept rows are HINTS (issuance is unauthenticated) —
only a nonzero ERC-20 balance triggers work.

## Modes

- **enterprise** (default) — the original portal path above: sweeps through the
  `PortalFactory`, proving the enterprise `deposit` (19 publics).
- **priv** (`MODE=priv`) — the consumer receive product
  ([`docs/portal.md`](../../docs/portal.md#receiving-the-consumer-pay-page)):
  sweeps through the `PortalPrivFactory`, proving `depositPriv` (16 publics)
  sealed to the recipient's REGISTERED consumer triple (resolved from the name
  directory per sweep — the work feed carries only name+owner). The sweep call
  carries the announcement tuple, which the factory re-emits on-chain as the
  recovery path. Balances strictly below `MIN_SWEEP` are left unswept. Each
  mode keeps to its own factory's feed rows, so the two bots coexist against
  one indexer.

## Run

```
SWEEPER_KEY=0x… INDEXER_URL=http://… FACTORY=0x… node --import tsx src/index.ts
```

Env (`SWEEPER_KEY` and `INDEXER_URL` are required — the sweeper refuses to boot
without either, one clear line each):

| var            | default                                        |
|----------------|------------------------------------------------|
| `SWEEPER_KEY`  | REQUIRED — the factory-owner EOA private key   |
| `INDEXER_URL`  | REQUIRED — indexer base URL (`/portal/unswept`)|
| `RPC`          | `http://127.0.0.1:8545` (anvil)                |
| `POOL`         | `deploy/addresses.<CHAIN_ID>.json` `pool`      |
| `FACTORY`      | the record's `portalFactory` field (mode enterprise) or `portalPrivFactory` (mode priv) |
| `TOKEN`        | sdk `TOKEN_ADDRESS` (`@bongtu/core/network`)   |
| `CHAIN_ID`     | the sdk `CHAIN_ID`                             |
| `PORT`         | `8710`                                         |
| `POLL_MS`      | `15000`                                        |
| `CIRCUITS_OUT` | `<repo>/circuits/out` (the mode's zkey + wasm) |
| `MODE`         | `enterprise` (`priv` flips the consumer path) |
| `MODULE`       | priv mode: `deploy/modules.<CHAIN_ID>.json` `depositPrivModule` |
| `MIN_SWEEP`    | priv mode: `0` (dust threshold, token base units) |
| `PORTAL_OPERATOR_TOKEN` | unset — REQUIRED once the indexer gates its attributed feed (401 without) |

Endpoint: `GET /health` → `{ ok, sweeper, balanceWei, lastSweepAt, unswept }`,
`ok=false` when the gas balance is zero (an unfunded sweeper silently stops
shielding payments — that must be visible). The key is never logged and never
served; its only public trace is the sweeper address.

## Test

```
npm test          # headless node:test — fake indexer client, fake viem clients, fake prover
npm run typecheck
```
