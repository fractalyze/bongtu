# @bongtu/sweeper

The portal-deposit operator bot (Slice ⑤ U-P3, PoC). A portal payer can only do
a plain kKRW transfer to the CREATE2 destination the resolver issued; this bot —
holding the PortalFactory owner key, `sweep` being `onlyOwner` by the recorded
Slice ⑤ trust concession — watches the indexer's `/portal/unswept` feed and, for
each **funded** destination, builds a deposit minting the full balance to the
announced recipient's bjj key, proves it on CPU snarkjs, and calls
`factory.sweep`. The indexer flips `swept` from the factory's `Swept` event; the
bot never marks state itself.

PoC boundaries (stated, not hidden): no batching, no fee, full-balance sweeps
only, retries by rescan. Unswept rows are HINTS (issuance is unauthenticated) —
only a nonzero ERC-20 balance triggers work.

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
| `FACTORY`      | the record's `portalFactory` field             |
| `TOKEN`        | sdk `TOKEN_ADDRESS` (`@bongtu/core/network`)   |
| `CHAIN_ID`     | the sdk `CHAIN_ID`                             |
| `PORT`         | `8710`                                         |
| `POLL_MS`      | `15000`                                        |
| `CIRCUITS_OUT` | `<repo>/circuits/out` (deposit zkey + wasm)    |

Endpoint: `GET /health` → `{ ok, sweeper, balanceWei, lastSweepAt, unswept }`,
`ok=false` when the gas balance is zero (an unfunded sweeper silently stops
shielding payments — that must be visible). The key is never logged and never
served; its only public trace is the sweeper address.

## Test

```
npm test          # headless node:test — fake indexer client, fake viem clients, fake prover
npm run typecheck
```
