# pay-web — the sender-facing pay page

The static page a stealth-receive URL points at: `/p/{label}` resolves the
recipient's directory record, derives a fresh one-time destination **in the
visitor's browser** (`@bongtu/core/stealth` — no server secret participates),
records the announcement **before** displaying anything, parity-checks the
server's destination recompute against the local CREATE2 mapping, and shows
the address + QR + chain facts. The visitor holds nothing and signs nothing:
no wallet code, no proving code — `@bongtu/core` plus a QR encoder is the
whole dependency surface.

Trust posture, failure modes, and the announce wire contract are owned by
[docs/portal.md](../../docs/portal.md) (receive section) and
[docs/indexer.md](../../docs/indexer.md) (`POST /portal/announce`).

## Run

```bash
npm run dev --workspace @bongtu/pay-web        # Vite dev server (proxies /indexer)
npm test --workspace @bongtu/pay-web           # headless issuance-decision gates
npm run typecheck --workspace @bongtu/pay-web
npm run build --workspace @bongtu/pay-web
```

The dev proxy forwards `/indexer/*` to a local indexer (vite.shared.ts, same
convention as the other apps). The indexer must run with `PORTAL_PRIV_FACTORY`
set or the announce route 404s.

## Configuration (build-time env)

- `VITE_INDEXER_URL` — indexer base (default `/indexer`, the rewrite/proxy path).
- `VITE_PORTAL_PRIV_FACTORY` — the PortalPrivFactory address (copy BY FIELD NAME from
  `deploy/addresses.<chainid>.json` `portalPrivFactory`).
- `VITE_SWEEPER_INITCODE_HASH` — the factory's `sweeperInitCodeHash` (the
  committed parity vector's value; see `chains/evm/test/PortalPriv.t.sol`).

The last two pin the CREATE2 mapping the page computes locally, so a hostile
indexer can at worst hide a payment, never redirect one: the server's
recomputed destination is only checked for parity, and a mismatch fails the
page closed. Unset, the page reports itself unconfigured instead of deriving
garbage.

## Deploy

Its own Vercel project (the other apps' pattern): `vercel.json` rewrites
`/indexer/*` to the live indexer and `/p/:label` to the SPA root, and skips
builds untouched by the app/packages/lock (`ignoreCommand`).
