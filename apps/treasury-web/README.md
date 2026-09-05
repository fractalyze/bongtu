# bongtu treasury wallet

The institution-side self-custody wallet (SPEC §7 public app): connect any installed
extension (EIP-6963) or WalletConnect through the RainbowKit modal, derive a BabyJubJub
spending key from an `eth_signTypedData_v4` signature (no seed to store — the same
account regenerates the same key every session), and drive the audited pool entrypoints
(transfer / transfer10x2 / withdraw / deposit) with proofs generated **in the browser** —
a self-custody wallet never sends spending-key witnesses to a server. Balance and
activity read from an arbiter indexer over a view-token session. It imports the
`@bongtu/*` workspace **source directly**, so every commitment / nullifier /
Poseidon-sponge ciphertext it builds is byte-identical to what the provers prove and the
contract verifies. The custody and UX story in depth — key derivation, the lock,
WalletConnect, spend chains, discovery, portal receive, pay-by-name — is
[`docs/wallet.md`](../../docs/wallet.md); its enterprise-wallet section names what is
specific to this app.

Vite + TypeScript + React; `wagmi` v2 + `viem` v2 + RainbowKit at the wallet edge, the
`@bongtu/client` protocol engine and `@bongtu/ui` shared app modules, `snarkjs` for
in-browser proving.

## Run

```sh
export PATH=$HOME/.foundry/bin:$HOME/.nvm/versions/node/v22.17.1/bin:$PATH
cd apps/treasury-web
npm install
npm run dev        # Vite dev server -> open the printed URL (needs a wallet extension
                   #   + a reachable arbiter-mode indexer)
```

Gates:

```sh
npm test           # headless node:test gates (no wallet/chain/assets), see Layout
npm run typecheck  # tsc --noEmit
npm run build      # vite production build (snarkjs splits into its own dynamic chunk)
```

**Gate reality.** A wallet extension and the live circuit assets are not present in the
build env, so the connect → sign → prove → submit I/O edge is wired but not exercised
here. Everything pure and security-critical gates headless: derivation determinism,
balance summing and the receiver-ciphertext trial decrypt, transfer/withdraw witness
assembly (`@bongtu/core/proving` `ProvingRequest` form — the same shape
`deploy/gates/e2e_orchestrator.ts` drives by hand), the action machine, error surfaces,
copy pins, and the selfscan wiring (see Layout).

## Env knobs

All are build-time Vite injects: an existing deployment does not pick up a change.

| var | default | meaning |
|---|---|---|
| `VITE_DISCOVERY` | `arbiter` | only the literal `selfscan` flips the no-auditor self-scan profile ([docs/wallet.md](../../docs/wallet.md#indexer-dependency)) |
| `VITE_INDEXER_URL` | `/indexer` (relative, same-origin) | where every indexer read goes; an absolute URL bypasses the proxy/rewrite path entirely |
| `VITE_INDEXER_PROXY_TARGET` | `http://localhost:8600` | dev only: where the Vite `/indexer` proxy forwards (root `vite.shared.ts`) |
| `VITE_TESTNET` | `true` | the literal `false` switches every testnet-only affordance (mint/faucet UI, Testnet chips) off in one place |
| `VITE_WC_PROJECT_ID` | unset | unset, the connect modal lists installed extensions only; set, the WalletConnect QR / deep-link path joins it ([docs/wallet.md](../../docs/wallet.md#connecting-and-walletconnect)) |

## Circuit assets

In-browser proving needs each circuit's `wasm` + `zkey` at
`${circuitBaseUrl}/<circuit>.{wasm,zkey}` (default `/circuits`). They are not bundled
(`transfer.zkey` ≈ 29 MB, `withdraw.zkey` ≈ 25 MB, `transfer10x2.zkey` ≈ 95 MB) and have
one home in every environment: the `bongtu-circuits` blob store under
`circuits/<CIRCUITS_VERSION>/`. Deployments reach it through the `vercel.json`
`/circuits` rewrite (which carries the same version in its destination path); local dev
reaches it through the proxy in `vite.config.ts`, which reads the version pin out of
`src/config.ts` so a bump re-points dev automatically. A circuit regen is one atomic
diff: upload the new assets (`deploy/gates/upload_circuits.sh`, which refuses assets
whose combined zkey hash does not match the pin), bump `CIRCUITS_VERSION`, and repoint
the `vercel.json` rewrite together. The stale-zkey hazard is
[docs/wallet.md](../../docs/wallet.md#proving-in-the-browser)'s.

## GPL decision

Shipping `snarkjs` (GPL-3.0) to the page **is** distribution, so no server-side
isolation applies (and a self-custody wallet must not delegate its proving anyway). The
recorded SPEC §6 decision is option **(a): accept GPL for the public app**; `snarkjs` is
dynamically imported so it loads only when the user actually proves. A non-GPL WASM
prover (b) or a local helper (c) are the documented alternatives. See
[`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).

## Defaults (the live deployment)

`src/config.ts` ships the live deployment's public facts — pool and token addresses,
chain id, RPC/explorer bases, the pool's **public** arbiter keys — re-exposed from
`@bongtu/core/network`, the one home equality-tested against
`deploy/addresses.450815.json`. It transcribes none of them, and neither should you: the
previous chain's replayed CREATE nonces make several addresses collide across the two
chains while naming *different* contracts, so copy addresses from the record by field
name, never from prose. `keyVersion` (the KDF rotation lever — bumping it rotates every
derived key) is pinned in `@bongtu/client/identity`
([docs/wallet.md](../../docs/wallet.md#key-derivation)). No private key ever lives in
the wallet.

## Layout

```
src/
  config.ts            app knobs: DEFAULTS (chain facts from @bongtu/core/network),
                       discovery + testnet ENV rules, CIRCUITS_VERSION pin +
                       per-asset byte table, circuitBaseUrl
  main.tsx             React entry + the desktop-only gate
  lib/
    assets.ts          app binding of @bongtu/ui/assets to this circuit family
    prove.ts           app binding of @bongtu/ui/prove (CPU circuit allow-list + wording)
    payName.ts         name lookup + the one-time deposit address (portal) client
    scanStore.ts       persisted self-scan state per owner (selfscan mode)
    errors.ts          the wording boundary over the shared failure classifier
  ui/
    App.tsx            the shell: login, discovery mode, routing
    actionMachine.ts   React adapter over @bongtu/ui/actionMachine + treasury wording
    hooks.ts, format.ts
    screens/           Onboarding, LockIntro, Home, Activity, Settings, Deposit,
                       SpendScreen (Send + Withdraw), Receive (portal addresses)
    components/        balance card, activity list, sync dot, staged/download progress,
                       receive panel, mint modal, modals, controls
test/                  15 headless gates: wallet.test.ts (derivation, balance + trial
                       decrypt, spend witnesses), actionMachine, assets cache,
                       connection + wagmi guards, copy pins, download progress, error
                       surfaces (errors + errorSurface), faucet, format, lock intro,
                       portal addresses, prove allow-list, selfscan wiring,
                       transfer10x2 fold
```

The lock, wagmi config, wallet branding, lock intro, toasts and the shared
proving/asset/action machinery come from `@bongtu/ui`; protocol flows from
`@bongtu/client`.

## License

Apache-2.0 — see the root [`LICENSE`](../../LICENSE); for snarkjs, see the GPL decision
above.
