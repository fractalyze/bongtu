# bongtu consumer wallet

The self-custody wallet for the consumer (no-auditor) op family: connect any installed
extension (EIP-6963) or WalletConnect through the RainbowKit modal, derive a BabyJubJub
spending key from an `eth_signTypedData_v4` signature, and pay peers through the four
registered consumer modules (`depositPriv` / `transferPriv` / `transfer10x2Priv` /
`withdrawPriv`), proved **in the browser**. It imports the `@bongtu/*` workspace
**source directly**, so every commitment, nullifier and sealed output it builds is
byte-identical to what the circuits prove and the modules verify.

**Every balance and activity fact on screen comes from self-scan.** The wallet scans the
indexer's PUBLIC endpoints (`/events`, `/nullifiers`, `/head`, `/path`, `/names`) with
its own keys and accepts a note only when the rebuilt commitment equals the on-chain
leaf. There is no view token, no owner-authed read and no arbiter coupling reachable
from this bundle: a login is tokenless by construction, and the persisted session record
holds routing data only (account, derived pubkey, transport), never a credential and
never a key. Sends are registry-name-only in v1: a recipient is a registered name whose
v2 consumer triple the payment seals to. The custody and UX story in depth, and how this
wallet differs from the enterprise one, is
[`docs/wallet.md`](../../docs/wallet.md#the-consumer-wallet-appswallet-web); the
protocol family it drives is [`docs/consumer.md`](../../docs/consumer.md).

## Run

```sh
export PATH=$HOME/.foundry/bin:$HOME/.nvm/versions/node/v22.17.1/bin:$PATH
cd apps/wallet-web
npm install
npm run dev        # Vite dev server -> open the printed URL (needs a wallet extension
                   #   + a reachable PUBLIC-mode indexer)
```

Gates:

```sh
npm test           # the eight headless node:test gates (no wallet/chain/assets), see Layout
npm run typecheck  # tsc --noEmit
npm run build      # vite production build
```

## Env knobs

All are build-time Vite injects: an existing deployment does not pick up a change.

| var | default | meaning |
|---|---|---|
| `VITE_INDEXER_URL` | `/indexer` (relative, same-origin) | where every public read goes; an absolute URL bypasses the proxy/rewrite path entirely |
| `VITE_INDEXER_PROXY_TARGET` | `http://localhost:8600` | dev/preview only: where the Vite `/indexer` proxy forwards (`vite.shared.ts`) |
| `VITE_TESTNET` | `true` | the literal `false` switches every testnet-only affordance (mint/faucet UI, Testnet chips) off in one place |
| `VITE_WC_PROJECT_ID` | unset | unset, the connect modal lists installed extensions only; set, the WalletConnect QR / deep-link path joins it |

**Ops note: `/indexer` must target a PUBLIC-mode indexer instance.** The consumer
wallet's whole contract is that it only ever reads the public endpoints, but the
`vercel.json` rewrite was copied from treasury-web and still points at the
institution-internal arbiter box; repointing it is an ops task recorded on issue #13
("Needs the user / ops"), not a code change.

## Circuit assets (the blob-store pipeline)

In-browser proving needs each circuit's `wasm` + `zkey` at
`${circuitBaseUrl}/<circuit>.{wasm,zkey}` (default `/circuits`). They are not bundled
(`transfer10x2Priv.zkey` alone is ~92 MB) and have **one home in every environment**:
the `bongtu-circuits` blob store under `circuits/<CIRCUITS_VERSION>/`. Deployments reach
it through the `vercel.json` `/circuits` rewrite; local dev reaches it through the Vite
proxy in `vite.config.ts`, which reads the version pin out of `src/config.ts` so a bump
re-points dev automatically. Fetched assets land in a version-keyed Cache Storage bucket
(`src/lib/assets.ts`), and `transfer10x2Priv` is fetched lazily, only when a spend needs
3+ input notes.

The pin (`CIRCUITS_VERSION` in `src/config.ts`) covers this app's OWN circuit set, a
different byte family than treasury-web's, alongside a per-asset byte table (the download
progress bar's denominator). A circuit regen is a three-part companion change: bump the
pin, upload the new assets (`deploy/gates/upload_consumer_circuits.sh`, which refuses a
hash that does not match the pin), and repoint the `vercel.json` rewrite at the new
`circuits/<version>/` path in the same change.

Shipping snarkjs (GPL-3.0) to the page is the same deliberate decision the enterprise
wallet took; see [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md).

## Layout

```
src/
  config.ts            consumer knobs: DEFAULTS (chain facts from @bongtu/core/network,
                       one home), CIRCUITS_VERSION pin + the per-asset byte table;
                       no discovery knob, no authority key (absent by design)
  main.tsx             React entry + the desktop-only gate
  lib/
    assets.ts          app binding of @bongtu/ui/assets (version-keyed prefetch)
    prove.ts           app binding of @bongtu/ui/prove (browser snarkjs proving)
    sessionStore.ts    the tokenless login record (routing data only, deployment-scoped)
    scanStore.ts       persisted self-scan state per owner (decrypted amounts, never keys)
    payName.ts         pay-by-name resolution + the wallet's words for each refusal
    payNameStore.ts    the device's own-name pointer (a hint; the live record decides)
    accountGuard.ts    account-switch lock/detach + the explicit-Disconnect forget plan
    refreshGate.ts     the auto-refresh gate (hidden tab runs no pass, no overlap)
    errors.ts          the wording boundary for chain/op failures
  ui/
    App.tsx            the shell: tokenless login, the self-scan world state, routing
    actionMachine.ts   React adapter over @bongtu/ui/actionMachine
    homeView.ts / activityView.ts   pure screen presenters
    screens/           Onboarding, LockIntro, Home, Activity, Settings, Deposit,
                       SpendScreen (Send + Withdraw), Receive (identity + v2 registration)
    components/        balance card, activity list, sync dot, staged progress, download
                       progress, modals, controls
test/
  config.test.ts       config invariants: key set, one-home values, version pin, byte table
  sessionStore.test.ts the tokenless record round-trip + deployment scoping
  selfscan.test.ts     sync-dot state table, scan store degradation, notices, balance hero
  discovery.test.ts    balance/activity presenters, account-switch + forget plans, gates
  ops.test.ts          the 4 op stage tables (unlock/approve/prove/submit, chains, one-op rule)
  payName.test.ts      resolve outcomes: unregistered, v1-only refusal, triple required
  receive.test.ts      own-name status table, v2-only registration, name-not-triple sharing
  copy.test.ts         pinned user-facing copy + the no-enterprise-coupling source scan
```

The lock (engine `createKeyCache`; the key never persists), wagmi config, wallet
branding, lock intro, login pending, clipboard and toasts come from `@bongtu/ui`;
protocol flows from `@bongtu/client`.

## License

Apache-2.0: see the root [`LICENSE`](../../LICENSE).
