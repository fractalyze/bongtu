# Wallet

`apps/wallet-web` is the self-custody public app: a wallet in (an injected extension, or WalletConnect when
the build is configured for it), a BabyJubJub spending key derived on the fly, notes read from an arbiter
indexer, and transfer / transfer10x2 / withdraw / deposit proved **in the browser**. It imports `@bongtu/core` source directly, so every commitment, nullifier and
Poseidon-sponge ciphertext it builds is byte-identical to what the provers prove and the contract
verifies. Run commands and the test layout are owned by `apps/wallet-web/README.md`.

## Key derivation

There is no seed and no persisted private key. The spending key is a pure function of a wallet
signature over a domain-separated EIP-712 struct (`src/lib/derive.ts`, `src/lib/metamask.ts`):

```
domain  = { name: "bongtu", version: keyVersion, chainId: 91342, verifyingContract: <pool> }
types   = { BongtuSpendingKey: [ statement: string, warning: string ] }

sig  = eth_signTypedData_v4(account, domain, types, message)
s    = keccak256(sig)  mod  SUBGROUP_ORDER          # bjj prime-order subgroup
key  = { formattedPrivateKey: s, publicKey: s · Base8 }
recv = packPubkey(publicKey)                        # compressed 32-byte hex — the receive address
```

`eth_signTypedData_v4` is RFC-6979 ECDSA, so a fixed (account, domain, message) yields a fixed
65-byte signature and therefore the same key every session and on every device. The domain binds
chain id, pool address and `keyVersion`, so a signature harvested for one pool, chain or version
cannot derive another's key, and a phishing page cannot present a raw string that silently yields a
spending key — which `personal_sign` would.

Consequences worth stating plainly:

- **The signature *is* the spending key.** Anyone who can make the account sign this exact struct
  reconstructs the bjj key. v1 assumes an EOA with deterministic ECDSA; ERC-4337 accounts need a
  different derivation. Injected wallets are taken to satisfy it, and a wallet reached over
  WalletConnect has to prove it — see *Signing in*.
- **`keyVersion` is a rotation lever.** It sits in the EIP-712 domain, so bumping it rotates every
  derived key — and orphans every note held under the old one. It is pinned per deployment in
  `src/config.ts`; never change it casually.
- The exact struct bytes are consensus for the user's identity: editing `name`, `version` or the
  message text rotates everybody's key.

## Signing in, and the lock

Two different secrets, two different lifetimes.

**Viewing** runs on a view token. Connecting derives the key once, signs a challenge with it, and
trades that for an HMAC token from the indexer (`/auth/challenge` + `/auth/token`, see
`docs/indexer.md`); the token and the compressed pubkey are all that reach `localStorage`
(`src/lib/session.ts`). Balance and activity read with the token alone — no key, no popup — so a
returning visit restores silently as long as the wallet still reports the same account.

**Spending** runs on the key itself, held by `src/lib/keyCache.ts` — the wallet's *lock*, and the
only place the bjj private key lives between actions. It is memory-only: never storage, never React
state, gone on reload.

A **fresh login starts unlocked**: connecting already derived the key to sign the token handshake,
so `App.connectWallet` hands that identity to the lock (`keyCache.seed`, which re-checks it against
the session pubkey exactly as `unlock` checks a derived one) instead of dropping it. No second
popup, and the idle clock starts at login. A **silently restored session starts locked** — nothing
persists the key — and its first send/withdraw/deposit derives it (one signature, shown as an
"Unlocking" stage). Either way later actions reuse the hold, so they cost only the transaction popup.

The hold ends on sign-out, on a wallet account switch, and after 10 idle minutes — enforced twice,
by a timer that also flips the header's padlock to closed, and by a timestamp check at use time that
a throttled background tab cannot skip. The first login on a device gets a one-screen explainer for
exactly this (`src/lib/lockIntro.ts` stores one boolean — not key material — under
`bongtu.lockIntro.v1`).

A held key belongs to exactly one wallet account. If the selected account changes, the wallet
refuses the action outright (`ACCOUNT_MISMATCH_MESSAGE`) rather than derive and spend under a
stranger's key — and when a held key already proves the mismatch, it refuses without a popup.

The login itself is a flow, not component code: `runLogin` (`src/lib/loginFlow.ts`) opens the
wallet, derives, runs the two checks below, trades the identity for a view token and persists —
and when a check fails it throws having written **nothing**. `App.connectWallet` is left with the
lock, the screen state and the one-shot read a tokenless session does.

### WalletConnect

A second way in, dark unless the build carries `VITE_WC_PROJECT_ID` (`src/lib/walletconnect.ts`).
Unset — the current default — there is no second button, no SDK fetch, and the wallet behaves
exactly as it did when an injected extension was the only option. Set, Onboarding offers
"WalletConnect" alongside (or, with no extension installed, instead of) the extension button; it
opens the SDK's own QR / deep-link modal, and everything after the connect is the same flow.

`connectWalletConnect` returns the same `Connection` the injected path returns — an ethers
`Web3Provider` over the WalletConnect EIP-1193 object — so `identity.ts`, `keyCache.ts`, the action
flows and every submit helper are untouched and cannot tell the difference. The SDK is reached
**only** through a dynamic `import()`, so it never enters the default chunk; a test walks the static
import graph from the entry to keep it that way. A session persists in the SDK's own storage and the
stored record carries `transport: "walletconnect"`, so a returning visit restores silently over the
same transport (`reconnectWalletConnect` reads the stored session and never calls `connect()` — a
reload can't pop a QR code at anyone). `accountsChanged` re-locks; over WalletConnect a `disconnect`
event is the peer hanging up and ends the session, while an injected wallet's `disconnect` means a
dropped RPC socket and is deliberately ignored. Signing out ends the pairing rather than leaving the
wallet app showing bongtu as connected.

Two things genuinely differ from an extension, both about the same risk.

**The determinism check.** The whole scheme assumes deterministic (RFC-6979) ECDSA — see *Key
derivation*. MetaMask-class extensions satisfy it; some mobile wallets reachable over WalletConnect
randomise their signatures, and such a wallet derives a **different key on every login**, which
would present as an empty balance and unspendable notes with nothing on screen explaining why.
Nothing on the wire distinguishes the two, so the wallet looks (`src/lib/loginGuard.ts`):

- **First WalletConnect login for an account this browser has never seen** — the same typed-data
  signature is requested **twice** and the bytes must match. Two popups, once. Injected logins never
  do this; neither does any account with a remembered key, where the remembered key is the stronger
  reference.
- **Any login for an account this browser remembers** — the freshly derived key must *be* the
  remembered one, or the login is refused with "This wallet produced a different signing key than
  last time…". Free, and it is the check that actually fires for returning users.

**What the check compares against.** A second localStorage record (`bongtu.keybinding.v1`) maps
account → compressed pubkey. It deliberately outlives the session record, which is dropped the
moment its token expires: "this account derives key K" stays true regardless. It holds an address
and a public key and nothing else, and an explicit Disconnect forgets it — a user asking to sign out
gets a clean device, and the next login is a first login again.

**Network switching** goes through the same `ensureChain`; over WalletConnect a wallet that won't
move to GIWA Sepolia gets a message saying to switch in the wallet app, since the raw relay error
says nothing a user can act on.

**Enabling it.** Create a project at [Reown Cloud](https://cloud.reown.com) and copy its project id
(it is public — it identifies the dapp to the relay and has no secret half). Set
`VITE_WC_PROJECT_ID` in the Vercel project's environment variables and redeploy; it is a build-time
inject, so an existing deployment does not pick it up. Nothing else changes — no contract, no
indexer, no circuit.

## Which wallet the UI shows

Any injected EIP-1193 wallet works, so nothing may be drawn or named as MetaMask by default
(`src/lib/walletBrand.ts`, `src/lib/eip6963.ts`). Identification has two sources:

- **Vendor flags** on the injected object decide the *brand*. Order matters: nearly every wallet
  also sets `isMetaMask: true` so that MetaMask-era dapps keep working, so the vendor's own flag
  (`isRabby`, `isOkxWallet`, `isCoinbaseWallet`, …) is tested first and `isMetaMask` last. Testing
  `isMetaMask` first is what showed the fox to everyone.
- **Self-descriptions** supply the wallet's own display name and icon, which is the only way to name
  a wallet this app has never heard of. Two sources feed one registry: EIP-6963 announcements from
  extensions, and WalletConnect peer metadata (`registerAnnouncedWallet`). Neither is trusted:
  `describeWallet` is the single place that length-caps names, strips control characters, and accepts
  only `data:image/*` icons — a remote icon URL would report every render back to the vendor, and
  peer icons are conventionally remote, so they are dropped. A remote wallet therefore shows its real
  name beside the generic glyph, and flies no vendor flag, so no brand is ever guessed for it.

What cannot be identified is called "your wallet" in copy and drawn with the generic wallet glyph;
the MetaMask fox is drawn only for a provider that identified itself as MetaMask. Nothing about the
brand is persisted: a silently-restored session re-detects it, because `reconnect()` wraps the same
injected object the announcement came from.

## Which circuit a spend uses

A spending circuit takes a **fixed** number of input notes, so the number of notes a payment needs
decides which circuit can prove it. The user never picks; `planSpendAction` (`src/lib/spend.ts`)
does, from amount-aware largest-first selection:

| the payment needs | send | withdraw |
|---|---|---|
| 1–2 notes | `transfer` (2-in / 2-out) | `withdraw` (2-in / 1-out) |
| 3–10 notes | `transfer10x2` (10-in / 2-out) | — past its arity |
| more than 10 notes | — past its arity | — past its arity |

Largest-first is what makes that a decision and not a guess: if any *k* notes cover the amount, the
largest *k* do, so a selection that overruns the arity proves no *k*-note cover exists. Unused input
slots are padded (`nullifier 0`, `value 0`, `enabled 0`, zeros path, and a real value-0 self-owned
commitment on its own salt) — the contract-derived `enabled=0` disables the slot's membership and
the §5.2 value belt forces its value to 0, so a pad can neither prove membership nor mint. Unused
This is the convention `circuits/inputs/transfer10x2.json` carries, and
`test/transfer10x2.test.ts` checks both sides against it.

**`transfer10` is deprecated** (user decision, 2026-07-28): the 10-in / 10-*out* circuit and its V4
entrypoint stay deployed on chain, but the wallet routes **nothing** to it anymore. An output is a
depth-32 IMT append — the dominant per-op gas — and a real spend only ever needs two outputs
(payment-or-merged-note + change), so transfer10 paid for eight zero-value pads on every use.
`transfer10x2` keeps the identical 10-slot input side and sheds those outputs; zero change is legal
(a merge's change note is value-0 — still a real note with a nonzero commitment). Its assets also
left the wallet's download set. `test/transfer10x2.test.ts` and `test/spendChain.test.ts` carry
deprecation pins that fail the moment any plan, merge leg or submit routes to `transfer10` again;
`deploy/giwa_transfer10x2_e2e.ts` is the live driver (`--dry` for a network-free structural check).

## A spend is a chain, not a transaction

Money arrives in separate notes — every deposit, every payment received, every disburse line is one —
and no circuit above can spend more than ten at once. Withdraw is stricter still: it has no arity-10
circuit, so three notes is already past it. That state is common, not exotic, and the wallet does not
answer it by sending the user off to tidy up first.

`planSpendChain` (`src/lib/spend.ts`) plans the **whole** way from the balance held to the payment
asked for: zero or more merge legs — `transfer10x2` self-sends folding the ten largest notes into
ONE merged note plus a zero-value change note, both the sender's own — then the terminal payment or
withdrawal. `runSpendChain`
(`src/lib/spendFlow.ts`) runs the legs back to back. One Confirm starts the whole thing; each leg is
one wallet approval. Duplicate output owners are safe in a merge because receiver ciphertext *i* is
encrypted under `encryptionNonce + i` (§11-8 v1.1), the property that also made self-send legal; the
shared-keystream ban applies only to `disburse`.

**Merge only as far as you must.** Planning stops the moment the amount is coverable within the
terminal circuit's arity. A 20-note wallet spending what its top 19 notes cover takes *one* fold;
only a near-full-balance spend takes two, because each fold turns 10 notes into 1 — a net loss of 9,
so *N* notes need ⌈(N − arity) / 9⌉ folds at worst. The confirm sheet states the result in the terms
the user is actually counting: "Your balance is in 20 pieces, so this takes 3 approvals: 2 to combine
them, then the payment." The running screen then steps through exactly those, one step per
transaction, with the assemble/prove/submit stage of the leg in flight written underneath.

**Between legs the chain waits.** A merge's output note has no leaf index and no membership path
until the indexer has seen the transaction, so leg *n+1* literally cannot be built until then. The
plan marks that note with a negative leaf index naming the leg that will produce it (`pendingLeaf`);
the runner polls `reloadNotes` for the commitment it knows the merge created — the same bounded-poll
policy as the post-action refresh (`pollUntil`, `src/lib/refresh.ts`) — and substitutes the real note
with its real leaf. This is a reported stage of its own, so the screen says what the pause is for.
Freshly appended transfer outputs *do* have paths: the indexer's 422 "no path" applies only to
leaves inside a `disburse` batch (§11-7).

**A chain that breaks partway is honest about it.** The error carries the leg's own cause plus what
it means for the money — nothing was sent, the balance is unchanged, and the folds that landed stay
folded. Retrying re-plans from the refreshed notes, so it is a *shorter* chain: the completed merges
are real and are not repeated. The single-transaction case is untouched by all of this — it fails
exactly as it always did, with no chain wording bolted on.

`test/spendChain.test.ts` gates both halves: the plan as a table, and the run against a fake
chain+indexer where a submit appends the transaction's outputs and only then does `/notes` show them.

## Proving in the browser

The wallet proves `transfer`, `transfer10x2`, `withdraw` and `deposit` locally with snarkjs — a
self-custody wallet must never send spending-key witnesses to a server. `disburse` is GPU-only and is
not a wallet operation. snarkjs is GPL-3.0 and shipping it to the page *is* distribution; the PoC
accepts that deliberately and dynamically imports it so it loads only when the user actually proves.

Circuit assets are **not bundled** (`transfer.zkey` ≈ 29 MB, `withdraw.zkey` ≈ 25 MB, and
`transfer10x2.zkey` ≈ 95 MB). They are served as static files at
`${circuitBaseUrl}/<circuit>.{wasm,zkey}` (`circuitBaseUrl` defaults to `/circuits`) and fetched once
into a version-keyed Cache Storage bucket (`src/lib/assets.ts`):

```
   CIRCUITS_VERSION = first 8 of sha256(transfer.zkey || transfer10x2.zkey || withdraw.zkey || deposit.zkey)
                                 |
   cache bucket  "bongtu-circuits-v<CIRCUITS_VERSION>"     <- kept, disk-backed
   other buckets "bongtu-circuits-*"                       <- evicted on prefetch
   unrelated caches                                        <- never touched
```

**Stale-zkey hazard.** A regenerated zkey that keeps the old version string is served from disk
forever and fails on-chain verification with no self-heal — the browser has no way to know the key
moved. `CIRCUITS_VERSION` in `src/config.ts` must be bumped the moment any zkey changes on disk; the
command that computes it is in the comment above the constant. Bumping it renames the bucket, evicts
the stale one and forces a one-time re-download.

`prove.ts` keeps the fetched wasm/zkey buffers for the session and uses the two-step
`wtns.calculate` + `groth16.prove` path, so a second proof in the same session skips the network.
`prewarmProver()` builds and immediately terminates a bn128 curve during the prefetch to pay the
one-time WASM compile early; it is best-effort and never blocks the UI.

**`transfer10x2` is fetched lazily, and only it.** Send/Withdraw prefetch their 2-arity key on
screen open, but the arity-10 key is three times the size — pulling it on open would make every send
wait on 95 MB it will almost never use. So the screen fetches it only once selection says this
amount needs 3+ notes, or a chain whose first leg is a fold: `useActionMachine` takes the circuit
the form currently implies — the FIRST leg's, which is the proof the user waits on next — and
re-fetches when it changes. A chained withdraw therefore ends up holding both keys, having
prefetched `withdraw` on screen open and `transfer10x2` when the plan grew a merge. Each circuit is fetched at most once per
session, and the existing download panel — progress, ETA, disabled Confirm — covers the switch
unchanged.

## Encapsulating to the arbiter

Every operation the wallet builds — deposit, transfer, transfer10x2, withdraw — draws fresh ML-KEM-768 material
against the arbiter's encapsulation key: the shared secret joins the witness as `kemSs`, and the
1088-byte ciphertext joins the transaction calldata. Encapsulation is sub-millisecond
(`@noble/post-quantum`), invisible next to a multi-second browser proof. It is fresh per
transaction; reusing a ciphertext would collapse several operations into one post-quantum
compartment.

**The bundled key is chain-vouched before it is used.** `assertPoolKemEpoch` reads
`arbiterKemPkHash(currentEpoch())` from the pool and compares it to `keccak256(ARBITER_KEM_PK)`
*before* the flow draws KEM material or starts proving; the result is memoized per pool address.
Two failures are distinguished and both are fatal:

| condition | outcome |
|---|---|
| on-chain hash differs from the bundled key | refuse — encapsulating to an unverified key would make the arbiter record a false tamper alarm |
| pool has no KEM epoch (pre-upgrade V1 pool) | refuse — this build only produces hybrid proofs, which such a pool cannot verify |

Failing here rather than at submit is the point: the alternative is an unlabeled `InvalidProof`
revert, or worse, an accepted operation whose envelope no one can open.

## Deposit and the dev faucet

Deposit is a 0-in / 2-out mint, and `BongtuPool.deposit` is permissionless (`external`, gated only
by `whenInitialized` + `nonReentrant`), so a browser can initiate one directly
(`src/lib/deposit.ts`, `depositFlow.ts`):

| output | note | why |
|---|---|---|
| 0 | `note(V)` — value `V`, fresh salt, owner = self | the shielded balance |
| 1 | `note(0)` — value 0, fresh salt, owner = self | a real, non-zero commitment; satisfies the contract's `ZeroOutputCommitment` check and gives the circuit its second output |

`sum(outputs) == V`, and on-chain `pub[0] == V` is exactly the amount the pool pulls with
`safeTransferFrom`. Both outputs belong to the depositor, which is safe here: deposit publishes no
per-recipient ciphertext, only one authority envelope over both notes, so the shared-ephemeral-key
two-time pad does not apply and `assertDistinctOwnerPubkeys` is not used. Four fresh random field
elements are drawn per deposit (ephemeral ECDH key, nonce, two salts), plus one ML-KEM-768
encapsulation; the authority public key is not drawn — it is the pool's stored key, which the
contract injects before verifying.

The flow approves the ERC-20 for exactly `V` (skipped when the allowance already covers it) and
pre-checks affordability before spending a proof on a doomed deposit.

**Faucet.** The deployed kKRW is `MockERC20`, whose `mint(to, amount)` is fully permissionless, so a
first-time user self-mints test tokens from their own wallet and pays their own gas. The button is
offered exactly when the public kKRW balance is zero (`src/lib/faucet.ts`, `FAUCET_AMOUNT =
1_000_000` raw units). This is a mock-token affordance and does not exist on a production token.

## Indexer dependency

Balance is `sum(value)` over unspent notes from a **signed `GET /notes`** against an arbiter-mode
indexer (`src/lib/balance.ts`). The wallet proves control of its own key with an EdDSA-Poseidon
read-auth signature over `Poseidon(ownerPub.x, ownerPub.y, ts)`, so it can read only its own row
even though the arbiter holds everyone's.

**There is no fallback balance path.** If `/notes` fails the wallet shows an error. The pure
`trialDecryptEvents` core still exists and is tested — it proves the protocol property that every
receiver ciphertext slice is key-only recoverable (ECDH-decrypt `[value, salt]`, rebuild the
commitment, accept iff it equals the on-chain leaf; the Poseidon sponge has no MAC, so the leaf
match *is* the "is this mine" test) — but no adapter wires it as a balance source. Funds safety
never depends on the indexer; discovery liveness does. See
[security-model.md](security-model.md#residual-gaps).

**Activity arrives one page at a time.** A read loads `/notes` plus the first 50-item `/history`
page and its cursor (`loadOwnerSnapshot` in `src/lib/refresh.ts`); the Activity screen's *Load more*
asks for the next page over the same view token — a cursor into an already-authorised feed, so
paging costs no extra signature — and the button disappears when the cursor comes back null. Home
still slices the head of whatever is loaded. Appends de-dup on `seq` (`appendHistoryPage`), because
a refresh can replace the feed while a next-page request is in flight; and a refresh **resets**
paging to page one, since the appended pages were read against a feed that has since moved. The
tokenless fallback session has nothing to page a second request with, so it reads the whole feed
unpaged in its one shot.

The indexer base URL defaults to the **relative** path `/indexer`, so every `/notes`, `/history`,
`/head`, `/path` call is same-origin: no CORS wall, and a port-forwarded remote box needs one tunnel
(the wallet port) rather than two. Who terminates `/indexer/*` depends on the mode
(`resolveIndexerProxy` in `vite.config.ts`):

| mode | `/indexer/*` handled by |
|---|---|
| `development` (`vite dev`) | the Vite proxy, forwarding to `VITE_INDEXER_PROXY_TARGET` (default `http://localhost:8600`) |
| `production` (`vite build`, and `vite preview`, which defaults to production) | **no Vite proxy** — the deployment's reverse-proxy/ingress must own the route |

Disabling the proxy in production is deliberate: a live proxy under `vite preview` would forward to
a `localhost:8600` that does not exist in prod and mask a missing infra route. `--mode` is the
escape hatch in either direction. Set `VITE_INDEXER_URL` to an absolute URL to bypass `/indexer`
entirely. The URL is **build-time only** (`App.INDEXER_URL`): the Settings screen's runtime override
was removed, because a typo there silently broke balance and activity with no way back.

## What the client bundles

Everything in `src/config.ts` and `@bongtu/core/network` is public: pool address, token address,
chain id, RPC and explorer bases, `H` and `B`, the gas-price floor, the **arbiter bjj public key**
and the **arbiter ML-KEM-768 encapsulation key** (`ARBITER_KEM_PK`, 1184 bytes). Both must ship —
the wallet encrypts every authority envelope under a key folded from the two — and both are checked
against the chain before use: the bjj key by the contract's own injection before verifying, the KEM
key by the pre-encapsulation hash guard above. A stale copy of either costs a wasted proof, not a
silent mis-encryption. No private key ever lives in the wallet.
