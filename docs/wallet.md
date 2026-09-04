# Wallet

`apps/wallet-web` is the self-custody public app: a wallet in through the RainbowKit connect modal
(every installed extension via EIP-6963, plus WalletConnect QR / deep-link when the build is
configured for it — wagmi v2 + viem v2 underneath), a BabyJubJub spending key derived on the fly,
notes read from an arbiter indexer, and transfer / transfer10x2 / withdraw / deposit proved
**in the browser**. It imports `@bongtu/core` source directly, so every commitment, nullifier and
Poseidon-sponge ciphertext it builds is byte-identical to what the provers prove and the contract
verifies. Run commands and the test layout are owned by `apps/wallet-web/README.md`.

Both web apps are **desktop-only**: a mobile browser gets a "use a PC" notice instead of the app
(`@bongtu/client` `device.ts`, a user-agent verdict shared by both roots — MetaMask has no injected
provider in a phone's system browser, and the flows would break mid-way rather than at the door).
The WalletConnect QR path pairs a *phone-held wallet* to a *desktop browser session*; it does not
make the apps themselves mobile.

## Key derivation

There is no seed and no persisted private key. The spending key is a pure function of a wallet
signature over a domain-separated EIP-712 struct (`@bongtu/client` `derive.ts` + `connection.ts` — the engine package both web apps share):

```
domain  = { name: "bongtu", version: keyVersion, chainId: 450815, verifyingContract: <pool> }
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
(`@bongtu/client` `session.ts`). Balance and activity read with the token alone — no key, no popup — so a
returning visit restores silently as long as the wallet still reports the same account.

**Spending** runs on the key itself, held by the `@bongtu/client` `KeyCache` (wired app-side in `src/lib/keyCache.ts`) — the wallet's *lock*, and the
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

"Idle" counts **user actions only**. A background poll that signs a read with the held key takes it
through `keyCache.peek()`, which returns the identity without re-arming the wipe or asking the wallet
which account is selected — otherwise a console left open on a refreshing screen would never re-lock.
The payroll console (whose tokenless reads are signed) is the caller that needs it; the wallet reads
with a view token and so peeks nowhere.

A held key belongs to exactly one wallet account. If the selected account changes, the wallet
refuses the action outright (`ACCOUNT_MISMATCH_MESSAGE`) rather than derive and spend under a
stranger's key — and when a held key already proves the mismatch, it refuses without a popup.

The login itself is a flow, not component code: `runLogin` (`@bongtu/client` `loginFlow.ts`) takes the
wallet the connect modal just opened (`connection.ts requireConnection`), derives, runs the two
checks below, trades the identity for a view token and persists — and when a check fails it throws
having written **nothing**. `App.connectWallet` is left with the lock, the screen state and the
one-shot read a tokenless session does; the Onboarding screen opens the RainbowKit modal first when
no wallet is live and runs the login the moment one is.

### Connecting, and WalletConnect

Pressing **Connect Wallet** opens the RainbowKit modal. Its contents are not a hardcoded wallet
list: wagmi discovers every installed extension per-page over EIP-6963
(`multiInjectedProviderDiscovery`) and RainbowKit renders each announcement in its "Installed"
section, so whatever the user actually has is what they can pick. The one explicitly configured
connector is WalletConnect (`src/lib/wagmi.ts buildConnectors`), and it is dark unless the build
carries `VITE_WC_PROJECT_ID`: unset — the local-dev default — the modal lists extensions only, no
WC connector joins the config, and the WC SDK is never fetched (the wagmi connector reaches
`@walletconnect/ethereum-provider` through a dynamic `import()` only). Set — as in the Vercel prod
env — the modal also offers the QR / deep-link path for phones and extension-less desktops.

Whatever the modal connects, `src/lib/connection.ts` wraps it into the same `Connection` every
other module works against: a viem wallet client over the connector's raw EIP-1193 provider
(signatures and txs reach the wallet the user picked), the app's one viem public client on the
chain's own RPC (reads and receipt waits never relay through a phone), and a `transport` tag — `"walletconnect"`
for the WC connector, `"injected"` otherwise — that only the login guard and the chain guard read.
`identity.ts`, `keyCache.ts`, the action flows and every submit helper cannot tell wallets apart.

Sessions restore silently over whatever connector made them: wagmi remembers its connector, and
`restoreConnection` re-opens it via `eth_accounts` (extensions — never a popup) or the WC
connector's own stored session (never a QR modal), then requires the stored account to still be
reported. `reconnectOnMount` is off; the restore is driven explicitly by App's one effect, so a
page load can never pop anything. `accountsChanged` re-locks the key; a `disconnected` transition
signs out over WalletConnect only (the peer hanging up is a real sign-out; an extension hiccup is
not). Signing out disconnects the wagmi connector, which for WalletConnect ends the pairing rather
than leaving the wallet app showing bongtu as connected.

Two things genuinely differ between transports, both about the same risk.

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

**Network switching** goes through the same `ensureChain` (raw EIP-3085/3326 requests through the
viem wallet client, so the same two RPCs reach an extension or relay to a phone); over WalletConnect
a wallet that won't move to the live chain gets a message saying to switch in the wallet app, since
the raw relay error says nothing a user can act on.

**The derivation payload is pinned, in two different senses.** The bjj key is a pure function of the
EIP-712 payload, so `packages/client/test/deriveDeterminism.test.ts` drives the REAL signing path
over a mock provider and pins both ends of it — but the two pins carry opposite rules:

- `PIN_SCALAR` / `PIN_COMPRESSED` — the identity a fixed signature derives, captured from the
  pre-migration (ethers v5) code. This is the compatibility contract with every existing user's
  key: **never regenerate it.** A red one means the KDF changed and every user's key rotated.
- `PIN_DIGEST` — the payload's EIP-712 digest. The domain contains `chainId` and the pool address,
  so moving the deployment **must** move this digest. Recomputing it as part of such a move is
  expected and correct; it was last recomputed on 2026-08-11 for the current chain. Only a red
  `PIN_DIGEST` with the deployment unchanged means the payload drifted.

**Enabling WalletConnect.** Create a project at [Reown Cloud](https://cloud.reown.com) and copy its
project id (it is public — it identifies the dapp to the relay and has no secret half). Set
`VITE_WC_PROJECT_ID` in the Vercel project's environment variables and redeploy; it is a build-time
inject, so an existing deployment does not pick it up. Nothing else changes — no contract, no
indexer, no circuit.

## Which wallet the UI shows

Any wallet the modal can connect works, so nothing may be drawn or named as MetaMask by default
(`src/lib/walletBrand.ts`). Identification has two sources:

- **Vendor flags** on the raw EIP-1193 provider behind the wagmi connector decide the *brand*.
  Order matters: nearly every wallet also sets `isMetaMask: true` so that MetaMask-era dapps keep
  working, so the vendor's own flag (`isRabby`, `isOkxWallet`, `isCoinbaseWallet`, …) is tested
  first and `isMetaMask` last. Testing `isMetaMask` first is what showed the fox to everyone.
- **Self-descriptions** supply the wallet's own display name and icon — the connector's `name` and
  `icon`, which wagmi fills from the wallet's EIP-6963 announcement (an extension) or the wallet
  metadata (a remote one). Neither is trusted: `describeWallet` is the single place that length-caps
  names, strips control characters, and accepts only `data:image/*` icons — a remote icon URL would
  report every render back to the vendor, so it is dropped. A remote wallet therefore shows its real
  name beside the generic glyph, and flies no vendor flag, so no brand is ever guessed for it.

What cannot be identified is called "your wallet" in copy and drawn with the generic wallet glyph;
the MetaMask fox is drawn only for a provider that identified itself as MetaMask. The connected-
wallet card on Home is **icon-only** (user decision, viem wave): the wallet's name lives in the
card's tooltip and aria-label, never as visible text. Nothing about the brand is persisted: a
silently-restored session re-detects it from the reconnected connector (`ui/hooks.ts
useWalletDescription`).

## Which circuit a spend uses

A spending circuit takes a **fixed** number of input notes, so the number of notes a payment needs
decides which circuit can prove it. The user never picks; `planSpendAction` (`@bongtu/client` `spend.ts`)
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
This is the convention `circuits/fixtures/inputs/transfer10x2.json` carries, and
`test/transfer10x2.test.ts` checks both sides against it.

**`transfer10` is deprecated** (user decision, 2026-07-28): the 10-in / 10-*out* circuit and its V4
entrypoint stay deployed on chain, but the wallet routes **nothing** to it anymore. An output is a
depth-32 IMT append — the dominant per-op gas — and a real spend only ever needs two outputs
(payment-or-merged-note + change), so transfer10 paid for eight zero-value pads on every use.
`transfer10x2` keeps the identical 10-slot input side and sheds those outputs; zero change is legal
(a merge's change note is value-0 — still a real note with a nonzero commitment). Its assets also
left the wallet's download set. `test/transfer10x2.test.ts` and `test/spendChain.test.ts` carry
deprecation pins that fail the moment any plan, merge leg or submit routes to `transfer10` again;
`deploy/live/transfer10x2_e2e.ts` is the live driver (`--dry` for a network-free structural check).

## A spend is a chain, not a transaction

Money arrives in separate notes — every deposit, every payment received, every disburse line is one —
and no circuit above can spend more than ten at once. Withdraw is stricter still: it has no arity-10
circuit, so three notes is already past it. That state is common, not exotic, and the wallet does not
answer it by sending the user off to tidy up first.

`planSpendChain` (`@bongtu/client` `spend.ts`) plans the **whole** way from the balance held to the payment
asked for: zero or more merge legs — `transfer10x2` self-sends folding the ten largest notes into
ONE merged note plus a zero-value change note, both the sender's own — then the terminal payment or
withdrawal. `runSpendChain`
(`@bongtu/client` `spendFlow.ts`) runs the legs back to back. One Confirm starts the whole thing; each leg is
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
policy as the post-action refresh (`pollUntil`, `@bongtu/client` `refresh.ts`) — and substitutes the real note
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

The wallet has two discovery modes, picked at build time (`VITE_DISCOVERY` via `discoveryFromEnv`
in `src/config.ts`; default `arbiter`, so every existing deployment is byte-unchanged):

**Arbiter mode** (the enterprise profile): balance is `sum(value)` over unspent notes from a
**signed `GET /notes`** against an arbiter-mode indexer (`packages/client/src/balance.ts`). The wallet proves
control of its own key with an EdDSA-Poseidon read-auth signature over
`Poseidon(ownerPub.x, ownerPub.y, ts)`, so it can read only its own row even though the arbiter
holds everyone's. Activity is the per-owner `/history` feed.

**Selfscan mode** (the no-auditor consumer profile): balance and activity derive from the PUBLIC
feed with only the wallet's own keys — the normative discovery pipeline of
`.dev/op-module-design.md` §3.6, implemented in `@bongtu/client` `selfscan.ts`. Per event, per
output slice: the published viewTag is checked against the wallet's own
(`Poseidon(3)([TAG_VIEWTAG, viewPriv·ecdhPublicKey]) & 0xff` — a miss skips all expensive work,
§3.2's ~256× filter); survivors are ML-KEM-decapsulated and decrypted at `nonce + i` (§3.5); a
note is accepted only when its rebuilt commitment equals the on-chain leaf — the same leaf-match
MAC substitute as `trialDecryptEvents`, fed from the published commitment run for a consumer batch
(`leafIndex = batchId + output index`, §4.4) and from an auth-free `GET /path` fold for a
single-append op. Spent flags come from the public `/nullifiers` set. Enterprise-era envelope
notes for the same wallet are found in the same pass (a deferred-acceptance twin of the spend-key
trial decrypt), so **single-append** enterprise notes keep that money on screen; an enterprise
DISBURSE-batch interior cannot be path-confirmed in public mode (its `/path` is 422-gated by
design), so it surfaces as a pending entry — the wallet may hold notes only an arbiter indexer
can open — never a silent drop. The scan is cursor-incremental and resumable: `selfscan.ts` owns the persisted-state
contract (`SelfScanState` — feed cursor, `/head` freshness stamp, discovered notes, unresolved
batches; `scan(A..B)` then `scan(B..C)` equals `scan(A..C)`), and `src/lib/scanStore.ts` wires it
to localStorage per owner — decrypted amounts land in that store, keys never do. A consumer
disburse whose kem-ct chunks are not yet assembled surfaces as a calm **"discovery pending"**
notice, never a silently smaller balance, and is re-read each scan until it completes. The sync
dot compares the scan's `/head` stamp against the live `/head` instead of `/health`; no arbiter
public key and no `/notes`/`/auth` endpoint is involved anywhere in the balance path. Activity
rows are derived from the op events the notes came from — what discovery can honestly attest
(received / deposit / withdraw-change; the public feed carries no block timestamps, so a selfscan
row carries no `blockTimestamp` and the activity list renders no time element for it — verb and
amount only, never a fabricated epoch date).

**In arbiter mode there is no fallback balance path.** If `/notes` fails the wallet says so on the surface the
failure's class earns ([errors.md](errors.md)): a failed background refresh sets the stale-data
*banner* and leaves the numbers already on screen alone (never a toast, never a blanked balance;
the next successful read clears it), a failed *manual* refresh additionally toasts, and a 401 —
the one conclusive verdict, since the view token is these reads' only auth — signs out back to
onboarding with the notice. The pure
`trialDecryptEvents` core still exists and is tested — it proves the protocol property that every
receiver ciphertext slice is key-only recoverable (ECDH-decrypt `[value, salt]`, rebuild the
commitment, accept iff it equals the on-chain leaf; the Poseidon sponge has no MAC, so the leaf
match *is* the "is this mine" test) — but no adapter wires it as an arbiter-mode balance source
(selfscan mode implements the same acceptance rule for both note families in `selfscan.ts`). Funds safety
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

## Withdraw destination, and who submits

The Withdraw screen takes an optional **destination address** (an ordinary L1
EOA; empty means the connected account, today's default). It can accept any
address the user types because the circuit binds the payout into the proof
(`recipient`, pub[26], docs/circuits.md): whoever submits the transaction,
the pool pays exactly the proven address. That binding is what makes the
**relayer** safe — see [Relayer](relayer.md) — so when one is configured the
wallet POSTs the proof there and the user pays no gas. A configured relayer
that fails SURFACES its error instead of quietly falling back to wallet
submission: silently charging the user's own account is precisely the promise
a sponsor breaks. With no relayer configured (the production default until a
`/relayer` rewrite ships) the wallet submits and pays gas itself, exactly as
before. Destination input is judged by its own validator (EVM address, not
`recipientError`): an L1 EOA and an in-pool bjj key are different address
universes, and a pasted pool address must read as a category mistake, not a
typo.

**Stealth addressing was repointed at the deposit direction** (user decision
2026-09-01): the withdraw toggle and the Stealth-funds screen left the wallet,
because with a relayer paying gas, "withdraw to a fresh address you control"
needs no stealth machinery — while non-interactive receiving does. The
primitives (`@bongtu/core/stealth`, `@bongtu/client/stealthKeys` /
`stealthFunds`, the lock's stealth custody) and their tests remain in the
packages as the deposit slice's foundation (`.dev/milestone-stealth.md`).

## Receiving through the portal

The Receive panel issues **one-time deposit addresses** (name-gated — the
issuance route is keyed on the registered name, and the wallet first proves
the directory owner is this session's key). The address accepts a plain kKRW
transfer from any wallet or exchange and the deposit lands shielded with no
further action; the mechanism, and its recorded v1 trust concession, are
[Portal](portal.md)'s.

## Pay by name

The Send screen's recipient field also takes a **registered name**
(`docs/indexer.md` `/names`). Which reading an input gets is decided by length
alone: a name normalizes to ≤ 32 chars (`normalizeName`, the ONE grammar the
registry itself registers under, `@bongtu/core/indexerApi`) while both address
encodings are longer — and a `0x` prefix declares an address outright, so a
fat-fingered hex address dies on its checksum instead of turning into a
directory lookup. Resolution runs when the user presses Continue — whether a
name is REGISTERED is the indexer's answer, not a form shape's — and the
confirm sheet shows both halves of the binding (the name AND the resolved
owner address), because what the user approves is "this name pays this key".
An unregistered name gets its own copy and keeps the form.
