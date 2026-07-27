# Wallet

`apps/wallet-web` is the self-custody public app: an injected wallet in, a BabyJubJub spending key derived on
the fly, notes read from an arbiter indexer, and transfer / withdraw / deposit proved **in the
browser**. It imports `@bongtu/core` source directly, so every commitment, nullifier and
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
  reconstructs the bjj key. v1 assumes an EOA with deterministic ECDSA (any injected EIP-1193 wallet); ERC-4337 accounts
  need a different derivation.
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
state, gone on reload. The first send/withdraw/deposit after a page load derives it (one signature,
shown as an "Unlocking" stage); later actions reuse it, so they cost only the transaction popup. The
hold ends on sign-out, on a wallet account switch, and after 10 idle minutes — enforced twice,
by a timer that also flips the header's Locked/Unlocked chip, and by a timestamp check at use time
that a throttled background tab cannot skip.

A held key belongs to exactly one wallet account. If the selected account changes, the wallet
refuses the action outright (`ACCOUNT_MISMATCH_MESSAGE`) rather than derive and spend under a
stranger's key — and when a held key already proves the mismatch, it refuses without a popup.

## Which wallet the UI shows

Any injected EIP-1193 wallet works, so nothing may be drawn or named as MetaMask by default
(`src/lib/walletBrand.ts`, `src/lib/eip6963.ts`). Identification has two sources:

- **Vendor flags** on the injected object decide the *brand*. Order matters: nearly every wallet
  also sets `isMetaMask: true` so that MetaMask-era dapps keep working, so the vendor's own flag
  (`isRabby`, `isOkxWallet`, `isCoinbaseWallet`, …) is tested first and `isMetaMask` last. Testing
  `isMetaMask` first is what showed the fox to everyone.
- **EIP-6963 announcements** supply the wallet's own display name and icon, which is the only way to
  name a wallet this app has never heard of. Announced names are length-capped and stripped of
  control characters, and only `data:image/*` icons are used — a remote icon URL would report every
  render back to the vendor.

What cannot be identified is called "your wallet" in copy and drawn with the generic wallet glyph;
the MetaMask fox is drawn only for a provider that identified itself as MetaMask. Nothing about the
brand is persisted: a silently-restored session re-detects it, because `reconnect()` wraps the same
injected object the announcement came from.

## Proving in the browser

The wallet proves `transfer`, `withdraw` and `deposit` locally with snarkjs — a self-custody wallet
must never send spending-key witnesses to a server. `disburse` is GPU-only and is not a wallet
operation. snarkjs is GPL-3.0 and shipping it to the page *is* distribution; the PoC accepts that
deliberately and dynamically imports it so it loads only when the user actually proves.

Circuit assets are **not bundled** (`transfer.zkey` ≈ 27 MB, `withdraw.zkey` ≈ 24 MB). They are
served as static files at `${circuitBaseUrl}/<circuit>.{wasm,zkey}` (`circuitBaseUrl` defaults to
`/circuits`) and fetched once into a version-keyed Cache Storage bucket (`src/lib/assets.ts`):

```
   CIRCUITS_VERSION = first 8 of sha256(transfer.zkey || withdraw.zkey || deposit.zkey)
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

## Encapsulating to the arbiter

Every operation the wallet builds — deposit, transfer, withdraw — draws fresh ML-KEM-768 material
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
entirely; the Settings screen can override it per session.

## What the client bundles

Everything in `src/config.ts` and `@bongtu/core/network` is public: pool address, token address,
chain id, RPC and explorer bases, `H` and `B`, the gas-price floor, the **arbiter bjj public key**
and the **arbiter ML-KEM-768 encapsulation key** (`ARBITER_KEM_PK`, 1184 bytes). Both must ship —
the wallet encrypts every authority envelope under a key folded from the two — and both are checked
against the chain before use: the bjj key by the contract's own injection before verifying, the KEM
key by the pre-encapsulation hash guard above. A stale copy of either costs a wasted proof, not a
silent mis-encryption. No private key ever lives in the wallet.
