# Wallet

`apps/wallet-web` is the self-custody public app: MetaMask in, a BabyJubJub spending key derived on
the fly, notes read from an arbiter indexer, and transfer / withdraw / deposit proved **in the
browser**. It imports `@bongtu/core` source directly, so every commitment, nullifier and
Poseidon-sponge ciphertext it builds is byte-identical to what the provers prove and the contract
verifies. Run commands and the test layout are owned by `apps/wallet-web/README.md`.

## Key derivation

There is no seed and no persisted private key. The spending key is a pure function of a MetaMask
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
  reconstructs the bjj key. v1 assumes an EOA with deterministic ECDSA (MetaMask); ERC-4337 accounts
  need a different derivation.
- **`keyVersion` is a rotation lever.** It sits in the EIP-712 domain, so bumping it rotates every
  derived key — and orphans every note held under the old one. It is pinned per deployment in
  `src/config.ts`; never change it casually.
- The exact struct bytes are consensus for the user's identity: editing `name`, `version` or the
  message text rotates everybody's key.

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
elements are drawn per deposit (ephemeral ECDH key, nonce, two salts); the authority public key is
not drawn — it is the pool's stored key, which the contract injects before verifying.

The flow approves the ERC-20 for exactly `V` (skipped when the allowance already covers it) and
pre-checks affordability before spending a proof on a doomed deposit.

**Faucet.** The deployed kKRW is `MockERC20`, whose `mint(to, amount)` is fully permissionless, so a
first-time user self-mints test tokens from their own MetaMask and pays their own gas. The button is
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
chain id, RPC and explorer bases, `H` and `B`, the gas-price floor, and the **arbiter public key**.
The arbiter public key must ship — the wallet encrypts every authority envelope to it, and the
contract injects the same key from storage before verifying, so a stale copy means a wasted proof
rejected on chain. No private key ever lives in the wallet.
