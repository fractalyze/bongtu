# bongtu wallet (public PoC)

A minimal, functional self-custody wallet (SPEC §7 public app) — connect any installed
extension (EIP-6963) or WalletConnect through the RainbowKit modal. No seed to
store: the wallet **derives** a BabyJubJub spending key from a wallet signature, so
the same account regenerates the same key every session. It imports the `@bongtu/core`
**source directly** (the indexer is reached over HTTP only), so every commitment /
nullifier / Poseidon-sponge ciphertext it builds is byte-identical to what the
provers prove and the contract verifies. All proving happens **in the browser** —
a self-custody wallet never sends spending-key witnesses to a server.

Vite + TypeScript + React, minimal deps (`wagmi` v2 + `viem` v2 + RainbowKit for the
wallet edge, `poseidon-lite` via the sdk, `snarkjs` for in-browser proving).

## The flow

### 1 · Identity — derive the spending key from a MetaMask signature (SPEC §6)

Connect MetaMask → the wallet asks the account to sign a **domain-separated EIP-712
struct** via `eth_signTypedData_v4`, then derives the bjj key from that signature:

```
domain  = { name: "bongtu", version, chainId: 91342, verifyingContract: <pool> }
types   = { BongtuSpendingKey: [ {statement}, {warning} ] }
message = { statement: "Derive my bongtu … spending key …", warning: "… only sign in the official wallet" }

s   = keccak256(signature)  mod  L          # L = the bjj prime-order subgroup order
key = deriveKeypair(s)  ->  { formattedPrivateKey: s, publicKey: s·Base8 }
```

- **Deterministic.** `eth_signTypedData_v4` over EIP-712 is RFC-6979 ECDSA, so a fixed
  (account, domain, message) yields a fixed 65-byte signature — and therefore the same
  key — every time. Same account + same pool + same `keyVersion` ⇒ same key.
- **Why typed, not `personal_sign`** (SPEC §6): the domain binds `chainId` + the pool
  address + a key `version`, so a signature harvested for one pool/chain/version cannot
  derive another's key, and a phishing page cannot present a raw string that silently
  yields the spending key.
- **Threat model** (SPEC §5.1): *the signature IS the spending key.* v1 = EOA +
  deterministic ECDSA only (MetaMask pinned); 4337 accounts need a different derivation
  (v1.1). Code: `src/lib/derive.ts` (pure) + `src/lib/connection.ts` (the signing edge).

### Receive address (the receive-key UX)

The wallet shows the user's **compressed bjj pubkey** (`@bongtu/core/pubkey` — a 32-byte hex
string, e.g. `0x05c818db…3c1f96`) as the **receive address**. Share it so others can
pay you: an employer disburses to it, a peer transfers to it. It is deterministic from
your MetaMask account, so it is stable across sessions and devices.

### 2 · Balance — sum unspent notes (SPEC §7)

One path (`src/lib/balance.ts`): **signed `GET /notes`** against an arbiter-mode
indexer that has already decrypted every op's authority envelope into a per-owner
directory. The wallet proves control of its own key with an EdDSA-Poseidon read-auth
signature (`@bongtu/core/eddsa`, bound to `Poseidon(ownerPub.x, ownerPub.y, ts)`), so
only it can read its row even though the arbiter holds everyone's. Balance =
`sum(value)` over `!spent` notes. **A reachable arbiter indexer is required** — if
`/notes` fails, the wallet shows an error; there is no fallback path.

> **2026-07-25 decision (architecture-review #17, option b):** the key-only `/events`
> trial-decrypt *fallback wrapper* was removed as unwired dead code — no adapter ever
> built its `leafCommitments` map, and the product scenario depends on the indexer.
> The pure `trialDecryptEvents` core **stays** (and stays tested): it proves the SPEC
> §7/§11-7 protocol property that every receiver ciphertext slice is key-only
> recoverable — ECDH-decrypt `[value, salt]`, rebuild the commitment, accept iff it
> equals the on-chain leaf (the Poseidon sponge has no MAC, so the leaf-match is the
> "is this mine" test) — and is the seed for future recovery tooling.

### 3 · Transfer (2-in / 2-out) · 4 · Withdraw (2-in / 1-out)

The small CPU circuits, provable in-browser (SPEC §6). `src/lib/spend.ts` (pure)
assembles the witness the same way `deploy/e2e_orchestrator.ts` does by hand, in
`ProvingRequest` form (`@bongtu/core/proving`):

- Spend 1–2 of the wallet's notes (a single note pads input[1] to `{nullifier:0,
  value:0, enabled:0}` — the §5.2 value belt forces the disabled input's value to 0).
- **transfer**: pay the recipient `amount`, change back to self; `sum(inputs) == amount
  + change`; the two output owners (recipient, self) MAY coincide — the circuit
  encrypts receiver ciphertext `i` under `encryptionNonce + i` (§11-8 v1.1, U-X3),
  so a self-pay is no longer a two-time pad.
- **withdraw**: push `amount` of the underlying ERC-20; the circuit's `out` public =
  `sum(inputs) − sum(outputs) = amount`, change = total − amount (a full withdrawal
  leaves a value-0, non-zero-commitment change note).
- Both encrypt an **authority envelope** to the pool's stored arbiter key (non-repudiation
  on every op); the contract injects the same key before verifying, so a mismatch fails.
- The ciphertext rides in the circuit's **public signals**, so the tx is just
  `(a, b, c, pub)` — no separate ciphertext arg (unlike disburse).

Then **prove in-browser** (`src/lib/prove.ts`, `snarkjs.groth16.fullProve` over the
transfer/withdraw `wasm` + `zkey`) → **submit** `pool.transfer` / `pool.withdraw` through
the connected wallet (`src/lib/connection.ts`, viem `writeContract` at the pinned gas floor).

## Run

```sh
export PATH=$HOME/.foundry/bin:$HOME/.nvm/versions/node/v22.17.1/bin:$PATH
cd apps/wallet-web
npm install
npm run dev        # Vite dev server → open the printed URL (needs MetaMask + a reachable indexer)
```

Gates:

```sh
npm test           # pure-logic gates (no MetaMask/chain/assets): deterministic derivation,
                   #   balance sum + trial-decrypt, transfer/withdraw witness assembly
npm run typecheck  # tsc --noEmit
npm run build      # vite production build (snarkjs splits into its own dynamic chunk)
```

### Gate reality (what is tested vs the un-tested edge)

MetaMask and the live circuit assets are not present in the build env, so the
**connect → sign → prove → submit** I/O edge (`connection.ts`, `prove.ts`) is wired but
not exercised here. The **pure, security-critical logic IS covered** headless
(`test/wallet.test.ts`, 18 tests): (1) a fixed signature hex derives a stable, pinned
bjj keypair; a different signature a different key; (2) mock notes (some spent) sum to
the right unspent balance, and the `/events` trial-decrypt discovers exactly the
wallet's notes (rejecting a stranger's envelope) with correct spent flags; (3) transfer
and withdraw witnesses whose output commitments == `sdk commitment()`, whose value is
conserved, whose owners are distinct, whose membership folds to root, plus the padded
single-input path.

### Circuit assets (documented boundary, SPEC §6 "one-time zkey download")

In-browser proving needs the transfer/withdraw `wasm` + `zkey` served at
`config.circuitBaseUrl` (`${base}/{transfer,withdraw}.wasm` and `.zkey`). They are **not
bundled** (`transfer.zkey` ~28 MB, `withdraw.zkey` ~24 MB): copy
`circuits/out/{transfer_js/transfer.wasm, transfer.zkey, withdraw_js/withdraw.wasm,
withdraw.zkey}` under the app's public dir or a CDN and point `circuitBaseUrl` at them.

### GPL decision (SPEC §6, explicit)

Shipping `snarkjs` (GPL-3.0) to the page **is** distribution, so no server-side
isolation applies (and a self-custody wallet must not delegate its proving anyway).
The PoC takes option **(a): accept GPL for the public app.** `snarkjs` is dynamically imported (`import("snarkjs")` in `prove.ts`)
so it loads only when the user actually proves. A non-GPL WASM prover (b) or a local
helper (c) are the documented alternatives.

## Defaults (live GIWA Sepolia — `deploy/addresses.91342.json`)

`src/config.ts` ships the live pool `0x93365980784ef504613EF5822ce1289CF858Fc10`, chain
91342, the pool's **public** arbiter key (the authority-envelope target — public, safe
to ship), and `keyVersion` (part of the EIP-712 domain; bumping it rotates every derived
key). No private key ever lives in the wallet — the spending key is derived at runtime
and never persisted.

## Layout

```
src/
  config.ts            live GIWA defaults (public data only) + keyVersion + circuitBaseUrl
  main.ts              the wallet UI (identity → balance → transfer/withdraw)
  snarkjs.d.ts         minimal ambient decl for the dynamically-imported GPL prover
  lib/
    derive.ts          PURE: EIP-712 struct + keccak256(sig) mod L -> bjj identity
    balance.ts         PURE: sumUnspent + /events trial-decrypt; signed /notes orchestration
    spend.ts           PURE: input notes + recipient + membership -> transfer/withdraw ProvingRequest
    indexerClient.ts   /head /path /events /nullifiers + signed /notes URL (@bongtu/core/eddsa)
    chain.ts           GIWA Sepolia as a viem chain + the pinned gas price
    wagmi.ts           the one wagmi config (EIP-6963 discovery + flag-guarded WalletConnect)
    connection.ts      Connection + eth_signTypedData_v4 + pool submits (wagmi + viem)
    prove.ts           browser snarkjs.groth16.fullProve over fetched wasm/zkey
    dom.ts             tiny framework-free DOM helpers
test/
  wallet.test.ts       the three headless gates (derivation, balance, spend witness)
```

## License

Apache-2.0 — see the root [`LICENSE`](../../LICENSE); for snarkjs, see the GPL
decision section above (SPEC §6).
