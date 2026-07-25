# bongtu admin (PoC)

A minimal, functional role-moded admin web app (SPEC §7 / Q10). One app, two modes,
switched by a tab. It imports the bongtu `sdk`, `indexer`, and `prover-cli` **source
directly**, so every commitment / nullifier / Poseidon-sponge ciphertext it builds is
byte-identical to what the prover proves and the contract verifies.

Vite + TypeScript, minimal deps (`ethers` v5 for MetaMask, `poseidon-lite` for the sdk).

## Two modes

### Employer mode — holds NO arbiter key
Assembles and submits a 256-recipient private disbursement:

1. **Recipients** — a form (add rows `{compressed pubkey, amount}`) and/or an optional
   CSV upload/paste (`pubkey,amount` per line). A recipient is identified by a
   **compressed bjj pubkey** (`@bongtu/sdk/pubkey` — a 32-byte hex string). Full ETH→bjj
   onboarding is out of scope for this PoC; recipients paste their compressed key.
2. **Input note** — the employer's note to spend (value, salt, bjj spending scalar).
3. **Membership witness** — the input note's `root` + 32-sibling path + leaf index,
   pasted, fetched from an indexer (`/head` + `/path/{leafIndex}`), or built locally
   for the demo.
4. **Build disbursement** (pure, `src/lib/disburse.ts`): derives fresh salts, lays out
   `N` recipients + one employer **change** note (remainder) + zero-value **padding** to
   exactly 256 outputs (so `sum(outputs) == inputValue`), computes the output
   commitments (`sdk`), enforces **distinct owner pubkeys** (§11-8 two-time-pad guard),
   builds the `subtreeRoot`, verifies the membership path folds to `root`, and emits a
   complete prover-cli **disburse `ProvingRequest`** plus the **2054-element** ciphertext
   (1024 receiver ++ 1030 authority = `disburseCiphertextLen` for B=256).
5. **Prove** — POST the request to a local prover-cli helper (browser GPU proving is
   infeasible: 1.24 GB zkey + rabbitsnark) → get calldata.
6. **Submit** — `disburseWithCiphertexts(a,b,c,pub, ciphertext)` via MetaMask.

The employer's **ledger** is its own authored recipients + change (no arbiter key
needed — it authored the batch), downloadable as a receipt CSV.

> PoC boundary (honest): if no GPU helper is reachable, employer-mode still fully
> assembles a valid `ProvingRequest` + the ciphertext and wires the MetaMask submit —
> the proving handoff is the only step that needs the employer's GPU box.

### Auditor mode — the ONLY mode with the arbiter key
The independent regulator seat. Configure an arbiter-mode indexer URL + the **arbiter
private key** (never leaves the browser), then **Load ledger**:

- Fetches the public `GET /events` feed + `GET /alarms`.
- Decrypts each **transfer / disburse** authority envelope **locally** with the arbiter
  key (`src/lib/ledger.ts`, reusing `@bongtu/indexer/envelope`) into "who received what /
  spent status" — grouped by owner, with unspent balances, plus a per-op feed and the
  disclosure alarms.
- **Coverage boundary:** the public `/events` feed carries an authority tail only for
  `transfer` and `disburse` (deposit/withdraw emit theirs in the raw `Deposited`/
  `Withdrawn` log, which the public feed strips — `ingest.ts` sets `ciphertext: []`). So
  the local decrypt reconstructs the transfer + disburse ledger (exactly the compliance
  beat: the auditor reads employees' p2p transfers AND the 256-batch). Deposit/withdraw
  notes come from an arbiter indexer's own `/notes` directory.

A secondary **`GET /notes` lookup** exercises the signed read-auth flow (`@bongtu/sdk/eddsa`).
Its auth binds to the **owner** key (the signature must verify against the queried
pubkey), so it needs the owner's private scalar — it is a recipient's own-notes lookup
via the arbiter indexer, not a general auditor browse.

## Run

```sh
export PATH=$HOME/.foundry/bin:$HOME/.nvm/versions/node/v22.17.1/bin:$PATH
cd apps/admin-web
npm install
npm run dev        # Vite dev server → open the printed URL
```

Gates:

```sh
npm test           # pure-logic assembly test (no GPU/chain): shapes, distinct owners,
                   #   commitments == sdk commitment(), the 2054 ciphertext rule
npm run typecheck  # tsc --noEmit
npm run build      # vite production build
```

### Local prover helper (employer's GPU box)

```sh
# same env as the root CLAUDE.md GPU contract: CUDA_VISIBLE_DEVICES=0, BONGTU_NODE_MODULES set,
# the 1.24GB artifacts/circuit.zkey present.
PORT=8700 npm run prover-helper       # POST /prove  (ProvingRequest -> {a,b,c,pub})
```

The employer-mode "Prove via helper" button POSTs the assembled request here. Cold zkey
compile is ~2 min; warm ~0.5 s.

## Defaults (live GIWA Sepolia — `deploy/addresses.91342.json`)

`src/config.ts` ships the live pool `0x93365980784ef504613EF5822ce1289CF858Fc10`, chain
91342, and the pool's **public** arbiter key (safe in employer-mode). The arbiter
**private** key is entered only in auditor-mode and lives in no file.

## Layout

```
src/
  config.ts            live GIWA defaults (public data only)
  main.ts              mode tabs (employer | auditor)
  lib/
    disburse.ts        PURE: recipients + input note + membership -> ProvingRequest + ciphertext
    ledger.ts          PURE: /events + arbiter key -> decrypted auditor ledger
    csv.ts             recipient CSV parser
    chain.ts           MetaMask disburseWithCiphertexts + pool reads (ethers v5)
    proverClient.ts    POST a request to the local GPU helper
    indexerClient.ts   /head /path /events /alarms fetch wrappers
    notesAuth.ts       signed GET /notes URL builder (@bongtu/sdk/eddsa)
    dom.ts             tiny framework-free DOM helpers
  views/
    employer.ts        employer-mode UI
    auditor.ts         auditor-mode UI
test/
  assemble.test.ts     the pure-logic assembly gate
prover-helper.ts       local prover-cli HTTP helper (run on the GPU box)
```
