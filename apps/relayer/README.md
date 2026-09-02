# @bongtu/relayer

Gas-sponsored **withdraw** submission (PoC). The withdraw circuit binds the payout
address into the proof (`pub[26]`), so anyone — this relayer included — can submit
the transaction without being able to redirect where the money goes. That is the
entire safety argument; the relayer only spends gas.

Withdraw-only by design: transfers/deposits have no proof-bound recipient, so
relaying them buys the user nothing the relayer could not tamper with — see the
header of `src/index.ts`.

## Run

```
SUBMITTER_KEY=0x… node --import tsx src/index.ts
```

Env (all optional except `SUBMITTER_KEY` — the funded EOA private key; the relayer
refuses to boot without it):

| var             | default                                    |
|-----------------|--------------------------------------------|
| `RPC`           | `http://127.0.0.1:8545` (anvil)            |
| `POOL`          | `deploy/addresses.<CHAIN_ID>.json` `pool`  |
| `CHAIN_ID`      | the sdk `CHAIN_ID` (`@bongtu/core/network`)|
| `PORT`          | `8700`                                     |

Endpoints: `POST /relay` (body `{calldata:{a,b,c,pub}, kemCiphertext, ephemeralPub?, viewTag?}`
→ `{txHash}`; 400 malformed / 422 simulation revert / 502 submit failure) and
`GET /health` (`{ok, submitter, balanceWei}`, `ok=false` when unfunded).

## Test

```
npm test          # headless node:test over fake viem clients — no chain, no key on the wire
npm run typecheck
```
