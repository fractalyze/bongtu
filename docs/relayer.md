# Relayer

The gas-sponsoring sidecar (`apps/relayer`): it submits **withdraw**
transactions with its own funded key so the user pays no gas and no
user-controlled address ever appears as the transaction sender.

## Why it can be trusted with the submission

The withdraw circuit binds the payout address into the proof (`recipient`,
pub[26] — docs/circuits.md). The relayer therefore holds a proof it can
submit but not redirect: tampering with any public signal fails Groth16
verification, and the announcement fields it could alter ride outside the
proof where changing them can only break discovery, never move funds
(docs/contracts.md). "Who submits" is a free variable, and the relayer is
just somebody who pays.

That is also why the service is **withdraw-only by design**: deposit and the
transfer arities have no recipient binding — their outputs are in-pool notes
addressed by owner pubkeys inside the proof — so third-party submission buys
nothing there.

## Surface

| endpoint | behavior |
|---|---|
| `POST /relay` | body `{calldata:{a,b,c,pub}, kemCiphertext, ephemeralPub?, viewTag?}`. Validates shape before touching the chain: `pub.length == 27`, `pub[26]` nonzero and `< 2^160`, KEM ct exactly 1088 bytes, announcement fields defaulting to the plain-withdraw zero sentinel. Then `simulateContract` — a revert must cost the sponsor an `eth_call`, not a gas fee — and only on success `writeContract` + receipt. `{txHash}` back; 400 malformed / 422 simulation revert (with reason) / 502 submit failure. |
| `GET /health` | `{ok, submitter, balanceWei}` — `ok` is false at balance 0, so an unfunded sponsor is visible before a user waits on it. |

`SUBMITTER_KEY` is required at boot (refused otherwise, one clear line), held
in memory only, never logged and never served — pinned by a spawn test that
scans logs and responses for the key hex. Run mechanics and env knobs:
`apps/relayer/README.md`.

## The client contract

`@bongtu/client` (`io/relayer.ts` + the `ops/spend/run.ts` withdraw leg) relays
exactly the terminal withdraw of a spend chain — merge legs are self-sends
and never leave the wallet's own submission path. A configured relayer that
fails **surfaces the failure**; there is no silent fallback to self-submit
(docs/wallet.md "Withdraw destination").

## PoC boundaries

No fee model, no rate limiting, no queue — one transaction at a time,
institution-run beside the arbiter indexer. Each is a deliberate deferral,
not an oversight; a public-facing deployment needs all three.
