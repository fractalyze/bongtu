# bongtu deploy — B=256 production stack

Reusable Foundry deploy of the full production BongtuPool stack. One script, one
node, env-driven — the same two scripts run on a local anvil and on the live
testnet, given the RPC, a funded key, and the two arbiter KEM variables that anvil
defaults but a live chain requires (see [Config](#config-env-with-defaults)).

This file owns the EVM stack; the Solana rail's cluster deploy (program,
one-shot `initialize`, per-cluster address records, upgrade-authority policy)
lives in [`solana/`](solana/README.md).

## What it deploys

`forge/Deploy.s.sol` broadcasts, from a single deployer:

1. **Poseidon-v1** — from the circomlibjs creation bytecode (`chains/evm/test/fixtures/poseidon2.hex`),
   the byte-identical hash the circuits / SDK / tests use (inline `create`).
2. the **6 real Groth16 verifiers** — `DepositVerifier`, `WithdrawVerifier`,
   **`Disburse256Verifier`** (production 256-arity), `TransferVerifier`,
   `Transfer10Verifier`, `Transfer10x2Verifier`.
3. a **mock kKRW** ERC-20 (`MockERC20`, 18-dec, non-fee-on-transfer — the only
   shape the pool supports). On a real network, swap this for the real token
   address (the pool takes the token as an `initialize` arg and there is no
   `setERC20`, so it is fixed for the life of the deployment).
4. **`BongtuPool(B=256)` behind a UUPS (ERC-1967) proxy**: the implementation is
   deployed first, then a proxy whose constructor runs
   `initialize(arbiterKey, ...)` atomically — seeding arbiter epoch 0 and wiring
   Poseidon + all six verifiers + the token. That single call produces the full
   production shape; there is no follow-up initializer. The **proxy** is the canonical,
   upgrade-stable pool address; the addresses file records both `pool` (proxy)
   and `poolImpl`. Owner = the deployer.

Addresses are written to `deploy/addresses.<chainid>.json` (forge also writes
`chains/evm/broadcast/Deploy.s.sol/<chainid>/run-latest.json`).

### Config (env, with defaults)

| env | default | meaning |
|-----|---------|---------|
| `DEPLOYER_KEY` | anvil account 0 | deployer privkey; also the owner |
| `BATCH_SIZE` | `256` | disburse batch size (production) |
| `ARBITER_KEY_X` / `ARBITER_KEY_Y` | disburse256 fixture `pub[8..9]` | arbiter authority pubkey |
| `ARBITER_KEM_PK_HASH` | fixture hash — **chain 31337 only** | `keccak256` of the arbiter's ML-KEM-768 encapsulation key. Off anvil there is no default: `Deploy.s.sol` reads it with `vm.envBytes32`, which reverts when unset, and refuses the fixture value outright |
| `ARBITER_KEM_PK` | fixture key — **chain 31337 only** | the full encapsulation key recorded next to the hash; must hash to `ARBITER_KEM_PK_HASH`. Off anvil the deploy self-check fails without it (`no ARBITER_KEM_PK recorded`) |
| `LIVE_RPC` | the sdk `RPC_URL` | the chain the live invocation below and the `live/` drivers talk to (`.env.example` carries it) |
| `MODULE_PROFILE` | `none` (Deploy) / `consumer` (UpgradeV3) | which consumer module set the deployment registers — see [Deploy profiles](#deploy-profiles) |
| `MODULE_CHUNK_ARITY` | 86 at B=256, else 6 (min B) | outputs per disburse kem-ct chunk tx (OPMOD §5) |

### Deploy profiles

Which op families a deployment serves is the module registration list (OPMOD §7/§9 —
registration is `onlyOwner` + event-logged, upgrade-equivalent power):

| profile | how | arbiter key | what is registered |
|---|---|---|---|
| audited-only / enterprise | `Deploy.s.sol` with `MODULE_PROFILE=none` (the default — byte-identical to the pre-profile deploy), or `UpgradeV3.s.sol` with `MODULE_PROFILE=none` | required (epoch 0) | no consumer modules — the pool-level audit guarantee holds |
| consumer (shared pool) | `Deploy.s.sol MODULE_PROFILE=consumer` (fresh — how the live 450815 pool got them at genesis), or `UpgradeV3.s.sol` (the migration an existing pool would take — drilled on anvil only, never run on the retired 84532 pool, which stayed audited-only) | required (enterprise family live) | the 5 consumer modules via `ConsumerModuleKit` (`deploy/modules.<chainid>.json`). The shipped Maroo pool subsequently deregistered the disburse module (mass payout is enterprise-path only); a leaner p2p profile knob is follow-up work |
| consumer-only | `DeployConsumerOnly.s.sol` | **none exists** — `initializeConsumerOnly` mints no arbiter epoch, wires no enterprise verifier; every enterprise entrypoint reverts | the 5 consumer modules (records `addresses.consumer.<chainid>.json` + `modules.consumer.<chainid>.json`) |

`UpgradeV3.s.sol` is the OPMOD §7.3 migration for an EXISTING pool: consumer verifiers +
modules deployed first (inert until registered), then ONE
`upgradeToAndCall(reinitializeV3(modules))` — drilled by `gates/test_upgrade_v3.sh`
(v1 proxy → v3, modules registered, enterprise Smoke still accepted, rerun refused).

Orthogonal to the module profile, `VERIFIER_PROFILE` picks the verifier set
(`Deploy.s.sol` only):

| value | what deploys | record file |
|---|---|---|
| `standard` (default) | today's six verifiers, byte-identical to the pre-profile deploy | `addresses.<chainid>.json` |
| `ctf` | the four spending slots swap to the **ct-free enterprise** verifiers (TransferCtf / Transfer10Ctf / Transfer10x2Ctf / DisburseCtf256 — no receiver ciphertext content exists on such a pool; deposit/withdraw are reused, they publish none today); `MODULE_PROFILE` must stay `none` (audited-only by design) | `addresses.ctf.<chainid>.json` — the chain's canonical record is never touched |

The ctf profile is how a **dedicated enterprise pool** stands up beside a chain's
shared pool ([`docs/deployment.md`](../docs/deployment.md#deploy-profiles-and-the-consumer-module-family));
`gates/ctf_pool_local.sh` proves it end to end.

The two KEM knobs are **required off anvil, and deliberately have no live default** — a silent
fixture fallback would make every auditor envelope world-readable with nothing in the deploy saying
so ([`Deploy.s.sol` `_resolveKemPkHash`](forge/Deploy.s.sol)).

The default arbiter key is read straight from the committed
`chains/evm/test/fixtures/disburse256.public.json` public signals `[8..9]`, i.e.
the `authorityPublicKey` the real GPU 256-disburse proof was made against — so a
real 256 disburse verifies against the deployed pool's stored key out of the box.
Override the two env vars for a production key.

## Run locally

```sh
cd bongtu && bash deploy/gates/deploy_local.sh    # exits 0 iff deploy + smoke pass
```

It starts a background anvil (chainId 31337, trap-killed on exit — no leak),
runs `forge script Deploy --broadcast`, records the addresses, reads the getters
back via `cast` (asserts `B()==256`), then runs `forge script Smoke --broadcast`:
a **real deposit** against the DEPLOYED pool using the committed real deposit
proof (`realproofs.json .deposit`) — mint mock kKRW → approve → `deposit(...)` —
and asserts the deployed instance advanced (`nextLeafIndex` 0 → 2) and custodied
the tokens. Proves the full stack is live and correctly wired.

Overridable: `DEPLOY_PORT` (default 8550), `RPC`, `CHAINID`, `FORGE`/`ANVIL`/`CAST`.

The dedicated ct-free pool has its own gate:

```sh
cd bongtu && bash deploy/gates/ctf_pool_local.sh    # exits 0 iff every assertion holds
```

Scratch anvil → `VERIFIER_PROFILE=ctf` deploy (B=256, named record) → verifier
wiring proven by BYTECODE compare (addresses cannot prove it: a fresh chain
replays the same CREATE nonces as a standard deploy) → a real CPU deposit seeds
the committed fixture's input note → the committed **real GPU ct-free 256
disburse** settles, and the gate refolds the zeroed-receiver disclosure blob
against the proof's `disclosureHash` (`gates/ctf_leg.ts`).

## Deploy to the live testnet

The live B=256 stack is already deployed with this pipeline; its addresses are in
the committed `deploy/addresses.450815.json` (the retired Base Sepolia stack stays
recorded in `addresses.84532.json`). **The live pool is canonical — do not
redeploy for new work**; a circuit change ships as a UUPS upgrade (repo
[`CLAUDE.md`](../CLAUDE.md)). The runbook below is the recipe that produced it,
kept for a from-scratch redeploy.

The live chain is the SAME `forge/Deploy.s.sol` with different env. Its facts —
chain id, RPC, explorer, faucet, gas-price pin — have one home,
`packages/core/src/chain/network.ts`, and are tabulated in
[`docs/deployment.md`](../docs/deployment.md#chain-facts). It is a sovereign EVM
L1 (Cosmos-SDK x/feemarket EIP-1559 fees, gas token tOKRW) with the BN254
precompiles present — the smoke deposit's Groth16 proof verified natively on-chain.

```sh
cd bongtu/chains/evm
export DEPLOYER_KEY=0x<funded-key>   # from the chain's faucet; lives in .env (gitignored, template .env.example)
export LIVE_RPC=<the chain's RPC>    # docs/deployment.md#chain-facts; .env.example carries the current one

# REQUIRED off anvil — no default, and the fixture value is refused:
export ARBITER_KEM_PK_HASH=0x<keccak256 of the institutional encapsulation key>
export ARBITER_KEM_PK=0x<the full 1184-byte encapsulation key>

# optional: real arbiter bjj key / real token (else a mock kKRW is deployed)
# export ARBITER_KEY_X=... ARBITER_KEY_Y=...
# export TOKEN_ADDRESS=0x<existing-erc20>

forge script ../deploy/forge/Deploy.s.sol:Deploy \
  --rpc-url "$LIVE_RPC" \
  --broadcast --skip-simulation
```

`--skip-simulation` is required (and is exactly what the validated `gates/deploy_local.sh`
uses): `Deploy.s.sol` deploys Poseidon via inline-assembly `create`, which forge's
on-chain simulation cannot model.

Addresses land in `deploy/addresses.<chainid>.json`. Then the same smoke, pointed
at the live chain (needs the deployer funded; with the default `MockERC20`, mint
is open):

```sh
forge script ../deploy/forge/Smoke.s.sol:Smoke --rpc-url "$LIVE_RPC" --broadcast --skip-simulation
```

Notes for the live run:
- For a real token, set `TOKEN_ADDRESS=0x<erc20>` (no source edit needed); the
  smoke deposit then needs the deployer to actually hold + approve the deposit's
  `out` amount. With the default `MockERC20` the script mints it.
- The chain is an L1, so a receipt's `gasUsed` × effective gas price is the whole
  cost (no OP-Stack L1 data fee). The x/feemarket base fee floor is high (8000
  gwei measured 2026-09-04) — budget deploys in whole tOKRW, not fractions.
- solc is pinned to 0.8.24 here; deployment is permissionless and BN254 verify is
  native.
- Source verification on the live chain's Blockscout works per contract:
  `forge verify-contract <addr> <path>:<Name> --chain-id 450815 --verifier blockscout
  --verifier-url https://explorer-testnet.maroo.io/blockscout/api` (constructor
  args for the proxy). The pool implementation, proxy and DepositVerifier are
  verified; Poseidon cannot be (no Solidity source).

### Deploy the receive factory (add-on, live chain — the human step)

The receive product's contracts (`PortalPrivFactory`/`PortalPrivSweeper`,
[docs/portal.md](../docs/portal.md#receiving-the-consumer-pay-page)) ship as an
add-on deploy beside the pool — no pool transaction of any kind. Preconditions
the script itself enforces: the chain's record holds a pool AND
`deploy/modules.<chainid>.json` holds a `depositPrivModule` (the consumer module
set must already be registered). Rerun-guarded on the record's `portalPrivFactory`
field (a second factory would strand every announcement issued against the
first).

```sh
cd bongtu/chains/evm
export DEPLOYER_KEY=0x<funded-key>
# optional: a dedicated sweep-bot EOA (defaults to the broadcaster)
# export BOT=0x<bot-address>
forge script ../deploy/forge/DeployPortalPriv.s.sol:DeployPortalPriv \
  --rpc-url "$LIVE_RPC" --broadcast --skip-simulation
```

The factory address lands in `deploy/addresses.<chainid>.json` as
`portalPrivFactory` — copy it BY FIELD NAME into the live wiring: the public
indexer's `PORTAL_PRIV_FACTORY` (+ `PORTAL_OPERATOR_TOKEN`, shared with the bot),
the receive-mode sweeper (`MODE=priv`, `apps/sweeper/README.md`), the
pay-web Vercel project's `VITE_PORTAL_PRIV_FACTORY` /
`VITE_SWEEPER_INITCODE_HASH` (`apps/pay-web/README.md`), and — if the pay-web
project's domain differs from the wallet's default — the wallet-web project's
`VITE_PAY_BASE_URL` (the Receive screen's copy-payment-link host). The anvil
drill for this script is `gates/test_deploy_portal_priv.sh`.

### Deploy the Sepolia payment-name demo stack

The payment name's acceptance environment
([docs/portal.md](../docs/portal.md#the-payment-name-ens-front-door)): a
consumer-only pool wrapping Circle's Sepolia USDC and the priv factory on
chain 11155111 — the live Maroo pool is never touched — plus the NAME leg
(the `.eth` registration and the CCIP resolver) on **mainnet**, because
Sepolia can no longer host a fresh name (step 1). The anvil drill for the
whole contract ladder is `gates/test_deploy_consumer_name.sh`; the automated
resolution gate is `gates/name_leg.ts` inside `e2e_m0.sh`. Every step below
is a human step (user-held keys); the funds side costs nothing but faucet
funds, the name leg a few dollars (rent $5/yr for 5+ characters, gas in
cents at mainnet's measured ~0.05 gwei).

**Step 0 — canary.** Before deploying anything, resolve
`test.offchaindemo.eth` in each wallet that matters (Phantom especially):
that measures its CCIP-Read support for free. Record the result in the
wallet-support matrix ([docs/portal.md](../docs/portal.md#the-payment-name-ens-front-door)).

**1. Register the root name on MAINNET** from the name-owner wallet.
Sepolia registration is dead for fresh names (measured 2026-09-08): the
ENSv2 cutover deauthorized the v1 `.eth` controllers there around block
10.93M, the six v2-system controllers carry no classic commit/reveal ABI,
and MetaMask's resolver snap reads only the v1 registry — so a name
registered on the v2 beta never reaches a wallet. The v1 READ path is
intact, which is why an already-owned Sepolia name would still resolve;
there is just no way to mint one. The ENS app works for mainnet
registration; so does cast against the current controller
`0x59E16fcCd424Cc24e280Be16E11Bcd56fb0CE547` (2025 Registration-struct ABI:
`commit(makeCommitment(...))`, wait 60 s, `register(...)` with the resolver
baked in). Everything below is parameterized on `{root}.eth`.

**2. Deploy the contracts** (deployer funded from a Sepolia faucet):

```sh
cd bongtu/chains/evm
export DEPLOYER_KEY=0x<funded-sepolia-key>     # .env (gitignored)
export LIVE_RPC=https://<sepolia-rpc>

# the consumer-only pool wrapping Circle's Sepolia USDC — copy the token
# address from Circle's published record AT DEPLOY TIME, by field name
TOKEN_ADDRESS=0x<circle-sepolia-usdc> \
forge script ../deploy/forge/DeployConsumerOnly.s.sol:DeployConsumerOnly \
  --rpc-url "$LIVE_RPC" --broadcast --skip-simulation

# the priv factory, against the CONSUMER record pair
RECORD_PROFILE=consumer \
forge script ../deploy/forge/DeployPortalPriv.s.sol:DeployPortalPriv \
  --rpc-url "$LIVE_RPC" --broadcast --skip-simulation

# the resolver goes on MAINNET beside the name; owner = the rotation-lever
# holder, signer = the gateway key's ADDRESS, URL = the public gateway.
# forge create, not DeployNameResolver: the script merge-writes the chain's
# consumer record, whose base fields (pool, factory) do not exist on
# mainnet. --constructor-args is greedy — it must come LAST.
forge create src/PortalPrivResolver.sol:PortalPrivResolver \
  --rpc-url "$MAINNET_RPC" --private-key "$DEPLOYER_KEY" \
  --constructor-args 0x<owner> 0x<address-of-ENS_GATEWAY_KEY> \
  '["https://<indexer-host>/ens/{sender}/{data}.json"]'
```

Commit the resulting `deploy/addresses.consumer.11155111.json` +
`modules.consumer.11155111.json`. Wire everything downstream from that pair
BY FIELD NAME. The mainnet resolver has no record file (the consumer
record's base fields are the pool's); the live one is recorded here
instead — see the demo record note below.

**3. `setResolver` on the root name** (one mainnet tx from the name-owner
wallet — free if the resolver was baked into `register()` in step 1): point
`{root}.eth` at the mainnet resolver. Wildcard resolution makes every
directory label resolve with no further per-name transaction.

**4. Host the indexer/gateway publicly over HTTPS** (MetaMask's resolver
snap fetches the gateway URL directly, so a tunnel or public host is
required). Env, beyond the standard table in
[`apps/indexer/README.md`](../apps/indexer/README.md): `CHAIN_ID=11155111`, a
Sepolia RPC (`LOG_CHUNK=10000` suits rate-capped public RPC), `POOL` +
`PORTAL_PRIV_FACTORY` from the consumer record, `PORTAL_OPERATOR_TOKEN`
(shared with the bot), `ENS_RESOLVER` (the MAINNET resolver from step 2),
`ENS_GATEWAY_KEY` (the signing key whose address the resolver holds as
signer), `ENS_GATEWAY_CHAIN_ID=1` — senders resolve with mainnet selected,
so the gateway must serve coinType 60 and the legacy `addr(bytes32)` form
(measured: a Sepolia-selected MetaMask resolves against Sepolia's OWN
registry and never falls back to mainnet, so `ENS_GATEWAY_CHAIN_ID=11155111`
answers nobody). No `AUTHORITY_KEY` exists on this profile.

This split (resolution on mainnet, funds on Sepolia) is a measured
wrong-chain hazard: the mainnet-selected wallet displays a Sepolia-only
destination, and any MAINNET asset sent there is permanently stranded.
The demo posture is resolve-to-view-and-copy only, then paste-send on
Sepolia (step 7); suppressing the chain-ambiguous answer forms when
resolution chain != funds chain is a named follow-up.

Funded detection knobs (defaults suit the demo): `FUNDED_CONFIRMATIONS=2`
(the transfer-tail lag), `FUNDED_RECONCILE_ON_BOOT=1` only to force the
one-time balance reconciliation on a suspect store. **Restart ordering on
an upgrade to the funded-tail build: the INDEXER first** — the bot's only
sweep trigger is the `funded` field this indexer serves, so a new bot
against an old indexer sweeps nothing (visible as a stuck `unswept` count
in the bot's `/health`); the indexer's first boot heals pre-existing rows
via the reconciliation pass, after which the bot follows.

**5. Run the sweeper bot** (`MODE=priv`, CPU prover, explicit env per
[`apps/sweeper/README.md`](../apps/sweeper/README.md)); fund its key from a
Sepolia faucet — `/health` alarms on a zero gas balance.

**6. Point the web apps** at the demo: wallet-web + pay-web with
`VITE_TOKEN_SYMBOL=USDC`, `VITE_TOKEN_DECIMALS=6`, `VITE_CHAIN_NAME=Sepolia`,
`VITE_PORTAL_PRIV_FACTORY` + `VITE_SWEEPER_INITCODE_HASH` from the record,
and the indexer URL. The browser fallback is a DNS wildcard on the product
domain redirecting `{label}.<domain>` to the pay page's `/p/{label}`.

**7. The acceptance loop** (spec R6, run personally, completed live
2026-09-08): register a v2 payment name; in MetaMask (extension updated —
a stale extension fails the step-0 canary too, root-caused live) with
**mainnet selected**, type `{label}.{root}.eth` into the send field and
note the resolved address. Expect 1–3 s before it appears: an offchain
resolution is a gateway HTTPS round trip, not a local lookup. Close the
popup or wait 60 s (the extension's forward cache is 60 s per (name,
chain), UI-session scoped; mobile caches nothing) and resolve again — the
two addresses differ; confirm both appear on `GET /portal/announcements`
and match the recipient's view-key scan. Copy the address, **switch the
wallet to Sepolia**, and send faucet USDC to it — the recorded `token`
(Circle's Sepolia USDC) ONLY: the sweeper serves exactly the pool's token,
and anything else at the destination is stranded (measured live — the
first demo send used a lookalike Sepolia "USDC" and stranded it; harmless
on testnet, the C1 warning on mainnet). The bot sweeps it unattended; the
shielded balance shows in wallet-web after the derive signature (the
signature IS the viewing key — an unsigned session scans nothing, by
design). An Etherscan name-page refresh is the secondary freshness display
(it re-resolves per load).

**Live demo record (2026-09-08).** The funds stack is the committed
`addresses.consumer.11155111.json` pair. The name leg, recorded here
because no chain-1 record file exists: `pripay.eth` (mainnet v1,
name-owner wallet), resolver `PortalPrivResolver` at
`0xFa309Ff90ef2cd1781824Cf8a7Fdb1Bf0D237E9E` (chain 1; owner = the
Sepolia record's `owner`, signer = its `gatewaySigner`). The recorded
`gatewayUrl` mirrors deploy time; a quick-tunnel host rotates on every
tunnel restart — `setGatewayUrls` from the resolver owner (on BOTH
resolvers if the Sepolia one is kept current) is the lever, then update
the record field.

**Signer rotation** (a leaked gateway key signs redirections — detectable,
per the evidence chain — until rotated): the resolver owner calls
`setSigner(newAddress)` (one tx), the indexer's `ENS_GATEWAY_KEY` env swaps
to the new key, restart. `setGatewayUrls` is the same lever for a URL move.

**Mainnet promotion** (the ladder after the demo passes; posture:
[docs/security-model.md](../docs/security-model.md#stealth-receiving-the-portalreceive-edge)
— real value on unaudited contracts, self-test scale, root unadvertised,
audit before anything beyond): the name and resolver are already on
mainnet, so promotion is the FUNDS stack — run `DeployConsumerOnly` +
`DeployPortalPriv` against mainnet with real USDC as the token (a few
dollars at the measured ~0.05 gwei); commit `addresses.consumer.1.json`
and merge the existing resolver triple into it by hand (DeployNameResolver
refuses a rerun where a resolver exists; rotation stays
`setSigner`/`setGatewayUrls`); point the gateway's `POOL` +
`PORTAL_PRIV_FACTORY` at the new record (`ENS_GATEWAY_CHAIN_ID=1`
unchanged — resolution chain now equals funds chain, which retires the
wrong-chain posture above); fund the mainnet bot key; re-run the loop with
real USDC. Only the pool's USDC is swept — ETH or any other token sent to
a destination is permanently stranded (the C1 warning in
security-model.md).

### Deploy the dedicated ct-free enterprise pool (second pool, same chain)

One command stands a dedicated enterprise pool BESIDE the chain's shared pool —
the record goes to `addresses.ctf.450815.json`, so `addresses.450815.json` (the
canonical Maroo consumer pool) is never touched:

```sh
cd bongtu/chains/evm
export DEPLOYER_KEY=0x<funded-key>
export LIVE_RPC=<the chain's RPC>            # docs/deployment.md#chain-facts

# REQUIRED: a FRESH institutional KEM keypair for this pool — never reuse the
# shared pool's arbiter-kem-pk.450815.hex, and the fixture key is refused:
export ARBITER_KEM_PK_HASH=0x<keccak256 of the institution's encapsulation key>
export ARBITER_KEM_PK=0x<the full 1184-byte encapsulation key>

# The bjj half DEFAULTS to the fixture key so the committed ct-free proof
# fixtures verify against the pool (docs/deployment.md#the-arbiter-key-is-fixed-at-deploy-and-the-fixtures-are-bound-to-it);
# override both halves together only with freshly re-proven fixtures.

VERIFIER_PROFILE=ctf forge script ../deploy/forge/Deploy.s.sol:Deploy \
  --rpc-url "$LIVE_RPC" --broadcast --skip-simulation
```

Prove wiring with the cast read-backs (`B()==256`, verifier getters == record
fields) rather than a smoke deposit — a live pool that runs the fixture-KEM smoke
carries one permanent envelope alarm (deployment.md). Then commit the new
`addresses.ctf.450815.json`.

## Layout

Canonical data stays at the top; everything else is grouped by what runs it.

- `addresses.31337.json` / `addresses.450815.json` — recorded deployments (local anvil / the live
  testnet); `addresses.84532.json` is the retired Base Sepolia stack, kept as a historical record.
  Take an address from these **by field name**: the deployer replays the same CREATE
  nonces on every chain, so several addresses recur across deployments while
  naming different contracts.
- `modules.<chainid>.json` — the consumer module set registered on the pool of
  `addresses.<chainid>.json` (written by `Deploy.s.sol MODULE_PROFILE=consumer` and
  `UpgradeV3.s.sol`; the canonical on-chain source is the `ModuleRegistered` event stream, this
  file is the deploy-time mirror). The 31337 file is tracked scratch, same as `addresses.31337.json`.
- `addresses.consumer.<chainid>.json` / `modules.consumer.<chainid>.json` — the consumer-only
  profile's record pair (`DeployConsumerOnly.s.sol`; tracked scratch at 31337).
  The **by field name** rule above covers the module records too: never take an address from any
  of these files by pattern-matching a remembered value.
- `addresses.ctf.<chainid>.json` — the dedicated ct-free enterprise pool's record
  (`Deploy.s.sol VERIFIER_PROFILE=ctf`; same field list as the unnamed record, tracked scratch
  at 31337). No modules file exists for it: the profile is audited-only by construction.
- `arbiter-kem-pk.450815.hex` — the live arbiter's ML-KEM-768 public key (byte-identical to the
  historical `arbiter-kem-pk.84532.hex`: the arbiter did not rotate on the chain move).

`forge/` — the Solidity scripts, run through `forge script` from `chains/evm/`:

- `Deploy.s.sol` — the whole stack in one broadcast (Poseidon + the six verifiers + impl + ERC-1967
  proxy running `initialize`) + the `addresses.<chainid>.json` writer; `MODULE_PROFILE=consumer`
  additionally deploys + registers the consumer module set.
- `UpgradeV2.s.sol` — the shipped stealth-withdraw upgrade (verifier + impl + `reinitializeV2`).
- `UpgradeV3.s.sol` — the op-module upgrade for an EXISTING pool: consumer verifiers + modules +
  ONE `upgradeToAndCall(reinitializeV3(modules))` (OPMOD §7.3); merge-writes `poolImpl`, writes
  `modules.<chainid>.json`.
- `DeployConsumerOnly.s.sol` — the consumer-only profile (`initializeConsumerOnly`: no arbiter key
  exists; consumer modules are the whole op surface).
- `ConsumerModuleKit.sol` — the one declaration of the consumer module-set deploy + its record writer.
- `DeployNameResolver.s.sol` — the payment name's CCIP resolver (`PortalPrivResolver`) beside a
  recorded priv factory: signer + gateway URL from env, recorded into the consumer record by field
  name (`resolver`, `gatewaySigner`, `gatewayUrl`); rerun-guarded.
- `Smoke.s.sol` — real-deposit smoke tx against the deployed pool.
- `AddressBook.sol` — the one declaration of the addresses-file field list, plus its read + merge-write.
- `ConsumerBook.sol` — the same declaration for the consumer record pair
  (`addresses.consumer.<chainid>.json`), so add-on scripts merge-write without dropping each
  other's fields.

`live/` — TypeScript drivers against the canonical LIVE pool (`addresses.<chainid>.json`). Each needs
`DEPLOYER_KEY` and pins `gasPrice` from `GAS_PRICE_PIN_GWEI`:

- `payroll_e2e.ts` — the payroll console's whole pay run, driving the console's own modules,
  every proof through the [`prover/`](../prover/README.md) service.
- `transfer10x2_e2e.ts` — the 10-in / 2-out spend gate (`--dry` for a network-free check).
- `gas_survey.ts` — per-action gas measurement feeding [`docs/performance.md`](../docs/performance.md).
- `lib/` — the viem rig + proof toolbox the drivers and the anvil gates share.

`gates/` — the pass/fail scripts (CI and pre-release):

- `deploy_local.sh` — anvil + Deploy + getter reads + Smoke (also the CI `forge` job's deploy gate).
- `test_upgrade_v3.sh` — the op-module upgrade drill (v1 proxy → UpgradeV3 → modules registered,
  enterprise Smoke still accepted, rerun refused).
- `e2e_m0.sh` / `e2e_orchestrator.ts` — the M0 full spend-cycle e2e on a fresh anvil, including the
  portal leg (`portal_leg.ts`), the arbiter-free consumer leg (`consumer_leg.ts`: profile deploy +
  V3 upgrade, CPU-proved consumer ops + disburse chunk txs, PUBLIC indexer, self-scan discovery +
  batch-interior spend via the auth-free `/path`, and the committed disbursePriv256 calldata replay),
  the receive leg (`portal_priv_leg.ts`: pay-page issuance, distinct-EOA payments, receive-mode
  depositPriv sweeps, the R7 unlinkability grep, self-scan discovery), and the payment-name leg
  (`name_leg.ts`: the wallet's CCIP-Read loop against the real resolver + gateway indexer —
  per-resolution freshness, announce-before-return, tamper/expiry rejection, coinType routing,
  sweep + self-scan).
- `test_deploy_portal_priv.sh` — the receive-factory add-on deploy drill (module-set precondition,
  happy path, rerun refusal).
- `test_deploy_consumer_name.sh` — the consumer-record ladder drill (DeployConsumerOnly →
  DeployPortalPriv `RECORD_PROFILE=consumer` → DeployNameResolver on a scratch anvil, asserting the
  record fields land, both rerun refusals, and the factory-first precondition).
- `test_one_shot_deploy.sh` — scratch-anvil drill of the deploy: B=256, all six verifier getters
  wired and matching the record, Initializable version 1, `currentEpoch() == 0`.
- `upload_circuits.sh` — publishes the wallet's proving assets to the Vercel Blob store.

## License

Apache-2.0 — see the root [`LICENSE`](../LICENSE).
