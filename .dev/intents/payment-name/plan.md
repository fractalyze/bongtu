# Payment name: plan

Spec: [spec.md](spec.md)

Grounding: repo facts verified in-session (indexer issuance seam, store
atomicity, sweeper config, deploy scripts, record triangle); MetaMask and ENS
facts are source-verified in the two knowledge notes the spec cites. No other
feature build is in flight; the only sibling worktrees are parked.

## Changes

Ordered work units, one commit each, every unit with the test that proves it.

### U1: core ENS wire helpers

- `packages/core/src/chain/ens.ts` (new, exported `@bongtu/core/ens`): DNS wire
  encoding of a name (`dnsEncodeName`), label extraction and ENSIP-15-safe
  normalization guard (fail closed to the directory grammar), namehash,
  ENSIP-11 coinType helpers (`coinTypeForChain(chainId)`, `chainForCoinType`),
  and the CCIP response signature preimage
  (`0x1900 ‖ resolver ‖ expires ‖ keccak(request) ‖ keccak(result)`, the
  ensdomains offchain-resolver convention) plus a local secp256k1 signer over
  it. No new dependency: keccak/secp are already in core.
- Proof: `packages/core/test/ens.test.ts` with vectors cross-checked against
  known namehash/dnsEncode values (e.g. the canary names) and a
  sign-then-recover round trip; normalization rejects what the directory
  grammar rejects.

### U2: PortalPrivResolver contract

- `chains/evm/src/PortalPrivResolver.sol` (new): ENSIP-10 `resolve(bytes name,
  bytes data)` reverting `OffchainLookup(sender, urls, callData, callbackFn,
  extraData)` (ERC-3668); `resolveWithProof` verifying the owner-set signer
  and expiry over the U1 preimage; owner ops `setSigner`/`setGatewayUrls`
  (Ownable2Step, the factory precedent); `supportsInterface` for ENSIP-10.
  It stores no name or address data. Minimal local interfaces, no ENS
  dependency (C9 stays closed; the lock is untouched).
- Proof: `chains/evm/test/PortalPrivResolver.t.sol`: the revert carries the
  configured urls and calldata; a gateway-shaped signed response verifies and
  an expired or wrong-signer one reverts; the parity vector for the signature
  preimage is shared with U1's TS test (committed constants both sides, the
  stealth.test.ts discipline).

### U3: indexer gateway routes

- `apps/indexer/src/api/routes/ensGateway.ts` (new) + router registration:
  `GET/POST /ens/{sender}/{data}.json` per the CCIP-Read transport. Flow per
  request: decode the dns-encoded name and the inner `addr(node[, coinType])`
  call from `data`; label -> `names.resolve` (v2 consumer record required,
  fail closed); map coinType to a configured funds chain (R13; unserved
  coinType or bare coinType-60 when mainnet is not a configured funds chain =
  empty answer, NO row minted); derive server-side with the
  `handlePayPortal` scalar-draw-and-discard seam against THAT chain's
  factory; `portal.issue` (announce-before-return, first-write-wins) with
  `rail: "evm"` and the chain's factory recorded; ABI-encode the address
  answer, sign with the gateway key (U1), return `{ data }` with
  `Cache-Control: no-store` and expiry <= 300 s.
- `apps/indexer/src/chain.ts`: `ENS_GATEWAY_KEY` (never logged, AUTHORITY_KEY
  discipline) and a funds-chain map (chainId -> { portalPrivFactory,
  sweeperInitCodeHash }) seeded from env; boot line states served coinTypes.
- Proof: `apps/indexer/test/ensGateway.test.ts` (fast suite): happy path
  returns a signed answer the U2 verifier accepts (shared vector); the same
  label twice returns two DIFFERENT addresses and two announce rows; a
  configured-chain coinType routes to that chain's factory address; unserved
  coinType answers empty and mints nothing; v1-only label fails closed; the
  scalar never appears in responses or logs; rows are indistinguishable from
  pay-page rows on the public feed.

### U4: deploy scripts and the Sepolia record shape

- `deploy/forge/DeployPortalPriv.s.sol`: teach it the consumer record pair
  (`addresses.consumer.<chainid>.json` + `modules.consumer.<chainid>.json`)
  when the enterprise record is absent (spec finding; today it reads only the
  enterprise files and cannot run on the consumer-only profile).
- `deploy/forge/DeployNameResolver.s.sol` (new): deploys PortalPrivResolver
  with signer + gateway URL from env, appends `resolver`, `gatewaySigner`,
  and `gatewayUrl` fields into the consumer record by name.
- `deploy/gates/test_deploy_consumer_name.sh` (new drill, the
  test_deploy_portal_priv.sh mold): scratch anvil, DeployConsumerOnly ->
  DeployPortalPriv (consumer pair path) -> DeployNameResolver, asserting the
  record fields land and reruns are refused; rewrites the 31337 consumer
  records (checkout before commits).
- Proof: the drill script exits 0; forge tests still green.

### U5: wallet-web and pay-web token facts knob (spec R12)

- `apps/wallet-web` + `apps/pay-web`: `VITE_TOKEN_SYMBOL` and
  `VITE_TOKEN_DECIMALS` (defaults kKRW/18 keep Maroo byte-identical); the
  payments fold, amount formatting, and facts cards read them; USDC/6 on the
  Sepolia profile.
- Proof: existing display tests extended with a 6-decimal profile case; Maroo
  default case pinned unchanged.

### U6: the resolution gate leg

- `deploy/gates/name_leg.ts` + wiring into `e2e_orchestrator.ts` behind its
  own database guard (the portal-priv leg pattern): anvil stack (consumer
  deploy + factory + resolver via U4 scripts), real indexer with the gateway
  routes, then a driver that mimics the wallet's CCIP loop: call
  `resolver.resolve`, catch `OffchainLookup`, fetch the gateway URL, submit
  through `resolveWithProof`, assert the returned destination equals the
  factory's `addressOf` for the minted row's salt. Assertions: (a) two
  resolutions differ; (b) both were announced BEFORE the response returned
  (row exists when the HTTP response lands); (c) tampered response and
  expired signature revert; (d) coinType routing picks the right factory;
  (e) pay the resolved destination and run the sweeper library once: the
  payment lands in the pool for the registered keys (the R6 loop, headless);
  (f) the public feed carries no attribution.
- Proof: the leg exits 0 inside `e2e_m0.sh` on the dev box.

### U7: docs

- `docs/portal.md` (name front door section), `docs/security-model.md`
  (gateway operator row, freshness-as-gateway-trust, wrong-asset stranding
  wording per C1), `docs/indexer.md` (gateway routes, env, coinType map),
  `docs/deployment.md` + `deploy/README.md` (Sepolia runbook: register name,
  set resolver, host gateway, bot), `apps/*/README.md` deltas, root README
  layout row.
- Proof: reviewer diff-vs-plan pass; no shielded-wording violations.

### U8: Sepolia ops preparation (build-side only)

- The runbook (in deploy/README.md, U7) enumerated as executable steps with
  exact commands: Sepolia ENS name registration (user wallet, ENS app),
  `setResolver`, DeployConsumerOnly + DeployPortalPriv + DeployNameResolver
  with `DEPLOYER_KEY`/RPC env, gateway hosting (public HTTPS; the indexer's
  existing hosting pattern or a tunnel), indexer + sweeper env for 11155111,
  Circle faucet USDC pointers, and the demo script (resolve, wait 60 s or
  close popup, resolve again, send, watch wallet-web). Canary pre-check
  (`test.offchaindemo.eth`) as step 0.
- Proof: none to automate; the human-executed R6 run is the acceptance.

## Risks

- **CCIP loop fidelity**: the gate's hand-rolled OffchainLookup loop could
  diverge from wallet behavior. Mitigation: U6 also resolves the name through
  viem's `getEnsAddress` with a local `universalResolver` override where
  practical; the Sepolia run with real MetaMask is the final word (R6).
- **ENS registry on the gate chain**: the leg does not deploy a full ENS
  registry; the driver calls the resolver directly (ENSIP-10 entry). The
  Sepolia environment exercises the registry path. Stated in the leg header.
- **Signature preimage mismatch TS vs Solidity**: pinned by a shared
  committed vector (U1/U2), the stealth parity-vector discipline.
- **Gateway key handling**: `ENS_GATEWAY_KEY` follows the AUTHORITY_KEY
  never-logged rule; tests grep boot output.
- **Row spam via public resolution** (C3): unserved coinTypes mint nothing;
  rate limiting stays ops; Etherscan-refresh minting documented.
- **Sweeper on Sepolia**: config reads the consumer record by chain id
  already parameterized; only env changes. The drill (U4) proves the record
  path; the leg (U6) proves the sweep.
- **Maroo regression**: defaults keep every Maroo surface byte-identical
  (U5 defaults, gateway routes 404 when unconfigured); quick gates plus the
  full e2e_m0 run before PR.
- **Lock file**: no new dependencies anywhere; if one proves necessary the
  CLAUDE.md scratch-dir regen procedure applies.

## Proving gates

- Per iteration: core tests, indexer `npm run test:unit`, forge
  `--match-contract PortalPrivResolver`, wallet-web/pay-web tests, root tsc +
  `npm run typecheck --workspaces --if-present`.
- Final, before PR: `deploy/gates/e2e_m0.sh` including the new name leg and
  the three existing legs; indexer conformance (`cd apps/indexer && npm
  test`); the U4 drill; lock untouched check.
