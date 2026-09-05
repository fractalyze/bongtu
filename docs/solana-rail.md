# The Solana rail

The same op-family design on Solana, reusing the moat assets verbatim: the
BN254 Groth16 circuits, `.zkey`/verifier artifacts, the Poseidon note algebra,
and the discovery crypto are byte-identical across rails — no circuit fork.
Only the pool program, indexer ingestion, client transaction building, and
deploy are Solana-specific. The program lives in
[`chains/solana/`](../chains/solana/README.md); the design spec with full
rationale is `.dev/solana-rail-design.md` (SOLR).

## Program shape

One program (`bongtu_pool`), instruction families, and a config-flag registry:

- **Families as flags.** The EVM module registry maps to family-enable bits in
  the `PoolConfig` account. Which families a pool serves is attestable from
  the config account; the flag history is permanent ledger data. Family
  provenance is the instruction discriminator — public per transaction, as on
  the EVM rail.
- **State as PDAs.** `PoolConfig` (`["config", mint]`) and `TreeState`
  (`["tree", config]`) give deterministic discovery from the mint. Nullifiers
  and known roots are marker PDAs (existence == fact); a disburse batch
  persists a `DisburseBatch` PDA. The escrow vault is a token account owned by
  the program's vault-authority PDA. Marker seeds carry no config key, so one
  pool per program deployment — a second pool needs a second program id.
- **`initialize` is one-shot.** A single signed transaction creates the
  config + tree PDAs and records the complete profile (flags, batch B,
  arbiter key + KEM pk hash — zeroed on consumer-only profiles: "no key
  exists" is attestable). Malformed profiles are refused on-chain: B must be
  a power of two, enabling `disburse256` requires B = 256, enterprise flags
  require a canonical nonzero key, and a consumer-only profile may carry no
  key. There is no re-initialize and no parameter ladder.

## Transactions

Every op is single-transaction under the Transaction v1 format (SIMD-0385,
4,096 B): after a 1-byte discriminator the payload is
`proof || carried publics || KEM ciphertexts (|| stealth tail)`. Publics the
program can reconstruct never ride the wire: `enabled` derives from the
nullifiers, the arbiter key injects from the config (a proof against any other
key fails), and the withdraw recipient binds from the accounts list under the
truncate-253 rule. On v1 the compute budget is mandatory header config;
per-op CU budgets are committed in `chains/solana/cu_budget.json` and
regression-gated by mollusk.

## The 1-tx disburse and served disclosure

On the EVM rail, disburse disclosure publication is a consensus rule. The
Solana default keeps the chain holding the **binding**, not the bytes: the
256-out disburse verifies `disclosureHash` (the in-circuit fold of the
2,054-element disclosure blob) and persists it in the fixed 82-byte
`DisburseBatch` anchor — no per-recipient record, so recipient-count hiding is
structural. The blob itself is institution-served:

- the indexer (Solana backend) holds blobs from the operator's
  `DISCLOSURE_DIR` and serves `GET /disclosure/{start}` with a refold verdict;
- ANY party refolds the served elements against the on-chain anchor — no key,
  no trust, only availability;
- a blob that fails the refold alarms `mismatch`; a batch unserved past the
  grace window alarms `withheld` ([`docs/indexer.md`](indexer.md)).

What this trades and what it keeps is stated in
[`docs/security-model.md`](security-model.md#per-rail-scope-of-from-on-chain-data-alone-solana);
a consensus-forced full-DA variant is documented in the spec (SOLR §3.3.3) for
deployments that demand it.

## Discovery

Ops emit self-CPI events; the indexer ingests by signature cursor from ledger
history and serves the same read model and API surface as the EVM backend
(`/head`, `/leaves`, `/events`, `/path` — plus `/disclosure` on this rail).
Consumer self-scan runs unchanged: a wallet discovers its balance from the
public feed with only its keys.

## Deploying

The program deploys via the BPF upgradeable loader; a pool is then one
`initialize`. Runbook, profiles, per-cluster addresses records, and the
upgrade-authority policy (testnet single key; mainnet multisig, never burned
while the ZK-syscall risk is open) live in
[`deploy/solana/README.md`](../deploy/solana/README.md).

## Gates

The mollusk suite (`chains/solana/gates/mollusk.sh`) is the iteration loop:
Poseidon conformance, verify parity against the committed EVM realproof
fixtures, CU budgets, transaction sizes, the invariant-gate matrix, the
disburse refold, attach differentials, and the `initialize` profile matrix.
The final gate is `chains/solana/gates/e2e_s.sh`: a local validator run of
both profiles — the consumer client path with real CPU proofs and self-scan,
and the enterprise family ending in a 1-tx 256-out disburse whose served
disclosure is independently refolded against the on-chain anchor.
