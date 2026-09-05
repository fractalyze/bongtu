# bongtu deploy — Solana rail

Deploying the `bongtu_pool` program to a cluster and initializing a pool
profile. The EVM stack's deploy lives one level up ([`deploy/README.md`](../README.md));
this folder owns the Solana side: the cluster runbook, the one-shot
`initialize` driver, and the per-cluster addresses record.

The local drill is the e2e gate — `bash chains/solana/gates/e2e_s.sh` runs
this exact sequence (deploy → initialize → operate) against a
`solana-test-validator` for both profiles on every heavy CI run.

## What a deployment is

1. **The program** — `bongtu_pool_solana.so`, deployed once per cluster via
   the BPF upgradeable loader. One pool per program deployment: the
   nullifier/root/batch PDA seeds carry no config key, so a second pool needs
   a second program id (`chains/solana/README.md` consensus conventions).
2. **The mint** — an existing SPL mint (the kKRW twin), or one you create.
3. **The vault** — a token account of that mint owned by the program's
   vault-authority PDA. Created outside the program (the program validates
   and records it; it never CPIs the ATA program).
4. **`initialize`** — discriminator 0, one signed transaction that creates
   the `PoolConfig` + `TreeState` PDAs and records the complete profile:
   family flags, batch B, arbiter key + KEM pk hash (zeroed on consumer-only
   profiles). There is no follow-up ladder and no re-initialize.

## Runbook

```sh
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
cd bongtu

# 1. Build + deploy the program (the deployer keypair pays and becomes the
#    upgrade authority — see the policy below).
cargo-build-sbf --manifest-path chains/solana/program/Cargo.toml
solana program deploy chains/solana/target/deploy/bongtu_pool_solana.so \
  --url "$SOLANA_RPC" --keypair "$DEPLOYER_KEYPAIR" \
  --program-id chains/solana/target/deploy/bongtu_pool_solana-keypair.json

# 2. Print the PDAs for your mint (config, tree, vault authority):
MINT=<mint address> node_modules/.bin/tsx deploy/solana/initialize_pool.ts --derive-only

# 3. Create the vault: a token account of the mint owned by the printed
#    vault-authority PDA (any such account works; the ATA is conventional):
spl-token create-account "$MINT" --owner <vault authority PDA> \
  --url "$SOLANA_RPC" --fee-payer "$DEPLOYER_KEYPAIR"

# 4. Initialize the profile and write the addresses record:
SOLANA_RPC=<rpc> CLUSTER=<name, e.g. devnet> \
MINT=<mint> VAULT=<vault token account> \
DEPLOYER_KEYPAIR=<path to id.json> \
FAMILY_FLAGS=0x01ff BATCH_B=256 \
ARBITER_KEY_X=<decimal> ARBITER_KEY_Y=<decimal> \
ARBITER_KEM_PK_HASH=0x<32-byte hex> \
  node_modules/.bin/tsx deploy/solana/initialize_pool.ts
```

Addresses land in `deploy/solana/addresses.<cluster>.json` — commit the
record; it is the per-cluster account set every client and gate binds
(`SolanaPoolAccounts`), the sibling of the EVM `deploy/addresses.<chainid>.json`.

### Profiles

Same semantics as the EVM deploy profiles ([`docs/deployment.md`](../../docs/deployment.md#deploy-profiles-and-the-consumer-module-family)),
expressed as the config's family flags instead of a module registry:

| profile | `FAMILY_FLAGS` | `BATCH_B` | arbiter material |
|---|---|---|---|
| consumer-only | `0x000f` (the four P2P ops) | 16 | MUST be absent — "no key exists", attestable from the config account |
| enterprise / mixed | `0x01ff` (full family) or a subset | 256 (required whenever the disburse256 flag is on) | required: canonical bjj key + the KEM pk hash |

`initialize` refuses a malformed profile on-chain (non-power-of-two B,
disburse256 with B ≠ 256, enterprise flags without a key, a lingering key on
a consumer-only profile) — the same checks the mollusk gate 8 pins.

### Arbiter key coupling

Every committed proof fixture binds ONE arbiter key (the repo `CLAUDE.md`
rule): fixture replays only verify against a pool initialized with the
disburse256 fixture's own `publics[9..10]`. A production deployment uses a
real key — and then none of the committed enterprise fixtures replay against
it, by design.

## Upgrade authority policy

From the rail spec (`.dev/solana-rail-design.md` §2.4):

- **Testnet**: the single deployer key holds upgrade authority — the analogue
  of the EVM single-key `Ownable2Step` posture, carried in the same
  testnet-caveats register ([`docs/security-model.md`](../../docs/security-model.md#testnet-caveats)).
- **Mainnet prerequisite**: upgrade authority moves to a multisig
  (Squads-class) or is burned with a migration plan — but **never burn while
  the ZK syscall risk is open**: an upgrade path is the only mitigation if a
  syscall this program depends on (alt_bn128, sol_poseidon) is feature-gated
  away and re-enabled in changed form.
- Admin authority (the config's admin field: family flags, future arbiter
  rotation) is separable from upgrade authority later; testnet keeps them one
  key.

Rotate or inspect with the stock tooling:

```sh
solana program show <program id> --url "$SOLANA_RPC"          # current authority
solana program set-upgrade-authority <program id> \
  --new-upgrade-authority <multisig> --url "$SOLANA_RPC"
```
