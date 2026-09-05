// txbuild/accounts.ts — PDA derivation and per-op account metas for the
// consumer instruction family. Seeds and their byte forms come from the ONE
// rail facts module (@bongtu/core/solana): seed VALUES are 32-byte BIG-ENDIAN
// field elements (the one-endianness rule), the prefixes are the state.rs
// SEED_* strings mirrored there. Account ORDER per op transcribes each op
// module's doc comment (chains/solana/program/src/<op>.rs "Accounts:") — the
// program re-derives every PDA and rejects a wrong meta, so a drift here
// fails loudly on-chain (and in the validator gate), never silently.

import { AccountRole, getProgramDerivedAddress, type Address, type Instruction } from "@solana/kit";
import {
  PROGRAM_ID_BASE58,
  SEED_DISBURSE_BATCH,
  SEED_EVENT_AUTHORITY,
  SEED_KNOWN_ROOT,
  SEED_NULLIFIER,
  SEED_VAULT_AUTHORITY,
  base58ToBytes,
} from "@bongtu/core/solana";
import { fieldBytes } from "./data.js";

/** Consensus-fixed platform program ids (Solana-wide, not bongtu rail facts —
 *  the op_common.rs SYSTEM_PROGRAM_ID / spl.rs TOKEN_PROGRAM_ID twins). */
export const SYSTEM_PROGRAM_ADDRESS = "11111111111111111111111111111111";
export const TOKEN_PROGRAM_ADDRESS = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
export const ASSOCIATED_TOKEN_PROGRAM_ADDRESS = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

const asAddress = (s: string): Address => s as Address;

async function pda(seeds: Uint8Array[], program: string = PROGRAM_ID_BASE58): Promise<string> {
  const [derived] = await getProgramDerivedAddress({
    programAddress: asAddress(program),
    seeds,
  });
  return derived;
}

const ascii = (s: string): Uint8Array => new TextEncoder().encode(s);

/** KnownRoot marker PDA: ["root", root 32 B BE]. */
export function knownRootPda(root: bigint): Promise<string> {
  return pda([ascii(SEED_KNOWN_ROOT), fieldBytes(root.toString())]);
}

/** Nullifier marker PDA: ["nf", nullifier 32 B BE]. */
export function nullifierPda(nullifier: bigint): Promise<string> {
  return pda([ascii(SEED_NULLIFIER), fieldBytes(nullifier.toString())]);
}

/** DisburseBatch PDA: ["batch", start_leaf_index u64 LE] — the counter
 *  convention, not the 32 B BE field encoding (state.rs SEED_DISBURSE_BATCH
 *  note). */
export function disburseBatchPda(startLeafIndex: number): Promise<string> {
  const le = new Uint8Array(8);
  for (const i of Array(8).keys()) le[i] = Math.floor(startLeafIndex / 2 ** (8 * i)) % 256;
  return pda([ascii(SEED_DISBURSE_BATCH), le]);
}

/** The self-CPI event authority PDA: ["__event_authority"]. */
export function eventAuthorityPda(): Promise<string> {
  return pda([ascii(SEED_EVENT_AUTHORITY)]);
}

/** The vault authority PDA: ["authority", config address bytes]. */
export function vaultAuthorityPda(configAddress: string): Promise<string> {
  return pda([ascii(SEED_VAULT_AUTHORITY), base58ToBytes(configAddress)]);
}

/** The associated token account of (owner, mint) — the default payer/recipient
 *  token account resolution (overridable in the consumer io config). */
export function associatedTokenAccount(owner: string, mint: string): Promise<string> {
  return pda(
    [base58ToBytes(owner), base58ToBytes(TOKEN_PROGRAM_ADDRESS), base58ToBytes(mint)],
    ASSOCIATED_TOKEN_PROGRAM_ADDRESS,
  );
}

/** The static pool account set every submit needs — the deployment's account
 *  record (per cluster), threaded in by the app/gate; the PROGRAM id itself is
 *  never part of it (one owner: @bongtu/core/solana). */
export interface SolanaPoolAccounts {
  /** PoolConfig account (base58). */
  config: string;
  /** TreeState account (base58). */
  tree: string;
  /** the pool's SPL mint (base58) — the kKRW twin on this rail. */
  mint: string;
  /** the config-bound escrow vault token account (base58). */
  vault: string;
}

interface Meta {
  address: string;
  role: AccountRole;
}

const ro = (address: string): Meta => ({ address, role: AccountRole.READONLY });
const w = (address: string): Meta => ({ address, role: AccountRole.WRITABLE });
const ws = (address: string): Meta => ({ address, role: AccountRole.WRITABLE_SIGNER });

const toInstruction = (metas: Meta[], data: Uint8Array): Instruction => ({
  programAddress: asAddress(PROGRAM_ID_BASE58),
  accounts: metas.map((m) => ({ address: asAddress(m.address), role: m.role })),
  data,
});

/** Base account counts per op shape (the program doc comments' fixed prefix,
 *  before the per-nullifier PDA run) — what the size worst cases derive from. */
export const DEPOSIT_PRIV_ACCOUNTS = 10;
export const SPEND_BASE_ACCOUNTS = 8;
export const WITHDRAW_PRIV_BASE_ACCOUNTS = 12;

/** deposit_priv accounts (deposit_priv.rs): config, tree, new KnownRoot,
 *  payer, system, event authority, this program, SPL token program, payer
 *  token account, vault. */
export async function depositPrivInstruction(args: {
  accounts: SolanaPoolAccounts;
  payer: string;
  payerTokenAccount: string;
  newRoot: bigint;
  data: Uint8Array;
}): Promise<Instruction> {
  const metas = [
    ro(args.accounts.config),
    w(args.accounts.tree),
    w(await knownRootPda(args.newRoot)),
    ws(args.payer),
    ro(SYSTEM_PROGRAM_ADDRESS),
    ro(await eventAuthorityPda()),
    ro(PROGRAM_ID_BASE58),
    ro(TOKEN_PROGRAM_ADDRESS),
    w(args.payerTokenAccount),
    w(args.accounts.vault),
  ];
  return toInstruction(metas, args.data);
}

/** transfer_priv / transfer10x2_priv accounts (one shape, transfer_priv.rs):
 *  config, tree, spent KnownRoot, new KnownRoot, payer, system, event
 *  authority, this program, then one Nullifier PDA per NONZERO nullifier in
 *  signal order. */
export async function spendInstruction(args: {
  accounts: SolanaPoolAccounts;
  payer: string;
  spentRoot: bigint;
  newRoot: bigint;
  /** the FULL nullifier run in signal order; zeros (padded slots) are skipped
   *  here exactly as the program skips them. */
  nullifiers: bigint[];
  data: Uint8Array;
}): Promise<Instruction> {
  const nfPdas = await Promise.all(args.nullifiers.filter((nf) => nf !== 0n).map((nf) => nullifierPda(nf)));
  const metas = [
    ro(args.accounts.config),
    w(args.accounts.tree),
    ro(await knownRootPda(args.spentRoot)),
    w(await knownRootPda(args.newRoot)),
    ws(args.payer),
    ro(SYSTEM_PROGRAM_ADDRESS),
    ro(await eventAuthorityPda()),
    ro(PROGRAM_ID_BASE58),
    ...nfPdas.map(w),
  ];
  return toInstruction(metas, args.data);
}

/** withdraw_priv accounts (withdraw_priv.rs): the spend prefix + SPL token
 *  program, vault, vault authority, recipient token account, then the
 *  nullifier PDA run. */
export async function withdrawPrivInstruction(args: {
  accounts: SolanaPoolAccounts;
  payer: string;
  recipientTokenAccount: string;
  spentRoot: bigint;
  newRoot: bigint;
  nullifiers: bigint[];
  data: Uint8Array;
}): Promise<Instruction> {
  const nfPdas = await Promise.all(args.nullifiers.filter((nf) => nf !== 0n).map((nf) => nullifierPda(nf)));
  const metas = [
    ro(args.accounts.config),
    w(args.accounts.tree),
    ro(await knownRootPda(args.spentRoot)),
    w(await knownRootPda(args.newRoot)),
    ws(args.payer),
    ro(SYSTEM_PROGRAM_ADDRESS),
    ro(await eventAuthorityPda()),
    ro(PROGRAM_ID_BASE58),
    ro(TOKEN_PROGRAM_ADDRESS),
    w(args.accounts.vault),
    ro(await vaultAuthorityPda(args.accounts.config)),
    w(args.recipientTokenAccount),
    ...nfPdas.map(w),
  ];
  return toInstruction(metas, args.data);
}
