// txbuild/initialize.ts — the `initialize` (discriminator 0) builder: the
// one-shot deploy instruction that creates the PoolConfig + TreeState PDAs
// and records the complete profile (initialize.rs; SOLR §2.5). Not an op —
// no proof, no publics — so it lives beside the op builders, not in the
// SOLANA_OPS layout table.
//
// PDA derivations mirror the program: config = ["config", mint],
// tree = ["tree", config] (the deterministic-discovery pair initialize
// introduced), with seeds from the ONE rail facts module.

import { AccountRole, getProgramDerivedAddress, type Address, type Instruction } from "@solana/kit";
import {
  INITIALIZE_DISCRIMINATOR,
  INITIALIZE_PAYLOAD_LEN,
  PROGRAM_ID_BASE58,
  SEED_CONFIG,
  SEED_TREE,
  base58ToBytes,
} from "@bongtu/core/solana";
import { SYSTEM_PROGRAM_ADDRESS } from "./accounts.js";
import { fieldBytes } from "./data.js";

const ascii = (s: string): Uint8Array => new TextEncoder().encode(s);

async function pda(seeds: Uint8Array[]): Promise<string> {
  const [derived] = await getProgramDerivedAddress({
    programAddress: PROGRAM_ID_BASE58 as Address,
    seeds,
  });
  return derived;
}

/** PoolConfig PDA: ["config", mint address bytes]. */
export function configPda(mint: string): Promise<string> {
  return pda([ascii(SEED_CONFIG), base58ToBytes(mint)]);
}

/** TreeState PDA: ["tree", config address bytes]. */
export function treePda(config: string): Promise<string> {
  return pda([ascii(SEED_TREE), base58ToBytes(config)]);
}

/** The deploy profile `initialize` records — flags decide the families, the
 *  arbiter material decides whether enterprise ops CAN be enabled (zeroed on
 *  consumer-only profiles: "no key exists", attestable from the account). */
export interface InitializeProfile {
  /** family-enable flags (state.rs bit assignment; u16). */
  familyFlags: number;
  /** batch size B (power of two; MUST be 256 when disburse256 is enabled). */
  batchB: number;
  /** arbiter bjj key limbs as decimal field strings; omit for consumer-only. */
  arbiterKeyX?: string;
  arbiterKeyY?: string;
  /** keccak256 of the arbiter's ML-KEM-768 encapsulation key (0x-hex 32 B);
   *  omit for consumer-only. */
  arbiterKemPkHash?: string;
}

/** Encode the initialize payload (discriminator + 102 B wire). */
export function encodeInitializeData(profile: InitializeProfile): Uint8Array {
  const data = new Uint8Array(1 + INITIALIZE_PAYLOAD_LEN);
  data[0] = INITIALIZE_DISCRIMINATOR;
  data[1] = profile.familyFlags & 0xff;
  data[2] = (profile.familyFlags >> 8) & 0xff;
  for (const i of Array(4).keys()) data[3 + i] = (profile.batchB >> (8 * i)) & 0xff;
  data.set(fieldBytes(profile.arbiterKeyX ?? "0"), 7);
  data.set(fieldBytes(profile.arbiterKeyY ?? "0"), 39);
  const kem = profile.arbiterKemPkHash ?? "0x" + "00".repeat(32);
  const hex = kem.replace(/^0x/, "");
  if (hex.length !== 64 || /[^0-9a-fA-F]/.test(hex)) {
    throw new Error(`arbiterKemPkHash must be 32 bytes of hex, got "${kem}"`);
  }
  for (const i of Array(32).keys()) data[71 + i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return data;
}

/** The one-shot pool initializer instruction (initialize.rs accounts order:
 *  config PDA, tree PDA, mint, vault, payer, system). The vault must already
 *  exist as a token account of the mint owned by the vault-authority PDA of
 *  the config (created outside the program — deploy runbook). */
export async function initializeInstruction(args: {
  mint: string;
  vault: string;
  payer: string;
  profile: InitializeProfile;
}): Promise<Instruction> {
  const config = await configPda(args.mint);
  const tree = await treePda(config);
  const metas = [
    { address: config as Address, role: AccountRole.WRITABLE },
    { address: tree as Address, role: AccountRole.WRITABLE },
    { address: args.mint as Address, role: AccountRole.READONLY },
    { address: args.vault as Address, role: AccountRole.READONLY },
    { address: args.payer as Address, role: AccountRole.WRITABLE_SIGNER },
    { address: SYSTEM_PROGRAM_ADDRESS as Address, role: AccountRole.READONLY },
  ];
  return {
    programAddress: PROGRAM_ID_BASE58 as Address,
    accounts: metas,
    data: encodeInitializeData(args.profile),
  };
}
