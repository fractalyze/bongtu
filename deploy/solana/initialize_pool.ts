// initialize_pool.ts — the cluster-deploy driver for the Solana rail's
// one-shot `initialize` (deploy/solana/README.md runbook): builds the
// instruction through the SAME @bongtu/client-solana builder the e2e gate
// uses, sends it, reads the created pool back, and writes the per-cluster
// addresses record (`deploy/solana/addresses.<cluster>.json`).
//
//   --derive-only   print the PDAs for MINT and exit — the vault must exist
//                   as a token account owned by the printed vault-authority
//                   PDA before `initialize` can validate and record it.
//
// Env: SOLANA_RPC, MINT, VAULT, DEPLOYER_KEYPAIR (solana id.json), CLUSTER,
// FAMILY_FLAGS (default 0x01ff), BATCH_B (default 256), ARBITER_KEY_X/Y
// (decimal; required with enterprise flags), ARBITER_KEM_PK_HASH (0x-hex).

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { getAccountData, getGenesisHash, keypairConnection } from "@bongtu/client-solana/connection";
import { sendV1Instruction } from "@bongtu/client-solana/consumer";
import {
  LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
  configPda,
  initializeInstruction,
  treePda,
  vaultAuthorityPda,
} from "@bongtu/client-solana/txbuild";
import { PROGRAM_ID_BASE58 } from "@bongtu/core/solana";

const HERE = dirname(fileURLToPath(import.meta.url));

function env(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name} (see deploy/solana/README.md)`);
  return v;
}

async function main(): Promise<void> {
  const mint = env("MINT");
  const config = await configPda(mint);
  const tree = await treePda(config);
  const vaultAuthority = await vaultAuthorityPda(config);
  console.log(`program:          ${PROGRAM_ID_BASE58}`);
  console.log(`config PDA:       ${config}`);
  console.log(`tree PDA:         ${tree}`);
  console.log(`vault authority:  ${vaultAuthority}`);
  if (process.argv.includes("--derive-only")) return;

  const rpc = env("SOLANA_RPC");
  const cluster = env("CLUSTER");
  const vault = env("VAULT");
  const familyFlags = Number(process.env.FAMILY_FLAGS ?? "0x01ff");
  const batchB = Number(process.env.BATCH_B ?? "256");
  const profile = {
    familyFlags,
    batchB,
    ...(process.env.ARBITER_KEY_X ? { arbiterKeyX: process.env.ARBITER_KEY_X } : {}),
    ...(process.env.ARBITER_KEY_Y ? { arbiterKeyY: process.env.ARBITER_KEY_Y } : {}),
    ...(process.env.ARBITER_KEM_PK_HASH ? { arbiterKemPkHash: process.env.ARBITER_KEM_PK_HASH } : {}),
  };

  // solana id.json is the 64-byte secret key as a JSON number array.
  const secretKey = Uint8Array.from(JSON.parse(readFileSync(env("DEPLOYER_KEYPAIR"), "utf8")) as number[]);
  const connection = await keypairConnection(rpc, secretKey);

  const existing = await getAccountData(rpc, config);
  if (existing !== null) {
    throw new Error(`config PDA ${config} already exists on this cluster — initialize is one-shot`);
  }

  const ix = await initializeInstruction({ mint, vault, payer: connection.address, profile });
  const signature = await sendV1Instruction(connection, ix, {
    computeUnitLimit: 150_000,
    loadedAccountsDataSizeLimit: LOADED_ACCOUNTS_DATA_SIZE_LIMIT,
  });
  console.log(`initialize landed: ${signature}`);

  const record = {
    cluster,
    genesisHash: await getGenesisHash(rpc),
    programId: PROGRAM_ID_BASE58,
    upgradeAuthority: connection.address,
    mint,
    vault,
    config,
    tree,
    profile,
    initializeSignature: signature,
  };
  const out = join(HERE, `addresses.${cluster}.json`);
  writeFileSync(out, JSON.stringify(record, null, 2) + "\n");
  console.log(`record written: ${out}`);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
