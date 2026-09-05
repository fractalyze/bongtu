// The `initialize` builder: wire bytes per initialize.rs (discriminator 0 +
// the 102-byte profile payload), PDA derivations from the ONE rail facts
// module, and the account meta order the program destructures. Acceptance of
// the produced instruction is the validator gate's job (e2e_s.sh) and the
// mollusk gate 8's — this suite pins the byte layout.

import { test } from "node:test";
import assert from "node:assert/strict";

import { INITIALIZE_DISCRIMINATOR, INITIALIZE_PAYLOAD_LEN, PROGRAM_ID_BASE58 } from "@bongtu/core/solana";
import {
  configPda,
  encodeInitializeData,
  initializeInstruction,
  treePda,
  SYSTEM_PROGRAM_ADDRESS,
} from "@bongtu/client-solana/txbuild";

test("encodeInitializeData lays out the 102-byte profile wire", () => {
  const kem = "0x" + "ab".repeat(32);
  const data = encodeInitializeData({
    familyFlags: 0x01ff,
    batchB: 256,
    arbiterKeyX: "1",
    arbiterKeyY: "2",
    arbiterKemPkHash: kem,
  });
  assert.equal(data.length, 1 + INITIALIZE_PAYLOAD_LEN);
  assert.equal(data[0], INITIALIZE_DISCRIMINATOR);
  // family_flags u16 LE
  assert.deepEqual([data[1], data[2]], [0xff, 0x01]);
  // batch B u32 LE
  assert.deepEqual([...data.slice(3, 7)], [0x00, 0x01, 0x00, 0x00]);
  // arbiter key limbs: 32 B BE field encoding
  assert.equal(data[7 + 31], 1);
  assert.ok(data.slice(7, 7 + 31).every((b) => b === 0));
  assert.equal(data[39 + 31], 2);
  // kem pk hash verbatim
  assert.ok(data.slice(71, 103).every((b) => b === 0xab));
});

test("consumer-only profile zeroes the arbiter material by default", () => {
  const data = encodeInitializeData({ familyFlags: 0x000f, batchB: 16 });
  assert.deepEqual([data[1], data[2]], [0x0f, 0x00]);
  assert.deepEqual([...data.slice(3, 7)], [16, 0, 0, 0]);
  assert.ok(data.slice(7, 103).every((b) => b === 0));
});

test("a malformed kem pk hash refuses before any bytes are built", () => {
  assert.throws(
    () => encodeInitializeData({ familyFlags: 0x01ff, batchB: 256, arbiterKemPkHash: "0x1234" }),
    /32 bytes of hex/,
  );
});

test("initializeInstruction derives the PDAs and orders the metas per initialize.rs", async () => {
  const mint = "So11111111111111111111111111111111111111112";
  const vault = "4Nd1mBQtrMJVYVfKf2PJy9NZUZdTAsp7D4xWLs4gDB4T";
  const payer = "7v91N7iZ9mNicL8WfG6cgSCKyRXydQjLh6UYBWwm6y1Q";
  const config = await configPda(mint);
  const tree = await treePda(config);
  assert.notEqual(config, tree);
  // Deterministic discovery: the same mint re-derives the same pair.
  assert.equal(await configPda(mint), config);
  assert.equal(await treePda(config), tree);

  const ix = await initializeInstruction({
    mint,
    vault,
    payer,
    profile: { familyFlags: 0x000f, batchB: 16 },
  });
  assert.equal(ix.programAddress, PROGRAM_ID_BASE58);
  const metas = ix.accounts ?? [];
  assert.deepEqual(
    metas.map((m) => m.address),
    [config, tree, mint, vault, payer, SYSTEM_PROGRAM_ADDRESS],
  );
  // config/tree writable, payer writable-signer, the rest readonly.
  assert.deepEqual(
    metas.map((m) => m.role),
    [1, 1, 0, 0, 3, 0],
  );
  assert.equal(ix.data?.length, 1 + INITIALIZE_PAYLOAD_LEN);
});
