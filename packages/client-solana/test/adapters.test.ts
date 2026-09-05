// Adapter shape gates: the self-scan feed adapter must satisfy the engine's
// SelfScanIo seam STRUCTURALLY (the declared return type already proves it at
// compile time — these tests keep the runtime surface honest), and the
// consumer io bundle must satisfy the engine's flow deps seams so
// consumerRunDeposit / consumerRunSpendChain drive this rail unchanged.

import { test } from "node:test";
import assert from "node:assert/strict";

import type { SelfScanIo } from "@bongtu/client/selfscan";
import type { RunConsumerDepositDeps, RunConsumerSpendDeps } from "@bongtu/client/consumer";
import { solanaSelfScanIo } from "@bongtu/client-solana/selfscan";
import { solanaConsumerIo, SPL_SIGNATURE_ALLOWANCE } from "@bongtu/client-solana/ops";
import { boundWithdrawRecipient, type SolanaConsumerConfig } from "@bongtu/client-solana/consumer";
import { PROGRAM_ID_BASE58 } from "@bongtu/core/solana";

const CFG: SolanaConsumerConfig = {
  genesisHash: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
  accounts: {
    config: PROGRAM_ID_BASE58, // shape test only — any base58 32-byte value
    tree: PROGRAM_ID_BASE58,
    mint: PROGRAM_ID_BASE58,
    vault: PROGRAM_ID_BASE58,
  },
};

test("solanaSelfScanIo satisfies the SelfScanIo seam (compile-time) and exposes the four reads", () => {
  const io: SelfScanIo = solanaSelfScanIo("http://127.0.0.1:1");
  assert.equal(typeof io.events, "function");
  assert.equal(typeof io.nullifiers, "function");
  assert.equal(typeof io.head, "function");
  assert.equal(typeof io.path, "function");
});

test("solanaConsumerIo satisfies the engine's consumer flow deps seams (compile-time)", () => {
  const io = solanaConsumerIo(CFG);
  // Method-style seam members are checked bivariantly, so the SolanaConnection-
  // typed implementations are assignable — the same rule client-evm rides.
  const depositSlice: Pick<
    RunConsumerDepositDeps,
    "ensureChain" | "readTokenState" | "approveToken" | "submitDepositPriv"
  > = io;
  const spendSlice: Pick<
    RunConsumerSpendDeps,
    "ensureChain" | "submitTransferPriv" | "submitTransfer10x2Priv" | "submitWithdrawPriv"
  > = io;
  assert.ok(depositSlice.submitDepositPriv !== undefined);
  assert.ok(spendSlice.submitTransfer10x2Priv !== undefined);
});

test("the approve seam is a rail fact: unlimited allowance, approveToken refuses", async () => {
  const io = solanaConsumerIo(CFG);
  assert.equal(SPL_SIGNATURE_ALLOWANCE > 1n << 200n, true);
  await assert.rejects(
    io.approveToken({} as never, "x", "y", 1n),
    /no approve exists on this rail/,
  );
});

test("boundWithdrawRecipient masks the top 3 bits of the 32-byte address (truncate-253)", () => {
  // PROGRAM_ID_BASE58 decodes to 32 bytes whose first byte may exceed 0x1f —
  // the mask must clear exactly the top 3 bits and keep the rest verbatim.
  const bound = BigInt(boundWithdrawRecipient(PROGRAM_ID_BASE58));
  assert.ok(bound >> 253n === 0n, "bound value fits 253 bits");
  assert.throws(() => boundWithdrawRecipient("abc"), /32-byte/);
});
