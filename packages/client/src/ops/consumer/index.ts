// The consumer (no-auditor) op (@bongtu/client/consumer), whole: plan/build
// stopping at the ProvingRequest boundary, the run layer that proves and submits at
// the module addresses, and the ConsumerOps facade (below) binding the login-time
// deps once. Parts: plan.ts (recipient shapes and the family planning deltas),
// requests.ts (the ProvingRequest builders), run.ts (the prove+submit
// orchestrations). The module submit edges need viem, so they live in the
// rail client (@bongtu/client-evm/consumer) — the engine stays rail-free.
//
// The build layer is PURE wallet-side witness assembly for the four CPU consumer
// circuits: depositPriv (0-in / 2-out mint), transferPriv (2-in / 2-out),
// transfer10x2Priv (10-in / 2-out) and withdrawPriv (2-in / 1-out + proof-bound
// recipient) — OPMOD §2, docs/consumer.md. Like the enterprise builders (ops/spend,
// ops/deposit.ts) the build layer stops at "a valid ProvingRequest"; what changes
// is the OUTPUT side: no authority envelope exists, so every output note is
// SEALED to its recipient's consumer triple instead — a receiver ciphertext
// under the hybrid per-output key (ECDH against the note-layer VIEW key + a
// fresh per-output ML-KEM-768 encapsulation against the registered kemEk), a
// viewTag, and the 1088-byte kem ct the tx carries as calldata (OPMOD §3.3–§3.5).
//
// Reused, not reimplemented: the input side (membership, nullifiers, padding) is
// assembleInputs (ops/spend/assemble.ts) verbatim — notes are UNTYPED, so the commitment/
// nullifier algebra is family-shared by construction and reusing the one
// function keeps it that way; note selection and chain planning
// (selectInputNotes / planSpendAction / planSpendChain) are arity-driven and
// family-blind, so consumer flows call them unchanged and map the picked circuit
// through consumerCircuitOf. Per-output sealing is @bongtu/core/consumer
// sealConsumerOutput — the same function the fixture generators
// (circuits/fixtures/consumer_lib.ts) and the consumer e2e leg
// (deploy/gates/consumer_leg.ts) call, which is what makes the witness objects
// built here byte-identical to the committed circuits/fixtures/inputs/
// {depositPriv,transferPriv,transfer10x2Priv,withdrawPriv}.json — pinned in
// test/consumerBuild.test.ts.
//
// What the client supplies vs what the chain injects (mirrors consumer_leg.ts):
// `enabled` and the withdraw `recipient` ARE witness inputs — the circuit needs
// them to build a witness — but on-chain the module re-derives/range-checks and
// injects them into the public vector before verify (OPMOD §2), so a witness
// that lies about either simply fails verification. The kem ciphertexts are NOT
// witness material: they ride the tx as `bytes[] kemCiphertexts` calldata, one
// entry per output, surfaced here in each result's meta.
// This barrel stitches the parts back into the ONE stable public subpath
// (@bongtu/client/consumer), plus the ConsumerOps facade defined below.
export * from "./plan.js";
export * from "./requests.js";
export * from "./run.js";


// =============================== ConsumerOps =================================

import type { Calldata, ProvingRequest } from "@bongtu/core/proving";
import type { Connection } from "@bongtu/client/rail";
import type { KeyCacheLike } from "@bongtu/client/keyCache";
import type { ScanNote } from "@bongtu/client/selfscan";
import {
  previewSpend,
  type SpendKind,
  type SpendOutcome,
  type SpendPreview,
  type OnSpendStage,
} from "@bongtu/client/spend";
import type { DepositStage } from "@bongtu/client/deposit";
import type { ConsumerRecipient } from "./plan.js";
import {
  consumerRunDeposit,
  consumerRunSpendChain,
  type ConsumerDepositOutcome,
  type RunConsumerDepositDeps,
  type RunConsumerSpendDeps,
} from "./run.js";

/** The discovered-note source ConsumerOps plans and spends over — the SELF-SCAN
 *  result set (this family has no /notes oracle): the current set on demand,
 *  and the reload a chain waits on between legs (the app wraps runSelfScan +
 *  its store into `reload`). The seam owns the note-shape translation (issue
 *  #27): the flows see ScanNote here, and the app stops threading a parallel
 *  note array into every call. */
export interface ConsumerNoteSource {
  notes(): ScanNote[];
  reload(): Promise<ScanNote[]>;
}

/** What a consumer session binds ONCE (the C1 IndexerClient precedent): the
 *  login-time inputs every consumerRunDeposit / consumerRunSpendChain call site
 *  was re-threading. Any extra RunConsumer*Deps members ride along into the
 *  flows' io seam unchanged, so a headless suite constructs one facade over its
 *  fakes and every method provably hits the same free-fn path. */
export type ConsumerOpsDeps = {
  connection: Connection;
  indexerUrl: string;
  /** the POOL address — the escrow the deposit's ERC-20 approve targets. */
  pool: string;
  /** the wrapped kKRW ERC-20 the pool escrows (app config). */
  token: string;
  /** the explorer base URL the success link is built on (app config). */
  explorer: string;
  /** the wallet's lock — the structural seam, so fakes need no class. */
  keyCache: KeyCacheLike;
  /** Turn a ProvingRequest into Groth16 calldata (the APP supplies this). */
  prove: (request: ProvingRequest) => Promise<Calldata>;
} & Pick<
  RunConsumerSpendDeps,
  "ensureChain" | "submitTransferPriv" | "submitTransfer10x2Priv" | "submitWithdrawPriv"
> &
  // the rail io — spread @bongtu/client-evm/ops EVM_CONSUMER_IO at the wiring
  // site (the engine has no rail defaults since the split).
  Pick<RunConsumerDepositDeps, "readTokenState" | "approveToken" | "submitDepositPriv"> &
  Partial<RunConsumerSpendDeps> &
  Partial<RunConsumerDepositDeps>;

/**
 * Bind once at login/session time, call per action. The free functions above
 * STAY the primitive layer — every method DELEGATES to them, so the class can
 * never drift from what the headless flow suites pin (the C1 house bar: state +
 * injected IO, never a data bag). What it holds is exactly what every call site
 * repeated: the session's connection + config + lock + prover, the session
 * pubkey, and the self-scan note source.
 */
export class ConsumerOps {
  constructor(
    private readonly deps: ConsumerOpsDeps,
    private readonly session: { compressedPubkey: string },
    private readonly noteSource: ConsumerNoteSource,
  ) {}

  /** consumerRunDeposit over the bound session: approve (if needed) → prove →
   *  submit to the deposit module; `recipient` mints to a third party's triple. */
  deposit(
    args: { amount: string; recipient?: ConsumerRecipient },
    onStage: (stage: DepositStage) => void,
  ): Promise<ConsumerDepositOutcome> {
    const { connection, pool, token, explorer } = this.deps;
    return consumerRunDeposit(
      { connection, pool, token, explorer, sessionPubkey: this.session.compressedPubkey },
      args,
      onStage,
      this.deps,
    );
  }

  /** consumerRunSpendChain over the bound session and self-scan note source. */
  spend(
    kind: SpendKind,
    args: { to?: ConsumerRecipient; amount: string; withdrawTo?: string },
    onStage: OnSpendStage,
  ): Promise<SpendOutcome> {
    const { connection, indexerUrl, explorer } = this.deps;
    return consumerRunSpendChain(
      kind,
      {
        connection,
        indexerUrl,
        explorer,
        notes: this.noteSource.notes(),
        sessionPubkey: this.session.compressedPubkey,
        reloadNotes: () => this.noteSource.reload(),
      },
      args,
      onStage,
      this.deps,
    );
  }

  /** previewSpend over the note source: which circuit, how many transactions. */
  preview(kind: SpendKind, amount: string): SpendPreview {
    return previewSpend(kind, this.noteSource.notes(), amount);
  }
}
