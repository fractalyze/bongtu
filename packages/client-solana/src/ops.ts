// The Solana io bundle for the engine's consumer flows — the twin of
// @bongtu/client-evm/ops EVM_CONSUMER_IO, as a FACTORY because this rail has
// no canonical deployment record yet (the deploy/addresses.* sibling lands
// with the cluster deploy profile): the app/gate binds the cluster + account
// record once and spreads the result into consumerRunDeposit /
// consumerRunSpendChain / the ConsumerOps facade. Members are exactly the
// engine's per-flow rail seams (ops/consumer/run.ts RunConsumer*Deps) —
// test/adapters.test.ts holds the bundle to them structurally.
//
// Two members are RAIL FACTS rather than network calls:
//   - allowance: the SPL transfer authority is the payer's own transaction
//     signature (deposit_priv.rs pulls with the payer as authority), so no
//     approve step exists — readTokenState reports an unlimited allowance and
//     the engine's approve branch is dead by construction;
//   - approveToken: therefore unreachable; it throws rather than fake-succeed
//     so a future flow change that starts calling it fails loudly.

import type { TokenState } from "@bongtu/client/rail";
import { ensureSolanaCluster, getTokenBalance, type SolanaConnection } from "./connection/edge.js";
import { associatedTokenAccount } from "./txbuild/accounts.js";
import { solanaConsumerSubmits, type SolanaConsumerConfig } from "./consumer.js";

/** The "allowance" a signature-authorized rail reports: effectively unlimited,
 *  so the engine's `allowance < V` approve branch never fires. */
export const SPL_SIGNATURE_ALLOWANCE = 1n << 255n;

/** The consumer-family rail io, bound to one cluster + account record. */
export function solanaConsumerIo(cfg: SolanaConsumerConfig) {
  const tokenAccountOf = cfg.tokenAccountOf ?? associatedTokenAccount;
  return {
    /** the chain guard: the pinned genesis hash, asserted before any signing
     *  or token motion (connection/edge.ts ensureSolanaCluster). */
    ensureChain(connection: SolanaConnection): Promise<void> {
      return ensureSolanaCluster(connection, cfg.genesisHash);
    },
    /** balance from the owner's token account (0 when absent); allowance is
     *  the rail fact above. `spender` (the EVM pool/escrow) plays no role —
     *  the vault pulls under the payer's signature. */
    async readTokenState(
      connection: SolanaConnection,
      tokenAddr: string,
      owner: string,
      _spender: string,
    ): Promise<TokenState> {
      const balance = await getTokenBalance(connection.rpcUrl, await tokenAccountOf(owner, tokenAddr));
      return { balance, allowance: SPL_SIGNATURE_ALLOWANCE };
    },
    /** Unreachable by construction (see readTokenState); throwing keeps a
     *  flow drift loud instead of silently pretending an approve landed. */
    approveToken(_connection: SolanaConnection, _tokenAddr: string, _spender: string, _amount: bigint): Promise<string> {
      return Promise.reject(
        new Error("no approve exists on this rail: SPL transfer authority is the transaction signature"),
      );
    },
    ...solanaConsumerSubmits(cfg),
  };
}
