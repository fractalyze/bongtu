// The dev-faucet amount for the Deposit/shield screen (SPEC §7). The deployed kKRW is
// MockERC20 whose `mint(to, amount)` is fully permissionless, so any user can self-mint
// test kKRW from their own MetaMask (paying their own GIWA gas) at ANY time — the
// affordance is deliberately not gated on balance (a tester with funds still needs more).
// The tx submission is viem-bound and lives in connection.ts (mintTestToken).

/**
 * The fixed raw-wei amount the dev faucet mints per tap: 1,000,000 kKRW at the token's
 * 18 decimals, so MetaMask and this wallet both display "1,000,000" after a mint. One
 * tap funds many test deposits without re-minting.
 */
export const FAUCET_AMOUNT = 1_000_000n * 10n ** 18n;
