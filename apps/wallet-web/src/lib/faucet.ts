// PURE dev-faucet UX logic for the Deposit/shield screen (SPEC §7). The deployed kKRW
// is MockERC20, whose `mint(to, amount)` is fully permissionless — so a first-time user
// with a zero public balance can self-mint test kKRW from their own MetaMask (paying
// their own GIWA gas) and immediately deposit it. The tx submission itself is
// ethers-bound and lives in metamask.ts (mintTestToken); this module keeps only the
// framework-free DECISION + the fixed dev amount, so both are unit-testable headlessly.

/**
 * The fixed raw-integer amount the dev faucet mints per tap. Raw token units (the pool
 * pulls exactly pub[0]=V raw units on deposit — MockERC20 is not scaled by 10^18 in
 * this app), chosen generous vs a typical hand-typed deposit so one faucet tap funds
 * many test deposits without re-minting.
 */
export const FAUCET_AMOUNT = 1_000_000n;

/**
 * Whether to offer the faucet: true exactly when the public kKRW balance is zero (a
 * fresh wallet that cannot deposit anything yet). Any non-zero balance means the user
 * already has funds to shield, so the faucet button is hidden.
 */
export function shouldOfferFaucet(balance: bigint): boolean {
  return balance === 0n;
}
