// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "./utils/IERC20.sol";
import {SafeERC20} from "./utils/SafeERC20.sol";

/// @dev The two BongtuPool surfaces a sweep touches, mirrored here so the
///      sweeper stays standalone (no import of the whole pool). Drift is caught
///      at runtime by the Portal test suite, which drives this interface against
///      the real BongtuPool — and a deposit-arity change is BREAKING by policy
///      (see interfaces/IVerifiers.sol), so uint[19] cannot silently move.
interface IPortalPool {
    function token() external view returns (IERC20);

    function deposit(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[19] calldata pub,
        bytes calldata kemCiphertext
    ) external;
}

/// @title PortalSweeper — the CREATE2 landing pad for a portal deposit.
///
/// A stealth payer (a CEX, a plain wallet) sends kKRW to a precomputed CREATE2
/// address; this contract is what the PortalFactory later deploys AT that
/// address to shield the funds: approve the pool for exactly the proof-bound
/// amount, then call the pool's `deposit` — the deposit proof is what mints the
/// notes, the sweeper itself holds no state worth keeping. A second payment to
/// the same address is legal: the sweeper stays deployed and may be re-swept
/// with a fresh proof (deposit carries no nullifier, so re-entry is a fresh
/// mint, not a replay hazard).
///
/// TRUST (v1 concession, recorded in .dev/milestone-stealth.md Slice ⑤ — do not
/// soften): `sweep` is callable ONLY by the factory, whose owner is the
/// institution's bot key. An on-chain binding of "these commitments belong to
/// the announced recipient" is impossible without exposing owners — the deposit
/// proof has no owner binding — so redirection-resistance rests on that
/// institution key, the SAME trust domain as the arbiter that already decrypts
/// every note. A cheated recipient detects the theft (the address was funded,
/// yet no note arrived via /notes) — that mismatch is the alarm surface.
///
/// Constructor takes no arguments (factory = msg.sender) ON PURPOSE: with no
/// constructor args the initcode is a compile-time constant, so the CREATE2
/// address is a pure function of (factory, salt, initcode hash) that the
/// resolver, the bot, and the recipient can all recompute off-chain.
contract PortalSweeper {
    using SafeERC20 for IERC20;

    /// @notice The one address allowed to trigger a sweep (set at CREATE2 time).
    address public immutable factory;

    error NotFactory(address caller);
    error NothingToSweep();
    error SweepExceedsBalance(uint256 want, uint256 have);

    constructor() {
        factory = msg.sender;
    }

    /// @notice Shield this address's token balance into the pool: approve the
    ///         pool for exactly `pub[0]` (the proof-bound deposit amount), then
    ///         `pool.deposit` pulls it and appends the two proof-bound notes.
    ///         The token is read from the pool itself rather than stored here —
    ///         a second copy could drift from the pool's.
    /// @dev Both balance guards run BEFORE the pool call so a mis-built proof
    ///      amount surfaces as a sweeper error, not a deep SafeERC20 failure:
    ///      a zero balance means nothing to shield (NothingToSweep), and a
    ///      `pub[0]` above the balance can never be pulled (SweepExceedsBalance).
    function sweep(
        IPortalPool pool,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[19] calldata pub,
        bytes calldata kemCiphertext
    ) external {
        if (msg.sender != factory) revert NotFactory(msg.sender);
        IERC20 token = pool.token();
        uint256 have = token.balanceOf(address(this));
        if (have == 0) revert NothingToSweep();
        if (pub[0] > have) revert SweepExceedsBalance(pub[0], have);
        token.safeApprove(address(pool), pub[0]);
        pool.deposit(a, b, c, pub, kemCiphertext);
    }
}
