// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "./utils/IERC20.sol";
import {SafeERC20} from "./utils/SafeERC20.sol";

/// @dev The pool surface a receive sweep touches, mirrored so the sweeper
///      stays standalone. The sweeper approves THIS address: DepositPrivModule
///      calls `applyOpWithPull(fx, msg.sender, pub[0])`, so the pool pulls the
///      tokens from the module's caller — this sweeper — via `transferFrom`.
interface IReceivePool {
    function token() external view returns (IERC20);
}

/// @dev The consumer mint surface, mirrored from DepositPrivModule. A
///      depositPriv-arity change is BREAKING by policy (see
///      interfaces/IVerifiers.sol), so uint[16] cannot silently move; drift is
///      caught by the Receive test suite driving this interface against the
///      real module.
interface IReceiveModule {
    function pool() external view returns (IReceivePool);

    function depositPriv(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[16] calldata pub,
        bytes[] calldata kemCiphertexts
    ) external;
}

/// @title ReceiveSweeper — the CREATE2 landing pad for a stealth receive.
///
/// The consumer-family sibling of PortalSweeper: a stealth payer sends kKRW to
/// a precomputed CREATE2 address; this contract is deployed AT that address to
/// shield the funds through the consumer `depositPriv` module — minting
/// no-auditor notes the operator's arbiter CANNOT open, unlike the enterprise
/// `deposit` the portal pair uses. The deposit proof is what mints the notes;
/// the sweeper holds no state worth keeping. A second payment to the same
/// address is legal: the sweeper stays deployed and may be re-swept with a
/// fresh proof (depositPriv is a 0-in mint with no nullifier, so re-entry is a
/// fresh mint, not a replay hazard).
///
/// TRUST (the portal v1 concession, unchanged here — do not soften): `sweep`
/// is callable ONLY by the factory, whose owner is the operator's bot key. The
/// deposit proof has no owner binding, so redirection-resistance rests on that
/// bot key. What the consumer path REMOVES is the arbiter's read: a cheated
/// recipient still detects theft (funded address, no note found by its own
/// scan) — that mismatch is the alarm surface.
///
/// Constructor takes no arguments (factory = msg.sender) ON PURPOSE: with no
/// constructor args the initcode is a compile-time constant, so the CREATE2
/// address is a pure function of (factory, salt, initcode hash) that the pay
/// page, the bot, and the recipient can all recompute off-chain.
contract ReceiveSweeper {
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
    ///         POOL (not the module — the pool is what pulls) for exactly
    ///         `pub[0]`, then `module.depositPriv` verifies and has the pool
    ///         pull the tokens and append the two proof-bound consumer notes.
    ///         The token is read from the pool itself rather than stored here —
    ///         a second copy could drift from the pool's.
    /// @dev Both balance guards run BEFORE the module call so a mis-built proof
    ///      amount surfaces as a sweeper error, not a deep SafeERC20 failure:
    ///      a zero balance means nothing to shield (NothingToSweep), and a
    ///      `pub[0]` above the balance can never be pulled (SweepExceedsBalance).
    function sweep(
        IReceiveModule module,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[16] calldata pub,
        bytes[] calldata kemCiphertexts
    ) external {
        if (msg.sender != factory) revert NotFactory(msg.sender);
        IReceivePool pool = module.pool();
        IERC20 token = pool.token();
        uint256 have = token.balanceOf(address(this));
        if (have == 0) revert NothingToSweep();
        if (pub[0] > have) revert SweepExceedsBalance(pub[0], have);
        token.safeApprove(address(pool), pub[0]);
        module.depositPriv(a, b, c, pub, kemCiphertexts);
    }
}
