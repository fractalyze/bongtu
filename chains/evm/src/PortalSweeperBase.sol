// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "./utils/IERC20.sol";
import {SafeERC20} from "./utils/SafeERC20.sol";

/// @title PortalSweeperBase — the shared half of every CREATE2 landing pad.
///
/// One portal mechanism, two deposit families: a stealth payer (a CEX, a plain
/// wallet) sends kKRW to a precomputed CREATE2 address, and a sweeper contract
/// is later deployed AT that address to shield the funds into the pool. What
/// every family shares lives here — the factory binding and its gate, and the
/// balance guards + escrow approval. What differs per family is ONLY the sweep
/// entrypoint each child declares: which verifier-backed deposit surface it
/// drives and with which proof arity (enterprise `deposit` in PortalSweeper,
/// consumer `depositPriv` in PortalPrivSweeper) — an arity change is BREAKING
/// by policy (see interfaces/IVerifiers.sol), so those signatures are pinned
/// in the children, never abstracted.
///
/// TRUST (v1 concession, recorded in .dev/milestone-stealth.md Slice ⑤ — do not
/// soften): `sweep` is callable ONLY by the factory, whose owner is the
/// operator's bot key. An on-chain binding of "these commitments belong to the
/// announced recipient" is impossible without exposing owners — the deposit
/// proofs have no owner binding — so redirection-resistance rests on that bot
/// key. A cheated recipient detects theft (the address was funded, yet no note
/// arrived through its discovery path) — that mismatch is the alarm surface.
///
/// Constructors take no arguments (factory = msg.sender) ON PURPOSE: with no
/// constructor args a child's initcode is a compile-time constant, so the
/// CREATE2 address is a pure function of (factory, salt, initcode hash) that
/// the issuer, the bot, and the recipient can all recompute off-chain.
abstract contract PortalSweeperBase {
    using SafeERC20 for IERC20;

    /// @notice The one address allowed to trigger a sweep (set at CREATE2 time).
    address public immutable factory;

    error NotFactory(address caller);
    error NothingToSweep();
    error SweepExceedsBalance(uint256 want, uint256 have);

    constructor() {
        factory = msg.sender;
    }

    modifier onlyFactory() {
        if (msg.sender != factory) revert NotFactory(msg.sender);
        _;
    }

    /// @notice Both balance guards + the escrow approval, shared verbatim by
    ///         every family's sweep. The guards run BEFORE the pool is ever
    ///         called so a mis-built proof amount surfaces as a sweeper error,
    ///         not a deep SafeERC20 failure: a zero balance means nothing to
    ///         shield (NothingToSweep), and a `want` above the balance can
    ///         never be pulled (SweepExceedsBalance). `spender` is whatever
    ///         address the family's deposit surface PULLS through — the pool
    ///         itself in both shipped families.
    function _guardAndApprove(IERC20 token, address spender, uint256 want) internal {
        uint256 have = token.balanceOf(address(this));
        if (have == 0) revert NothingToSweep();
        if (want > have) revert SweepExceedsBalance(want, have);
        token.safeApprove(spender, want);
    }
}
