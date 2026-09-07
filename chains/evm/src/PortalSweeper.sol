// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "./utils/IERC20.sol";
import {PortalSweeperBase} from "./PortalSweeperBase.sol";

/// @dev The two BongtuPool surfaces an enterprise sweep touches, mirrored here
///      so the sweeper stays standalone (no import of the whole pool). Drift is
///      caught at runtime by the Portal test suite, which drives this interface
///      against the real BongtuPool — and a deposit-arity change is BREAKING by
///      policy (see interfaces/IVerifiers.sol), so uint[19] cannot silently move.
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

/// @title PortalSweeper — the ENTERPRISE-family CREATE2 landing pad.
///
/// The family delta over PortalSweeperBase (which owns the trust posture, the
/// factory gate and the balance guards — see its header): this sweeper shields
/// through the pool's enterprise `deposit`, so the minted notes carry the
/// authority envelope the arbiter can open. Approve the pool for exactly the
/// proof-bound `pub[0]`, then `pool.deposit` pulls it and appends the two
/// proof-bound notes. The token is read from the pool itself rather than
/// stored here — a second copy could drift from the pool's. A second payment
/// to the same address is legal: the sweeper stays deployed and may be
/// re-swept with a fresh proof (deposit carries no nullifier, so re-entry is a
/// fresh mint, not a replay hazard).
contract PortalSweeper is PortalSweeperBase {
    function sweep(
        IPortalPool pool,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[19] calldata pub,
        bytes calldata kemCiphertext
    ) external onlyFactory {
        _guardAndApprove(pool.token(), address(pool), pub[0]);
        pool.deposit(a, b, c, pub, kemCiphertext);
    }
}
