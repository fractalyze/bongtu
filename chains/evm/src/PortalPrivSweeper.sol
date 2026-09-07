// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "./utils/IERC20.sol";
import {PortalSweeperBase} from "./PortalSweeperBase.sol";

/// @dev The pool surface a priv sweep touches, mirrored so the sweeper stays
///      standalone. The sweeper approves THIS address: DepositPrivModule calls
///      `applyOpWithPull(fx, msg.sender, pub[0])`, so the pool pulls the
///      tokens from the module's caller — this sweeper — via `transferFrom`.
interface IPortalPrivPool {
    function token() external view returns (IERC20);
}

/// @dev The consumer mint surface, mirrored from DepositPrivModule. A
///      depositPriv-arity change is BREAKING by policy (see
///      interfaces/IVerifiers.sol), so uint[16] cannot silently move; drift is
///      caught by the PortalPriv test suite driving this interface against the
///      real module.
interface IPortalPrivModule {
    function pool() external view returns (IPortalPrivPool);

    function depositPriv(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[16] calldata pub,
        bytes[] calldata kemCiphertexts
    ) external;
}

/// @title PortalPrivSweeper — the CONSUMER-family CREATE2 landing pad.
///
/// The family delta over PortalSweeperBase (which owns the trust posture, the
/// factory gate and the balance guards — see its header): this sweeper shields
/// through the consumer `depositPriv` module, minting no-auditor notes the
/// operator's arbiter CANNOT open — what the consumer path removes from the
/// enterprise sweep is exactly that arbiter read; a cheated recipient still
/// detects theft through its own scan. Approve the POOL (not the module — the
/// pool is what pulls) for exactly the proof-bound `pub[0]`, then
/// `module.depositPriv` verifies and has the pool pull the tokens and append
/// the two proof-bound consumer notes. A second payment to the same address is
/// legal: depositPriv is a 0-in mint with no nullifier, so a re-sweep is a
/// fresh mint, not a replay hazard.
contract PortalPrivSweeper is PortalSweeperBase {
    function sweep(
        IPortalPrivModule module,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[16] calldata pub,
        bytes[] calldata kemCiphertexts
    ) external onlyFactory {
        IPortalPrivPool pool = module.pool();
        _guardAndApprove(pool.token(), address(pool), pub[0]);
        module.depositPriv(a, b, c, pub, kemCiphertexts);
    }
}
