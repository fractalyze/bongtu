// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IERC20} from "./IERC20.sol";

// Minimal SafeERC20: tolerates non-standard ERC-20s that return no boolean, and
// reverts when a token returns false. Self-contained (no OpenZeppelin dependency)
// so the M0 gate has no network install step. The pool additionally forbids
// fee-on-transfer / rebasing tokens by construction (SPEC §5.3): amounts are
// proof-bound before the pull, so a balance-mutating token makes the pool
// insolvent — tests use a plain mock ERC-20.
library SafeERC20 {
    error SafeERC20FailedOperation(address token);

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(IERC20.transfer, (to, value)));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(IERC20.transferFrom, (from, to, value)));
    }


    // Added for the portal sweeper (PortalSweeper.sol): approve the pool for the
    // exact proof-bound amount with the same optional-return tolerance as the
    // transfer paths. No increase/decrease dance is needed — the sweep approves
    // exactly what the immediately-following deposit pulls, so the allowance
    // returns to zero within the same transaction.
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(IERC20.approve, (spender, value)));
    }

    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        (bool ok, bytes memory ret) = address(token).call(data);
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) {
            revert SafeERC20FailedOperation(address(token));
        }
        if (address(token).code.length == 0) {
            revert SafeERC20FailedOperation(address(token));
        }
    }
}
