// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {BongtuPool} from "../../src/BongtuPool.sol";

/// @notice Test-only module: forwards arbitrary OpEffects to the pool so the
///         applyOp* invariant gate can be probed directly (a registered
///         module is the only legal caller). Reverts bubble unmodified.
contract StubModule {
    BongtuPool public immutable pool;

    constructor(BongtuPool _pool) {
        pool = _pool;
    }

    function apply_(BongtuPool.OpEffects calldata fx) external returns (uint256) {
        return pool.applyOp(fx);
    }

    function applyPull(BongtuPool.OpEffects calldata fx, address from, uint256 amount) external returns (uint256) {
        return pool.applyOpWithPull(fx, from, amount);
    }

    function applyPush(BongtuPool.OpEffects calldata fx, address to, uint256 amount) external returns (uint256) {
        return pool.applyOpWithPush(fx, to, amount);
    }
}

/// @notice ERC-777-style reentrancy probe: a minimal token whose transfer
///         hooks re-call the pool with configured calldata and RECORD the
///         outcome (the vendored SafeERC20 folds a bubbled revert into its
///         own SafeERC20FailedOperation, which would mask the selector) — so
///         a test can pin that the shared `_locked` latch rejects
///         cross-family reentry during applyOpWithPull/Push escrow motion
///         with exactly `Reentrancy()`, while the outer op completes
///         (OPMOD §1.6).
contract ReentrantToken {
    address public target;
    bytes public reentryCalldata;
    bool public reentryAttempted;
    bool public reentrySucceeded;
    bytes4 public reentryRevertSelector;

    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setReentry(address _target, bytes calldata data) external {
        target = _target;
        reentryCalldata = data;
    }

    function _hook() private {
        if (target != address(0) && reentryCalldata.length > 0) {
            (bool ok, bytes memory ret) = target.call(reentryCalldata);
            reentryAttempted = true;
            reentrySucceeded = ok;
            if (!ok && ret.length >= 4) {
                reentryRevertSelector = bytes4(ret);
            }
        }
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        _hook();
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _hook();
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function approve(address, uint256) external pure returns (bool) {
        return true;
    }

    function allowance(address, address) external pure returns (uint256) {
        return type(uint256).max;
    }

    function totalSupply() external pure returns (uint256) {
        return 0;
    }
}
