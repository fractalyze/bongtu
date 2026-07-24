// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Base} from "./Base.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IDepositVerifier, IWithdrawVerifier, IDisburseVerifier, ITransferVerifier} from "../src/interfaces/IVerifiers.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {Ownable2StepUpgradeable} from "../src/utils/Ownable2StepUpgradeable.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {
    StubDepositVerifier,
    StubWithdrawVerifier,
    StubDisburseVerifier,
    StubTransferVerifier
} from "./mocks/StubVerifiers.sol";

/// @notice M0 Done#3-(vi): arbiter epochs (§5.3, Q9). initialize REQUIRES a
///         non-zero key (kills the (0,0) footgun); rotateArbiter appends an
///         epoch and emits its index.
///
/// Post-UUPS the single initializer folds the arbiter-key check into the wiring,
/// so these tests deploy an UNINITIALIZED proxy and drive `initialize(...)`
/// themselves (via {_init}) to exercise the key validation + the epoch-0 emit.
contract ArbiterTest is Base {
    BongtuPool pool;

    // deps captured for the pool-under-test, replayed into every initialize call
    IPoseidon2 _poseidon;
    IDepositVerifier _dv;
    IWithdrawVerifier _wv;
    IDisburseVerifier _dsv;
    ITransferVerifier _tv;
    IERC20 _token;

    event ArbiterRotated(uint256 indexed epoch, uint256 keyX, uint256 keyY, uint256 activatedBlock);

    function _newPool() internal returns (BongtuPool) {
        _poseidon = deployPoseidon();
        _token = IERC20(address(new MockERC20()));
        _dv = new StubDepositVerifier();
        _wv = new StubWithdrawVerifier();
        _dsv = new StubDisburseVerifier();
        _tv = new StubTransferVerifier();
        return deployUninitializedPool();
    }

    /// @dev Drive the 8-arg initializer with the captured deps + a given key.
    function _init(uint256[2] memory key) internal {
        pool.initialize(_poseidon, _dv, _wv, _dsv, _tv, _token, B, key);
    }

    function testInitializeRejectsZeroKey() public {
        pool = _newPool();
        vm.expectRevert(BongtuPool.ZeroArbiterKey.selector);
        _init([uint256(0), uint256(0)]);

        // a partially-zero key is also rejected
        vm.expectRevert(BongtuPool.ZeroArbiterKey.selector);
        _init([uint256(0), uint256(7)]);

        assertTrue(!pool.initialized(), "must not be initialized after a rejected key");
    }

    function testInitializeSetsEpochZero() public {
        pool = _newPool();
        vm.expectEmit(true, false, false, true, address(pool));
        emit ArbiterRotated(0, 101, 202, block.number);
        _init([uint256(101), uint256(202)]);

        assertTrue(pool.initialized(), "initialized");
        assertEq(pool.currentEpoch(), 0, "epoch 0");
        (uint256 x, uint256 y) = pool.currentArbiterKey();
        assertEq(x, 101);
        assertEq(y, 202);
    }

    function testRotateArbiterAppendsAndEmits() public {
        pool = _newPool();
        _init([uint256(101), uint256(202)]);

        vm.roll(block.number + 5);
        vm.expectEmit(true, false, false, true, address(pool));
        emit ArbiterRotated(1, 303, 404, block.number);
        pool.rotateArbiter([uint256(303), uint256(404)]);

        assertEq(pool.currentEpoch(), 1, "epoch advanced to 1");
        (uint256 x, uint256 y) = pool.currentArbiterKey();
        assertEq(x, 303, "rotated keyX");
        assertEq(y, 404, "rotated keyY");

        // rotation also rejects a zero key
        vm.expectRevert(BongtuPool.ZeroArbiterKey.selector);
        pool.rotateArbiter([uint256(5), uint256(0)]);
    }

    function testRotateOnlyOwner() public {
        pool = _newPool();
        _init([uint256(101), uint256(202)]);
        address stranger = address(0xBEEF);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable2StepUpgradeable.OwnableUnauthorized.selector, stranger));
        pool.rotateArbiter([uint256(1), uint256(2)]);
    }
}
