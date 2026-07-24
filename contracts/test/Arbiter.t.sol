// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Base} from "./Base.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {Ownable2Step} from "../src/utils/Ownable2Step.sol";
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
contract ArbiterTest is Base {
    BongtuPool pool;

    event ArbiterRotated(uint256 indexed epoch, uint256 keyX, uint256 keyY, uint256 activatedBlock);

    function _newPool() internal returns (BongtuPool) {
        IPoseidon2 poseidon = deployPoseidon();
        MockERC20 token = new MockERC20();
        return deployPool(
            poseidon,
            new StubDepositVerifier(),
            new StubWithdrawVerifier(),
            new StubDisburseVerifier(),
            new StubTransferVerifier(),
            IERC20(address(token))
        );
    }

    function testInitializeRejectsZeroKey() public {
        pool = _newPool();
        vm.expectRevert(BongtuPool.ZeroArbiterKey.selector);
        pool.initialize([uint256(0), uint256(0)]);

        // a partially-zero key is also rejected
        vm.expectRevert(BongtuPool.ZeroArbiterKey.selector);
        pool.initialize([uint256(0), uint256(7)]);

        assertTrue(!pool.initialized(), "must not be initialized after a rejected key");
    }

    function testInitializeSetsEpochZero() public {
        pool = _newPool();
        vm.expectEmit(true, false, false, true, address(pool));
        emit ArbiterRotated(0, 101, 202, block.number);
        pool.initialize([uint256(101), uint256(202)]);

        assertTrue(pool.initialized(), "initialized");
        assertEq(pool.currentEpoch(), 0, "epoch 0");
        (uint256 x, uint256 y) = pool.currentArbiterKey();
        assertEq(x, 101);
        assertEq(y, 202);
    }

    function testRotateArbiterAppendsAndEmits() public {
        pool = _newPool();
        pool.initialize([uint256(101), uint256(202)]);

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
        pool.initialize([uint256(101), uint256(202)]);
        address stranger = address(0xBEEF);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable2Step.OwnableUnauthorized.selector, stranger));
        pool.rotateArbiter([uint256(1), uint256(2)]);
    }
}
