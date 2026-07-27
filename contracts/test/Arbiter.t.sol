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
    event ArbiterKemPkHashSet(uint256 indexed epoch, bytes32 kemPkHash);

    bytes32 constant KEM_HASH_0 = keccak256("kem-pk-epoch-0");
    bytes32 constant KEM_HASH_1 = keccak256("kem-pk-epoch-1");

    function _newPool() internal returns (BongtuPool) {
        _poseidon = deployPoseidon();
        _token = IERC20(address(new MockERC20()));
        _dv = new StubDepositVerifier();
        _wv = new StubWithdrawVerifier();
        _dsv = new StubDisburseVerifier();
        _tv = new StubTransferVerifier();
        return deployUninitializedPool();
    }

    /// @dev Drive the 9-arg initializer with the captured deps + a given key pair.
    function _init(uint256[2] memory key) internal {
        pool.initialize(_poseidon, _dv, _wv, _dsv, _tv, _token, B, key, KEM_HASH_0);
    }

    function testInitializeRejectsZeroKey() public {
        pool = _newPool();
        vm.expectRevert(BongtuPool.ZeroArbiterKey.selector);
        _init([uint256(0), uint256(0)]);

        // a partially-zero key is also rejected
        vm.expectRevert(BongtuPool.ZeroArbiterKey.selector);
        _init([uint256(0), uint256(7)]);

        // a zero KEM pk hash is rejected: bytes32(0) is the reserved pre-KEM
        // marker (design doc §4) and a fresh deploy must never mint one.
        vm.expectRevert(BongtuPool.ZeroKemPkHash.selector);
        pool.initialize(_poseidon, _dv, _wv, _dsv, _tv, _token, B, [uint256(101), uint256(202)], bytes32(0));

        assertTrue(!pool.initialized(), "must not be initialized after a rejected key");
    }

    function testInitializeSetsEpochZero() public {
        pool = _newPool();
        vm.expectEmit(true, false, false, true, address(pool));
        emit ArbiterRotated(0, 101, 202, block.number);
        vm.expectEmit(true, false, false, true, address(pool));
        emit ArbiterKemPkHashSet(0, KEM_HASH_0);
        _init([uint256(101), uint256(202)]);

        assertTrue(pool.initialized(), "initialized");
        assertEq(pool.currentEpoch(), 0, "epoch 0");
        (uint256 x, uint256 y) = pool.currentArbiterKey();
        assertEq(x, 101);
        assertEq(y, 202);
        assertEq(pool.arbiterKemPkHash(0), KEM_HASH_0, "epoch 0 must carry the seeded KEM pk hash");
    }

    function testRotateArbiterAppendsAndEmits() public {
        pool = _newPool();
        _init([uint256(101), uint256(202)]);

        vm.roll(block.number + 5);
        vm.expectEmit(true, false, false, true, address(pool));
        emit ArbiterRotated(1, 303, 404, block.number);
        vm.expectEmit(true, false, false, true, address(pool));
        emit ArbiterKemPkHashSet(1, KEM_HASH_1);
        pool.rotateArbiter([uint256(303), uint256(404)], KEM_HASH_1);

        assertEq(pool.currentEpoch(), 1, "epoch advanced to 1");
        (uint256 x, uint256 y) = pool.currentArbiterKey();
        assertEq(x, 303, "rotated keyX");
        assertEq(y, 404, "rotated keyY");
        assertEq(pool.arbiterKemPkHash(1), KEM_HASH_1, "rotation must write the new epoch's KEM pk hash");
        assertEq(pool.arbiterKemPkHash(0), KEM_HASH_0, "rotation must not touch prior epochs' hashes");

        // rotation also rejects a zero key / a zero KEM pk hash (the latter
        // would mint a post-KEM epoch indistinguishable from the pre-KEM marker)
        vm.expectRevert(BongtuPool.ZeroArbiterKey.selector);
        pool.rotateArbiter([uint256(5), uint256(0)], KEM_HASH_1);
        vm.expectRevert(BongtuPool.ZeroKemPkHash.selector);
        pool.rotateArbiter([uint256(5), uint256(6)], bytes32(0));
    }

    /// The pre-KEM marker semantics (design doc §4): an epoch index the V2 code
    /// never wrote reads bytes32(0) — exactly what the live pool's pre-upgrade
    /// epochs return after the UUPS swap (mapping slots default to zero; only
    /// rotateArbiter/initialize ever write nonzero, both zero-hash-guarded).
    function testUnwrittenEpochsReadZeroKemPkHash() public {
        pool = _newPool();
        _init([uint256(101), uint256(202)]);
        assertEq(pool.arbiterKemPkHash(1), bytes32(0), "an unminted epoch must read the pre-KEM marker 0");
        assertEq(pool.arbiterKemPkHash(42), bytes32(0), "any unwritten epoch index must read 0");
    }

    function testRotateOnlyOwner() public {
        pool = _newPool();
        _init([uint256(101), uint256(202)]);
        address stranger = address(0xBEEF);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable2StepUpgradeable.OwnableUnauthorized.selector, stranger));
        pool.rotateArbiter([uint256(1), uint256(2)], KEM_HASH_1);
    }
}
