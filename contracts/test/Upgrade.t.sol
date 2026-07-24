// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Base} from "./Base.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IDepositVerifier, IWithdrawVerifier, IDisburseVerifier, ITransferVerifier} from "../src/interfaces/IVerifiers.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {Ownable2StepUpgradeable} from "../src/utils/Ownable2StepUpgradeable.sol";
import {Initializable} from "../src/utils/proxy/Initializable.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {BongtuPoolV2} from "./mocks/BongtuPoolV2.sol";
import {
    StubDepositVerifier,
    StubWithdrawVerifier,
    StubDisburseVerifier,
    StubTransferVerifier
} from "./mocks/StubVerifiers.sol";

/// @notice UUPS upgrade gate (SPEC §5.2, `docs/zeto-derivation.md`
///         "Upgradeability"): a `upgradeToAndCall` through the ERC-1967 proxy
///         swaps the implementation while PRESERVING the pool address + the whole
///         tree/nullifier/arbiter state — the property that makes the Unit-0
///         redeploy the LAST forced one. Also pins the access control: only the
///         owner may upgrade, and the pool cannot be re-initialized.
///
/// State is built with always-accept stub verifiers (the upgrade mechanics are
/// independent of proof validity): a deposit advances the tree + custodies
/// tokens, a transfer spends a nullifier — then the upgrade must leave all of it
/// intact behind the same address.
contract UpgradeTest is Base {
    BongtuPool pool;
    MockERC20 token;
    IPoseidon2 poseidon;
    IDepositVerifier dv;
    IWithdrawVerifier wv;
    IDisburseVerifier dsv;
    ITransferVerifier tv;

    uint256 constant ARB_X = 101;
    uint256 constant ARB_Y = 202;
    uint256 constant SPENT_NF = uint256(0xBADC0FFEE);

    function setUp() public {
        poseidon = deployPoseidon();
        token = new MockERC20();
        dv = new StubDepositVerifier();
        wv = new StubWithdrawVerifier();
        dsv = new StubDisburseVerifier();
        tv = new StubTransferVerifier();
        pool = deployPool(poseidon, dv, wv, dsv, tv, IERC20(address(token)), [ARB_X, ARB_Y]);
        token.mint(address(this), 1_000_000);
        token.approve(address(pool), type(uint256).max);
    }

    /// @dev deposit (2-out mint) then transfer (spends SPENT_NF), so the pool
    ///      carries real, non-trivial state before the upgrade.
    function _buildState() internal {
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();

        uint[18] memory dpub;
        dpub[0] = 1000; // `out` tokens pulled from this contract
        dpub[13] = 111; // oc0 (nonzero — real note)
        dpub[14] = 222; // oc1
        pool.deposit(a, b, c, dpub);

        uint[36] memory tpub;
        tpub[26] = SPENT_NF; // input nullifier 0 (real => enabled=1 injected)
        tpub[27] = 0; // input nullifier 1 padded
        tpub[28] = pool.root(); // membership root (known after the deposit)
        tpub[31] = 333; // oc0 output
        tpub[32] = 444; // oc1 output
        pool.transfer(a, b, c, tpub);
    }

    function testUpgradePreservesState() public {
        _buildState();

        uint256 rootBefore = pool.root();
        uint256 nliBefore = pool.nextLeafIndex();
        (uint256 kxBefore, uint256 kyBefore) = pool.currentArbiterKey();
        uint256 epochBefore = pool.currentEpoch();
        assertEq(nliBefore, 4, "precondition: deposit(2) + transfer(2) => nextLeafIndex 4");
        assertTrue(pool.nullifierUsed(SPENT_NF), "precondition: nullifier spent");

        BongtuPoolV2 v2 = new BongtuPoolV2();
        pool.upgradeToAndCall(address(v2), ""); // as owner (this contract), no reinit

        // the new logic is live behind the SAME address ...
        assertEq(BongtuPoolV2(address(pool)).version(), 2, "upgrade did not take");
        // ... and every preserved slot survived the impl swap.
        assertEq(pool.root(), rootBefore, "root not preserved");
        assertEq(pool.nextLeafIndex(), nliBefore, "nextLeafIndex not preserved");
        assertTrue(pool.knownRoots(rootBefore), "root history not preserved");
        assertTrue(pool.nullifierUsed(SPENT_NF), "spent nullifier not preserved");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        assertEq(kx, kxBefore, "arbiter key x not preserved");
        assertEq(ky, kyBefore, "arbiter key y not preserved");
        assertEq(pool.currentEpoch(), epochBefore, "arbiter epoch not preserved");
        assertEq(pool.owner(), address(this), "owner not preserved");
    }

    function testNonOwnerUpgradeReverts() public {
        BongtuPoolV2 v2 = new BongtuPoolV2();
        address stranger = address(0xBEEF);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable2StepUpgradeable.OwnableUnauthorized.selector, stranger));
        pool.upgradeToAndCall(address(v2), "");
    }

    function testReinitializeReverts() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        pool.initialize(poseidon, dv, wv, dsv, tv, IERC20(address(token)), B, [ARB_X, ARB_Y]);
    }

    /// @dev The bare implementation is locked (`_disableInitializers` in the
    ///      constructor): it can never be initialized directly, closing the
    ///      classic UUPS implementation-takeover footgun.
    function testImplementationIsLocked() public {
        BongtuPool impl = new BongtuPool();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(poseidon, dv, wv, dsv, tv, IERC20(address(token)), B, [ARB_X, ARB_Y]);
    }
}
