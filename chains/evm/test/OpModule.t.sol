// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Base} from "./Base.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {Ownable2StepUpgradeable} from "../src/utils/Ownable2StepUpgradeable.sol";
import {StubModule, ReentrantToken} from "./mocks/OpModuleMocks.sol";
import {
    StubDepositVerifier,
    StubWithdrawVerifier,
    StubDisburseVerifier,
    StubTransferVerifier,
    StubTransfer10Verifier,
    StubTransfer10x2Verifier
} from "./mocks/StubVerifiers.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier,
    ITransfer10Verifier,
    ITransfer10x2Verifier
} from "../src/interfaces/IVerifiers.sol";

/// @notice The applyOp invariant gate (OPMOD §1), probed directly through a
///         test-only StubModule that forwards arbitrary OpEffects: the module
///         registry lifecycle, the full §1.3 invariant list, the escrow
///         variants' CEI ordering, and the shared reentrancy latch (§1.6).
contract OpModuleTest is Base {
    BongtuPool pool;
    MockERC20 token;
    IPoseidon2 poseidon;
    StubModule mod;

    event ModuleRegistered(address indexed module);
    event ModuleRemoved(address indexed module);
    event OpApplied(
        address indexed module,
        uint256 startLeafIndex,
        uint256 nullifierCount,
        uint256 leafCount,
        uint256 subtreeRoot,
        uint256 root
    );

    function setUp() public {
        poseidon = deployPoseidon();
        token = new MockERC20();
        pool = _newPool(IERC20(address(token)));
        mod = new StubModule(pool);
        pool.registerModule(address(mod));
        token.mint(address(this), 1_000_000);
        token.mint(address(pool), 1_000_000);
        token.approve(address(pool), type(uint256).max);
    }

    function _newPool(IERC20 tok) internal returns (BongtuPool) {
        return deployPoolWith10(
            poseidon,
            IDepositVerifier(address(new StubDepositVerifier())),
            IWithdrawVerifier(address(new StubWithdrawVerifier())),
            IDisburseVerifier(address(new StubDisburseVerifier())),
            ITransferVerifier(address(new StubTransferVerifier())),
            ITransfer10Verifier(address(new StubTransfer10Verifier())),
            ITransfer10x2Verifier(address(new StubTransfer10x2Verifier())),
            tok,
            [uint256(101), uint256(202)]
        );
    }

    // --- OpEffects builders ---------------------------------------------------
    function _fx(uint256 root_, uint256[] memory nfs, uint256[] memory leaves, uint256 subtree)
        internal
        pure
        returns (BongtuPool.OpEffects memory)
    {
        return BongtuPool.OpEffects({root: root_, nullifiers: nfs, leaves: leaves, subtreeRoot: subtree});
    }

    function _arr() internal pure returns (uint256[] memory a) {
        a = new uint256[](0);
    }

    function _arr(uint256 x) internal pure returns (uint256[] memory a) {
        a = new uint256[](1);
        a[0] = x;
    }

    function _arr(uint256 x, uint256 y) internal pure returns (uint256[] memory a) {
        a = new uint256[](2);
        a[0] = x;
        a[1] = y;
    }

    // ===================== registry lifecycle ================================

    function testRegisterAndRemoveModuleLifecycle() public {
        StubModule m2 = new StubModule(pool);
        assertFalse(pool.registeredModules(address(m2)));

        vm.expectEmit(true, false, false, true, address(pool));
        emit ModuleRegistered(address(m2));
        pool.registerModule(address(m2));
        assertTrue(pool.registeredModules(address(m2)));

        vm.expectEmit(true, false, false, true, address(pool));
        emit ModuleRemoved(address(m2));
        pool.removeModule(address(m2));
        assertFalse(pool.registeredModules(address(m2)));

        // a removed module is rejected at the gate again
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.ModuleNotRegistered.selector, address(m2)));
        m2.apply_(_fx(0, _arr(), _arr(1), 0));
    }

    function testRegisterModuleOnlyOwner() public {
        address stranger = address(0xBEEF);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable2StepUpgradeable.OwnableUnauthorized.selector, stranger));
        pool.registerModule(address(0x1234));

        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable2StepUpgradeable.OwnableUnauthorized.selector, stranger));
        pool.removeModule(address(mod));
    }

    function testRegisterZeroModuleReverts() public {
        vm.expectRevert(BongtuPool.ZeroModule.selector);
        pool.registerModule(address(0));
    }

    function testRegisterAlreadyRegisteredReverts() public {
        // no-op re-register must revert: the ModuleRegistered/ModuleRemoved
        // stream is the canonical registry reconstruction source, so it must
        // stay a balanced add/remove log — never spurious
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.ModuleAlreadyRegistered.selector, address(mod)));
        pool.registerModule(address(mod));
    }

    function testRemoveUnregisteredModuleReverts() public {
        // same balanced-log rule on the remove side
        address never = address(0x5E7E2);
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.ModuleNotRegistered.selector, never));
        pool.removeModule(never);

        // a registered-then-removed module cannot be removed twice
        pool.removeModule(address(mod));
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.ModuleNotRegistered.selector, address(mod)));
        pool.removeModule(address(mod));
    }

    function testUnregisteredCallerReverts() public {
        // direct EOA-style caller
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.ModuleNotRegistered.selector, address(this)));
        pool.applyOp(_fx(0, _arr(), _arr(1), 0));

        // unregistered module contract
        StubModule m2 = new StubModule(pool);
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.ModuleNotRegistered.selector, address(m2)));
        m2.apply_(_fx(0, _arr(), _arr(1), 0));
    }

    // ===================== §1.3 invariant list ===============================

    function testApplyOpMintThenSpend() public {
        uint256 start = mod.apply_(_fx(0, _arr(), _arr(11, 22), 0));
        assertEq(start, 0, "mint must start at leaf 0");
        assertEq(pool.nextLeafIndex(), 2, "mint must append 2 leaves");
        uint256 r = pool.root();
        assertTrue(pool.isKnownRoot(r), "post-mint root must be known");

        // spend against the known root, appending one output
        uint256 nf = uint256(0xA11CE);
        uint256 start2 = mod.apply_(_fx(r, _arr(nf), _arr(33), 0));
        assertEq(start2, 2, "spend must append at leaf 2");
        assertTrue(pool.nullifierUsed(nf), "nullifier must be marked");
    }

    function testRootlessMintMayNotClaimRoot() public {
        // even a KNOWN root is rejected when no nullifiers ride along
        mod.apply_(_fx(0, _arr(), _arr(11), 0));
        uint256 known = pool.root();
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.UnknownRoot.selector, known));
        mod.apply_(_fx(known, _arr(), _arr(22), 0));
    }

    function testUnknownRootReverts() public {
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.UnknownRoot.selector, uint256(0xDEAD)));
        mod.apply_(_fx(0xDEAD, _arr(7), _arr(), 0));
    }

    function testZeroNullifierReverts() public {
        mod.apply_(_fx(0, _arr(), _arr(11), 0));
        uint256 r = pool.root();
        // a zero entry is a REVERT here, not a skip (padding is stripped by
        // modules before the boundary — unlike the in-core _spendNullifier)
        vm.expectRevert(BongtuPool.ZeroNullifier.selector);
        mod.apply_(_fx(r, _arr(5, 0), _arr(), 0));
    }

    function testReusedNullifierReverts() public {
        mod.apply_(_fx(0, _arr(), _arr(11), 0));
        uint256 r = pool.root();
        mod.apply_(_fx(r, _arr(5), _arr(), 0));
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, uint256(5)));
        mod.apply_(_fx(r, _arr(5), _arr(), 0));
    }

    function testInTransactionDuplicateNullifierReverts() public {
        mod.apply_(_fx(0, _arr(), _arr(11), 0));
        uint256 r = pool.root();
        // sequential-and-complete marking: the duplicate's SECOND occurrence hits
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, uint256(9)));
        mod.apply_(_fx(r, _arr(9, 9), _arr(), 0));
    }

    function testZeroLeafReverts() public {
        vm.expectRevert(BongtuPool.ZeroOutputCommitment.selector);
        mod.apply_(_fx(0, _arr(), _arr(11, 0), 0));
    }

    function testMixedAppendShapeReverts() public {
        vm.expectRevert(BongtuPool.MixedAppendShape.selector);
        mod.apply_(_fx(0, _arr(), _arr(11), 42));
    }

    function testEmptyOpReverts() public {
        // a zero-effect op has no legitimate module use and would emit an
        // ambiguous OpApplied — even from a registered module
        vm.expectRevert(BongtuPool.EmptyOp.selector);
        mod.apply_(_fx(0, _arr(), _arr(), 0));
    }

    function testSubtreeAttach() public {
        // an unaligned frontier (1 leaf) gets closed to a B boundary in-call
        mod.apply_(_fx(0, _arr(), _arr(11), 0));
        uint256 start = mod.apply_(_fx(0, _arr(), _arr(), uint256(0x5AB7EE)));
        assertEq(start, B, "attach must start at the next B boundary");
        assertEq(pool.nextLeafIndex(), 2 * B, "attach advances by B");
        assertTrue(pool.isKnownRoot(pool.root()), "post-attach root must be known");
    }

    // ===================== escrow variants + CEI =============================

    function testApplyOpMovesNoTokens() public {
        uint256 poolBefore = token.balanceOf(address(pool));
        uint256 mineBefore = token.balanceOf(address(this));
        mod.apply_(_fx(0, _arr(), _arr(11), 0));
        assertEq(token.balanceOf(address(pool)), poolBefore, "plain applyOp must move no escrow");
        assertEq(token.balanceOf(address(this)), mineBefore, "plain applyOp must move no escrow");
    }

    function testApplyOpWithPullMovesExactlyAmount() public {
        uint256 poolBefore = token.balanceOf(address(pool));
        uint256 mineBefore = token.balanceOf(address(this));
        mod.applyPull(_fx(0, _arr(), _arr(11), 0), address(this), 777);
        assertEq(token.balanceOf(address(pool)) - poolBefore, 777, "pull must move exactly amount in");
        assertEq(mineBefore - token.balanceOf(address(this)), 777, "pull must debit the from address");
    }

    function testApplyOpWithPushMovesExactlyAmount() public {
        address to = address(0xCAFE);
        mod.apply_(_fx(0, _arr(), _arr(11), 0));
        uint256 r = pool.root();
        uint256 poolBefore = token.balanceOf(address(pool));
        mod.applyPush(_fx(r, _arr(3), _arr(44), 0), to, 555);
        assertEq(token.balanceOf(to), 555, "push must move exactly amount out");
        assertEq(poolBefore - token.balanceOf(address(pool)), 555, "push must debit the pool");
    }

    function testApplyOpWithPushZeroRecipientReverts() public {
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.InvalidRecipient.selector, uint256(0)));
        mod.applyPush(_fx(0, _arr(), _arr(11), 0), address(0), 1);
    }

    // ===================== shared reentrancy latch (§1.6) ====================

    function testReentrancyIntoEnterpriseOpDuringPull() public {
        ReentrantToken rtok = new ReentrantToken();
        BongtuPool pool2 = _newPool(IERC20(address(rtok)));
        StubModule m2 = new StubModule(pool2);
        pool2.registerModule(address(m2));
        rtok.mint(address(this), 1_000_000);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[19] memory dpub;
        dpub[14] = 1;
        dpub[15] = 2;
        rtok.setReentry(address(pool2), abi.encodeCall(BongtuPool.deposit, (a, b, c, dpub, dummyKemCt())));

        // the ERC-777-style callback lands while _locked == 2: the shared
        // latch closes cross-family reentry (module escrow -> enterprise op)
        // while the outer op itself completes
        m2.applyPull(_fx(0, _arr(), _arr(11), 0), address(this), 100);
        assertTrue(rtok.reentryAttempted(), "hook must have fired");
        assertFalse(rtok.reentrySucceeded(), "reentry into deposit must fail");
        assertEq(rtok.reentryRevertSelector(), BongtuPool.Reentrancy.selector, "reentry must die on the latch");
        assertEq(pool2.nextLeafIndex(), 1, "outer applyOpWithPull must still land");
    }

    function testReentrancyIntoApplyOpDuringPush() public {
        ReentrantToken rtok = new ReentrantToken();
        BongtuPool pool2 = _newPool(IERC20(address(rtok)));
        StubModule m2 = new StubModule(pool2);
        pool2.registerModule(address(m2));
        rtok.mint(address(pool2), 1_000_000);

        BongtuPool.OpEffects memory inner = _fx(0, _arr(), _arr(99), 0);
        rtok.setReentry(address(pool2), abi.encodeCall(BongtuPool.applyOp, (inner)));

        // nested module -> core recursion is closed by the same latch
        m2.applyPush(_fx(0, _arr(), _arr(11), 0), address(0xCAFE), 1);
        assertTrue(rtok.reentryAttempted(), "hook must have fired");
        assertFalse(rtok.reentrySucceeded(), "nested applyOp must fail");
        assertEq(rtok.reentryRevertSelector(), BongtuPool.Reentrancy.selector, "reentry must die on the latch");
        assertEq(pool2.nextLeafIndex(), 1, "outer applyOpWithPush must still land (inner leaf 99 must not)");
    }
}
