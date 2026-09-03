// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Base} from "./Base.sol";
import {stdStorage, StdStorage} from "forge-std/Test.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier,
    ITransfer10Verifier,
    ITransfer10x2Verifier
} from "../src/interfaces/IVerifiers.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {Ownable2StepUpgradeable} from "../src/utils/Ownable2StepUpgradeable.sol";
import {Initializable} from "../src/utils/proxy/Initializable.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {StubModule, ReentrantToken} from "./mocks/OpModuleMocks.sol";
import {
    StubDepositVerifier,
    StubWithdrawVerifier,
    StubDisburseVerifier,
    StubTransferVerifier,
    StubTransfer10Verifier,
    StubTransfer10x2Verifier
} from "./mocks/StubVerifiers.sol";

/// @notice UUPS upgrade gate (SPEC §5.2, `docs/zeto-derivation.md`
///         "Upgradeability"): an `upgradeToAndCall` through the ERC-1967 proxy
///         swaps the implementation while PRESERVING the pool address and the
///         whole tree/nullifier/arbiter state — the property that lets a circuit
///         change ship without a redeploy. Also pins the access control: only
///         the owner may upgrade, and the pool cannot be re-initialized.
///
/// Each test upgrades to a FRESHLY DEPLOYED, byte-identical implementation and
/// reads the ERC-1967 implementation slot to prove the swap happened. Identical
/// code is the sharpest instrument available here: any difference the tests then
/// observe comes from the storage moving, not from the new logic behaving
/// differently.
///
/// State is built with always-accept stub verifiers (the upgrade mechanics are
/// independent of proof validity): a deposit advances the tree + custodies
/// tokens, a transfer spends a nullifier — then the upgrade must leave all of it
/// intact behind the same address.
contract UpgradeTest is Base {
    using stdStorage for StdStorage;
    BongtuPool pool;
    MockERC20 token;
    IPoseidon2 poseidon;
    IDepositVerifier dv;
    IWithdrawVerifier wv;
    IDisburseVerifier dsv;
    ITransferVerifier tv;
    ITransfer10Verifier tv10;
    ITransfer10x2Verifier tv10x2;

    /// ERC-1967 implementation slot — the only witness that a swap to an
    /// identical implementation actually landed.
    bytes32 constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// ERC-7201 Initializable storage word; its low 8 bytes are the uint64
    /// `_initialized` version.
    bytes32 constant INIT_SLOT = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    uint256 constant ARB_X = 101;
    uint256 constant ARB_Y = 202;
    uint256 constant SPENT_NF = uint256(0xBADC0FFEE);
    bytes32 constant KEM_HASH_1 = keccak256("kem-pk-epoch-1");

    function setUp() public {
        poseidon = deployPoseidon();
        token = new MockERC20();
        dv = new StubDepositVerifier();
        wv = new StubWithdrawVerifier();
        dsv = new StubDisburseVerifier();
        tv = new StubTransferVerifier();
        tv10 = new StubTransfer10Verifier();
        tv10x2 = new StubTransfer10x2Verifier();
        pool = deployPoolWith10(poseidon, dv, wv, dsv, tv, tv10, tv10x2, IERC20(address(token)), [ARB_X, ARB_Y]);
        token.mint(address(this), 1_000_000);
        token.approve(address(pool), type(uint256).max);
    }

    /// @dev deposit (2-out mint) then transfer (spends SPENT_NF), so the pool
    ///      carries real, non-trivial state before the upgrade.
    function _buildState() internal {
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();

        uint[19] memory dpub;
        dpub[0] = 1000; // `out` tokens pulled from this contract
        dpub[14] = 111; // oc0 (nonzero — real note)
        dpub[15] = 222; // oc1
        pool.deposit(a, b, c, dpub, dummyKemCt());

        uint[37] memory tpub;
        tpub[27] = SPENT_NF; // input nullifier 0 (real => enabled=1 injected)
        tpub[28] = 0; // input nullifier 1 padded
        tpub[29] = pool.root(); // membership root (known after the deposit)
        tpub[32] = 333; // oc0 output
        tpub[33] = 444; // oc1 output
        pool.transfer(a, b, c, tpub, dummyKemCt());
    }

    function testUpgradePreservesState() public {
        _buildState();

        uint256 rootBefore = pool.root();
        uint256 nliBefore = pool.nextLeafIndex();
        (uint256 kxBefore, uint256 kyBefore) = pool.currentArbiterKey();
        uint256 epochBefore = pool.currentEpoch();
        assertEq(nliBefore, 4, "precondition: deposit(2) + transfer(2) => nextLeafIndex 4");
        assertTrue(pool.nullifierUsed(SPENT_NF), "precondition: nullifier spent");

        address newImpl = address(new BongtuPool());
        pool.upgradeToAndCall(newImpl, ""); // as owner (this contract), no payload

        // the new implementation is live behind the SAME address ...
        assertEq(_implementation(), newImpl, "upgrade did not take");
        // ... and every preserved slot survived the impl swap.
        assertEq(address(pool.transfer10Verifier()), address(tv10), "transfer10 verifier not preserved");
        assertEq(address(pool.transfer10x2Verifier()), address(tv10x2), "transfer10x2 verifier not preserved");
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

    /// The design-doc §4 storage rule under an actual impl swap: arbiterKemPkHash
    /// is the first of the tail slots, after every slot declared above it. If any
    /// slot had shifted, the epoch-keyed mapping (or a neighbor like
    /// disburseAllowed / the epochs array / the two arity-10 verifier slots that
    /// follow it) would read garbage after the upgrade — so we pin the kem hashes
    /// AND their neighbors across the swap, on a pool carrying real tree + epoch
    /// state.
    function testUpgradePreservesKemPkHashAndGapNeighbors() public {
        _buildState();
        pool.rotateArbiter([uint256(303), uint256(404)], KEM_HASH_1); // epoch 1, both keys
        // neighbor slot before the kem-hash mapping (the retired allowlist
        // mapping — written via stdstore since its setter is gone with the gate)
        stdstore.target(address(pool)).sig("disburseAllowed(address)").with_key(address(0xB0B)).checked_write(true);

        bytes32 h0Before = pool.arbiterKemPkHash(0); // epoch 0: Base's placeholder hash
        assertTrue(h0Before != bytes32(0), "precondition: epoch 0 carries a nonzero hash");

        address newImpl = address(new BongtuPool());
        pool.upgradeToAndCall(newImpl, "");

        assertEq(_implementation(), newImpl, "upgrade did not take");
        assertEq(pool.arbiterKemPkHash(0), h0Before, "epoch 0 kem pk hash not preserved");
        assertEq(pool.arbiterKemPkHash(1), KEM_HASH_1, "epoch 1 kem pk hash not preserved");
        assertEq(pool.arbiterKemPkHash(2), bytes32(0), "unminted epoch must still read 0");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        assertEq(kx, 303, "rotated arbiter key x not preserved");
        assertEq(ky, 404, "rotated arbiter key y not preserved");
        assertTrue(pool.disburseAllowed(address(0xB0B)), "disburseAllowed neighbor slot not preserved");
        assertEq(address(pool.transfer10Verifier()), address(tv10), "transfer10 verifier slot not preserved");
        assertEq(address(pool.transfer10x2Verifier()), address(tv10x2), "transfer10x2 verifier slot not preserved");
        assertTrue(pool.nullifierUsed(SPENT_NF), "spent nullifier not preserved");
    }

    function testNonOwnerUpgradeReverts() public {
        address newImpl = address(new BongtuPool());
        address implBefore = _implementation();
        address stranger = address(0xBEEF);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable2StepUpgradeable.OwnableUnauthorized.selector, stranger));
        pool.upgradeToAndCall(newImpl, "");
        assertEq(_implementation(), implBefore, "a refused upgrade must leave the implementation alone");
    }

    function _implementation() internal view returns (address) {
        return address(uint160(uint256(vm.load(address(pool), IMPL_SLOT))));
    }

    /// The pool has ONE initializer and no follow-on payloads. Reading the
    /// ERC-7201 version slot is what pins that from the outside: it must be
    /// exactly 1, so no `reinitializer(n)` ran during deployment and a future
    /// implementation's payload — which must declare n >= 2 — is still available.
    /// A payload that quietly shipped alongside `initialize` would show up here
    /// as a version above 1, whatever it was named.
    ///
    /// Re-running `initialize` must fail on the proxy and on a bare impl alike.
    function testInitializerVersionIsOneAndCannotRerun() public {
        assertEq(uint64(uint256(vm.load(address(pool), INIT_SLOT))), 1, "initializer version must be 1");

        vm.expectRevert(Initializable.InvalidInitialization.selector);
        pool.initialize(
            poseidon, dv, wv, dsv, tv, tv10, tv10x2, IERC20(address(token)), B, [ARB_X, ARB_Y], DUMMY_KEM_PK_HASH
        );

        // the bare implementation is locked by `_disableInitializers()` — the
        // classic UUPS implementation-takeover footgun.
        BongtuPool impl = new BongtuPool();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(
            poseidon, dv, wv, dsv, tv, tv10, tv10x2, IERC20(address(token)), B, [ARB_X, ARB_Y], DUMMY_KEM_PK_HASH
        );
    }

    // ==========================================================================
    //                 OPMOD §7.4 — the op-module (V3) upgrade gate
    // ==========================================================================

    function _v3Payload(address m) internal pure returns (bytes memory) {
        address[] memory mods = new address[](1);
        mods[0] = m;
        return abi.encodeCall(BongtuPool.reinitializeV3, (mods));
    }

    /// @dev The LIVE proxy sits at initializer version 2 (reinitializeV2 was
    ///      consumed by the U-P0 upgrade), so the V3 upgradeToAndCall tests
    ///      must start there to pin the exact 2->3 transition the one-shot
    ///      live upgrade performs. Consuming version 2 the way the production
    ///      proxy did (a real reinitializeV2 call) matches the file's
    ///      call-through style; the verifier argument is the one already wired.
    function _consumeV2() internal {
        pool.reinitializeV2(wv);
        assertEq(uint64(uint256(vm.load(address(pool), INIT_SLOT))), 2, "precondition: live proxy version is 2");
    }

    /// OPMOD §7.1: `registeredModules` is the first slot after
    /// {transfer10x2Verifier}, so the pre-existing tail neighbors are the
    /// witnesses that the append did not re-stride anything — pinned across a
    /// REAL `upgradeToAndCall(reinitializeV3)` on a pool carrying tree + epoch
    /// + retired-slot state.
    function testUpgradeV3RegistersModulesAndPreservesTail() public {
        _buildState();
        _consumeV2(); // the live proxy's 2->3 transition, not a fresh pool's 1->3
        pool.rotateArbiter([uint256(303), uint256(404)], KEM_HASH_1); // epoch 1
        stdstore.target(address(pool)).sig("disburseAllowed(address)").with_key(address(0xB0B)).checked_write(true);
        uint256 rootBefore = pool.root();
        uint256 nliBefore = pool.nextLeafIndex();
        bytes32 h0Before = pool.arbiterKemPkHash(0);

        StubModule stub = new StubModule(pool);
        address newImpl = address(new BongtuPool());
        pool.upgradeToAndCall(newImpl, _v3Payload(address(stub)));

        assertEq(_implementation(), newImpl, "upgrade did not take");
        assertTrue(pool.registeredModules(address(stub)), "reinitializeV3 did not register the module");
        assertEq(uint64(uint256(vm.load(address(pool), INIT_SLOT))), 3, "ERC-7201 version must be 3 after V3");
        // every pre-existing neighbor pin stays green
        assertEq(pool.root(), rootBefore, "root not preserved");
        assertEq(pool.nextLeafIndex(), nliBefore, "nextLeafIndex not preserved");
        assertTrue(pool.knownRoots(rootBefore), "root history not preserved");
        assertTrue(pool.nullifierUsed(SPENT_NF), "spent nullifier not preserved");
        assertEq(pool.currentEpoch(), 1, "arbiter epoch not preserved");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        assertEq(kx, 303, "rotated arbiter key x not preserved");
        assertEq(ky, 404, "rotated arbiter key y not preserved");
        assertEq(pool.arbiterKemPkHash(0), h0Before, "epoch 0 kem pk hash not preserved");
        assertEq(pool.arbiterKemPkHash(1), KEM_HASH_1, "epoch 1 kem pk hash not preserved");
        assertEq(pool.arbiterKemPkHash(2), bytes32(0), "unminted epoch must still read 0");
        assertTrue(pool.disburseAllowed(address(0xB0B)), "disburseAllowed neighbor slot not preserved");
        assertEq(address(pool.transfer10Verifier()), address(tv10), "transfer10 verifier slot not preserved");
        assertEq(address(pool.transfer10x2Verifier()), address(tv10x2), "transfer10x2 verifier slot not preserved");
        assertEq(pool.owner(), address(this), "owner not preserved");
    }

    /// The applyOp gate through a post-V3 registered stub module: the access
    /// check plus every OPMOD §1.3 invariant a registered module must satisfy.
    function testApplyOpGate() public {
        _buildState();
        _consumeV2();
        StubModule stub = new StubModule(pool);

        BongtuPool.OpEffects memory fx;
        fx.leaves = new uint256[](1);
        fx.leaves[0] = 555;

        // unregistered caller is the whole access story
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.ModuleNotRegistered.selector, address(stub)));
        stub.apply_(fx);

        pool.upgradeToAndCall(address(new BongtuPool()), _v3Payload(address(stub)));

        // registered: a spend + append lands
        uint256 r = pool.root();
        BongtuPool.OpEffects memory spend;
        spend.root = r;
        spend.nullifiers = new uint256[](1);
        spend.nullifiers[0] = uint256(0xFEED);
        spend.leaves = new uint256[](1);
        spend.leaves[0] = 666;
        uint256 start = stub.apply_(spend);
        assertEq(start, 4, "spend must append after _buildState's 4 leaves");
        assertTrue(pool.nullifierUsed(0xFEED), "module-spent nullifier not marked");

        // zero nullifier is a revert, not a skip
        spend.nullifiers[0] = 0;
        vm.expectRevert(BongtuPool.ZeroNullifier.selector);
        stub.apply_(spend);

        // used nullifier
        spend.nullifiers[0] = SPENT_NF;
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, SPENT_NF));
        stub.apply_(spend);

        // zero leaf
        fx.leaves[0] = 0;
        vm.expectRevert(BongtuPool.ZeroOutputCommitment.selector);
        stub.apply_(fx);

        // mixed shape: leaves + subtree
        fx.leaves[0] = 777;
        fx.subtreeRoot = 42;
        vm.expectRevert(BongtuPool.MixedAppendShape.selector);
        stub.apply_(fx);

        // a rootless op may not smuggle a root claim — even a known one
        fx.subtreeRoot = 0;
        fx.root = r;
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.UnknownRoot.selector, r));
        stub.apply_(fx);

        // unknown root
        spend.root = uint256(0xDEAD);
        spend.nullifiers[0] = uint256(0xF00D);
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.UnknownRoot.selector, uint256(0xDEAD)));
        stub.apply_(spend);
    }

    /// OPMOD §1.6: the ONE `_locked` latch guards both families. A token
    /// callback landing mid-escrow-motion (applyOpWithPull's pull, applyOp
    /// nested under a push) finds _locked == 2 and cannot reenter `deposit`
    /// nor any applyOp*.
    function testApplyOpEscrowCEI() public {
        ReentrantToken rtok = new ReentrantToken();
        BongtuPool rpool = deployPoolWith10(
            poseidon, dv, wv, dsv, tv, tv10, tv10x2, IERC20(address(rtok)), [ARB_X, ARB_Y]
        );
        StubModule stub = new StubModule(rpool);
        rpool.registerModule(address(stub));
        rtok.mint(address(this), 1_000_000);
        rtok.mint(address(rpool), 1_000_000);

        BongtuPool.OpEffects memory fx;
        fx.leaves = new uint256[](1);
        fx.leaves[0] = 11;

        // pull hook -> enterprise deposit: shared latch rejects
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[19] memory dpub;
        dpub[14] = 1;
        dpub[15] = 2;
        rtok.setReentry(address(rpool), abi.encodeCall(BongtuPool.deposit, (a, b, c, dpub, dummyKemCt())));
        stub.applyPull(fx, address(this), 100);
        assertFalse(rtok.reentrySucceeded(), "reentry into deposit must fail");
        assertEq(rtok.reentryRevertSelector(), BongtuPool.Reentrancy.selector, "reentry must die on the latch");
        assertEq(rpool.nextLeafIndex(), 1, "outer applyOpWithPull must still land");

        // push hook -> nested applyOp: same latch, same rejection
        BongtuPool.OpEffects memory inner;
        inner.leaves = new uint256[](1);
        inner.leaves[0] = 22;
        fx.leaves[0] = 12; // a fresh leaf for the second outer op
        rtok.setReentry(address(rpool), abi.encodeCall(BongtuPool.applyOp, (inner)));
        stub.applyPush(fx, address(0xCAFE), 1);
        assertFalse(rtok.reentrySucceeded(), "nested applyOp must fail");
        assertEq(rtok.reentryRevertSelector(), BongtuPool.Reentrancy.selector, "reentry must die on the latch");
        assertEq(rpool.nextLeafIndex(), 2, "outer applyOpWithPush must still land (inner leaf 22 must not)");
    }

    /// Twin-oracle comparison for deposit + transfer only: an upgraded+V3
    /// pool and a freshly deployed twin run the same stub-backed deposit and
    /// transfer and must land on identical roots at every step — pinning the
    /// shared tree/nullifier path those two ops exercise. The other four
    /// enterprise entrypoints are byte-untouched by the V3 diff and covered
    /// by their own suites.
    function testEnterpriseOpsSurviveModuleUpgrade() public {
        _consumeV2();
        StubModule stub = new StubModule(pool);
        pool.upgradeToAndCall(address(new BongtuPool()), _v3Payload(address(stub)));

        BongtuPool twin =
            deployPoolWith10(poseidon, dv, wv, dsv, tv, tv10, tv10x2, IERC20(address(token)), [ARB_X, ARB_Y]);
        token.approve(address(twin), type(uint256).max);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[19] memory dpub;
        dpub[0] = 1000;
        dpub[14] = 111;
        dpub[15] = 222;
        pool.deposit(a, b, c, dpub, dummyKemCt());
        twin.deposit(a, b, c, dpub, dummyKemCt());
        assertEq(pool.root(), twin.root(), "post-V3 deposit root != un-upgraded twin oracle");

        uint[37] memory tpub;
        tpub[27] = SPENT_NF;
        tpub[29] = pool.root();
        tpub[32] = 333;
        tpub[33] = 444;
        pool.transfer(a, b, c, tpub, dummyKemCt());
        twin.transfer(a, b, c, tpub, dummyKemCt());
        assertEq(pool.root(), twin.root(), "post-V3 transfer root != un-upgraded twin oracle");
        assertEq(pool.nextLeafIndex(), twin.nextLeafIndex(), "post-V3 nextLeafIndex != twin");
        assertTrue(pool.nullifierUsed(SPENT_NF) && twin.nullifierUsed(SPENT_NF), "nullifier split across twins");
    }

    /// Left at initializer version 1 deliberately: reinitializer(3) accepts
    /// any lower version, so this doubles as the 1->3 coverage while the
    /// upgradeToAndCall tests above pin the live proxy's exact 2->3 hop.
    /// A duplicate address in the one-shot V3 payload must revert: the
    /// ModuleRegistered stream is the canonical registry reconstruction
    /// source, and a double emit would unbalance it (same class as the
    /// setter guards).
    function testReinitializeV3DuplicateModuleReverts() public {
        StubModule stub = new StubModule(pool);
        address[] memory dup = new address[](2);
        dup[0] = address(stub);
        dup[1] = address(stub);
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.ModuleAlreadyRegistered.selector, address(stub)));
        pool.reinitializeV3(dup);
    }

    function testReinitializeV3OnlyOwnerOnce() public {
        StubModule stub = new StubModule(pool);
        address[] memory mods = new address[](1);
        mods[0] = address(stub);

        // non-owner cannot claim the version-3 slot after a bare upgradeTo
        address stranger = address(0xBEEF);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable2StepUpgradeable.OwnableUnauthorized.selector, stranger));
        pool.reinitializeV3(mods);

        // a zero module address is rejected atomically
        address[] memory zero = new address[](1);
        vm.expectRevert(BongtuPool.ZeroModule.selector);
        pool.reinitializeV3(zero);

        pool.reinitializeV3(mods);
        assertTrue(pool.registeredModules(address(stub)), "V3 did not register");
        assertEq(uint64(uint256(vm.load(address(pool), INIT_SLOT))), 3, "version must be 3");

        // version 3 is consumed — no re-run, whoever calls
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        pool.reinitializeV3(mods);
    }
}
