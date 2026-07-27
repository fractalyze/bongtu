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
    bytes32 constant KEM_HASH_1 = keccak256("kem-pk-epoch-1");

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

    /// The design-doc §4 storage rule under an actual impl swap: arbiterKemPkHash
    /// lives in the FIRST slot the V1 __gap reserved (gap 50 -> 49), after every
    /// V1 slot. If any slot had shifted, the epoch-keyed mapping (or a neighbor
    /// like disburseAllowed / the epochs array) would read garbage after the
    /// upgrade — so we pin BOTH the kem hashes and their neighbors across the
    /// swap, on a pool carrying real tree + epoch state.
    function testUpgradePreservesKemPkHashAndGapNeighbors() public {
        _buildState();
        pool.rotateArbiter([uint256(303), uint256(404)], KEM_HASH_1); // epoch 1, both keys
        pool.setDisburseAllowed(address(0xB0B), true); // neighbor slot before the V2 mapping

        bytes32 h0Before = pool.arbiterKemPkHash(0); // epoch 0: Base's placeholder hash
        assertTrue(h0Before != bytes32(0), "precondition: epoch 0 carries a nonzero hash");

        BongtuPoolV2 v2 = new BongtuPoolV2();
        pool.upgradeToAndCall(address(v2), "");

        assertEq(BongtuPoolV2(address(pool)).version(), 2, "upgrade did not take");
        assertEq(pool.arbiterKemPkHash(0), h0Before, "epoch 0 kem pk hash not preserved");
        assertEq(pool.arbiterKemPkHash(1), KEM_HASH_1, "epoch 1 kem pk hash not preserved");
        assertEq(pool.arbiterKemPkHash(2), bytes32(0), "unminted epoch must still read the pre-KEM marker 0");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        assertEq(kx, 303, "rotated arbiter key x not preserved");
        assertEq(ky, 404, "rotated arbiter key y not preserved");
        assertTrue(pool.disburseAllowed(address(0xB0B)), "disburseAllowed neighbor slot not preserved");
        assertTrue(pool.nullifierUsed(SPENT_NF), "spent nullifier not preserved");
    }

    /// The migration payload the live pool's PQ upgrade uses (UpgradePq.s.sol):
    /// upgradeToAndCall(impl, initializeV2(...)) must, in ONE tx, swap the four
    /// verifier addresses AND mint a fresh epoch carrying both keys — atomicity
    /// is what closes the partial-deploy window (old proofs vs new verifiers
    /// fail on public count). reinitializer(2) then burns the payload: a second
    /// call must revert.
    function testInitializeV2RejectsZeroVerifier() public {
        _buildState();
        IWithdrawVerifier nwv = new StubWithdrawVerifier();
        IDisburseVerifier ndsv = new StubDisburseVerifier();
        ITransferVerifier ntv = new StubTransferVerifier();
        BongtuPoolV2 v2 = new BongtuPoolV2();
        vm.expectRevert(BongtuPool.ZeroVerifier.selector);
        pool.upgradeToAndCall(
            address(v2),
            abi.encodeCall(
                BongtuPool.initializeV2,
                (IDepositVerifier(address(0)), nwv, ndsv, ntv, [ARB_X, ARB_Y], KEM_HASH_1)
            )
        );
    }

    function testUpgradeToAndCallInitializeV2SwapsVerifiersAndMintsEpoch() public {
        _buildState();
        IDepositVerifier ndv = new StubDepositVerifier();
        IWithdrawVerifier nwv = new StubWithdrawVerifier();
        IDisburseVerifier ndsv = new StubDisburseVerifier();
        ITransferVerifier ntv = new StubTransferVerifier();

        BongtuPoolV2 v2 = new BongtuPoolV2();
        pool.upgradeToAndCall(
            address(v2),
            abi.encodeCall(BongtuPool.initializeV2, (ndv, nwv, ndsv, ntv, [ARB_X, ARB_Y], KEM_HASH_1))
        );

        assertEq(address(pool.depositVerifier()), address(ndv), "deposit verifier not swapped");
        assertEq(address(pool.withdrawVerifier()), address(nwv), "withdraw verifier not swapped");
        assertEq(address(pool.disburseVerifier()), address(ndsv), "disburse verifier not swapped");
        assertEq(address(pool.transferVerifier()), address(ntv), "transfer verifier not swapped");
        assertEq(pool.currentEpoch(), 1, "migration epoch not minted");
        assertEq(pool.arbiterKemPkHash(1), KEM_HASH_1, "migration epoch kem pk hash not stored");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        assertEq(kx, ARB_X, "same-key rotation keyX");
        assertEq(ky, ARB_Y, "same-key rotation keyY");
        assertTrue(pool.nullifierUsed(SPENT_NF), "pre-upgrade state lost across initializeV2");

        // run-once: reinitializer(2) is consumed
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        pool.initializeV2(ndv, nwv, ndsv, ntv, [ARB_X, ARB_Y], KEM_HASH_1);
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
        pool.initialize(poseidon, dv, wv, dsv, tv, IERC20(address(token)), B, [ARB_X, ARB_Y], DUMMY_KEM_PK_HASH);
    }

    /// @dev The bare implementation is locked (`_disableInitializers` in the
    ///      constructor): it can never be initialized directly, closing the
    ///      classic UUPS implementation-takeover footgun.
    function testImplementationIsLocked() public {
        BongtuPool impl = new BongtuPool();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(poseidon, dv, wv, dsv, tv, IERC20(address(token)), B, [ARB_X, ARB_Y], DUMMY_KEM_PK_HASH);
    }
}
