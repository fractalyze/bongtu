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
        bytes32 slot = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;
        // low 8 bytes of the ERC-7201 word = uint64 _initialized
        assertEq(uint64(uint256(vm.load(address(pool), slot))), 1, "initializer version must be 1");

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
}
