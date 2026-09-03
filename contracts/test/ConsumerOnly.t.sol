// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Base} from "./Base.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier,
    ITransfer10Verifier,
    ITransfer10x2Verifier,
    IDepositPrivVerifier
} from "../src/interfaces/IVerifiers.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {ERC1967Proxy} from "../src/utils/proxy/ERC1967Proxy.sol";
import {Initializable} from "../src/utils/proxy/Initializable.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {StubModule} from "./mocks/OpModuleMocks.sol";
import {DepositPrivModule} from "../src/modules/DepositPrivModule.sol";
import {DepositPrivVerifier} from "../src/verifiers/DepositPrivVerifier.sol";

/// @notice The CONSUMER-ONLY deploy profile (OPMOD §9 resolved default; issue #6
///         acceptance: "a consumer-only profile initializes with no arbiter key
///         at all"): `initializeConsumerOnly` brings up the core with NO arbiter
///         epoch, NO KEM pk hash and NO enterprise verifier — no auditor key
///         exists rather than being burned — and the consumer module family is
///         the pool's only op surface.
///
/// Pinned here:
///   - shape: B / owner / initialized / empty-tree root; every enterprise
///     verifier getter zero; `currentEpoch()` reverts (empty epoch list);
///   - every enterprise entrypoint reverts (deposit is the witness — it injects
///     `currentArbiterKey()` first, which panics on the empty list);
///   - the module layer fully operates: registerModule + a stub-module mint,
///     AND the committed REAL depositPriv fixture proof through the real
///     DepositPrivModule/DepositPrivVerifier — a consumer mint end to end on a
///     pool that never carried an arbiter key;
///   - run-once: the version slot is SHARED with `initialize`, so neither
///     initializer can run after the other.
contract ConsumerOnlyTest is Base {
    BongtuPool pool;
    MockERC20 token;
    IPoseidon2 poseidon;

    function setUp() public {
        poseidon = deployPoseidon();
        token = new MockERC20();
        pool = _deployConsumerOnly(B);
        token.mint(address(this), 1_000_000);
        token.approve(address(pool), type(uint256).max);
    }

    function _deployConsumerOnly(uint256 batchSize) internal returns (BongtuPool) {
        BongtuPool impl = new BongtuPool();
        bytes memory init =
            abi.encodeCall(BongtuPool.initializeConsumerOnly, (poseidon, IERC20(address(token)), batchSize));
        return BongtuPool(address(new ERC1967Proxy(address(impl), init)));
    }

    function testConsumerOnlyShape() public view {
        assertEq(pool.B(), B, "batch size");
        assertEq(pool.owner(), address(this), "owner = deployer");
        assertTrue(pool.initialized(), "initialized flag");
        assertTrue(pool.isKnownRoot(pool.root()), "empty-tree root known");
        assertEq(pool.nextLeafIndex(), 0, "fresh tree");
        // no enterprise verifier exists on this profile
        assertEq(address(pool.depositVerifier()), address(0), "deposit verifier must be zero");
        assertEq(address(pool.withdrawVerifier()), address(0), "withdraw verifier must be zero");
        assertEq(address(pool.disburseVerifier()), address(0), "disburse verifier must be zero");
        assertEq(address(pool.transferVerifier()), address(0), "transfer verifier must be zero");
        assertEq(address(pool.transfer10Verifier()), address(0), "transfer10 verifier must be zero");
        assertEq(address(pool.transfer10x2Verifier()), address(0), "transfer10x2 verifier must be zero");
        assertEq(pool.arbiterKemPkHash(0), bytes32(0), "no KEM epoch material");
    }

    /// No arbiter epoch was EVER minted: the epoch getters revert (empty list)
    /// rather than serving a placeholder key — "no key exists", not "key is
    /// burned".
    function testConsumerOnlyHasNoArbiterEpoch() public {
        vm.expectRevert(); // arbiterEpochs.length - 1 underflows (panic 0x11)
        pool.currentEpoch();
        vm.expectRevert(); // arbiterEpochs[length - 1] on an empty array
        pool.currentArbiterKey();
    }

    /// The enterprise family does not exist on this profile: deposit injects
    /// the stored arbiter key before anything else, and there is none.
    function testEnterpriseEntrypointsRevertOnConsumerOnlyPool() public {
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[19] memory pub;
        vm.expectRevert(); // currentArbiterKey() panics on the empty epoch list
        pool.deposit(a, b, c, pub, dummyKemCt());
    }

    /// The module layer is the pool's whole op surface and works immediately:
    /// registration is live at version 1 (owner set by the initializer), and a
    /// registered module can mint through applyOpWithPull.
    function testConsumerOnlyModuleMintOperates() public {
        StubModule stub = new StubModule(pool);
        pool.registerModule(address(stub));
        assertTrue(pool.registeredModules(address(stub)), "module not registered");

        uint256[] memory leaves = new uint256[](2);
        leaves[0] = 111;
        leaves[1] = 222;
        uint256 balBefore = token.balanceOf(address(pool));
        stub.applyPull(
            BongtuPool.OpEffects({root: 0, nullifiers: new uint256[](0), leaves: leaves, subtreeRoot: 0}),
            address(this),
            500
        );
        assertEq(pool.nextLeafIndex(), 2, "mint appended 2 leaves");
        assertEq(token.balanceOf(address(pool)) - balBefore, 500, "escrow pull");
    }

    /// THE acceptance witness: the committed REAL depositPriv Groth16 proof is
    /// accepted end to end (real verifier, real module) on a pool that
    /// initialized with no arbiter key at all.
    function testRealDepositPrivAcceptsOnConsumerOnlyPool() public {
        DepositPrivModule mod =
            new DepositPrivModule(pool, IDepositPrivVerifier(address(new DepositPrivVerifier())));
        pool.registerModule(address(mod));

        string memory j = vm.readFile("test/fixtures/consumer_realproofs.json");
        uint256[] memory av = vm.parseJsonUintArray(j, ".depositPriv.a");
        uint256[] memory b0 = vm.parseJsonUintArray(j, ".depositPriv.b[0]");
        uint256[] memory b1 = vm.parseJsonUintArray(j, ".depositPriv.b[1]");
        uint256[] memory cv = vm.parseJsonUintArray(j, ".depositPriv.c");
        uint256[] memory pv = vm.parseJsonUintArray(j, ".depositPriv.pub");
        uint[2] memory a = [av[0], av[1]];
        uint[2][2] memory b = [[b0[0], b0[1]], [b1[0], b1[1]]];
        uint[2] memory c = [cv[0], cv[1]];
        uint[16] memory pub;
        for (uint256 i = 0; i < 16; i++) {
            pub[i] = pv[i];
        }
        bytes[] memory kemCts = vm.parseJsonBytesArray(j, ".depositPriv.kemCiphertexts");

        uint256 balBefore = token.balanceOf(address(pool));
        mod.depositPriv(a, b, c, pub, kemCts);
        assertEq(pool.nextLeafIndex(), 2, "depositPriv appends 2 leaves");
        assertEq(pool.root(), vm.parseJsonUint(j, ".depositPriv.rootAfter"), "root != fixture oracle");
        assertEq(token.balanceOf(address(pool)) - balBefore, pub[0], "escrow pull of `out`");
    }

    /// One version slot, two profiles: neither initializer can run twice, and
    /// the ENTERPRISE initializer cannot run on a consumer-only pool (or vice
    /// versa) — a pool is one profile forever, short of an upgrade payload.
    function testInitializersAreMutuallyExclusiveRunOnce() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        pool.initializeConsumerOnly(poseidon, IERC20(address(token)), B);

        InitArgs memory p = InitArgs({
            poseidon: poseidon,
            dv: IDepositVerifier(address(new StubTransfer10VerifierShim())),
            wv: IWithdrawVerifier(address(new StubTransfer10VerifierShim())),
            dsv: IDisburseVerifier(address(new StubTransfer10VerifierShim())),
            tv: ITransferVerifier(address(new StubTransfer10VerifierShim())),
            tv10: ITransfer10Verifier(address(new StubTransfer10VerifierShim())),
            tv10x2: ITransfer10x2Verifier(address(new StubTransfer10VerifierShim())),
            token: IERC20(address(token)),
            batchSize: B,
            arbiterKey: [uint256(1), uint256(2)],
            kemPkHash: DUMMY_KEM_PK_HASH
        });
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        pool.initialize(
            p.poseidon, p.dv, p.wv, p.dsv, p.tv, p.tv10, p.tv10x2, p.token, p.batchSize, p.arbiterKey, p.kemPkHash
        );
    }

    function testConsumerOnlyRejectsBadBatchSize() public {
        BongtuPool impl = new BongtuPool();
        bytes memory init =
            abi.encodeCall(BongtuPool.initializeConsumerOnly, (poseidon, IERC20(address(token)), uint256(3)));
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.BatchSizeNotPowerOfTwo.selector, uint256(3)));
        new ERC1967Proxy(address(impl), init);
    }
}

/// @dev Minimal always-true stand-in for every enterprise verifier interface in
///      the mutual-exclusion test (only the ADDRESS matters there — the call
///      never executes because the initializer reverts first).
contract StubTransfer10VerifierShim {
    fallback() external {
        // return true for any verifyProof shape
        assembly {
            mstore(0, 1)
            return(0, 32)
        }
    }
}
