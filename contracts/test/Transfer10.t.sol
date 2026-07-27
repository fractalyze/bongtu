// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Base} from "./Base.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier,
    ITransfer10Verifier
} from "../src/interfaces/IVerifiers.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {Initializable} from "../src/utils/proxy/Initializable.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {
    StubDepositVerifier,
    StubWithdrawVerifier,
    StubDisburseVerifier,
    StubTransferVerifier,
    StubTransfer10Verifier
} from "./mocks/StubVerifiers.sol";
import {BongtuPoolV2} from "./mocks/BongtuPoolV2.sol";
import {DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";
import {DisburseVerifier} from "../src/verifiers/DisburseVerifier.sol";
import {TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {Transfer10Verifier} from "../src/verifiers/Transfer10Verifier.sol";

/// @notice The transfer10 (10-in / 10-out) entry point, U-Z1.
///
/// Two committed REAL proofs drive the accept legs — the partly-filled spend
/// (4 real inputs, 6 padded) and the full-arity consolidation (all 10 real) —
/// so both the "contract injects enabled=0 on a padded slot" and the "all ten
/// slots enabled" vectors are exercised against the real Groth16 verifier.
///
/// The rest of the suite pins what only the CONTRACT can enforce:
///   - in-tx double spend: the circuit never checked nullifier distinctness, so
///     spending all ten slots sequentially is the whole defense;
///   - the KEM ciphertext length rule on this path;
///   - `initializeV4` — an ADD-only, run-once verifier payload — and the fact
///     that transfer10 is unreachable until it has run.
contract Transfer10Test is Base {
    MockERC20 token;
    IPoseidon2 poseidon;
    string j;
    uint256[2] arbiterKey;

    uint256 constant N = 10; // transfer10 arity
    // Public-signal bases, restated from the pool's index map (141 publics):
    // [0..1]=ecdhPub [2..41]=cipherTexts[10][4] [42..105]=cipherTextAuthority[64]
    // [106]=kemBinding [107..116]=nf [117]=root [118..127]=enabled
    // [128..137]=oc [138]=nonce [139..140]=authorityPubKey
    uint256 constant P_RECEIVER_CT = 2;
    uint256 constant P_AUTHORITY_CT = 42;
    uint256 constant P_KEM_BINDING = 106;
    uint256 constant P_NF = 107;
    uint256 constant P_ROOT = 117;
    uint256 constant P_OC = 128;
    uint256 constant P_NONCE = 138;

    function setUp() public {
        poseidon = deployPoseidon();
        j = vm.readFile("test/fixtures/realproofs.json");
        uint256[] memory k = vm.parseJsonUintArray(j, ".arbiterKey");
        arbiterKey = [k[0], k[1]];
    }

    // A fresh pool whose transfer10 verifier is wired by initializeV4 — the same
    // payload the live pool takes, run here directly on a freshly-initialized
    // pool (reinitializer(4) only requires version < 4). `real` picks the real
    // Groth16 transfer10 verifier vs an always-accept stub; deposit is always
    // stubbed so the tree can be seeded with arbitrary commitments.
    function _pool(bool real) internal returns (BongtuPool pool) {
        token = new MockERC20();
        pool = deployPool(
            poseidon,
            IDepositVerifier(address(new StubDepositVerifier())),
            IWithdrawVerifier(address(new WithdrawVerifier())),
            IDisburseVerifier(address(new DisburseVerifier())),
            ITransferVerifier(address(new TransferVerifier())),
            IERC20(address(token)),
            arbiterKey
        );
        pool.initializeV4(
            real
                ? ITransfer10Verifier(address(new Transfer10Verifier()))
                : ITransfer10Verifier(address(new StubTransfer10Verifier()))
        );
        token.mint(address(pool), 1_000_000);
        token.mint(address(this), 1_000_000);
        token.approve(address(pool), type(uint256).max);
    }

    // --- fixture helpers (same JSON shape the RealProof suite reads) ----------

    function _abc(string memory key)
        internal
        view
        returns (uint[2] memory a, uint[2][2] memory b, uint[2] memory c)
    {
        uint256[] memory av = vm.parseJsonUintArray(j, string.concat(key, ".a"));
        uint256[] memory b0 = vm.parseJsonUintArray(j, string.concat(key, ".b[0]"));
        uint256[] memory b1 = vm.parseJsonUintArray(j, string.concat(key, ".b[1]"));
        uint256[] memory cv = vm.parseJsonUintArray(j, string.concat(key, ".c"));
        a = [av[0], av[1]];
        b = [[b0[0], b0[1]], [b1[0], b1[1]]];
        c = [cv[0], cv[1]];
    }

    function _pub141(string memory key) internal view returns (uint[141] memory pub) {
        uint256[] memory p = vm.parseJsonUintArray(j, string.concat(key, ".pub"));
        require(p.length == 141, "transfer10 fixture is not 141 publics");
        for (uint256 i = 0; i < 141; i++) pub[i] = p[i];
    }

    function _kemCt(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, string.concat(key, ".kemCiphertext"));
    }

    /// Seed the membership tree the fixture proved against: its REAL input
    /// commitments, appended in order via stub 2-leaf deposits. Every
    /// intermediate root is recorded (§5.3 any-historical-root), so the proof's
    /// root is known once the last seed leaf lands. Both fixtures have an even
    /// count (4 and 10), which is what lets a 2-out deposit place them exactly.
    function _seed(BongtuPool pool, string memory key) internal {
        uint256[] memory seed = vm.parseJsonUintArray(j, string.concat(key, ".seedLeaves"));
        require(seed.length % 2 == 0, "seed leaves must pair into 2-out deposits");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        for (uint256 i = 0; i < seed.length; i += 2) {
            uint[19] memory pub;
            pub[14] = seed[i];
            pub[15] = seed[i + 1];
            pool.deposit(a, b, c, pub, dummyKemCt());
        }
    }

    // ======================= REAL-PROOF ACCEPT ===============================

    /// The partly-filled spend: 4 real inputs (nullifiers nonzero, enabled=1),
    /// 6 padded (nullifier 0, enabled 0). The contract derives enabled from the
    /// nullifiers and must land on exactly the vector the proof was made with —
    /// so acceptance here is itself the proof that the arity-10 derivation is
    /// right, not just that the verifier was called.
    function testTransfer10Accepts() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10");
        uint[141] memory pub = _pub141(".transfer10");
        uint256 rootAfter = vm.parseJsonUint(j, ".transfer10.rootAfter");

        pool.transfer10(a, b, c, pub, _kemCt(".transfer10"));

        assertEq(pool.nextLeafIndex(), 14, "seed 4 + 10 outputs => nextLeafIndex 14");
        assertEq(pool.root(), rootAfter, "transfer10 root != oracle");
        for (uint256 i = 0; i < 4; i++) {
            assertTrue(pool.nullifierUsed(pub[P_NF + i]), "real nullifier not marked");
        }
        assertTrue(!pool.nullifierUsed(0), "the padded slots' zero nullifier must never be marked");
    }

    /// The full-arity consolidation: all 10 inputs real, merged into one
    /// self-owned output (the other 9 outputs are value-0 self notes). This is
    /// the headline shape — the 2-in ceiling needed a chain of self-sends for it.
    function testTransfer10ConsolidateAccepts() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10_consolidate");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10_consolidate");
        uint[141] memory pub = _pub141(".transfer10_consolidate");
        uint256 rootAfter = vm.parseJsonUint(j, ".transfer10_consolidate.rootAfter");

        pool.transfer10(a, b, c, pub, _kemCt(".transfer10_consolidate"));

        assertEq(pool.nextLeafIndex(), 20, "seed 10 + 10 outputs => nextLeafIndex 20");
        assertEq(pool.root(), rootAfter, "consolidate root != oracle");
        for (uint256 i = 0; i < N; i++) {
            assertTrue(pool.nullifierUsed(pub[P_NF + i]), "consolidation must spend all ten inputs");
        }
    }

    /// Replaying an accepted transfer10 reverts on the first nullifier: the
    /// membership root is still known, so the proof re-verifies and the spend
    /// set is what stops it.
    function testTransfer10ReplayReverts() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10");
        uint[141] memory pub = _pub141(".transfer10");
        bytes memory kemCt = _kemCt(".transfer10");

        pool.transfer10(a, b, c, pub, kemCt);
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, pub[P_NF]));
        pool.transfer10(a, b, c, pub, kemCt);
    }

    /// Flipping one public signal fails the Groth16 verify (the root is left
    /// alone so the known-root guard still passes and the failure isolates).
    function testTransfer10TamperedPublicSignalReverts() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10");
        uint[141] memory pub = _pub141(".transfer10");
        pub[P_OC] = pub[P_OC] ^ 1;

        vm.expectRevert(BongtuPool.InvalidProof.selector);
        pool.transfer10(a, b, c, pub, _kemCt(".transfer10"));
    }

    /// §6b v2 on the arity-10 path: the stored arbiter key is injected at
    /// pub[139..140], so a proof encrypted to a different key cannot verify.
    /// Control = testTransfer10Accepts (same proof, un-rotated key).
    function testTransfer10WrongAuthorityKeyReverts() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10");
        uint[141] memory pub = _pub141(".transfer10");

        pool.rotateArbiter([uint256(0x1234), uint256(0x5678)], bytes32(uint256(0x9abc)));

        vm.expectRevert(BongtuPool.InvalidProof.selector);
        pool.transfer10(a, b, c, pub, _kemCt(".transfer10"));
    }

    // ================= IN-TX DOUBLE SPEND (contract-only) ====================

    /// THE reason all ten slots must be spent, in order. `ZetoTransferSmall` has
    /// never constrained the nullifiers to be DISTINCT — at arity 2 nobody
    /// noticed, at arity 10 the same note could fund ten slots of one call. The
    /// contract's sequential `_spendNullifier` loop is the entire defense: the
    /// second occurrence hits an already-marked nullifier and reverts.
    ///
    /// Driven with an always-accept stub verifier on purpose: a real proof for
    /// this vector is exactly what the circuit does NOT forbid, so the test must
    /// hand the contract the vector directly rather than assume one cannot exist.
    function testInTxDoubleSpendReverts() public {
        BongtuPool pool = _pool(false);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();

        uint256 dup = uint256(0xDEADBEEF);
        uint[141] memory pub;
        pub[P_ROOT] = pool.root(); // the empty-tree root is a known root
        pub[P_NF] = dup; // slot 0
        pub[P_NF + 3] = dup; // ...and again at slot 3
        for (uint256 i = 0; i < N; i++) pub[P_OC + i] = 1000 + i;

        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, dup));
        pool.transfer10(a, b, c, pub, dummyKemCt());
    }

    /// Control for the test above: the SAME shape with ten DISTINCT nullifiers
    /// goes through and marks every one of them, so the revert above is
    /// attributable to the duplicate and not to the ten-slot loop as such.
    function testTenDistinctNullifiersAllSpend() public {
        BongtuPool pool = _pool(false);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();

        uint[141] memory pub;
        pub[P_ROOT] = pool.root();
        for (uint256 i = 0; i < N; i++) {
            pub[P_NF + i] = 0xC0FFEE + i;
            pub[P_OC + i] = 2000 + i;
        }
        pool.transfer10(a, b, c, pub, dummyKemCt());

        for (uint256 i = 0; i < N; i++) {
            assertTrue(pool.nullifierUsed(0xC0FFEE + i), "every distinct nullifier must be marked");
        }
        assertEq(pool.nextLeafIndex(), N, "all ten outputs appended");
    }

    /// The self-burn guard reaches every one of the ten output slots, not just
    /// the first (a padded output slot is a real value-0 note, so its commitment
    /// is nonzero — a zero here is always a malformed/forged vector).
    function testZeroOutputCommitmentInAnySlotReverts() public {
        BongtuPool pool = _pool(false);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();

        uint[141] memory pub;
        pub[P_ROOT] = pool.root();
        for (uint256 i = 0; i < N; i++) pub[P_OC + i] = 3000 + i;
        pub[P_OC + 7] = 0; // the LAST-but-two slot, so a first-slots-only guard fails here

        vm.expectRevert(BongtuPool.ZeroOutputCommitment.selector);
        pool.transfer10(a, b, c, pub, dummyKemCt());
    }

    // ================= ciphertext length enforcement =========================

    /// transfer10's receiver ciphertexts (40 elements) and authority envelope
    /// (64) ride inside the fixed `uint[141]` public vector — the verifier binds
    /// them, so there is no free-calldata length rule to break, unlike
    /// `disburseWithCiphertexts`. The one free ciphertext argument is the
    /// ML-KEM-768 encapsulation, and this path enforces its FIPS 203 wire size
    /// exactly like every other op, before the verifier is ever called.
    function testTransfer10WrongKemCiphertextLengthReverts() public {
        BongtuPool pool = _pool(false);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[141] memory pub;
        pub[P_ROOT] = pool.root();
        for (uint256 i = 0; i < N; i++) pub[P_OC + i] = 4000 + i;

        vm.expectRevert(abi.encodeWithSelector(BongtuPool.WrongKemCiphertextLength.selector, 1087, 1088));
        pool.transfer10(a, b, c, pub, new bytes(1087));

        vm.expectRevert(abi.encodeWithSelector(BongtuPool.WrongKemCiphertextLength.selector, 1089, 1088));
        pool.transfer10(a, b, c, pub, new bytes(1089));
    }

    /// The in-vector ciphertext runs are exactly what the envelope codec
    /// computes for arity 10 (packages/core/src/envelope.ts: 10x4 receiver
    /// elements, and authorityCiphertextLen of transfer10 == 64) — pinned here so
    /// a layout change cannot pass by only moving the event.
    function testCiphertextRunsMatchTheArity10Layout() public pure {
        assertEq(P_AUTHORITY_CT - P_RECEIVER_CT, 4 * N, "receiver run must be 10 x 4 elements");
        assertEq(P_KEM_BINDING - P_AUTHORITY_CT, 64, "authority envelope must be 64 elements");
    }

    // ============ the event the indexer ingests ==============================

    event Transferred10(
        uint256 indexed epoch,
        uint256[10] nullifiers,
        uint256[10] outputCommitments,
        uint256[2] ecdhPublicKey,
        uint256[40] encryptedValuesForReceivers,
        uint256[64] encryptedValuesForAuthority,
        uint256 encryptionNonce,
        uint256 root,
        uint256 kemBinding,
        bytes kemCiphertext
    );

    /// Full-data expectEmit on the real fixture: everything the indexer needs to
    /// correlate leaves, mark spends, and open the authority envelope must come
    /// off the log alone (the arbiter reads logs, not calldata).
    function testTransferred10EventCarriesEverythingIngestNeeds() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10");
        uint[141] memory pub = _pub141(".transfer10");
        bytes memory kemCt = _kemCt(".transfer10");
        assertEq(pub[P_KEM_BINDING], vm.parseJsonUint(j, ".transfer10.kemBinding"), "pub[106] != fixture kemBinding");

        uint256[10] memory nfs;
        uint256[10] memory ocs;
        for (uint256 i = 0; i < N; i++) {
            nfs[i] = pub[P_NF + i];
            ocs[i] = pub[P_OC + i];
        }
        uint256[40] memory rct;
        for (uint256 i = 0; i < 40; i++) rct[i] = pub[P_RECEIVER_CT + i];
        uint256[64] memory cta;
        for (uint256 i = 0; i < 64; i++) cta[i] = pub[P_AUTHORITY_CT + i];

        vm.expectEmit(true, false, false, true, address(pool));
        emit Transferred10(
            0,
            nfs,
            ocs,
            [pub[0], pub[1]],
            rct,
            cta,
            pub[P_NONCE],
            vm.parseJsonUint(j, ".transfer10.rootAfter"),
            pub[P_KEM_BINDING],
            kemCt
        );
        pool.transfer10(a, b, c, pub, kemCt);
    }

    // ======================= initializeV4 ====================================

    /// The migration payload on a pool that has taken V2 then V3 — the live
    /// pool's actual state. It must ADD the transfer10 verifier and touch
    /// nothing else: the four existing verifiers, the arbiter key and the epoch
    /// all stay, and the pre-upgrade tree/nullifier state survives.
    function testInitializeV4OnV3PoolAddsOnlyTransfer10Verifier() public {
        (BongtuPool pool, uint256 spentNf) = _v3Pool();

        address dvBefore = address(pool.depositVerifier());
        address wvBefore = address(pool.withdrawVerifier());
        address dsvBefore = address(pool.disburseVerifier());
        address tvBefore = address(pool.transferVerifier());
        uint256 epochBefore = pool.currentEpoch();
        (uint256 kxBefore, uint256 kyBefore) = pool.currentArbiterKey();
        uint256 rootBefore = pool.root();
        assertEq(address(pool.transfer10Verifier()), address(0), "precondition: no transfer10 verifier yet");

        ITransfer10Verifier t10 = ITransfer10Verifier(address(new StubTransfer10Verifier()));
        pool.upgradeToAndCall(address(new BongtuPoolV2()), abi.encodeCall(BongtuPool.initializeV4, (t10)));

        assertEq(address(pool.transfer10Verifier()), address(t10), "transfer10 verifier not wired");
        assertEq(address(pool.depositVerifier()), dvBefore, "deposit verifier must not change");
        assertEq(address(pool.withdrawVerifier()), wvBefore, "withdraw verifier must not change");
        assertEq(address(pool.disburseVerifier()), dsvBefore, "disburse verifier must not change");
        assertEq(address(pool.transferVerifier()), tvBefore, "the 2-in transfer verifier must not change");
        assertEq(pool.currentEpoch(), epochBefore, "initializeV4 must mint NO epoch");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        assertEq(kx, kxBefore, "arbiter key x must not change");
        assertEq(ky, kyBefore, "arbiter key y must not change");
        assertEq(pool.root(), rootBefore, "tree state lost across initializeV4");
        assertTrue(pool.nullifierUsed(spentNf), "spent nullifier lost across initializeV4");
    }

    /// run-once: reinitializer(4) is consumed by the payload above.
    function testInitializeV4IsBurnedAfterUse() public {
        (BongtuPool pool,) = _v3Pool();
        ITransfer10Verifier t10 = ITransfer10Verifier(address(new StubTransfer10Verifier()));
        pool.upgradeToAndCall(address(new BongtuPoolV2()), abi.encodeCall(BongtuPool.initializeV4, (t10)));

        // The deploy is hoisted out of the expectRevert: a CREATE counts as the
        // "next call" and would swallow the expectation.
        ITransfer10Verifier again = ITransfer10Verifier(address(new StubTransfer10Verifier()));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        pool.initializeV4(again);
    }

    function testInitializeV4RejectsZeroVerifier() public {
        (BongtuPool pool,) = _v3Pool();
        BongtuPoolV2 v4 = new BongtuPoolV2();
        vm.expectRevert(BongtuPool.ZeroVerifier.selector);
        pool.upgradeToAndCall(
            address(v4), abi.encodeCall(BongtuPool.initializeV4, (ITransfer10Verifier(address(0))))
        );
    }

    /// Until the payload runs, `transfer10Verifier` is address(0) and the entry
    /// point is simply unreachable — a pool that skipped the upgrade cannot be
    /// tricked into accepting an arity-10 spend.
    function testTransfer10UnreachableBeforeInitializeV4() public {
        (BongtuPool pool,) = _v3Pool();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[141] memory pub;
        pub[P_ROOT] = pool.root();
        for (uint256 i = 0; i < N; i++) pub[P_OC + i] = 5000 + i;

        vm.expectRevert(); // staticcall into address(0) returns no data
        pool.transfer10(a, b, c, pub, dummyKemCt());
    }

    /// A stub-verifier pool carrying real tree + nullifier state, upgraded
    /// through the live pool's actual initializer ladder (V2 then V3) so the V4
    /// payload is tested from the state it will really run against. Returns the
    /// pool and the nullifier its pre-upgrade transfer spent.
    function _v3Pool() internal returns (BongtuPool pool, uint256 spentNf) {
        token = new MockERC20();
        pool = deployPool(
            poseidon,
            IDepositVerifier(address(new StubDepositVerifier())),
            IWithdrawVerifier(address(new StubWithdrawVerifier())),
            IDisburseVerifier(address(new StubDisburseVerifier())),
            ITransferVerifier(address(new StubTransferVerifier())),
            IERC20(address(token)),
            arbiterKey
        );
        token.mint(address(this), 1_000_000);
        token.approve(address(pool), type(uint256).max);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[19] memory dpub;
        dpub[0] = 1000;
        dpub[14] = 111;
        dpub[15] = 222;
        pool.deposit(a, b, c, dpub, dummyKemCt());

        spentNf = uint256(0xBADC0FFEE);
        uint[37] memory tpub;
        tpub[27] = spentNf;
        tpub[29] = pool.root();
        tpub[32] = 333;
        tpub[33] = 444;
        pool.transfer(a, b, c, tpub, dummyKemCt());

        pool.upgradeToAndCall(
            address(new BongtuPoolV2()),
            abi.encodeCall(
                BongtuPool.initializeV2,
                (
                    IDepositVerifier(address(new StubDepositVerifier())),
                    IWithdrawVerifier(address(new StubWithdrawVerifier())),
                    IDisburseVerifier(address(new StubDisburseVerifier())),
                    ITransferVerifier(address(new StubTransferVerifier())),
                    arbiterKey,
                    keccak256("kem-pk-epoch-1")
                )
            )
        );
        pool.upgradeToAndCall(
            address(new BongtuPoolV2()),
            abi.encodeCall(BongtuPool.initializeV3, (ITransferVerifier(address(new StubTransferVerifier()))))
        );
    }
}
