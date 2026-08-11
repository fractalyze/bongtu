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
    ITransfer10Verifier,
    ITransfer10x2Verifier
} from "../src/interfaces/IVerifiers.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {
    StubDepositVerifier,
    StubWithdrawVerifier,
    StubDisburseVerifier,
    StubTransferVerifier,
    StubTransfer10Verifier,
    StubTransfer10x2Verifier
} from "./mocks/StubVerifiers.sol";
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
///   - that `initialize` wires this verifier like every other one, and refuses a
///     zero address for it, so the entry point is never live-but-unbacked.
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

    // `real` picks the real Groth16 transfer10 verifier vs an always-accept
    // stub; deposit is always stubbed so the tree can be seeded with arbitrary
    // commitments.
    function _pool(bool real) internal returns (BongtuPool pool) {
        token = new MockERC20();
        pool = deployPoolWith10(
            poseidon,
            IDepositVerifier(address(new StubDepositVerifier())),
            IWithdrawVerifier(address(new WithdrawVerifier())),
            IDisburseVerifier(address(new DisburseVerifier())),
            ITransferVerifier(address(new TransferVerifier())),
            real
                ? ITransfer10Verifier(address(new Transfer10Verifier()))
                : ITransfer10Verifier(address(new StubTransfer10Verifier())),
            ITransfer10x2Verifier(address(new StubTransfer10x2Verifier())),
            IERC20(address(token)),
            arbiterKey
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

    // ======================= initialize wiring ==============================

    /// `initialize` refuses a zero transfer10 verifier. Without this the pool
    /// would come up advertising {transfer10} and revert on every call to it —
    /// a call into address(0) — with no way back short of an upgrade.
    function testInitializeRejectsZeroTransfer10Verifier() public {
        token = new MockERC20();
        Base.InitArgs memory p = Base.InitArgs({
            poseidon: poseidon,
            dv: IDepositVerifier(address(new StubDepositVerifier())),
            wv: IWithdrawVerifier(address(new StubWithdrawVerifier())),
            dsv: IDisburseVerifier(address(new StubDisburseVerifier())),
            tv: ITransferVerifier(address(new StubTransferVerifier())),
            tv10: ITransfer10Verifier(address(0)),
            tv10x2: ITransfer10x2Verifier(address(new StubTransfer10x2Verifier())),
            token: IERC20(address(token)),
            batchSize: B,
            arbiterKey: arbiterKey,
            kemPkHash: DUMMY_KEM_PK_HASH
        });
        BongtuPool impl = new BongtuPool();
        vm.expectRevert(BongtuPool.ZeroVerifier.selector);
        deployPoolOn(impl, p);
    }

    /// The verifier is wired by the one initializer, so {transfer10} is live from
    /// the pool's first block — and the other five verifiers are live with it.
    function testInitializeWiresEverySixVerifier() public {
        BongtuPool pool = _pool(false);
        assertTrue(address(pool.depositVerifier()) != address(0), "deposit verifier not wired");
        assertTrue(address(pool.withdrawVerifier()) != address(0), "withdraw verifier not wired");
        assertTrue(address(pool.disburseVerifier()) != address(0), "disburse verifier not wired");
        assertTrue(address(pool.transferVerifier()) != address(0), "transfer verifier not wired");
        assertTrue(address(pool.transfer10Verifier()) != address(0), "transfer10 verifier not wired");
        assertTrue(address(pool.transfer10x2Verifier()) != address(0), "transfer10x2 verifier not wired");
        assertEq(pool.currentEpoch(), 0, "a fresh deploy carries exactly one arbiter epoch");
    }
}
