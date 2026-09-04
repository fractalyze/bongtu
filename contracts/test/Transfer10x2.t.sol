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
import {Transfer10x2Verifier} from "../src/verifiers/Transfer10x2Verifier.sol";

/// @notice The transfer10x2 (10-in / 2-out) entry point, U-Z3.
///
/// Two committed REAL proofs drive the accept legs — the partly-filled spend
/// (4 real inputs, payment + change) and the pure merge (all 10 real, merged
/// note + zero self change) — so both the "contract injects enabled=0 on a
/// padded slot" and the "all ten slots enabled" vectors are exercised against
/// the real Groth16 verifier, at the arity whose whole point is appending TWO
/// leaves instead of ten.
///
/// The rest of the suite pins what only the CONTRACT can enforce:
///   - in-tx double spend: the circuit never checked nullifier distinctness, so
///     spending all ten slots sequentially is the whole defense;
///   - the KEM ciphertext length rule on this path;
///   - that `initialize` wires this verifier like every other one, and refuses a
///     zero address for it, so the entry point is never live-but-unbacked.
contract Transfer10x2Test is Base {
    MockERC20 token;
    IPoseidon2 poseidon;
    string j;
    uint256[2] arbiterKey;

    uint256 constant N = 10; // input arity (outputs are 2)
    // Public-signal bases, restated from the pool's index map (68 publics):
    // [0..1]=ecdhPub [2..9]=cipherTexts[2][4] [10..40]=cipherTextAuthority[31]
    // [41]=kemBinding [42..51]=nf [52]=root [53..62]=enabled
    // [63..64]=oc [65]=nonce [66..67]=authorityPubKey
    uint256 constant P_RECEIVER_CT = 2;
    uint256 constant P_AUTHORITY_CT = 10;
    uint256 constant P_KEM_BINDING = 41;
    uint256 constant P_NF = 42;
    uint256 constant P_ROOT = 52;
    uint256 constant P_OC = 63;
    uint256 constant P_NONCE = 65;

    function setUp() public {
        poseidon = deployPoseidon();
        j = vm.readFile("test/fixtures/realproofs.json");
        uint256[] memory k = vm.parseJsonUintArray(j, ".arbiterKey");
        arbiterKey = [k[0], k[1]];
    }

    // `real` picks the real Groth16 transfer10x2 verifier vs an always-accept
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
            ITransfer10Verifier(address(new StubTransfer10Verifier())),
            real
                ? ITransfer10x2Verifier(address(new Transfer10x2Verifier()))
                : ITransfer10x2Verifier(address(new StubTransfer10x2Verifier())),
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

    function _pub68(string memory key) internal view returns (uint[68] memory pub) {
        uint256[] memory p = vm.parseJsonUintArray(j, string.concat(key, ".pub"));
        require(p.length == 68, "transfer10x2 fixture is not 68 publics");
        for (uint256 i = 0; i < 68; i++) pub[i] = p[i];
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
    /// so acceptance here is itself the proof that the arity-(10,2) derivation
    /// is right, not just that the verifier was called.
    function testTransfer10x2Accepts() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10x2");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2");
        uint[68] memory pub = _pub68(".transfer10x2");
        uint256 rootAfter = vm.parseJsonUint(j, ".transfer10x2.rootAfter");

        pool.transfer10x2(a, b, c, pub, _kemCt(".transfer10x2"));

        assertEq(pool.nextLeafIndex(), 6, "seed 4 + 2 outputs => nextLeafIndex 6");
        assertEq(pool.root(), rootAfter, "transfer10x2 root != oracle");
        for (uint256 i = 0; i < 4; i++) {
            assertTrue(pool.nullifierUsed(pub[P_NF + i]), "real nullifier not marked");
        }
        assertTrue(!pool.nullifierUsed(0), "the padded slots' zero nullifier must never be marked");
    }

    /// The pure merge — the wallet auto-chain's shape: all 10 inputs real,
    /// output 0 the merged total back to self, output 1 a zero-value self
    /// change note. Ten spends, TWO appends — the gas headline of the arity.
    function testTransfer10x2MergeAccepts() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10x2_merge");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2_merge");
        uint[68] memory pub = _pub68(".transfer10x2_merge");
        uint256 rootAfter = vm.parseJsonUint(j, ".transfer10x2_merge.rootAfter");

        pool.transfer10x2(a, b, c, pub, _kemCt(".transfer10x2_merge"));

        assertEq(pool.nextLeafIndex(), 12, "seed 10 + 2 outputs => nextLeafIndex 12");
        assertEq(pool.root(), rootAfter, "merge root != oracle");
        for (uint256 i = 0; i < N; i++) {
            assertTrue(pool.nullifierUsed(pub[P_NF + i]), "the merge must spend all ten inputs");
        }
    }

    /// A proof against a root this pool never held reverts UnknownRoot before
    /// the Groth16 verify — the arity-(10,2) path takes the same any-historical-
    /// root guard as every other spend, and an unseeded pool knows no roots.
    function testTransfer10x2UnknownRootReverts() public {
        BongtuPool pool = _pool(true); // deliberately NOT seeded
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2");
        uint[68] memory pub = _pub68(".transfer10x2");

        vm.expectRevert(abi.encodeWithSelector(BongtuPool.UnknownRoot.selector, pub[P_ROOT]));
        pool.transfer10x2(a, b, c, pub, _kemCt(".transfer10x2"));
    }

    /// Replaying an accepted transfer10x2 reverts on the first nullifier: the
    /// membership root is still known, so the proof re-verifies and the spend
    /// set is what stops it.
    function testTransfer10x2ReplayReverts() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10x2");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2");
        uint[68] memory pub = _pub68(".transfer10x2");
        bytes memory kemCt = _kemCt(".transfer10x2");

        pool.transfer10x2(a, b, c, pub, kemCt);
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, pub[P_NF]));
        pool.transfer10x2(a, b, c, pub, kemCt);
    }

    /// Flipping one public signal fails the Groth16 verify (the root is left
    /// alone so the known-root guard still passes and the failure isolates).
    function testTransfer10x2TamperedPublicSignalReverts() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10x2");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2");
        uint[68] memory pub = _pub68(".transfer10x2");
        pub[P_OC] = pub[P_OC] ^ 1;

        vm.expectRevert(BongtuPool.InvalidProof.selector);
        pool.transfer10x2(a, b, c, pub, _kemCt(".transfer10x2"));
    }

    /// §6b v2 on this path: the stored arbiter key is injected at pub[66..67],
    /// so a proof encrypted to a different key cannot verify. Control =
    /// testTransfer10x2Accepts (same proof, un-rotated key).
    function testTransfer10x2WrongAuthorityKeyReverts() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10x2");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2");
        uint[68] memory pub = _pub68(".transfer10x2");

        pool.rotateArbiter([uint256(0x1234), uint256(0x5678)], bytes32(uint256(0x9abc)));

        vm.expectRevert(BongtuPool.InvalidProof.selector);
        pool.transfer10x2(a, b, c, pub, _kemCt(".transfer10x2"));
    }

    // ================= IN-TX DOUBLE SPEND (contract-only) ====================

    /// Same defense, same vector as transfer10: `ZetoTransferSmall` never
    /// constrained the ten nullifiers to be DISTINCT, so the contract's
    /// sequential `_spendNullifier` loop over every input slot is the entire
    /// in-tx double-spend defense — the second occurrence hits an
    /// already-marked nullifier and reverts.
    ///
    /// Driven with an always-accept stub verifier on purpose: a real proof for
    /// this vector is exactly what the circuit does NOT forbid, so the test must
    /// hand the contract the vector directly rather than assume one cannot exist.
    function testInTxDoubleSpendReverts() public {
        BongtuPool pool = _pool(false);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();

        uint256 dup = uint256(0xDEADBEEF);
        uint[68] memory pub;
        pub[P_ROOT] = pool.root(); // the empty-tree root is a known root
        pub[P_NF] = dup; // slot 0
        pub[P_NF + 3] = dup; // ...and again at slot 3
        for (uint256 i = 0; i < 2; i++) pub[P_OC + i] = 1000 + i;

        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, dup));
        pool.transfer10x2(a, b, c, pub, dummyKemCt());
    }

    /// Control for the test above: the SAME shape with ten DISTINCT nullifiers
    /// goes through and marks every one of them, so the revert above is
    /// attributable to the duplicate and not to the ten-slot loop as such.
    function testTenDistinctNullifiersAllSpend() public {
        BongtuPool pool = _pool(false);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();

        uint[68] memory pub;
        pub[P_ROOT] = pool.root();
        for (uint256 i = 0; i < N; i++) pub[P_NF + i] = 0xC0FFEE + i;
        for (uint256 i = 0; i < 2; i++) pub[P_OC + i] = 2000 + i;
        pool.transfer10x2(a, b, c, pub, dummyKemCt());

        for (uint256 i = 0; i < N; i++) {
            assertTrue(pool.nullifierUsed(0xC0FFEE + i), "every distinct nullifier must be marked");
        }
        assertEq(pool.nextLeafIndex(), 2, "exactly two outputs appended");
    }

    /// The self-burn guard reaches BOTH output slots (an unused output slot is
    /// a real value-0 note, so its commitment is nonzero — a zero here is
    /// always a malformed/forged vector).
    function testZeroOutputCommitmentInEitherSlotReverts() public {
        BongtuPool pool = _pool(false);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();

        uint[68] memory pub;
        pub[P_ROOT] = pool.root();
        pub[P_OC] = 3000;
        pub[P_OC + 1] = 0; // the SECOND slot, so a first-slot-only guard fails here

        vm.expectRevert(BongtuPool.ZeroOutputCommitment.selector);
        pool.transfer10x2(a, b, c, pub, dummyKemCt());
    }

    // ================= ciphertext length enforcement =========================

    /// transfer10x2's receiver ciphertexts (8 elements) and authority envelope
    /// (31) ride inside the fixed `uint[68]` public vector — the verifier binds
    /// them, so there is no free-calldata length rule to break, unlike
    /// `disburseWithCiphertexts`. The one free ciphertext argument is the
    /// ML-KEM-768 encapsulation, and this path enforces its FIPS 203 wire size
    /// exactly like every other op, before the verifier is ever called.
    function testTransfer10x2WrongKemCiphertextLengthReverts() public {
        BongtuPool pool = _pool(false);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[68] memory pub;
        pub[P_ROOT] = pool.root();
        for (uint256 i = 0; i < 2; i++) pub[P_OC + i] = 4000 + i;

        vm.expectRevert(abi.encodeWithSelector(BongtuPool.WrongKemCiphertextLength.selector, 1087, 1088));
        pool.transfer10x2(a, b, c, pub, new bytes(1087));

        vm.expectRevert(abi.encodeWithSelector(BongtuPool.WrongKemCiphertextLength.selector, 1089, 1088));
        pool.transfer10x2(a, b, c, pub, new bytes(1089));
    }

    /// The in-vector ciphertext runs are exactly what the envelope codec
    /// computes for (10,2) (packages/core/src/crypto/envelope.ts: 2x4 receiver
    /// elements, and authorityCiphertextLen of transfer10x2 == 31 — 30
    /// plaintext fields, the one arity whose sponge pads by zero) — pinned here
    /// so a layout change cannot pass by only moving the event.
    function testCiphertextRunsMatchTheArity10x2Layout() public pure {
        assertEq(P_AUTHORITY_CT - P_RECEIVER_CT, 4 * 2, "receiver run must be 2 x 4 elements");
        assertEq(P_KEM_BINDING - P_AUTHORITY_CT, 31, "authority envelope must be 31 elements");
    }

    // ============ the event the indexer ingests ==============================

    event Transferred10x2(
        uint256 indexed epoch,
        uint256[10] nullifiers,
        uint256[2] outputCommitments,
        uint256[2] ecdhPublicKey,
        uint256[8] encryptedValuesForReceivers,
        uint256[31] encryptedValuesForAuthority,
        uint256 encryptionNonce,
        uint256 root,
        uint256 kemBinding,
        bytes kemCiphertext
    );

    /// Full-data expectEmit on the real fixture: everything the indexer needs to
    /// correlate leaves, mark spends, and open the authority envelope must come
    /// off the log alone (the arbiter reads logs, not calldata).
    function testTransferred10x2EventCarriesEverythingIngestNeeds() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10x2");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2");
        uint[68] memory pub = _pub68(".transfer10x2");
        bytes memory kemCt = _kemCt(".transfer10x2");
        assertEq(pub[P_KEM_BINDING], vm.parseJsonUint(j, ".transfer10x2.kemBinding"), "pub[41] != fixture kemBinding");

        uint256[10] memory nfs;
        for (uint256 i = 0; i < N; i++) nfs[i] = pub[P_NF + i];
        uint256[8] memory rct;
        for (uint256 i = 0; i < 8; i++) rct[i] = pub[P_RECEIVER_CT + i];
        uint256[31] memory cta;
        for (uint256 i = 0; i < 31; i++) cta[i] = pub[P_AUTHORITY_CT + i];

        vm.expectEmit(true, false, false, true, address(pool));
        emit Transferred10x2(
            0,
            nfs,
            [pub[P_OC], pub[P_OC + 1]],
            [pub[0], pub[1]],
            rct,
            cta,
            pub[P_NONCE],
            vm.parseJsonUint(j, ".transfer10x2.rootAfter"),
            pub[P_KEM_BINDING],
            kemCt
        );
        pool.transfer10x2(a, b, c, pub, kemCt);
    }

    // ======================= initialize wiring ==============================

    /// `initialize` refuses a zero transfer10x2 verifier. Without this the pool
    /// would come up advertising {transfer10x2} and revert on every call to it —
    /// a call into address(0) — with no way back short of an upgrade.
    function testInitializeRejectsZeroTransfer10x2Verifier() public {
        token = new MockERC20();
        Base.InitArgs memory p = Base.InitArgs({
            poseidon: poseidon,
            dv: IDepositVerifier(address(new StubDepositVerifier())),
            wv: IWithdrawVerifier(address(new StubWithdrawVerifier())),
            dsv: IDisburseVerifier(address(new StubDisburseVerifier())),
            tv: ITransferVerifier(address(new StubTransferVerifier())),
            tv10: ITransfer10Verifier(address(new StubTransfer10Verifier())),
            tv10x2: ITransfer10x2Verifier(address(0)),
            token: IERC20(address(token)),
            batchSize: B,
            arbiterKey: arbiterKey,
            kemPkHash: DUMMY_KEM_PK_HASH
        });
        BongtuPool impl = new BongtuPool();
        vm.expectRevert(BongtuPool.ZeroVerifier.selector);
        deployPoolOn(impl, p);
    }

    // ======================= gas (GasReport pattern) =========================

    /// Clean gasleft() delta around the merge — the ten-note consolidation that
    /// motivated the arity. Compare with the live transfer10 consolidation
    /// (11.59M measured): ten spends but TWO appends instead of ten.
    function testGasTransfer10x2Merge() public {
        BongtuPool pool = _pool(true);
        _seed(pool, ".transfer10x2_merge");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2_merge");
        uint[68] memory pub = _pub68(".transfer10x2_merge");
        bytes memory kemCt = _kemCt(".transfer10x2_merge");
        uint256 g = gasleft();
        pool.transfer10x2(a, b, c, pub, kemCt);
        emit log_named_uint("gas transfer10x2 (10-in/2-out merge, +KEM ct)", g - gasleft());
    }
}
