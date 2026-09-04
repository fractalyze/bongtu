// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Base} from "./Base.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {
    StubDepositVerifier,
    StubWithdrawVerifier,
    StubDisburseVerifier,
    StubTransferVerifier
} from "./mocks/StubVerifiers.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier,
    IDepositPrivVerifier,
    ITransferPrivVerifier,
    ITransfer10x2PrivVerifier,
    IWithdrawPrivVerifier,
    IDisbursePrivVerifier
} from "../src/interfaces/IVerifiers.sol";
import {ConsumerOpModule} from "../src/modules/ConsumerOpModule.sol";
import {DepositPrivModule} from "../src/modules/DepositPrivModule.sol";
import {TransferPrivModule} from "../src/modules/TransferPrivModule.sol";
import {Transfer10x2PrivModule} from "../src/modules/Transfer10x2PrivModule.sol";
import {WithdrawPrivModule} from "../src/modules/WithdrawPrivModule.sol";
import {ConsumerDisburseModule} from "../src/modules/ConsumerDisburseModule.sol";
import {DepositPrivVerifier} from "../src/verifiers/DepositPrivVerifier.sol";
import {TransferPrivVerifier} from "../src/verifiers/TransferPrivVerifier.sol";
import {Transfer10x2PrivVerifier} from "../src/verifiers/Transfer10x2PrivVerifier.sol";
import {WithdrawPrivVerifier} from "../src/verifiers/WithdrawPrivVerifier.sol";
import {DisbursePrivVerifier} from "../src/verifiers/DisbursePrivVerifier.sol";
import {DisbursePriv256Verifier} from "../src/verifiers/DisbursePriv256Verifier.sol";

/// @notice The five consumer (no-auditor) op modules against the REAL Groth16
///         verifiers and the committed consumer_realproofs.json fixtures:
///         per-module accept paths (root == oracle, nullifiers marked, escrow
///         moved), the disburse chunk lifecycle (OPMOD §5 Option A-chunked),
///         the §4.4 canonical-form binding, cross-family note interop, and
///         the module-level negative checks.
///
/// The pool's SIX enterprise verifier slots are always-accept stubs here: a
/// stub enterprise `deposit`/`withdraw` is how tests seed the tree with the
/// fixtures' input commitments (the RealProof.t.sol pattern), and doubling as
/// the enterprise half of the interop tests. Consumer proof validity is the
/// thing under test, and the real enterprise verifiers have their own suites.
contract ConsumerModulesTest is Base {
    uint256 constant KARST_CAP = 16_777_216; // EIP-7825 per-tx gas cap (2^24)
    uint256 constant B256 = 256;
    uint256 constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    MockERC20 token;
    IPoseidon2 poseidon;
    string j;

    event WithdrawAnnouncement(uint256 recipient, bytes32 stealthEphemeralPub, uint8 stealthViewTag);
    event DisburseKemChunkAccepted(uint256 indexed batchId, uint256 chunkIndex);

    function setUp() public {
        poseidon = deployPoseidon();
        j = vm.readFile("test/fixtures/consumer_realproofs.json");
    }

    // --- pool + module wiring -------------------------------------------------

    function _freshPool() internal returns (BongtuPool pool) {
        return _freshPoolWithBatch(B);
    }

    function _freshPoolWithBatch(uint256 batchSize) internal returns (BongtuPool pool) {
        token = new MockERC20();
        pool = deployPoolWithBatch(
            poseidon,
            IDepositVerifier(address(new StubDepositVerifier())),
            IWithdrawVerifier(address(new StubWithdrawVerifier())),
            IDisburseVerifier(address(new StubDisburseVerifier())),
            ITransferVerifier(address(new StubTransferVerifier())),
            IERC20(address(token)),
            batchSize,
            [uint256(101), uint256(202)],
            DUMMY_KEM_PK_HASH
        );
        token.mint(address(pool), 1_000_000);
        token.mint(address(this), 1_000_000);
        token.approve(address(pool), type(uint256).max);
    }

    // --- fixture loaders ------------------------------------------------------

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

    function _pub(string memory key) internal view returns (uint256[] memory) {
        return vm.parseJsonUintArray(j, string.concat(key, ".pub"));
    }

    function _kemCts(string memory key) internal view returns (bytes[] memory) {
        return vm.parseJsonBytesArray(j, string.concat(key, ".kemCiphertexts"));
    }

    function _rootAfter(string memory key) internal view returns (uint256) {
        return vm.parseJsonUint(j, string.concat(key, ".rootAfter"));
    }

    // Seed the tree with the fixture's input commitments through the ENTERPRISE
    // deposit entrypoint (stub-verified, 2 leaves per call) — the same genuine
    // tree writes + Appended feed a live enterprise mint produces.
    function _seed(BongtuPool pool, string memory key) internal {
        uint256[] memory seed = vm.parseJsonUintArray(j, string.concat(key, ".seedLeaves"));
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        for (uint256 i = 0; i < seed.length; i += 2) {
            uint[19] memory pub;
            pub[14] = seed[i];
            pub[15] = seed[i + 1];
            pool.deposit(a, b, c, pub, dummyKemCt());
        }
    }

    // Seed exactly ONE leaf via a stub enterprise withdraw (its change output
    // is the only append) — the Disburse256.t.sol single-leaf pattern.
    function _seedSingle(BongtuPool pool, uint256 leaf) internal {
        uint[27] memory w;
        w[19] = pool.root();
        w[22] = leaf;
        w[26] = uint160(address(this));
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        pool.withdraw(a, b, c, w, dummyKemCt(), bytes32(0), 0);
    }

    function _pub16(string memory key) internal view returns (uint[16] memory pub) {
        uint256[] memory p = _pub(key);
        for (uint256 i = 0; i < 16; i++) pub[i] = p[i];
    }

    function _pub20(string memory key) internal view returns (uint[20] memory pub) {
        uint256[] memory p = _pub(key);
        for (uint256 i = 0; i < 20; i++) pub[i] = p[i];
    }

    function _pub36(string memory key) internal view returns (uint[36] memory pub) {
        uint256[] memory p = _pub(key);
        for (uint256 i = 0; i < 36; i++) pub[i] = p[i];
    }

    function _pub8(string memory key) internal view returns (uint[8] memory pub) {
        uint256[] memory p = _pub(key);
        for (uint256 i = 0; i < 8; i++) pub[i] = p[i];
    }

    // ========================= depositPriv ===================================

    function testDepositPrivAccepts() public {
        BongtuPool pool = _freshPool();
        DepositPrivModule mod =
            new DepositPrivModule(pool, IDepositPrivVerifier(address(new DepositPrivVerifier())));
        pool.registerModule(address(mod));

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".depositPriv");
        uint[16] memory pub = _pub16(".depositPriv");
        bytes[] memory kemCts = _kemCts(".depositPriv");
        uint256 balBefore = token.balanceOf(address(pool));

        uint256 g = gasleft();
        mod.depositPriv(a, b, c, pub, kemCts);
        emit log_named_uint("depositPriv gas (module + applyOpWithPull)", g - gasleft());

        assertEq(pool.nextLeafIndex(), 2, "depositPriv appends 2 leaves");
        assertEq(pool.root(), _rootAfter(".depositPriv"), "depositPriv root != oracle");
        assertEq(token.balanceOf(address(pool)) - balBefore, pub[0], "depositPriv did not pull `out` tokens");
    }

    // ============== transferPriv + cross-family interop (D1) =================

    /// CROSS-FAMILY INTEROP, direction 1: notes minted by the ENTERPRISE
    /// deposit entrypoint are spent through the CONSUMER transferPriv module
    /// with a REAL Groth16 proof — the untyped-note invariant on-chain. (The
    /// mint side is stub-verified: the committed real enterprise deposit mints
    /// different commitments than this proof's inputs, and no enterprise
    /// fixture proof targets them — see testConsumerNoteSpentThroughEnterpriseOp
    /// for the evidence in the other direction.)
    function testTransferPrivSpendsEnterpriseMintedNotes() public {
        BongtuPool pool = _freshPool();
        TransferPrivModule mod =
            new TransferPrivModule(pool, ITransferPrivVerifier(address(new TransferPrivVerifier())));
        pool.registerModule(address(mod));
        _seed(pool, ".transferPriv"); // the enterprise-created notes

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transferPriv");
        uint[20] memory pub = _pub20(".transferPriv");
        bytes[] memory kemCts = _kemCts(".transferPriv"); // hoisted: json parsing must not pollute the gas window

        uint256 g = gasleft();
        mod.transferPriv(a, b, c, pub, kemCts);
        emit log_named_uint("transferPriv gas (module + applyOp)", g - gasleft());

        assertEq(pool.nextLeafIndex(), 4, "transferPriv appends 2 outputs (seed 2 + 2)");
        assertEq(pool.root(), _rootAfter(".transferPriv"), "transferPriv root != oracle");
        assertTrue(pool.nullifierUsed(pub[12]) && pool.nullifierUsed(pub[13]), "transferPriv nullifiers not marked");
    }

    /// CROSS-FAMILY INTEROP, direction 2: notes minted by the CONSUMER
    /// depositPriv module with a REAL proof are spent through the ENTERPRISE
    /// transfer entrypoint. The enterprise side is stub-verified OF NECESSITY:
    /// the committed consumer depositPriv mints commitments
    /// {pub[13], pub[14]} == the real enterprise deposit's outputs, but no
    /// committed ENTERPRISE spend proof was made against that 2-leaf tree
    /// (realproofs.json: transfer's membership root covers different seed
    /// leaves, withdraw's likewise), so a real-proof enterprise spend of these
    /// notes is not constructible from fixture material. What IS on-chain-real
    /// here: the consumer mint's root enters the shared history and the
    /// enterprise entrypoint spends against it — one tree, one nullifier set.
    function testConsumerNoteSpentThroughEnterpriseOp() public {
        BongtuPool pool = _freshPool();
        DepositPrivModule mod =
            new DepositPrivModule(pool, IDepositPrivVerifier(address(new DepositPrivVerifier())));
        pool.registerModule(address(mod));

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".depositPriv");
        mod.depositPriv(a, b, c, _pub16(".depositPriv"), _kemCts(".depositPriv")); // consumer-created notes

        uint256 nf = uint256(0xC0FFEE);
        (uint[2] memory da, uint[2][2] memory db, uint[2] memory dc) = dummyABC();
        uint[37] memory tpub;
        tpub[27] = nf;
        tpub[29] = pool.root(); // known ONLY because the consumer mint created it
        tpub[32] = 333;
        tpub[33] = 444;
        pool.transfer(da, db, dc, tpub, dummyKemCt());

        assertEq(pool.nextLeafIndex(), 4, "enterprise transfer appends 2 outputs after the consumer mint");
        assertTrue(pool.nullifierUsed(nf), "enterprise spend against the consumer-minted root not marked");
    }

    // ========================= transfer10x2Priv ==============================

    function testTransfer10x2PrivAccepts() public {
        BongtuPool pool = _freshPool();
        Transfer10x2PrivModule mod = new Transfer10x2PrivModule(
            pool, ITransfer10x2PrivVerifier(address(new Transfer10x2PrivVerifier()))
        );
        pool.registerModule(address(mod));
        _seed(pool, ".transfer10x2Priv"); // 4 real input notes, 2 stub deposits

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2Priv");
        uint[36] memory pub = _pub36(".transfer10x2Priv");
        bytes[] memory kemCts = _kemCts(".transfer10x2Priv"); // hoisted: json parsing must not pollute the gas window

        uint256 g = gasleft();
        mod.transfer10x2Priv(a, b, c, pub, kemCts);
        emit log_named_uint("transfer10x2Priv gas (module + applyOp)", g - gasleft());

        assertEq(pool.nextLeafIndex(), 6, "transfer10x2Priv appends 2 outputs (seed 4 + 2)");
        assertEq(pool.root(), _rootAfter(".transfer10x2Priv"), "transfer10x2Priv root != oracle");
        for (uint256 i = 0; i < 10; i++) {
            if (pub[12 + i] != 0) {
                assertTrue(pool.nullifierUsed(pub[12 + i]), "real 10x2 nullifier not marked");
            }
        }
        assertFalse(pool.nullifierUsed(0), "zero nullifier must never be marked");
    }

    // ========================= withdrawPriv ==================================

    function testWithdrawPrivAccepts() public {
        BongtuPool pool = _freshPool();
        WithdrawPrivModule mod =
            new WithdrawPrivModule(pool, IWithdrawPrivVerifier(address(new WithdrawPrivVerifier())));
        pool.registerModule(address(mod));
        _seed(pool, ".withdrawPriv");

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".withdrawPriv");
        uint[16] memory pub = _pub16(".withdrawPriv");
        address recipient = address(uint160(pub[15]));
        uint256 balBefore = token.balanceOf(recipient);
        uint256 mineBefore = token.balanceOf(address(this));

        bytes[] memory kemCts = _kemCts(".withdrawPriv"); // hoisted: json parsing must not pollute the gas window
        vm.expectEmit(false, false, false, true, address(mod));
        emit WithdrawAnnouncement(pub[15], bytes32(uint256(1)), 7);
        uint256 g = gasleft();
        mod.withdrawPriv(a, b, c, pub, kemCts, bytes32(uint256(1)), 7);
        emit log_named_uint("withdrawPriv gas (module + applyOpWithPush)", g - gasleft());

        assertEq(pool.nextLeafIndex(), 3, "withdrawPriv appends 1 change leaf (seed 2 + 1)");
        assertEq(pool.root(), _rootAfter(".withdrawPriv"), "withdrawPriv root != oracle");
        assertTrue(pool.nullifierUsed(pub[8]) && pool.nullifierUsed(pub[9]), "withdrawPriv nullifiers not marked");
        assertEq(token.balanceOf(recipient) - balBefore, pub[0], "withdrawPriv did not push `out` to the recipient");
        assertEq(token.balanceOf(address(this)), mineBefore, "the submitter must receive nothing");
    }

    // =================== disbursePriv (1x16 dev twin) ========================

    function _newDisburseModule16(BongtuPool pool) internal returns (ConsumerDisburseModule mod) {
        // chunkArity = B => K = 1: the dev twin's whole kem-ct set is one chunk
        mod = new ConsumerDisburseModule(pool, IDisbursePrivVerifier(address(new DisbursePrivVerifier())), 16);
        pool.registerModule(address(mod));
    }

    /// @dev Own frame (stack relief): the fixture-driven batch call alone.
    function _callDisbursePriv16(ConsumerDisburseModule mod, bytes32[] memory hashes) internal {
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disbursePriv");
        uint256[] memory disclosure = vm.parseJsonUintArray(j, ".disbursePriv.disclosure");
        uint[8] memory pub = _pub8(".disbursePriv"); // hoisted: json parsing must not pollute the gas window
        uint256 g = gasleft();
        mod.disbursePriv256(a, b, c, pub, disclosure, hashes);
        emit log_named_uint("disbursePriv (1x16) gas (module + applyOp attach)", g - gasleft());
    }

    function testDisbursePrivAcceptsAndChunkCompletes() public {
        BongtuPool pool = _freshPool(); // B = 16
        ConsumerDisburseModule mod = _newDisburseModule16(pool);
        _seed(pool, ".disbursePriv");

        // chunk 0 = the 16 kem cts concatenated in leaf order, keccak-committed
        bytes memory chunk0 = _concat(_kemCts(".disbursePriv"));
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = keccak256(chunk0);
        _callDisbursePriv16(mod, hashes);

        assertEq(pool.root(), _rootAfter(".disbursePriv"), "disbursePriv root != oracle");
        assertEq(pool.nextLeafIndex(), 32, "disbursePriv pad(2->16)+attach(16) => 32");
        assertTrue(pool.nullifierUsed(_pub(".disbursePriv")[4]), "disbursePriv nullifier not marked");

        uint256 batchId = 16; // the attach's startLeafIndex
        assertEq(mod.kemChunkHashes(batchId).length, 1, "batch must store K=1 chunk hash");
        vm.expectEmit(true, false, false, true, address(mod));
        emit DisburseKemChunkAccepted(batchId, 0);
        mod.submitDisburseKemChunk(batchId, 0, chunk0);
        assertTrue(mod.kemChunkAccepted(batchId, 0), "chunk 0 not marked accepted");
    }

    function _concat(bytes[] memory parts) internal pure returns (bytes memory out) {
        for (uint256 i = 0; i < parts.length; i++) {
            out = bytes.concat(out, parts[i]);
        }
    }

    // =================== disbursePriv256 (production) ========================

    function _pool256WithDisburseModule() internal returns (BongtuPool pool, ConsumerDisburseModule mod) {
        pool = _freshPoolWithBatch(B256);
        mod = new ConsumerDisburseModule(pool, IDisbursePrivVerifier(address(new DisbursePriv256Verifier())), 86);
        pool.registerModule(address(mod));
    }

    function _disburse256(BongtuPool pool, ConsumerDisburseModule mod) internal returns (uint256 batchId) {
        uint256[] memory seed = vm.parseJsonUintArray(j, ".disbursePriv256.seedLeaves");
        _seedSingle(pool, seed[0]);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disbursePriv256");
        uint[8] memory pub = _pub8(".disbursePriv256");
        assertEq(pool.root(), pub[5], "seed: pool.root() != membership root pub[5]");
        uint256[] memory disclosure = vm.parseJsonUintArray(j, ".disbursePriv256.disclosure");
        bytes32[] memory hashes = vm.parseJsonBytes32Array(j, ".disbursePriv256.kemChunkHashes");

        uint256 g = gasleft();
        mod.disbursePriv256(a, b, c, pub, disclosure, hashes);
        uint256 gas = g - gasleft();
        emit log_named_uint("disbursePriv256 batch-tx gas (module + verify + attach + disclosure)", gas);
        emit log_named_uint("disbursePriv256 batch-tx gas / 256 recipients", gas / B256);
        assertLt(gas, KARST_CAP, "disbursePriv256 batch tx over the EIP-7825 Karst cap");

        assertEq(pool.root(), _rootAfter(".disbursePriv256"), "disbursePriv256 root != oracle");
        assertEq(pool.nextLeafIndex(), 2 * B256, "attach: nextLeafIndex != 512");
        assertTrue(pool.nullifierUsed(pub[4]), "disbursePriv256 nullifier not marked");
        batchId = B256; // block 0 closed at 256, subtree attached there
        assertEq(mod.kemChunkHashes(batchId).length, 3, "batch must store K=3 chunk hashes");
    }

    function testDisbursePriv256AcceptsUnderCap() public {
        (BongtuPool pool, ConsumerDisburseModule mod) = _pool256WithDisburseModule();
        _disburse256(pool, mod);
    }

    /// The OPMOD §5 chunk lifecycle, all five named error checks + accept:
    /// UnknownBatch, BadChunkIndex, ChunkAlreadyAccepted,
    /// WrongKemCiphertextLength, ChunkHashMismatch.
    function testDisbursePriv256ChunkLifecycle() public {
        (BongtuPool pool, ConsumerDisburseModule mod) = _pool256WithDisburseModule();
        uint256 batchId = _disburse256(pool, mod);

        bytes memory chunk0 = vm.parseJsonBytes(j, ".disbursePriv256.kemChunks[0]");
        bytes memory chunk1 = vm.parseJsonBytes(j, ".disbursePriv256.kemChunks[1]");
        bytes memory chunk2 = vm.parseJsonBytes(j, ".disbursePriv256.kemChunks[2]");
        assertEq(chunk0.length, 86 * 1088, "chunk 0 arity");
        assertEq(chunk2.length, 84 * 1088, "last chunk carries the remainder (84)");

        // unknown batch: nothing stored at a never-minted id
        vm.expectRevert(abi.encodeWithSelector(ConsumerDisburseModule.UnknownBatch.selector, uint256(999)));
        mod.submitDisburseKemChunk(999, 0, chunk0);

        // chunk index out of range (K = 3)
        vm.expectRevert(abi.encodeWithSelector(ConsumerDisburseModule.BadChunkIndex.selector, uint256(3)));
        mod.submitDisburseKemChunk(batchId, 3, chunk0);

        // wrong byte length (a truncated chunk)
        bytes memory shortChunk = new bytes(86 * 1088 - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                ConsumerOpModule.WrongKemCiphertextLength.selector, uint256(1), 86 * 1088 - 1, 86 * 1088
            )
        );
        mod.submitDisburseKemChunk(batchId, 1, shortChunk);

        // right length, wrong bytes: keccak mismatch vs the committed hash
        bytes memory tampered = vm.parseJsonBytes(j, ".disbursePriv256.kemChunks[1]");
        tampered[0] = bytes1(uint8(tampered[0]) ^ 0xff);
        vm.expectRevert(
            abi.encodeWithSelector(ConsumerDisburseModule.ChunkHashMismatch.selector, batchId, uint256(1))
        );
        mod.submitDisburseKemChunk(batchId, 1, tampered);

        // wrong-index cross-submit: chunk 1's bytes at index 0 hash-mismatch
        vm.expectRevert(
            abi.encodeWithSelector(ConsumerDisburseModule.ChunkHashMismatch.selector, batchId, uint256(0))
        );
        mod.submitDisburseKemChunk(batchId, 0, chunk1);

        // accept all three, in arbitrary order (permissionless completion)
        vm.prank(address(0xB0B)); // anyone holding the bytes can complete
        mod.submitDisburseKemChunk(batchId, 1, chunk1);
        mod.submitDisburseKemChunk(batchId, 0, chunk0);
        mod.submitDisburseKemChunk(batchId, 2, chunk2);
        assertTrue(
            mod.kemChunkAccepted(batchId, 0) && mod.kemChunkAccepted(batchId, 1) && mod.kemChunkAccepted(batchId, 2),
            "all chunks accepted"
        );

        // double-submit
        vm.expectRevert(
            abi.encodeWithSelector(ConsumerDisburseModule.ChunkAlreadyAccepted.selector, batchId, uint256(0))
        );
        mod.submitDisburseKemChunk(batchId, 0, chunk0);
    }

    // =================== §4.4 canonical-form binding =========================

    /// A disclosure element x + p folds to the same disclosureHash after
    /// poseidon's silent mod-p reduction, so ONLY the module's >= p rejection
    /// upgrades the fold binding to byte equality — a recorded review
    /// obligation. The tamper must revert BEFORE the verifier runs.
    function testNonCanonicalDisclosureElementReverts() public {
        BongtuPool pool = _freshPool();
        ConsumerDisburseModule mod = _newDisburseModule16(pool);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disbursePriv");
        uint[8] memory pub = _pub8(".disbursePriv");
        uint256[] memory disclosure = vm.parseJsonUintArray(j, ".disbursePriv.disclosure");
        disclosure[3] = disclosure[3] + SNARK_SCALAR_FIELD; // mod-p alias of the proven element
        bytes32[] memory hashes = new bytes32[](1);
        hashes[0] = bytes32(uint256(1));

        vm.expectRevert(
            abi.encodeWithSelector(
                ConsumerDisburseModule.NonCanonicalDisclosureElement.selector, uint256(3), disclosure[3]
            )
        );
        mod.disbursePriv256(a, b, c, pub, disclosure, hashes);
    }

    // =================== module-level negative checks ========================

    function testDisclosureWrongLengthReverts() public {
        BongtuPool pool = _freshPool();
        ConsumerDisburseModule mod = _newDisburseModule16(pool);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disbursePriv");
        uint256[] memory shortDisclosure = new uint256[](95);
        bytes32[] memory hashes = new bytes32[](1);
        vm.expectRevert(
            abi.encodeWithSelector(ConsumerDisburseModule.WrongCiphertextLength.selector, uint256(95), uint256(96))
        );
        mod.disbursePriv256(a, b, c, _pub8(".disbursePriv"), shortDisclosure, hashes);
    }

    function testDisburseZeroNullifierReverts() public {
        BongtuPool pool = _freshPool();
        ConsumerDisburseModule mod = _newDisburseModule16(pool);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disbursePriv");
        uint[8] memory pub = _pub8(".disbursePriv");
        pub[4] = 0; // the S2.1 obligation: revert BEFORE the enabled=1 injection
        uint256[] memory disclosure = vm.parseJsonUintArray(j, ".disbursePriv.disclosure");
        bytes32[] memory hashes = new bytes32[](1);
        vm.expectRevert(ConsumerDisburseModule.ZeroNullifier.selector);
        mod.disbursePriv256(a, b, c, pub, disclosure, hashes);
    }

    function testWrongKemChunkHashCountReverts() public {
        BongtuPool pool = _freshPool();
        ConsumerDisburseModule mod = _newDisburseModule16(pool);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disbursePriv");
        uint256[] memory disclosure = vm.parseJsonUintArray(j, ".disbursePriv.disclosure");
        bytes32[] memory hashes = new bytes32[](2); // K = 1 at chunkArity 16
        vm.expectRevert(
            abi.encodeWithSelector(ConsumerDisburseModule.WrongKemChunkHashCount.selector, uint256(2), uint256(1))
        );
        mod.disbursePriv256(a, b, c, _pub8(".disbursePriv"), disclosure, hashes);
    }

    function testUnregisteredConsumerModuleReverts() public {
        BongtuPool pool = _freshPool();
        DepositPrivModule mod =
            new DepositPrivModule(pool, IDepositPrivVerifier(address(new DepositPrivVerifier())));
        // NOT registered: the core gate is the module family's whole access story
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".depositPriv");
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.ModuleNotRegistered.selector, address(mod)));
        mod.depositPriv(a, b, c, _pub16(".depositPriv"), _kemCts(".depositPriv"));
    }

    function testTamperedConsumerProofReverts() public {
        BongtuPool pool = _freshPool();
        TransferPrivModule mod =
            new TransferPrivModule(pool, ITransferPrivVerifier(address(new TransferPrivVerifier())));
        pool.registerModule(address(mod));
        _seed(pool, ".transferPriv");

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transferPriv");
        uint[20] memory pub = _pub20(".transferPriv");
        pub[17] = pub[17] ^ 1; // flip one bit of an output commitment public

        bytes[] memory kemCts = _kemCts(".transferPriv");
        vm.expectRevert(ConsumerOpModule.InvalidProof.selector);
        mod.transferPriv(a, b, c, pub, kemCts);
    }

    function testConsumerReplayReverts() public {
        BongtuPool pool = _freshPool();
        TransferPrivModule mod =
            new TransferPrivModule(pool, ITransferPrivVerifier(address(new TransferPrivVerifier())));
        pool.registerModule(address(mod));
        _seed(pool, ".transferPriv");

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transferPriv");
        uint[20] memory pub = _pub20(".transferPriv");
        bytes[] memory kemCts = _kemCts(".transferPriv");
        mod.transferPriv(a, b, c, pub, kemCts);

        // the membership root is still known, so the proof re-verifies; the
        // replay dies in the core on nullifier reuse
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, pub[12]));
        mod.transferPriv(a, b, c, pub, kemCts);
    }

    function testConsumerUnknownRootReverts() public {
        BongtuPool pool = _freshPool(); // deliberately NOT seeded
        TransferPrivModule mod =
            new TransferPrivModule(pool, ITransferPrivVerifier(address(new TransferPrivVerifier())));
        pool.registerModule(address(mod));

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transferPriv");
        uint[20] memory pub = _pub20(".transferPriv");
        bytes[] memory kemCts = _kemCts(".transferPriv");
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.UnknownRoot.selector, pub[14]));
        mod.transferPriv(a, b, c, pub, kemCts);
    }

    function testWrongKemCiphertextCountReverts() public {
        BongtuPool pool = _freshPool();
        DepositPrivModule mod =
            new DepositPrivModule(pool, IDepositPrivVerifier(address(new DepositPrivVerifier())));
        pool.registerModule(address(mod));

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".depositPriv");
        bytes[] memory one = new bytes[](1);
        one[0] = new bytes(1088);
        vm.expectRevert(
            abi.encodeWithSelector(ConsumerOpModule.WrongKemCiphertextCount.selector, uint256(1), uint256(2))
        );
        mod.depositPriv(a, b, c, _pub16(".depositPriv"), one);
    }

    function testWrongKemCiphertextEntryLengthReverts() public {
        BongtuPool pool = _freshPool();
        DepositPrivModule mod =
            new DepositPrivModule(pool, IDepositPrivVerifier(address(new DepositPrivVerifier())));
        pool.registerModule(address(mod));

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".depositPriv");
        bytes[] memory cts = new bytes[](2);
        cts[0] = new bytes(1088);
        cts[1] = new bytes(1087);
        vm.expectRevert(
            abi.encodeWithSelector(
                ConsumerOpModule.WrongKemCiphertextLength.selector, uint256(1), uint256(1087), uint256(1088)
            )
        );
        mod.depositPriv(a, b, c, _pub16(".depositPriv"), cts);
    }
}
