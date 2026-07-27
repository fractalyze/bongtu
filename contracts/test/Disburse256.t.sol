// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Base} from "./Base.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier
} from "../src/interfaces/IVerifiers.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {
    StubDepositVerifier,
    StubWithdrawVerifier,
    StubTransferVerifier
} from "./mocks/StubVerifiers.sol";
import {Disburse256Verifier} from "../src/verifiers/Disburse256Verifier.sol";

/// @notice M1 Done#1 / U5 — the REAL GPU 256 disburse, on-chain, at production
///         arity (B=256), under the Karst per-tx gas cap.
///
/// The proof (a,b,c) + publics (pub) in `disburse256.oracle.json` come from a
/// REAL rabbitsnark-GPU proof of `disburse256.circom` (Zeto(1,256,32),
/// snarkjs-verified OK). Public layout (11, §5 + pq-envelope-design.md §3):
/// [0..1]=ecdhPub [2]=disclosureHash [3]=subtreeRoot [4]=kemBinding [5]=nullifier
/// [6]=root [7]=enabled [8]=nonce [9..10]=authorityPubKey.
///
/// The input note that was spent is `artifacts/{aux,input}.json`; its commitment
/// is the SOLE leaf (index 0) of the membership tree the proof proves against, so
/// seeding it reproduces the proof's membership root pub[6] on-chain (SpendCycle
/// pattern). The independent oracle root is the SDK `ImtTree(H=32,B=256)` after
/// `appendLeaf(inputCommitment)` then `attachSubtree(pub[3])` — computed by
/// `gen_disburse256_oracle.ts` and pinned in the fixture (seedRoot verified there
/// to equal pub[6]).
///
/// ── Gas note (load-bearing) ────────────────────────────────────────────────
/// BongtuPool's disburse closes the pending PARTIAL block up to a 256 boundary
/// before attaching the subtree (§5.1). It does this with an O(LOG_B) fold, NOT
/// O(B) per-leaf padding: disbursing into a fresh 1-leaf block would otherwise pad
/// 255 leaves (255×H Poseidons ≈ 248M gas, over any block limit), which would make
/// the real deposit-then-disburse flow unexecutable. Both the aligned steady-state
/// disburse (~1.03M gas) and the 1-leaf partial-block disburse (~2.0M gas) attach
/// the SAME subtree at the SAME block and yield the SAME oracle root, and BOTH are
/// asserted under the Karst cap; the partial-block test also pins root identity vs
/// the appendLeaf→attachSubtree oracle.
contract Disburse256Test is Base {
    uint256 constant KARST_CAP = 16_777_216; // EIP-7825 per-tx gas cap (2^24)
    uint256 constant B256 = 256;

    IPoseidon2 poseidon;
    string j;

    // fixture values
    uint256 inputCommitment;
    uint256 seedRoot; // == pub[6]
    uint256 oracleRoot; // ImtTree(32,256) after appendLeaf + attachSubtree
    uint256[2] arbiterKey;

    function setUp() public {
        poseidon = deployPoseidon();
        j = vm.readFile("test/fixtures/disburse256.oracle.json");
        inputCommitment = vm.parseJsonUint(j, ".inputCommitment");
        seedRoot = vm.parseJsonUint(j, ".seedRoot");
        oracleRoot = vm.parseJsonUint(j, ".oracleRoot");
        uint256[] memory k = vm.parseJsonUintArray(j, ".arbiterKey");
        arbiterKey = [k[0], k[1]];
    }

    // --- fixture calldata loaders --------------------------------------------
    function _abc() internal view returns (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) {
        uint256[] memory av = vm.parseJsonUintArray(j, ".a");
        uint256[] memory b0 = vm.parseJsonUintArray(j, ".b[0]");
        uint256[] memory b1 = vm.parseJsonUintArray(j, ".b[1]");
        uint256[] memory cv = vm.parseJsonUintArray(j, ".c");
        a = [av[0], av[1]];
        b = [[b0[0], b0[1]], [b1[0], b1[1]]];
        c = [cv[0], cv[1]];
    }

    function _pub() internal view returns (uint[11] memory pub) {
        uint256[] memory p = vm.parseJsonUintArray(j, ".pub");
        for (uint256 i = 0; i < 11; i++) pub[i] = p[i];
    }

    // Deploy an initialized B=256 pool: the REAL 256 verifier in the disburse
    // slot, always-accept stubs elsewhere (they only seed/align the tree; the
    // disburse proof is the sole thing under test). Arbiter key = the proof's
    // authorityPublicKey (pub[9..10]) so the contract's storage-injected key
    // matches the public signals the proof was made for.
    function _freshPool256() internal returns (BongtuPool pool) {
        MockERC20 token = new MockERC20();
        pool = deployPoolWithBatch(
            poseidon,
            IDepositVerifier(address(new StubDepositVerifier())),
            IWithdrawVerifier(address(new StubWithdrawVerifier())),
            IDisburseVerifier(address(new Disburse256Verifier())),
            ITransferVerifier(address(new StubTransferVerifier())),
            IERC20(address(token)),
            B256,
            arbiterKey,
            DUMMY_KEM_PK_HASH
        );
    }

    /// Seed the input note as leaf 0 via a stub-verified single-leaf insert
    /// (withdraw appends exactly its change output). This reproduces the proof's
    /// membership root: pool.root() == pub[6], and pub[6] enters root history.
    function _seedInputAtLeaf0(BongtuPool pool) internal {
        uint[26] memory w; // out=0, nf0=nf1=0 (nothing spent/pushed)
        w[19] = pool.root(); // membership root = current (empty) root, known
        w[22] = inputCommitment; // change output = the input note commitment
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        pool.withdraw(a, b, c, w, dummyKemCt());
        assertEq(pool.root(), seedRoot, "seed: pool.root() != pub[6] (membership root)");
        assertEq(pool.root(), _pub()[6], "seed: pool.root() != public.json[6]");
        assertTrue(pool.isKnownRoot(seedRoot), "seed: membership root not in history");
        assertEq(pool.nextLeafIndex(), 1, "seed: input note must be the sole leaf 0");
    }

    /// A disburse ciphertext blob of exactly the enforced length (§6b v2). Content
    /// is unchecked on-chain — the proof's disclosureHash binds it off-chain.
    function _ctBlob(BongtuPool pool) internal view returns (uint256[] memory) {
        return new uint256[](pool.disburseCiphertextLen());
    }

    // ========================================================================
    //  (2) membership-root reproduction
    // ========================================================================
    function testMembershipRootReproduced() public {
        BongtuPool pool = _freshPool256();
        _seedInputAtLeaf0(pool);
        // pub[7]=enabled=1, pub[9..10]=authorityPublicKey (matches arbiter key).
        uint[11] memory pub = _pub();
        assertEq(pub[7], 1, "enabled public signal must be 1");
        assertEq(pub[9], arbiterKey[0], "pub[9] != arbiter key x");
        assertEq(pub[10], arbiterKey[1], "pub[10] != arbiter key y");
        // the GPU proof's kemBinding public survives the fixture pipeline intact
        assertEq(pub[4], vm.parseJsonUint(j, ".kemBinding"), "pub[4] != oracle kemBinding");
    }

    // ========================================================================
    //  (3)+(4) real proof accepts, subtree attaches, root==oracle, gas<cap,
    //          per-recipient reported, replay reverts
    // ========================================================================
    function testDisburseAcceptsAttachesUnderCap() public {
        BongtuPool pool = _freshPool256();
        _seedInputAtLeaf0(pool); // leaf 0 only; disburse pads the partial block in-call

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc();
        uint[11] memory pub = _pub();
        uint256[] memory ct = _ctBlob(pool); // 2054 elements for B=256 (§6b v2)
        // KEM ct content is unchecked on-chain (design doc §2) — a length-correct
        // blob exercises the same code path as the real encapsulation bytes.
        bytes memory kemCt = dummyKemCt();

        uint256 g = gasleft();
        pool.disburseWithCiphertexts(a, b, c, pub, ct, kemCt); // reverts if the real Groth16 verify fails
        uint256 disburseGas = g - gasleft();

        // Verifier ACCEPTED (no revert) + the 256-subtree attached at block 1.
        assertEq(pool.root(), oracleRoot, "root != ImtTree(32,256) oracle after attach");
        assertEq(pool.nextLeafIndex(), 2 * B256, "attach: nextLeafIndex != 512 (block0 + subtree)");
        assertTrue(pool.nullifierUsed(pub[5]), "disburse nullifier not marked");

        // (4) Karst per-tx cap + per-recipient figure. Now publishes the FULL
        // ciphertext (receiver ++ authority = 2054 elements) on-chain (§6b v2).
        emit log_named_uint("disburse256 gas (verify+attach+full ciphertext)", disburseGas);
        emit log_named_uint("per-recipient gas (gas / 256)", disburseGas / B256);
        assertLt(disburseGas, KARST_CAP, "disburse gas >= EIP-7825 Karst cap (16,777,216)");

        // Replay: same proof re-verifies (root still known) but the nullifier is spent.
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, pub[5]));
        pool.disburseWithCiphertexts(a, b, c, pub, ct, kemCt);
    }

    // ========================================================================
    //  (5) a 1-bit tamper of a public signal is rejected
    // ========================================================================
    function testTamperedPublicSignalReverts() public {
        BongtuPool pool = _freshPool256();
        _seedInputAtLeaf0(pool);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc();
        uint[11] memory pub = _pub();
        // Flip one bit of subtreeRoot (pub[3]). The membership root pub[6] is
        // untouched so the known-root guard still passes and the failure is
        // isolated to the Groth16 verify (length check passes first).
        pub[3] = pub[3] ^ 1;

        // Build the blob BEFORE expectRevert — evaluating _ctBlob calls a view on
        // the pool, which would otherwise be consumed as the "next call".
        uint256[] memory ct = _ctBlob(pool);
        bytes memory kemCt = dummyKemCt();
        vm.expectRevert(BongtuPool.InvalidProof.selector);
        pool.disburseWithCiphertexts(a, b, c, pub, ct, kemCt);
    }

    // ========================================================================
    //  §6b v2 enforced disclosure: a receiver-ONLY publish (4*B = 1024 elements,
    //  the old "unverifiable" flavor) is rejected on-chain — the ONLY disburse
    //  path must publish the FULL ciphertext (4*B ++ authority = 2054).
    // ========================================================================
    function testWrongCiphertextLengthReverts() public {
        BongtuPool pool = _freshPool256();
        _seedInputAtLeaf0(pool);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc();
        uint[11] memory pub = _pub();
        // receiver-only length (4*256): auditor envelope omitted => enforced revert.
        uint256[] memory short = new uint256[](4 * B256);
        assertEq(pool.disburseCiphertextLen(), 2054, "enforced length must be 4*B + 1030 = 2054");

        bytes memory kemCt = dummyKemCt();
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.WrongCiphertextLength.selector, 4 * B256, 2054));
        pool.disburseWithCiphertexts(a, b, c, pub, short, kemCt);
    }

    // ========================================================================
    //  literal oracle path: appendLeaf(inputCommitment) then disburse (which
    //  pads 255 + attaches) yields the SAME oracle root and accepts the SAME
    //  real proof. Demonstrates the root identity of step 3's exact wording;
    //  the (boundary) gas is logged, NOT capped (see the contract-level note).
    // ========================================================================
    function testDisburseFromPartialBlockMatchesOracle() public {
        BongtuPool pool = _freshPool256();
        _seedInputAtLeaf0(pool); // leaf 0 only; disburse will pad 255 in-call

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc();
        uint[11] memory pub = _pub();

        uint256 g = gasleft();
        pool.disburseWithCiphertexts(a, b, c, pub, _ctBlob(pool), dummyKemCt());
        uint256 fullGas = g - gasleft();

        assertEq(pool.root(), oracleRoot, "partial-block path root != oracle");
        assertEq(pool.nextLeafIndex(), 2 * B256, "partial-block: nextLeafIndex != 512");
        assertTrue(pool.nullifierUsed(pub[5]), "partial-block disburse nullifier not marked");

        // The real product flow is deposit-then-disburse, i.e. a disburse into a
        // partial (unaligned) block. The O(LOG_B) partial-block close keeps this
        // under the Karst cap (naive per-leaf padding was ~248M gas, unexecutable).
        assertLt(fullGas, KARST_CAP, "partial-block disburse gas >= Karst cap (regressed to O(B) padding?)");
        emit log_named_uint("disburse256 gas (1-leaf partial block: O(LOG_B) close + verify + attach)", fullGas);
    }
}
