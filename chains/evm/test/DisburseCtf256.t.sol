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
import {DisburseCtf256Verifier} from "../src/verifiers/DisburseCtf256Verifier.sol";

/// @notice The REAL GPU ct-free 256 disburse, on-chain, at production arity
///         (B=256), under the Karst per-tx gas cap — the ct-free sibling of
///         Disburse256.t.sol.
///
/// The proof in `disburseCtf256.oracle.json` is a real rabbitsnark-GPU proof of
/// `disburseCtf256.circom` (ZetoCtf(1,256,32)), generated from the PARENT's
/// committed witness input — the variants take the identical input signal set,
/// so every public except disclosureHash equals the parent fixture's (same
/// roots, same nullifier, same arbiter key) and the oracle roots are shared
/// with the parent oracle. The on-chain publish still carries the full
/// 2054-element blob (the receiver run is zeros — content is unchecked
/// on-chain, disclosureHash binds it off-chain), so the pool's length check,
/// event, and gas envelope are exercised unchanged.
contract DisburseCtf256Test is Base {
    uint256 constant KARST_CAP = 16_777_216; // EIP-7825 per-tx gas cap (2^24)
    uint256 constant B256 = 256;

    IPoseidon2 poseidon;
    string j;

    uint256 inputCommitment;
    uint256 seedRoot; // == pub[6]
    uint256 oracleRoot; // ImtTree(32,256) after appendLeaf + attachSubtree
    uint256[2] arbiterKey;

    function setUp() public {
        poseidon = deployPoseidon();
        j = vm.readFile("test/fixtures/disburseCtf256.oracle.json");
        inputCommitment = vm.parseJsonUint(j, ".inputCommitment");
        seedRoot = vm.parseJsonUint(j, ".seedRoot");
        oracleRoot = vm.parseJsonUint(j, ".oracleRoot");
        uint256[] memory k = vm.parseJsonUintArray(j, ".arbiterKey");
        arbiterKey = [k[0], k[1]];
    }

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

    function _freshPool256() internal returns (BongtuPool pool) {
        MockERC20 token = new MockERC20();
        pool = deployPoolWithBatch(
            poseidon,
            IDepositVerifier(address(new StubDepositVerifier())),
            IWithdrawVerifier(address(new StubWithdrawVerifier())),
            IDisburseVerifier(address(new DisburseCtf256Verifier())),
            ITransferVerifier(address(new StubTransferVerifier())),
            IERC20(address(token)),
            B256,
            arbiterKey,
            DUMMY_KEM_PK_HASH
        );
    }

    /// Seed the input note as leaf 0 (Disburse256.t.sol pattern).
    function _seedInputAtLeaf0(BongtuPool pool) internal {
        uint[27] memory w;
        w[19] = pool.root();
        w[22] = inputCommitment;
        w[26] = uint160(address(this));
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        pool.withdraw(a, b, c, w, dummyKemCt(), bytes32(0), 0);
        assertEq(pool.root(), seedRoot, "seed: pool.root() != pub[6] (membership root)");
        assertTrue(pool.isKnownRoot(seedRoot), "seed: membership root not in history");
        assertEq(pool.nextLeafIndex(), 1, "seed: input note must be the sole leaf 0");
    }

    function _ctBlob(BongtuPool pool) internal view returns (uint256[] memory) {
        return new uint256[](pool.disburseCiphertextLen());
    }

    /// The ctf proof shares the parent's roots and arbiter binding (same witness
    /// input by construction); only disclosureHash differs.
    function testPublicsSharedWithParentExceptDisclosureHash() public view {
        uint[11] memory pub = _pub();
        string memory pj = vm.readFile("test/fixtures/disburse256.oracle.json");
        uint256[] memory pp = vm.parseJsonUintArray(pj, ".pub");
        assertEq(pub[3], pp[3], "subtreeRoot differs from parent");
        assertEq(pub[5], pp[5], "nullifier differs from parent");
        assertEq(pub[6], pp[6], "membership root differs from parent");
        assertEq(pub[9], pp[9], "arbiter key x differs from parent");
        assertEq(pub[10], pp[10], "arbiter key y differs from parent");
        assertTrue(pub[2] != pp[2], "disclosureHash must differ (zeroed receiver run)");
        assertEq(pub[7], 1, "enabled public signal must be 1");
        assertEq(pub[9], arbiterKey[0], "pub[9] != arbiter key x");
        assertEq(pub[10], arbiterKey[1], "pub[10] != arbiter key y");
    }

    function testDisburseCtfAcceptsAttachesUnderCap() public {
        BongtuPool pool = _freshPool256();
        _seedInputAtLeaf0(pool);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc();
        uint[11] memory pub = _pub();
        uint256[] memory ct = _ctBlob(pool); // 2054 elements, receiver run zeros
        bytes memory kemCt = dummyKemCt();

        uint256 g = gasleft();
        pool.disburseWithCiphertexts(a, b, c, pub, ct, kemCt);
        uint256 disburseGas = g - gasleft();

        assertEq(pool.root(), oracleRoot, "root != ImtTree(32,256) oracle after attach");
        assertEq(pool.nextLeafIndex(), 2 * B256, "attach: nextLeafIndex != 512");
        assertTrue(pool.nullifierUsed(pub[5]), "disburse nullifier not marked");

        emit log_named_uint("disburseCtf256 gas (verify+attach+zeroed-receiver blob)", disburseGas);
        emit log_named_uint("per-recipient gas (gas / 256)", disburseGas / B256);
        assertLt(disburseGas, KARST_CAP, "disburse gas >= EIP-7825 Karst cap");

        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, pub[5]));
        pool.disburseWithCiphertexts(a, b, c, pub, ct, kemCt);
    }

    function testTamperedPublicSignalReverts() public {
        BongtuPool pool = _freshPool256();
        _seedInputAtLeaf0(pool);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc();
        uint[11] memory pub = _pub();
        pub[3] = pub[3] ^ 1;

        uint256[] memory ct = _ctBlob(pool);
        bytes memory kemCt = dummyKemCt();
        vm.expectRevert(BongtuPool.InvalidProof.selector);
        pool.disburseWithCiphertexts(a, b, c, pub, ct, kemCt);
    }

    /// The parent's GPU proof (real receiver ciphertexts, identical layout and
    /// witness input) must NOT verify against the ctf verifier: the ct-free
    /// family is a different constraint system, so a ct-carrying disburse can
    /// never settle on a pool wired with the ctf verifier.
    function testParentProofRejectsOnCtfPool() public {
        BongtuPool pool = _freshPool256();
        _seedInputAtLeaf0(pool); // same input note — the parent proof's root is known

        string memory pj = vm.readFile("test/fixtures/disburse256.oracle.json");
        uint256[] memory av = vm.parseJsonUintArray(pj, ".a");
        uint256[] memory b0 = vm.parseJsonUintArray(pj, ".b[0]");
        uint256[] memory b1 = vm.parseJsonUintArray(pj, ".b[1]");
        uint256[] memory cv = vm.parseJsonUintArray(pj, ".c");
        uint256[] memory pp = vm.parseJsonUintArray(pj, ".pub");
        uint[11] memory pub;
        for (uint256 i = 0; i < 11; i++) pub[i] = pp[i];

        uint256[] memory ct = _ctBlob(pool);
        bytes memory kemCt = dummyKemCt();
        vm.expectRevert(BongtuPool.InvalidProof.selector);
        pool.disburseWithCiphertexts(
            [av[0], av[1]], [[b0[0], b0[1]], [b1[0], b1[1]]], [cv[0], cv[1]], pub, ct, kemCt
        );
    }

    function testWrongCiphertextLengthReverts() public {
        BongtuPool pool = _freshPool256();
        _seedInputAtLeaf0(pool);

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc();
        uint[11] memory pub = _pub();
        uint256[] memory short = new uint256[](4 * B256);
        assertEq(pool.disburseCiphertextLen(), 2054, "enforced length must be 4*B + 1030 = 2054");

        bytes memory kemCt = dummyKemCt();
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.WrongCiphertextLength.selector, 4 * B256, 2054));
        pool.disburseWithCiphertexts(a, b, c, pub, short, kemCt);
    }
}
