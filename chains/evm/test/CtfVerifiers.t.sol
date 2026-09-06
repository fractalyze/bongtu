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
    StubDisburseVerifier,
    StubTransferVerifier
} from "./mocks/StubVerifiers.sol";
import {TransferCtfVerifier} from "../src/verifiers/TransferCtfVerifier.sol";
import {Transfer10CtfVerifier} from "../src/verifiers/Transfer10CtfVerifier.sol";
import {Transfer10x2CtfVerifier} from "../src/verifiers/Transfer10x2CtfVerifier.sol";
import {DisburseCtfVerifier} from "../src/verifiers/DisburseCtfVerifier.sol";
import {DisburseCtf256Verifier} from "../src/verifiers/DisburseCtf256Verifier.sol";

/// @notice The ct-free enterprise family: real committed proofs accept, and
///         ct-freeness is PROOF-ENFORCED, not conventional.
///
/// The variants keep the parents' exact public layouts (the pool's literal
/// indices and the verifier ABIs are unchanged); the receiver-ct slots are
/// constrained to zero in-circuit. Three properties are pinned here:
///
///  1. every committed ctf fixture proof verifies against its ctf verifier
///     (and the ctf transfer family's receiver-ct publics are all zero);
///  2. the SAME proof with a nonzero receiver-ct slot is REJECTED — the zero
///     constraint is in the proving system, so no ct-carrying publish can ever
///     verify on a ct-free pool;
///  3. the PARENT's committed proof (real ciphertexts, identical layout and
///     witness inputs) is REJECTED by the ctf verifier — the variant is a
///     different constraint system, not a recompile.
///
/// Pool-path coverage (unchanged contract, ctf verifier wired) rides the same
/// realproofs entries: transfer at B=16 and disburse at B=16; the production
/// B=256 disburse lives in DisburseCtf256.t.sol.
contract CtfVerifiersTest is Base {
    IPoseidon2 poseidon;
    string j;
    uint256[2] arbiterKey;

    function setUp() public {
        poseidon = deployPoseidon();
        j = vm.readFile("test/fixtures/realproofs.json");
        uint256[] memory k = vm.parseJsonUintArray(j, ".arbiterKey");
        arbiterKey = [k[0], k[1]];
    }

    // --- JSON helpers (RealProof.t.sol pattern) ------------------------------
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

    function _kemCt(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, string.concat(key, ".kemCiphertext"));
    }

    function _pub37(string memory key) internal view returns (uint[37] memory pub) {
        uint256[] memory p = _pub(key);
        for (uint256 i = 0; i < 37; i++) pub[i] = p[i];
    }

    function _pub68(string memory key) internal view returns (uint[68] memory pub) {
        uint256[] memory p = _pub(key);
        for (uint256 i = 0; i < 68; i++) pub[i] = p[i];
    }

    function _pub141(string memory key) internal view returns (uint[141] memory pub) {
        uint256[] memory p = _pub(key);
        for (uint256 i = 0; i < 141; i++) pub[i] = p[i];
    }

    function _pub11(string memory key) internal view returns (uint[11] memory pub) {
        uint256[] memory p = _pub(key);
        for (uint256 i = 0; i < 11; i++) pub[i] = p[i];
    }

    // Receiver-ct publics start at index 2 in every transfer-family layout
    // (after ecdhPublicKey[2]); 4 elements per output.
    function _assertCtPublicsZero(uint256[] memory p, uint256 nOutputs) internal pure {
        for (uint256 i = 0; i < 4 * nOutputs; i++) {
            require(p[2 + i] == 0, "receiver-ct public not zero");
        }
    }

    // ===================== (1) committed proofs accept ======================

    function testTransferCtfProofAcceptsAndCtsAreZero() public {
        TransferCtfVerifier v = new TransferCtfVerifier();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transferCtf");
        _assertCtPublicsZero(_pub(".transferCtf"), 2);
        assertTrue(v.verifyProof(a, b, c, _pub37(".transferCtf")), "transferCtf proof rejected");
    }

    function testTransfer10CtfProofAcceptsAndCtsAreZero() public {
        Transfer10CtfVerifier v = new Transfer10CtfVerifier();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10Ctf");
        _assertCtPublicsZero(_pub(".transfer10Ctf"), 10);
        assertTrue(v.verifyProof(a, b, c, _pub141(".transfer10Ctf")), "transfer10Ctf proof rejected");
    }

    function testTransfer10x2CtfProofAcceptsAndCtsAreZero() public {
        Transfer10x2CtfVerifier v = new Transfer10x2CtfVerifier();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2Ctf");
        _assertCtPublicsZero(_pub(".transfer10x2Ctf"), 2);
        assertTrue(v.verifyProof(a, b, c, _pub68(".transfer10x2Ctf")), "transfer10x2Ctf proof rejected");
    }

    function testDisburseCtfProofAccepts() public {
        DisburseCtfVerifier v = new DisburseCtfVerifier();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disburseCtf");
        assertTrue(v.verifyProof(a, b, c, _pub11(".disburseCtf")), "disburseCtf proof rejected");
    }

    function testDisburseCtf256ProofAccepts() public {
        DisburseCtf256Verifier v = new DisburseCtf256Verifier();
        string memory o = vm.readFile("test/fixtures/disburseCtf256.oracle.json");
        uint256[] memory av = vm.parseJsonUintArray(o, ".a");
        uint256[] memory b0 = vm.parseJsonUintArray(o, ".b[0]");
        uint256[] memory b1 = vm.parseJsonUintArray(o, ".b[1]");
        uint256[] memory cv = vm.parseJsonUintArray(o, ".c");
        uint256[] memory p = vm.parseJsonUintArray(o, ".pub");
        uint[11] memory pub;
        for (uint256 i = 0; i < 11; i++) pub[i] = p[i];
        assertTrue(
            v.verifyProof([av[0], av[1]], [[b0[0], b0[1]], [b1[0], b1[1]]], [cv[0], cv[1]], pub),
            "disburseCtf256 GPU proof rejected"
        );
    }

    // ============ (2) a nonzero receiver-ct slot fails verification =========

    function testTransferCtfNonzeroCtSlotRejects() public {
        TransferCtfVerifier v = new TransferCtfVerifier();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transferCtf");
        uint[37] memory pub = _pub37(".transferCtf");
        pub[2] = 1; // first receiver-ct element
        assertFalse(v.verifyProof(a, b, c, pub), "ct-carrying publics verified on the ct-free verifier");
    }

    function testTransfer10CtfNonzeroCtSlotRejects() public {
        Transfer10CtfVerifier v = new Transfer10CtfVerifier();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10Ctf");
        uint[141] memory pub = _pub141(".transfer10Ctf");
        pub[41] = 1; // last receiver-ct element (middle-of-run tamper is covered by transferCtf)
        assertFalse(v.verifyProof(a, b, c, pub), "ct-carrying publics verified on the ct-free verifier");
    }

    function testTransfer10x2CtfNonzeroCtSlotRejects() public {
        Transfer10x2CtfVerifier v = new Transfer10x2CtfVerifier();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer10x2Ctf");
        uint[68] memory pub = _pub68(".transfer10x2Ctf");
        pub[5] = 1;
        assertFalse(v.verifyProof(a, b, c, pub), "ct-carrying publics verified on the ct-free verifier");
    }

    // ========= (3) the parent's ct-carrying proof is a different system =====

    function testParentTransferProofRejectsOnCtfVerifier() public {
        TransferCtfVerifier v = new TransferCtfVerifier();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer");
        // Same layout, same witness inputs, REAL receiver ciphertexts: must fail
        // against the ctf verifying key (and would fail the zero constraint even
        // re-proven — the constraint system differs).
        assertFalse(v.verifyProof(a, b, c, _pub37(".transfer")), "parent ct-carrying proof verified on ctf verifier");
    }

    // ================= pool path with the ctf verifiers wired ===============

    function _seed(BongtuPool pool, string memory key) internal {
        uint256[] memory seed = vm.parseJsonUintArray(j, string.concat(key, ".seedLeaves"));
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[19] memory pub;
        pub[14] = seed[0];
        pub[15] = seed[1];
        pool.deposit(a, b, c, pub, dummyKemCt());
    }

    function _ctfPool() internal returns (BongtuPool pool) {
        MockERC20 token = new MockERC20();
        pool = deployPool(
            poseidon,
            IDepositVerifier(address(new StubDepositVerifier())),
            IWithdrawVerifier(address(new StubWithdrawVerifier())),
            IDisburseVerifier(address(new DisburseCtfVerifier())),
            ITransferVerifier(address(new TransferCtfVerifier())),
            IERC20(address(token)),
            arbiterKey
        );
        token.mint(address(pool), 1_000_000);
        token.mint(address(this), 1_000_000);
        token.approve(address(pool), type(uint256).max);
    }

    /// The unchanged BongtuPool settles a ct-free transfer exactly like a
    /// ct-carrying one: same entrypoint, same indices, the ct publics just
    /// happen to be zeros (layout preservation, the R3/R4 falsifiable check).
    function testTransferCtfAcceptsOnPool() public {
        BongtuPool pool = _ctfPool();
        _seed(pool, ".transferCtf");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transferCtf");
        uint256[] memory p = _pub(".transferCtf");
        uint256 rootAfter = vm.parseJsonUint(j, ".transferCtf.rootAfter");

        pool.transfer(a, b, c, _pub37(".transferCtf"), _kemCt(".transferCtf"));

        assertEq(pool.nextLeafIndex(), 4, "transferCtf appends 2 outputs (seed 2 + 2)");
        assertEq(pool.root(), rootAfter, "transferCtf root != oracle");
        assertTrue(pool.nullifierUsed(p[27]) && pool.nullifierUsed(p[28]), "transferCtf nullifiers not marked");
    }

    /// Ct-free disburse at the B=16 dev arity: the zeroed receiver run rides
    /// inside disclosureHash, so the length check and the event path are the
    /// parent's, byte for byte.
    function testDisburseCtfAcceptsOnPool() public {
        BongtuPool pool = _ctfPool();
        _seed(pool, ".disburseCtf");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disburseCtf");
        uint256[] memory p = _pub(".disburseCtf");
        uint256 rootAfter = vm.parseJsonUint(j, ".disburseCtf.rootAfter");

        pool.disburseWithCiphertexts(
            a, b, c, _pub11(".disburseCtf"), new uint256[](pool.disburseCiphertextLen()), _kemCt(".disburseCtf")
        );

        assertEq(pool.root(), rootAfter, "disburseCtf root != oracle");
        assertEq(pool.nextLeafIndex(), 32, "disburseCtf pad(2->16)+attach(16) => 32");
        assertTrue(pool.nullifierUsed(p[5]), "disburseCtf nullifier not marked");
    }
}
