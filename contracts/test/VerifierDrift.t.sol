// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";

/// @notice The missing half of the verifier drift gate.
///
/// `circuits/build/prove_all.sh` writes the snarkjs Groth16 exports into
/// `circuits/verifiers/`, and CI gates THAT directory with
/// `git diff --exit-code circuits/verifiers` after a rebuild — so a circuit
/// change that is not recommitted fails. But `contracts/src/verifiers/*.sol` is
/// a HAND copy of those files with one edit (`contract Groth16Verifier` →
/// `contract <Name>Verifier`), and nothing gated the copy: a regenerated
/// circuits/verifiers with a stale contracts/src/verifiers passed every gate,
/// while the pool would keep verifying against the OLD verifying key and reject
/// every freshly-proven op.
///
/// This test closes it in the `forge test` job (no circuit build needed — both
/// sides are committed): for each pair, apply the one permitted substitution to
/// the generated file and require byte identity with the shipped one.
contract VerifierDriftTest is Test {
    /// The one edit allowed between a generated verifier and its shipped copy.
    string constant GENERATED_NAME = "contract Groth16Verifier {";

    function _assertRenameOnly(string memory circuitFile, string memory contractName) internal view {
        string memory generated = vm.readFile(string.concat("../circuits/verifiers/", circuitFile));
        string memory shipped = vm.readFile(string.concat("src/verifiers/", contractName, ".sol"));

        // Belt: if snarkjs ever stopped emitting this exact declaration the
        // substitution below would silently no-op, and the test would then be
        // asserting the wrong thing rather than failing.
        assertTrue(vm.contains(generated, GENERATED_NAME), string.concat(circuitFile, ": no 'contract Groth16Verifier {' to rename"));

        string memory renamed = vm.replace(generated, GENERATED_NAME, string.concat("contract ", contractName, " {"));
        assertEq(
            keccak256(bytes(renamed)),
            keccak256(bytes(shipped)),
            string.concat("src/verifiers/", contractName, ".sol is not ../circuits/verifiers/", circuitFile, " renamed - regenerate the copy")
        );
    }

    function testDepositVerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("deposit_verifier.sol", "DepositVerifier");
    }

    function testWithdrawVerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("withdraw_verifier.sol", "WithdrawVerifier");
    }

    function testDisburseVerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("disburse_verifier.sol", "DisburseVerifier");
    }

    function testDisburse256VerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("disburse256_verifier.sol", "Disburse256Verifier");
    }

    function testTransferVerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("transfer_verifier.sol", "TransferVerifier");
    }

    function testTransfer10VerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("transfer10_verifier.sol", "Transfer10Verifier");
    }

    function testTransfer10x2VerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("transfer10x2_verifier.sol", "Transfer10x2Verifier");
    }

    // --- consumer (no-auditor) family (OPMOD §2) — same rename-only rule ----

    function testDepositPrivVerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("depositPriv_verifier.sol", "DepositPrivVerifier");
    }

    function testTransferPrivVerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("transferPriv_verifier.sol", "TransferPrivVerifier");
    }

    function testTransfer10x2PrivVerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("transfer10x2Priv_verifier.sol", "Transfer10x2PrivVerifier");
    }

    function testWithdrawPrivVerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("withdrawPriv_verifier.sol", "WithdrawPrivVerifier");
    }

    function testDisbursePrivVerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("disbursePriv_verifier.sol", "DisbursePrivVerifier");
    }

    function testDisbursePriv256VerifierIsTheGeneratedOneRenamed() public view {
        _assertRenameOnly("disbursePriv256_verifier.sol", "DisbursePriv256Verifier");
    }
}
