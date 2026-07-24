// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

// Matches the circomlibjs poseidonContract(2) generated ABI:
//   function poseidon(uint256[2]) pure returns (uint256)
// Deployed from creation bytecode (test/fixtures/poseidon2.hex); this is
// Poseidon-v1, byte-identical to the circuits' and the SDK's hash.
interface IPoseidon2 {
    function poseidon(uint256[2] calldata input) external pure returns (uint256);
}
