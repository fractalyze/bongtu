// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";

/// @notice Load-bearing Poseidon-v1 parity gate: deploy the circomlibjs
///         Poseidon(2) from creation bytecode and assert its on-chain output
///         equals the circomlib reference. If this passes, the on-chain hash
///         matches the circuits + the SDK ImtTree by construction (same
///         constants), which every differential/root claim depends on.
contract PoseidonTest is Test {
    IPoseidon2 poseidon;

    function setUp() public {
        bytes memory code = vm.parseBytes(vm.readFile("test/fixtures/poseidon2.hex"));
        address p;
        assembly {
            p := create(0, add(code, 0x20), mload(code))
        }
        require(p != address(0), "poseidon deploy failed");
        poseidon = IPoseidon2(p);
    }

    function testPoseidonMatchesCircomlib() public {
        uint256 expected = vm.parseUint(vm.readFile("test/fixtures/poseidon_ref.txt"));
        uint256 got = poseidon.poseidon([uint256(1), uint256(2)]);
        assertEq(got, expected, "on-chain Poseidon(2) != circomlib reference");
        assertEq(
            got,
            7853200120776062878684798364095072458815029376092732009249414926327459813530,
            "Poseidon-v1 parity constant drifted"
        );
    }
}
