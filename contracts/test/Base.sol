// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IDepositVerifier, IWithdrawVerifier, IDisburseVerifier, ITransferVerifier} from "../src/interfaces/IVerifiers.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

/// @dev Shared setup: deploy the circomlibjs Poseidon(2) from creation bytecode
///      (same pattern as the reusable PoC), a mock kKRW token, and the pool.
abstract contract Base is Test {
    uint256 constant B = 16; // M0 disburse batch size

    function deployPoseidon() internal returns (IPoseidon2) {
        bytes memory code = vm.parseBytes(vm.readFile("test/fixtures/poseidon2.hex"));
        address p;
        assembly {
            p := create(0, add(code, 0x20), mload(code))
        }
        require(p != address(0), "poseidon deploy failed");
        return IPoseidon2(p);
    }

    function deployPool(
        IPoseidon2 poseidon,
        IDepositVerifier dv,
        IWithdrawVerifier wv,
        IDisburseVerifier dsv,
        ITransferVerifier tv,
        IERC20 token
    ) internal returns (BongtuPool) {
        return new BongtuPool(poseidon, dv, wv, dsv, tv, token, B);
    }

    // dummy Groth16 args (ignored by stub verifiers)
    function dummyABC() internal pure returns (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) {
        a = [uint256(1), 2];
        b = [[uint256(3), 4], [uint256(5), 6]];
        c = [uint256(7), 8];
    }
}
