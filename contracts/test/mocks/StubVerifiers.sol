// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IDepositVerifier, IWithdrawVerifier, IDisburseVerifier, ITransferVerifier} from "../../src/interfaces/IVerifiers.sol";

// Always-accept stubs: the differential test isolates the single-frontier IMT
// tree logic, whose root correctness is independent of proof validity.
contract StubDepositVerifier is IDepositVerifier {
    function verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[18] calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}

contract StubWithdrawVerifier is IWithdrawVerifier {
    function verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[25] calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}

contract StubDisburseVerifier is IDisburseVerifier {
    function verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[10] calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}

contract StubTransferVerifier is ITransferVerifier {
    function verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[36] calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}
