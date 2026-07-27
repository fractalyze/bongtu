// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier,
    ITransfer10Verifier
} from "../../src/interfaces/IVerifiers.sol";

// Always-accept stubs: the differential test isolates the single-frontier IMT
// tree logic, whose root correctness is independent of proof validity.
contract StubDepositVerifier is IDepositVerifier {
    function verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[19] calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}

contract StubWithdrawVerifier is IWithdrawVerifier {
    function verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[26] calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}

contract StubDisburseVerifier is IDisburseVerifier {
    function verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[11] calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}

contract StubTransferVerifier is ITransferVerifier {
    function verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[37] calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}

contract StubTransfer10Verifier is ITransfer10Verifier {
    function verifyProof(uint[2] calldata, uint[2][2] calldata, uint[2] calldata, uint[141] calldata)
        external
        pure
        returns (bool)
    {
        return true;
    }
}
