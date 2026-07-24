// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

// One interface per circuit: the Groth16 public-signal arity is circuit-specific
// (deposit 18, withdraw 25, disburse 10, transfer 36 — derived from the committed
// out/<name>.public.json + .sym), so each verifier has its own typed arity and a
// nPublic-changing circuit edit is BREAKING (SPEC §5.3). deposit/withdraw grew an
// in-circuit authority envelope (SPEC §6b v2): deposit 3->18, withdraw 7->25.

interface IDepositVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[18] calldata pub)
        external
        view
        returns (bool);
}

interface IWithdrawVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[25] calldata pub)
        external
        view
        returns (bool);
}

interface IDisburseVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[10] calldata pub)
        external
        view
        returns (bool);
}

interface ITransferVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[36] calldata pub)
        external
        view
        returns (bool);
}
