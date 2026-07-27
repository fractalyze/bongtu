// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

// One interface per circuit: the Groth16 public-signal arity is circuit-specific
// (deposit 19, withdraw 26, disburse 11, transfer 37 — derived from the committed
// out/<name>.public.json + .sym), so each verifier has its own typed arity and a
// nPublic-changing circuit edit is BREAKING (SPEC §5.3). deposit/withdraw grew an
// in-circuit authority envelope (SPEC §6b v2); the PQ hybrid envelope
// (.dev/pq-envelope-design.md §3) then appended a `kemBinding` output to every
// circuit, shifting each arity by exactly +1 (18->19, 25->26, 10->11, 36->37).

interface IDepositVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[19] calldata pub)
        external
        view
        returns (bool);
}

interface IWithdrawVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[26] calldata pub)
        external
        view
        returns (bool);
}

interface IDisburseVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[11] calldata pub)
        external
        view
        returns (bool);
}

interface ITransferVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[37] calldata pub)
        external
        view
        returns (bool);
}
