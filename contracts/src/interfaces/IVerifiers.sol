// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

// One interface per circuit: the Groth16 public-signal arity is circuit-specific
// (deposit 19, withdraw 26, disburse 11, transfer 37, transfer10 141, transfer10x2
// 68 — derived from the committed out/<name>.public.json + .sym), so each verifier
// has its own typed arity and a nPublic-changing circuit edit is BREAKING (SPEC §5.3).
// deposit/withdraw grew an in-circuit authority envelope (SPEC §6b v2); the PQ
// hybrid envelope (.dev/pq-envelope-design.md §3) then appended a `kemBinding`
// output to every circuit, shifting each arity by exactly +1 (18->19, 25->26,
// 10->11, 36->37).

interface IDepositVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[19] calldata pub)
        external
        view
        returns (bool);
}

interface IWithdrawVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[27] calldata pub)
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

// transfer10 (10-in / 10-out) is the SAME circuit template at arity 10, so its
// vector grows with the arity rather than the shape: 10 receiver ciphertexts
// (40 elements) and a 64-element authority envelope instead of 2 and 16, and 10
// each of nullifiers / enabled / outputCommitments instead of 2. Its own
// interface, not a widened ITransferVerifier: the 2-in path keeps its verifier
// and both must be callable from the same implementation.
interface ITransfer10Verifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[141] calldata pub)
        external
        view
        returns (bool);
}

// transfer10x2 (10-in / 2-out) keeps transfer10's input side but drops to 2
// outputs, so the vector shrinks to 68: 2 receiver ciphertexts (8 elements) and
// a 31-element authority envelope (30 plaintext fields — the one arity whose
// sponge pads by zero), with nullifiers/enabled still 10-wide.
interface ITransfer10x2Verifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[68] calldata pub)
        external
        view
        returns (bool);
}

// --- consumer (no-auditor) family (OPMOD §2) --------------------------------
// Same one-interface-per-circuit rule at the consumer arities (depositPriv 16,
// transferPriv 20, transfer10x2Priv 36, withdrawPriv 16, disbursePriv 8). The
// consumer circuits strip every authority signal (no cipherTextAuthority, no
// kemBinding, no authorityPublicKey) and add receiver ciphertexts + viewTags,
// so no consumer arity equals its enterprise twin's. Like the enterprise
// disburse pair, the 1x16 dev twin and the 1x256 production disburse verifier
// share one interface: the batch size changes the subtree, not the vector.

interface IDepositPrivVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[16] calldata pub)
        external
        view
        returns (bool);
}

interface ITransferPrivVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[20] calldata pub)
        external
        view
        returns (bool);
}

interface ITransfer10x2PrivVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[36] calldata pub)
        external
        view
        returns (bool);
}

interface IWithdrawPrivVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[16] calldata pub)
        external
        view
        returns (bool);
}

interface IDisbursePrivVerifier {
    function verifyProof(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[8] calldata pub)
        external
        view
        returns (bool);
}
