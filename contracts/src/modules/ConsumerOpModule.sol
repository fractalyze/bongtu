// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {BongtuPool} from "../BongtuPool.sol";

/// @title ConsumerOpModule — shared base of the consumer (no-auditor) op
///        modules (OPMOD §1.1/§2).
///
/// A module is a plain (non-proxied) contract holding no funds and no
/// consensus state: it wires ONE verifier, owns ONE public-signal layout,
/// injects `enabled` from nullifiers before verify (the same rule the core
/// applies to the in-core ops), emits its family's event, and calls the
/// core's applyOp* for every state effect. A module bug is fixed by deploying
/// a replacement and swapping registration — never by touching core storage.
///
/// Deliberately latch-free (OPMOD §1.6): modules hold no state worth
/// guarding, and the core's single `_locked` latch is taken at applyOp*
/// entry, so all consensus writes and the token move happen inside it. The
/// verifier call a module makes before applyOp is `view`.
abstract contract ConsumerOpModule {
    /// @notice ML-KEM-768 ciphertext wire size (FIPS 203) — the only on-chain
    ///         check possible on a receiver kem ct (content can only break the
    ///         sender's own delivery, OPMOD §3.3).
    uint256 public constant KEM_CIPHERTEXT_LEN = 1088;

    /// @notice The core: escrow holder, tree/nullifier owner, applyOp* gate.
    ///         Users approve THIS address for pulls, never the module.
    BongtuPool public immutable pool;

    error ZeroPool();
    error ZeroVerifier();
    error InvalidProof();
    error WrongKemCiphertextCount(uint256 got, uint256 want);
    error WrongKemCiphertextLength(uint256 index, uint256 got, uint256 want);

    constructor(BongtuPool _pool) {
        if (address(_pool) == address(0)) revert ZeroPool();
        pool = _pool;
    }

    /// @dev OPMOD §3.4: one 1088-byte entry per output, in output order. The
    ///      count equals the circuit's output arity — a missing or extra ct
    ///      would desync the scanner's per-output slicing.
    function _checkKemCiphertexts(bytes[] calldata kemCiphertexts, uint256 want) internal pure {
        if (kemCiphertexts.length != want) revert WrongKemCiphertextCount(kemCiphertexts.length, want);
        for (uint256 i = 0; i < kemCiphertexts.length; i++) {
            if (kemCiphertexts[i].length != KEM_CIPHERTEXT_LEN) {
                revert WrongKemCiphertextLength(i, kemCiphertexts[i].length, KEM_CIPHERTEXT_LEN);
            }
        }
    }

    /// @dev OPMOD §1.3 #3: padding is a circuit-layout concern — the module
    ///      strips zero (padded) nullifier slots before crossing the applyOp
    ///      boundary, where a zero entry is a revert, not a skip.
    function _stripZeros(uint256[] memory raw) internal pure returns (uint256[] memory out) {
        uint256 n = 0;
        for (uint256 i = 0; i < raw.length; i++) {
            if (raw[i] != 0) n++;
        }
        out = new uint256[](n);
        uint256 k = 0;
        for (uint256 i = 0; i < raw.length; i++) {
            if (raw[i] != 0) {
                out[k] = raw[i];
                k++;
            }
        }
    }

    function _none() internal pure returns (uint256[] memory) {
        return new uint256[](0);
    }
}
