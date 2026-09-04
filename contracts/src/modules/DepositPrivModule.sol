// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {BongtuPool} from "../BongtuPool.sol";
import {IDepositPrivVerifier} from "../interfaces/IVerifiers.sol";
import {ConsumerOpModule} from "./ConsumerOpModule.sol";

/// @title DepositPrivModule — depositPriv (0-in / 2-out consumer mint), OPMOD §2.
///
/// publics (16): [0]=out [1..2]=ecdhPub [3..10]=cipherTexts[2][4]
///               [11..12]=viewTags [13..14]=outputCommitments [15]=nonce
///
/// No authority material and no injection: a 0-in mint has no `enabled` run,
/// and unlike the enterprise deposit no arbiter key rides in the vector. The
/// mint can pay a third party directly — the recipient discovers it by scan
/// (viewTag filter + hybrid receiver ct), so per-output kem cts ride along.
contract DepositPrivModule is ConsumerOpModule {
    IDepositPrivVerifier public immutable verifier;

    /// @notice OPMOD §3.4 — every ciphertext field is copied from publics the
    ///         verifier accepted; only `kemCiphertexts` is free calldata, with
    ///         the same "can only break discovery" property. No `epoch`:
    ///         consumer events carry no arbiter coupling.
    event DepositedPriv(
        uint256 firstLeafIndex,
        uint256 oc0,
        uint256 oc1,
        uint256 amount,
        uint256[2] ecdhPublicKey,
        uint256[4] ctReceiver0,
        uint256[4] ctReceiver1,
        uint256[2] viewTags,
        uint256 encryptionNonce,
        uint256 root,
        bytes[] kemCiphertexts
    );

    constructor(BongtuPool _pool, IDepositPrivVerifier _verifier) ConsumerOpModule(_pool) {
        if (address(_verifier) == address(0)) revert ZeroVerifier();
        verifier = _verifier;
    }

    /// @notice Verify, mint the two output notes, pull `out` (pub[0]) tokens
    ///         from the caller into the core. The pull is proof-bound via
    ///         pub[0] — the OPMOD §1.3 #6 module obligation — and users
    ///         approve the core, so `from` is this call's msg.sender.
    function depositPriv(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[16] calldata pub,
        bytes[] calldata kemCiphertexts
    ) external {
        _checkKemCiphertexts(kemCiphertexts, 2);
        if (!verifier.verifyProof(a, b, c, pub)) revert InvalidProof();

        uint256[] memory leaves = new uint256[](2);
        leaves[0] = pub[13];
        leaves[1] = pub[14];
        uint256 first = pool.applyOpWithPull(
            BongtuPool.OpEffects({root: 0, nullifiers: _none(), leaves: leaves, subtreeRoot: 0}), msg.sender, pub[0]
        );

        _emitDepositedPriv(pub, kemCiphertexts, first);
    }

    /// @dev Own frame: the 11-field emit plus the applyOp locals overflows the
    ///      EVM stack under non-via-IR solc (the pool's `_emit*` precedent).
    function _emitDepositedPriv(uint[16] calldata pub, bytes[] calldata kemCiphertexts, uint256 first) private {
        emit DepositedPriv(
            first,
            pub[13],
            pub[14],
            pub[0],
            [pub[1], pub[2]],
            [pub[3], pub[4], pub[5], pub[6]],
            [pub[7], pub[8], pub[9], pub[10]],
            [pub[11], pub[12]],
            pub[15],
            pool.root(),
            kemCiphertexts
        );
    }
}
