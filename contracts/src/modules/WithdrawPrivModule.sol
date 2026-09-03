// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {BongtuPool} from "../BongtuPool.sol";
import {IWithdrawPrivVerifier} from "../interfaces/IVerifiers.sol";
import {ConsumerOpModule} from "./ConsumerOpModule.sol";

/// @title WithdrawPrivModule — withdrawPriv (2-in / 1-out change +
///        proof-bound public recipient), OPMOD §2. RELAYABLE like the
///        enterprise withdraw: tokens go to the proof-bound pub[15], never to
///        msg.sender. The change note gains a receiver ct — the consumer
///        sender must recover change from chain scan alone.
///
/// publics (16): [0]=out [1..2]=ecdhPub [3..6]=cipherTexts[1][4] (change)
///               [7]=viewTag [8..9]=nullifiers [10]=root [11..12]=enabled
///               [13]=outputCommitments[0] (change) [14]=nonce [15]=recipient
contract WithdrawPrivModule is ConsumerOpModule {
    IWithdrawPrivVerifier public immutable verifier;

    error InvalidRecipient(uint256 recipient);

    event WithdrawnPriv(
        uint256[2] nullifiers,
        uint256 amount,
        uint256 changeCommitment,
        uint256[2] ecdhPublicKey,
        uint256[4] ctChange,
        uint256 viewTag,
        uint256 encryptionNonce,
        uint256 root,
        bytes[] kemCiphertexts
    );
    /// @notice Same shape as the pool's WithdrawAnnouncement: the stealth
    ///         announcement halves are calldata-carried, NOT proof-bound —
    ///         tampering them can only break discovery; funds still reach the
    ///         proof-bound recipient.
    event WithdrawAnnouncement(uint256 recipient, bytes32 stealthEphemeralPub, uint8 stealthViewTag);

    constructor(BongtuPool _pool, IWithdrawPrivVerifier _verifier) ConsumerOpModule(_pool) {
        if (address(_verifier) == address(0)) revert ZeroVerifier();
        verifier = _verifier;
    }

    /// @notice Range-check the recipient (the circuit binds a field element
    ///         but cannot range-check an address — truncation would let two
    ///         field values alias one address), inject enabled, verify, apply
    ///         with a push of `out` (pub[0]) to the recipient.
    function withdrawPriv(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[16] calldata pub,
        bytes[] calldata kemCiphertexts,
        bytes32 stealthEphemeralPub,
        uint8 stealthViewTag
    ) external {
        _checkKemCiphertexts(kemCiphertexts, 1);
        if (pub[15] == 0 || pub[15] > type(uint160).max) revert InvalidRecipient(pub[15]);

        uint[16] memory injected = pub;
        injected[11] = pub[8] != 0 ? 1 : 0;
        injected[12] = pub[9] != 0 ? 1 : 0;
        if (!verifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        uint256[] memory raw = new uint256[](2);
        raw[0] = pub[8];
        raw[1] = pub[9];
        uint256[] memory leaves = new uint256[](1);
        leaves[0] = pub[13];
        pool.applyOpWithPush(
            BongtuPool.OpEffects({root: pub[10], nullifiers: _stripZeros(raw), leaves: leaves, subtreeRoot: 0}),
            address(uint160(pub[15])),
            pub[0]
        );

        _emitWithdrawnPriv(pub, kemCiphertexts);
        emit WithdrawAnnouncement(pub[15], stealthEphemeralPub, stealthViewTag);
    }

    /// @dev Own frame: the 9-field emit plus the applyOp locals overflows the
    ///      EVM stack under non-via-IR solc (the pool's `_emit*` precedent).
    function _emitWithdrawnPriv(uint[16] calldata pub, bytes[] calldata kemCiphertexts) private {
        emit WithdrawnPriv(
            [pub[8], pub[9]],
            pub[0],
            pub[13],
            [pub[1], pub[2]],
            [pub[3], pub[4], pub[5], pub[6]],
            pub[7],
            pub[14],
            pool.root(),
            kemCiphertexts
        );
    }
}
