// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {BongtuPool} from "../BongtuPool.sol";
import {ITransferPrivVerifier} from "../interfaces/IVerifiers.sol";
import {ConsumerOpModule} from "./ConsumerOpModule.sol";

/// @title TransferPrivModule — transferPriv (2-in / 2-out), OPMOD §2.
///
/// publics (20): [0..1]=ecdhPub [2..9]=cipherTexts[2][4] [10..11]=viewTags
///               [12..13]=nullifiers [14]=root [15..16]=enabled
///               [17..18]=outputCommitments [19]=nonce
contract TransferPrivModule is ConsumerOpModule {
    ITransferPrivVerifier public immutable verifier;

    event TransferredPriv(
        uint256[2] nullifiers,
        uint256[2] outputCommitments,
        uint256[2] ecdhPublicKey,
        uint256[4] ctReceiver0,
        uint256[4] ctReceiver1,
        uint256[2] viewTags,
        uint256 encryptionNonce,
        uint256 root,
        bytes[] kemCiphertexts
    );

    constructor(BongtuPool _pool, ITransferPrivVerifier _verifier) ConsumerOpModule(_pool) {
        if (address(_verifier) == address(0)) revert ZeroVerifier();
        verifier = _verifier;
    }

    /// @notice Inject enabled[i]=(nullifier[i]!=0) — never read from calldata,
    ///         the same soundness rule as the in-core ops — verify, then apply:
    ///         padded (zero) nullifier slots are stripped before the core
    ///         boundary and both outputs append as single leaves.
    function transferPriv(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[20] calldata pub,
        bytes[] calldata kemCiphertexts
    ) external {
        _checkKemCiphertexts(kemCiphertexts, 2);

        uint[20] memory injected = pub;
        injected[15] = pub[12] != 0 ? 1 : 0;
        injected[16] = pub[13] != 0 ? 1 : 0;
        if (!verifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        uint256[] memory raw = new uint256[](2);
        raw[0] = pub[12];
        raw[1] = pub[13];
        uint256[] memory leaves = new uint256[](2);
        leaves[0] = pub[17];
        leaves[1] = pub[18];
        pool.applyOp(
            BongtuPool.OpEffects({root: pub[14], nullifiers: _stripZeros(raw), leaves: leaves, subtreeRoot: 0})
        );

        _emitTransferredPriv(pub, kemCiphertexts);
    }

    /// @dev Own frame: the 9-field emit plus the applyOp locals overflows the
    ///      EVM stack under non-via-IR solc (the pool's `_emit*` precedent).
    function _emitTransferredPriv(uint[20] calldata pub, bytes[] calldata kemCiphertexts) private {
        emit TransferredPriv(
            [pub[12], pub[13]],
            [pub[17], pub[18]],
            [pub[0], pub[1]],
            [pub[2], pub[3], pub[4], pub[5]],
            [pub[6], pub[7], pub[8], pub[9]],
            [pub[10], pub[11]],
            pub[19],
            pool.root(),
            kemCiphertexts
        );
    }
}
