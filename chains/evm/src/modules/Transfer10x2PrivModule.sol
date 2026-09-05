// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {BongtuPool} from "../BongtuPool.sol";
import {ITransfer10x2PrivVerifier} from "../interfaces/IVerifiers.sol";
import {ConsumerOpModule} from "./ConsumerOpModule.sol";

/// @title Transfer10x2PrivModule — transfer10x2Priv (10-in / 2-out), OPMOD §2.
///        The consolidation + payment workhorse: outputs, not inputs, are what
///        a spend pays for, so the 10-arity sheds eight zero-value pads.
///
/// publics (36): [0..1]=ecdhPub [2..9]=cipherTexts[2][4] [10..11]=viewTags
///               [12..21]=nullifiers[10] [22]=root [23..32]=enabled[10]
///               [33..34]=outputCommitments [35]=nonce
contract Transfer10x2PrivModule is ConsumerOpModule {
    uint256 private constant ARITY = 10;

    ITransfer10x2PrivVerifier public immutable verifier;

    event Transferred10x2Priv(
        uint256[10] nullifiers,
        uint256[2] outputCommitments,
        uint256[2] ecdhPublicKey,
        uint256[8] ctReceivers,
        uint256[2] viewTags,
        uint256 encryptionNonce,
        uint256 root,
        bytes[] kemCiphertexts
    );

    constructor(BongtuPool _pool, ITransfer10x2PrivVerifier _verifier) ConsumerOpModule(_pool) {
        if (address(_verifier) == address(0)) revert ZeroVerifier();
        verifier = _verifier;
    }

    /// @notice Inject all ten enabled[i]=(nullifier[i]!=0), verify, apply. The
    ///         stripped nullifier array preserves slot order, so an in-tx
    ///         duplicate still reverts on its second occurrence in the core.
    function transfer10x2Priv(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[36] calldata pub,
        bytes[] calldata kemCiphertexts
    ) external {
        _checkKemCiphertexts(kemCiphertexts, 2);

        uint[36] memory injected = pub;
        for (uint256 i = 0; i < ARITY; i++) {
            injected[23 + i] = pub[12 + i] != 0 ? 1 : 0;
        }
        if (!verifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        uint256[] memory raw = new uint256[](ARITY);
        for (uint256 i = 0; i < ARITY; i++) {
            raw[i] = pub[12 + i];
        }
        uint256[] memory leaves = new uint256[](2);
        leaves[0] = pub[33];
        leaves[1] = pub[34];
        pool.applyOp(
            BongtuPool.OpEffects({root: pub[22], nullifiers: _stripZeros(raw), leaves: leaves, subtreeRoot: 0})
        );

        _emitTransferred10x2Priv(pub, kemCiphertexts);
    }

    /// @dev Own frame: the 8-field emit plus the applyOp locals overflows the
    ///      EVM stack under non-via-IR solc (the pool's `_emit*` precedent).
    function _emitTransferred10x2Priv(uint[36] calldata pub, bytes[] calldata kemCiphertexts) private {
        uint256[10] memory nfs;
        for (uint256 i = 0; i < ARITY; i++) {
            nfs[i] = pub[12 + i];
        }
        uint256[8] memory rct;
        for (uint256 i = 0; i < 8; i++) {
            rct[i] = pub[2 + i];
        }
        emit Transferred10x2Priv(
            nfs,
            [pub[33], pub[34]],
            [pub[0], pub[1]],
            rct,
            [pub[10], pub[11]],
            pub[35],
            pool.root(),
            kemCiphertexts
        );
    }
}
