// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {PortalFactoryBase} from "./PortalFactoryBase.sol";
import {PortalPrivSweeper, IPortalPrivModule} from "./PortalPrivSweeper.sol";

/// @title PortalPrivFactory — the CONSUMER-family deploy-and-sweep operator.
///
/// The salt/addressOf mechanics, the idempotent deploy, the `Swept` event and
/// the trust posture are PortalFactoryBase's (see its header); this child owns
/// the consumer sweep entrypoint (depositPriv, uint[16], per-output kem
/// ciphertexts — no-auditor notes the operator cannot open) plus the ONE
/// family event with no enterprise counterpart: the sweep-time on-chain
/// announcement, which makes every swept payment recoverable from chain data
/// alone even if the indexer's announcement store is lost or hostile. Its
/// sweeper's initcode differs from PortalSweeper's, so this pair pins its OWN
/// TS parity vector (`packages/core/test/stealth.test.ts` beside the
/// enterprise one).
contract PortalPrivFactory is PortalFactoryBase {
    /// @notice The chain-only recovery path: the DKSAP announcement tuple the
    ///         pay page recorded off-chain, re-emitted at sweep time so a
    ///         recipient holding only its view key and chain access can
    ///         re-derive the destination and find its swept payments with no
    ///         indexer at all. Shapes match the wallet scan predicate
    ///         (`ephemeralPub` = packed bjj point, the WithdrawAnnouncement
    ///         convention).
    event Announced(bytes32 indexed salt, bytes32 ephemeralPub, uint8 viewTag);

    constructor(address bot) PortalFactoryBase(bot, keccak256(type(PortalPrivSweeper).creationCode)) {}

    function sweep(
        bytes32 salt,
        IPortalPrivModule module,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[16] calldata pub,
        bytes[] calldata kemCiphertexts,
        bytes32 ephemeralPub,
        uint8 viewTag
    ) external onlyOwner {
        address sweeper = _ensureSweeper(salt);
        PortalPrivSweeper(sweeper).sweep(module, a, b, c, pub, kemCiphertexts);
        emit Swept(salt, sweeper, pub[0]);
        emit Announced(salt, ephemeralPub, viewTag);
    }

    function _deploySweeper(bytes32 salt) internal override returns (address) {
        return address(new PortalPrivSweeper{salt: salt}());
    }
}
