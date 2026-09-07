// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {PortalFactoryBase} from "./PortalFactoryBase.sol";
import {PortalSweeper, IPortalPool} from "./PortalSweeper.sol";

/// @title PortalFactory — the ENTERPRISE-family deploy-and-sweep operator.
///
/// The salt/addressOf mechanics, the idempotent deploy, the `Swept` event and
/// the trust posture are PortalFactoryBase's (see its header); this child owns
/// only the enterprise sweep entrypoint: the deposit proof is the pool's
/// `deposit` (uint[19]), minting arbiter-openable notes — the depositor-facing
/// portal product. Deployed on 450815 as `portalFactory` in
/// `deploy/addresses.450815.json`; NOTE the live instance predates the
/// base-contract refactor, so its ON-CHAIN sweeperInitCodeHash differs from a
/// fresh build's — the chain is the one owner of that fact (every live
/// derivation goes through eth_call `addressOf`), and the committed parity
/// vector pins the CURRENT source, not the live deploy.
contract PortalFactory is PortalFactoryBase {
    constructor(address bot) PortalFactoryBase(bot, keccak256(type(PortalSweeper).creationCode)) {}

    function sweep(
        bytes32 salt,
        IPortalPool pool,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[19] calldata pub,
        bytes calldata kemCiphertext
    ) external onlyOwner {
        address sweeper = _ensureSweeper(salt);
        PortalSweeper(sweeper).sweep(pool, a, b, c, pub, kemCiphertext);
        emit Swept(salt, sweeper, pub[0]);
    }

    function _deploySweeper(bytes32 salt) internal override returns (address) {
        return address(new PortalSweeper{salt: salt}());
    }
}
