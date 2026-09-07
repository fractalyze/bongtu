// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Ownable2Step} from "./utils/Ownable2Step.sol";

/// @title PortalFactoryBase — the shared half of every deploy-and-sweep operator.
///
/// The salt IS the DKSAP-derived stealth address (bytes32-left-padded, i.e.
/// `bytes32(uint256(uint160(stealthAddress)))`): that is what lets the issuer
/// (handing out the address), the bot (sweeping it), and the recipient
/// (scanning announcements) all recompute the SAME destination from the
/// announcement alone — `addressOf` is a pure function of the factory address,
/// that salt, and the family sweeper's constant initcode hash. The TS mirror is
/// `packages/core/src/notes/stealth.ts` (`portalSalt` + `create2Address`),
/// pinned per family by a committed parity vector (the two sweepers' initcodes
/// differ, so each pair pins its own).
///
/// What every family shares lives here: the CREATE2 math, the idempotent
/// deploy-if-absent with its hard mismatch stop, the `Swept` event, and the
/// owner gate. A child declares only its own `sweep` entrypoint (family proof
/// arity + any family event) and the `_deploySweeper` hook naming its concrete
/// sweeper type.
///
/// TRUST (v1 concession — see PortalSweeperBase's header, one statement for
/// both halves): `sweep` implementations are onlyOwner (the operator's bot
/// key); redirection-resistance rests on that key, detection covers a
/// malicious bot.
abstract contract PortalFactoryBase is Ownable2Step {
    /// @notice keccak256 of the family sweeper's CREATION code — constant per
    ///         build because the sweepers take no constructor args (their
    ///         factory binding is `msg.sender`, not an argument baked into
    ///         initcode). Set by the child, which knows its concrete type.
    bytes32 public immutable sweeperInitCodeHash;

    /// @notice A sweep landed: `salt` links back to the announcement (it IS the
    ///         stealth address), `sweeper` is the CREATE2 landing pad, `amount`
    ///         the proof-bound deposit — the indexer marks the announcement
    ///         swept off this event, identically for every family.
    event Swept(bytes32 indexed salt, address indexed sweeper, uint256 amount);

    /// @dev Unreachable unless `sweeperInitCodeHash` drifts from the bytecode
    ///      actually deployed; kept as a hard stop because the whole portal
    ///      contract with the issuer is "the salt determines the address".
    error SweeperAddressMismatch(address predicted, address deployed);

    constructor(address bot, bytes32 initCodeHash) Ownable2Step(bot) {
        sweeperInitCodeHash = initCodeHash;
    }

    /// @notice The CREATE2 address `salt` maps to — EIP-1014:
    ///         keccak256(0xff ‖ this ‖ salt ‖ sweeperInitCodeHash)[12..].
    function addressOf(bytes32 salt) public view returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encodePacked(hex"ff", address(this), salt, sweeperInitCodeHash))))
        );
    }

    /// @notice Deploy the sweeper for `salt` if (and only if) none exists yet —
    ///         idempotent, so a repeat call on an already-deployed sweeper goes
    ///         straight to the sweep (re-sweeping the same address after a
    ///         second payment is a supported flow in every family).
    function _ensureSweeper(bytes32 salt) internal returns (address sweeper) {
        sweeper = addressOf(salt);
        if (sweeper.code.length == 0) {
            address deployed = _deploySweeper(salt);
            if (deployed != sweeper) revert SweeperAddressMismatch(sweeper, deployed);
        }
    }

    /// @dev `new X{salt: salt}()` needs the concrete sweeper type, so the
    ///      CREATE2 itself is the one thing a child must supply.
    function _deploySweeper(bytes32 salt) internal virtual returns (address);
}
