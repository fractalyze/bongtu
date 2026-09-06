// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Ownable2Step} from "./utils/Ownable2Step.sol";
import {ReceiveSweeper, IReceiveModule} from "./ReceiveSweeper.sol";

/// @title ReceiveFactory — deploy-and-sweep operator for stealth receives.
///
/// The consumer-family sibling of PortalFactory, with two deltas: the sweep
/// shields through the consumer `depositPriv` module (no-auditor notes — the
/// operator's arbiter cannot open them), and the sweep transaction EMITS the
/// stealth announcement on-chain (`Announced`), so every swept payment is
/// recoverable from chain data alone even if the indexer's announcement store
/// is lost or hostile. The salt convention is identical: the salt IS the
/// DKSAP-derived stealth address (bytes32-left-padded), so the pay page
/// (issuing the address), the bot (sweeping it), and the recipient (scanning
/// announcements) all recompute the SAME destination from the announcement
/// alone. The TS mirror is `packages/core/src/notes/stealth.ts` (`portalSalt`
/// + `create2Address`), pinned by this pair's OWN committed parity vector
/// (the sweeper initcode differs from PortalSweeper's, so the hash differs).
///
/// TRUST (the portal v1 concession, unchanged here — do not soften): `sweep`
/// is onlyOwner (the operator's bot key). The deposit proof has NO owner
/// binding — an on-chain binding of "these commitments belong to the announced
/// recipient" is impossible without exposing owners — so without this gate
/// anyone could deploy-and-sweep a funded receive address with a proof minting
/// the notes to THEMSELVES. Redirection-resistance therefore rests on the bot
/// key. Detection, not prevention, covers a malicious bot: the cheated
/// recipient sees a funded address whose note never arrives via its own scan.
contract ReceiveFactory is Ownable2Step {
    /// @notice keccak256 of the sweeper CREATION code — constant per build
    ///         because ReceiveSweeper takes no constructor args (its factory
    ///         binding is `msg.sender`, not an argument baked into initcode).
    bytes32 public immutable sweeperInitCodeHash;

    /// @notice A sweep landed: `salt` links back to the announcement (it IS the
    ///         stealth address), `sweeper` is the CREATE2 landing pad, `amount`
    ///         the proof-bound deposit — the indexer marks the announcement
    ///         swept off this event.
    event Swept(bytes32 indexed salt, address indexed sweeper, uint256 amount);

    /// @notice The chain-only recovery path: the DKSAP announcement tuple the
    ///         pay page recorded off-chain, re-emitted at sweep time so a
    ///         recipient holding only its view key and chain access can
    ///         re-derive the destination and find its swept payments with no
    ///         indexer at all. Shapes match the wallet scan predicate
    ///         (`ephemeralPub` = packed bjj point, the WithdrawAnnouncement
    ///         convention).
    event Announced(bytes32 indexed salt, bytes32 ephemeralPub, uint8 viewTag);

    /// @dev Unreachable unless `sweeperInitCodeHash` drifts from the bytecode
    ///      actually deployed; kept as a hard stop because the whole receive
    ///      contract with the pay page is "the salt determines the address".
    error SweeperAddressMismatch(address predicted, address deployed);

    constructor(address bot) Ownable2Step(bot) {
        sweeperInitCodeHash = keccak256(type(ReceiveSweeper).creationCode);
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
    ///         second payment is a supported flow) — then sweep its balance
    ///         through the consumer `depositPriv` module with the bot-built
    ///         proof, and log the announcement tuple for chain-only recovery.
    function sweep(
        bytes32 salt,
        IReceiveModule module,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[16] calldata pub,
        bytes[] calldata kemCiphertexts,
        bytes32 ephemeralPub,
        uint8 viewTag
    ) external onlyOwner {
        address sweeper = addressOf(salt);
        if (sweeper.code.length == 0) {
            ReceiveSweeper deployed = new ReceiveSweeper{salt: salt}();
            if (address(deployed) != sweeper) revert SweeperAddressMismatch(sweeper, address(deployed));
        }
        ReceiveSweeper(sweeper).sweep(module, a, b, c, pub, kemCiphertexts);
        emit Swept(salt, sweeper, pub[0]);
        emit Announced(salt, ephemeralPub, viewTag);
    }
}
