// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Ownable2Step} from "./utils/Ownable2Step.sol";
import {PortalSweeper, IPortalPool} from "./PortalSweeper.sol";

/// @title PortalFactory — deploy-and-sweep operator for portal deposits.
///
/// The salt IS the DKSAP-derived stealth address (bytes32-left-padded, i.e.
/// `bytes32(uint256(uint160(stealthAddress)))`): that is what lets the resolver
/// (issuing the address), the bot (sweeping it), and the recipient (scanning
/// announcements) all recompute the SAME destination from the announcement
/// alone — `addressOf` is a pure function of this factory's address, that salt,
/// and the sweeper's constant initcode hash. The TS mirror is
/// `packages/core/src/stealth.ts` (`portalSalt` + `create2Address`), pinned by
/// a committed parity vector.
///
/// TRUST (v1 concession, recorded in .dev/milestone-stealth.md Slice ⑤ — do not
/// soften): `sweep` is onlyOwner (the institution's bot key). The deposit proof
/// has NO owner binding — an on-chain binding of "these commitments belong to
/// the announced recipient" is impossible without exposing owners — so without
/// this gate anyone could deploy-and-sweep a funded portal address with a proof
/// minting the notes to THEMSELVES. Redirection-resistance therefore rests on
/// the institution key, the SAME trust domain as the arbiter that already
/// decrypts every note. Detection, not prevention, covers a malicious bot: the
/// cheated recipient sees a funded address with no note arriving via /notes —
/// that mismatch is the alarm surface.
contract PortalFactory is Ownable2Step {
    /// @notice keccak256 of the sweeper CREATION code — constant per build
    ///         because PortalSweeper takes no constructor args (its factory
    ///         binding is `msg.sender`, not an argument baked into initcode).
    bytes32 public immutable sweeperInitCodeHash;

    /// @notice A sweep landed: `salt` links back to the announcement (it IS the
    ///         stealth address), `sweeper` is the CREATE2 landing pad, `amount`
    ///         the proof-bound deposit — the indexer marks the announcement
    ///         swept off this event.
    event Swept(bytes32 indexed salt, address indexed sweeper, uint256 amount);

    /// @dev Unreachable unless `sweeperInitCodeHash` drifts from the bytecode
    ///      actually deployed; kept as a hard stop because the whole portal
    ///      contract with the resolver is "the salt determines the address".
    error SweeperAddressMismatch(address predicted, address deployed);

    constructor(address bot) Ownable2Step(bot) {
        sweeperInitCodeHash = keccak256(type(PortalSweeper).creationCode);
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
    ///         into `pool` with the bot-built deposit proof.
    function sweep(
        bytes32 salt,
        IPortalPool pool,
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[19] calldata pub,
        bytes calldata kemCiphertext
    ) external onlyOwner {
        address sweeper = addressOf(salt);
        if (sweeper.code.length == 0) {
            PortalSweeper deployed = new PortalSweeper{salt: salt}();
            if (address(deployed) != sweeper) revert SweeperAddressMismatch(sweeper, address(deployed));
        }
        PortalSweeper(sweeper).sweep(pool, a, b, c, pub, kemCiphertext);
        emit Swept(salt, sweeper, pub[0]);
    }
}
