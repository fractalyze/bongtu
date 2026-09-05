// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Initializable} from "./proxy/Initializable.sol";

/// @notice Upgradeable twin of {Ownable2Step} (SPEC §5.3 role split). Identical
///         two-step semantics, errors and events as the non-upgradeable version,
///         but the owner is held in REGULAR storage and seeded by
///         `__Ownable2Step_init` from `initialize()` rather than a constructor —
///         so it is safe behind an ERC-1967 proxy, whose implementation
///         constructor never runs against the proxy's storage.
///
/// The current owner nominates a pending owner, who must `acceptOwnership()` —
/// this prevents a typo'd address from bricking the pool. Self-contained (no
/// OpenZeppelin dependency), matching the rest of `utils/`.
abstract contract Ownable2StepUpgradeable is Initializable {
    address private _owner;
    address private _pendingOwner;

    error OwnableUnauthorized(address account);
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    modifier onlyOwner() {
        if (msg.sender != _owner) revert OwnableUnauthorized(msg.sender);
        _;
    }

    /// @dev Seed the initial owner. Must be called from an `initializer` /
    ///      `reinitializer` function (guarded by `onlyInitializing`).
    function __Ownable2Step_init(address initialOwner) internal onlyInitializing {
        if (initialOwner == address(0)) revert OwnableInvalidOwner(address(0));
        _owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function pendingOwner() public view returns (address) {
        return _pendingOwner;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(_owner, newOwner);
    }

    function acceptOwnership() public {
        if (msg.sender != _pendingOwner) revert OwnableUnauthorized(msg.sender);
        address old = _owner;
        _owner = _pendingOwner;
        _pendingOwner = address(0);
        emit OwnershipTransferred(old, _owner);
    }
}
