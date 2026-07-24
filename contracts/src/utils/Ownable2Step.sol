// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

// Minimal two-step ownable (SPEC §5.3 role split for PoC). Self-contained so the
// M0 gate needs no OpenZeppelin install. Ownership transfer is two-step: the
// current owner nominates a pending owner, who must accept — this prevents a
// typo'd address from bricking the pool.
abstract contract Ownable2Step {
    address private _owner;
    address private _pendingOwner;

    error OwnableUnauthorized(address account);
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert OwnableInvalidOwner(address(0));
        _owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);
    }

    modifier onlyOwner() {
        if (msg.sender != _owner) revert OwnableUnauthorized(msg.sender);
        _;
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
