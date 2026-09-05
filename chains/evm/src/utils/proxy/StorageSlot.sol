// SPDX-License-Identifier: MIT
// Vendored verbatim from OpenZeppelin Contracts v5.0
// (utils/StorageSlot.sol), trimmed to the AddressSlot accessor used by
// ERC1967Utils. Kept byte-faithful to the audited slot-typing so the ERC-1967
// storage math is not hand-improvised (see chains/evm/src/utils/proxy/README.md).
pragma solidity ^0.8.20;

/// @dev Library for reading and writing primitive types to specific storage
///      slots — the ERC-1967 implementation pointer lives at a fixed, computed
///      slot (see ERC1967Utils.IMPLEMENTATION_SLOT), never in the linear layout.
library StorageSlot {
    struct AddressSlot {
        address value;
    }

    /// @dev Returns an `AddressSlot` with member `value` located at `slot`.
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        assembly {
            r.slot := slot
        }
    }
}
