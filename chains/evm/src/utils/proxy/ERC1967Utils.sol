// SPDX-License-Identifier: MIT
// Vendored from OpenZeppelin Contracts v5.0 (proxy/ERC1967/ERC1967Utils.sol),
// trimmed to the IMPLEMENTATION-slot machinery a UUPS proxy needs (the admin /
// beacon slots and helpers are dropped — UUPS keeps upgrade authority in the
// implementation, not a separate admin). The IMPLEMENTATION_SLOT constant and
// the upgrade logic are byte-faithful to the audited source; do NOT hand-edit
// the slot math (see chains/evm/src/utils/proxy/README.md).
pragma solidity ^0.8.20;

import {IERC1822Proxiable} from "./IERC1822Proxiable.sol";
import {Address} from "./Address.sol";
import {StorageSlot} from "./StorageSlot.sol";

/// @dev This library provides getters and event emitting update functions for
///      https://eips.ethereum.org/EIPS/eip-1967[ERC-1967] slots.
library ERC1967Utils {
    /// @dev Storage slot with the address of the current implementation.
    ///      This is the keccak-256 hash of "eip1967.proxy.implementation"
    ///      subtracted by 1.
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /// @dev Emitted when the implementation is upgraded.
    event Upgraded(address indexed implementation);

    /// @dev The `implementation` of the proxy is invalid.
    error ERC1967InvalidImplementation(address implementation);

    /// @dev An upgrade function sees `msg.value > 0` that may be lost.
    error ERC1967NonPayable();

    /// @dev Returns the current implementation address.
    function getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value;
    }

    /// @dev Stores a new address in the ERC-1967 implementation slot.
    function _setImplementation(address newImplementation) private {
        if (newImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(newImplementation);
        }
        StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value = newImplementation;
    }

    /// @dev Performs implementation upgrade with additional setup call if
    ///      data is nonempty. This function is payable only if the setup call is
    ///      performed, otherwise `msg.value` is rejected to avoid stuck value in
    ///      the contract.
    ///
    /// Emits an {Upgraded} event.
    function upgradeToAndCall(address newImplementation, bytes memory data) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);

        if (data.length > 0) {
            Address.functionDelegateCall(newImplementation, data);
        } else {
            _checkNonPayable();
        }
    }

    /// @dev Reverts if `msg.value` is not zero. It can be used to avoid `msg.value`
    ///      stuck in the contract if an upgrade doesn't perform an initialization
    ///      call.
    function _checkNonPayable() private {
        if (msg.value > 0) {
            revert ERC1967NonPayable();
        }
    }
}
