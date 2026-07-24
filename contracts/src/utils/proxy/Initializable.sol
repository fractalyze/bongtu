// SPDX-License-Identifier: MIT
// Vendored verbatim from OpenZeppelin Contracts (proxy/utils/Initializable.sol),
// v5.0. This is the audited ERC-7201 namespaced-storage initializer — do NOT
// hand-edit the INITIALIZABLE_STORAGE constant or the initializer state machine
// (see contracts/src/utils/proxy/README.md).
pragma solidity ^0.8.20;

/// @dev This is a base contract to aid in writing upgradeable contracts, or any
///      kind of contract that will be deployed behind a proxy. Since proxied
///      contracts do not make use of a constructor, it is common to move
///      constructor logic to an external initializer function, usually called
///      `initialize`. It then becomes necessary to protect this initializer
///      function so it can only be called once.
///
/// The {initializer} and {reinitializer} modifiers protect functions that can
/// only be called once.
///
/// [CAUTION]
/// ====
/// Avoid leaving a contract uninitialized. An uninitialized contract can be
/// taken over by an attacker. This applies to both a proxy and its
/// implementation contract, which may impact the proxy. To prevent the
/// implementation contract from being used, you should invoke the
/// {_disableInitializers} function in the constructor to automatically lock it
/// when it is deployed.
/// ====
abstract contract Initializable {
    /// @dev Storage of the initializable contract (ERC-7201 namespaced storage).
    struct InitializableStorage {
        /// @dev Indicates that the contract has been initialized.
        uint64 _initialized;
        /// @dev Indicates that the contract is in the process of being initialized.
        bool _initializing;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant INITIALIZABLE_STORAGE =
        0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    /// @dev The contract is already initialized.
    error InvalidInitialization();

    /// @dev The contract is not initializing.
    error NotInitializing();

    /// @dev Triggered when the contract has been initialized or reinitialized.
    event Initialized(uint64 version);

    /// @dev A modifier that defines a protected initializer function that can be
    ///      invoked at most once. In its scope, `onlyInitializing` functions can
    ///      be used to initialize parent contracts.
    ///
    /// Similar to `reinitializer(1)`, except that in the context of a
    /// constructor an `initializer` may be invoked any number of times. This
    /// behavior in the constructor can be useful during testing and is not
    /// expected to be used in production.
    ///
    /// Emits an {Initialized} event.
    modifier initializer() {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        // Cache values to avoid duplicated sloads
        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;

        // Allowed calls:
        // - initialSetup: the contract is not in the initializing state and no
        //   previous version was initialized
        // - construction: the contract is initialized at version 1 (no reininitialization) and the
        //   current contract is just being deployed
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $._initialized = 1;
        if (isTopLevelCall) {
            $._initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $._initializing = false;
            emit Initialized(1);
        }
    }

    /// @dev A modifier that defines a protected reinitializer function that can
    ///      be invoked at most once, and only if the contract hasn't been
    ///      initialized to a greater version before. In its scope,
    ///      `onlyInitializing` functions can be used to initialize parent
    ///      contracts.
    ///
    /// Emits an {Initialized} event.
    modifier reinitializer(uint64 version) {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing || $._initialized >= version) {
            revert InvalidInitialization();
        }
        $._initialized = version;
        $._initializing = true;
        _;
        $._initializing = false;
        emit Initialized(version);
    }

    /// @dev Modifier to protect an initialization function so that it can only be
    ///      invoked by functions with the {initializer} and {reinitializer}
    ///      modifiers, directly or indirectly.
    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }

    /// @dev Reverts if the contract is not in an initializing state. See
    ///      {onlyInitializing}.
    function _checkInitializing() internal view virtual {
        if (!_isInitializing()) {
            revert NotInitializing();
        }
    }

    /// @dev Locks the contract, preventing any future reinitialization. This
    ///      cannot be part of an initializer call. Calling this in the
    ///      constructor to automatically lock it when it is deployed is
    ///      recommended.
    ///
    /// Emits an {Initialized} event the first time it is successfully executed.
    function _disableInitializers() internal virtual {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing) {
            revert InvalidInitialization();
        }
        if ($._initialized != type(uint64).max) {
            $._initialized = type(uint64).max;
            emit Initialized(type(uint64).max);
        }
    }

    /// @dev Returns the highest version that has been initialized. See
    ///      {reinitializer}.
    function _getInitializedVersion() internal view returns (uint64) {
        return _getInitializableStorage()._initialized;
    }

    /// @dev Returns `true` if the contract is currently initializing. See
    ///      {onlyInitializing}.
    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }

    /// @dev Pointer to storage slot. Allows integrators to override it with a
    ///      custom storage location.
    function _initializableStorageSlot() internal pure virtual returns (bytes32) {
        return INITIALIZABLE_STORAGE;
    }

    /// @dev Returns a pointer to the storage namespace.
    // solhint-disable-next-line var-name-mixedcase
    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        bytes32 slot = _initializableStorageSlot();
        assembly {
            $.slot := slot
        }
    }
}
