// SPDX-License-Identifier: MIT
// Vendored from OpenZeppelin Contracts v5.0 (utils/Address.sol), trimmed to the
// delegatecall helpers ERC1967Utils needs. Byte-faithful to the audited revert
// bubbling (see contracts/src/utils/proxy/README.md).
pragma solidity ^0.8.20;

/// @dev Collection of functions related to the address type.
library Address {
    /// @dev There's no code at `target` (it is not a contract).
    error AddressEmptyCode(address target);

    /// @dev A call to an address target failed. The target may have reverted.
    error FailedCall();

    /// @dev Same as {Address-functionCall}, but performing a delegate call.
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /// @dev Tool to verify that a low level call to smart-contract was successful,
    ///      and reverts if the target was not a contract or bubbling up the
    ///      revert reason (falling back to {FailedCall}) in case of an
    ///      unsuccessful call.
    function verifyCallResultFromTarget(address target, bool success, bytes memory returndata)
        internal
        view
        returns (bytes memory)
    {
        if (!success) {
            _revert(returndata);
        } else {
            // only check if target is a contract if the call was successful and the return data is empty
            // otherwise we already know that it was a contract
            if (returndata.length == 0 && target.code.length == 0) {
                revert AddressEmptyCode(target);
            }
            return returndata;
        }
    }

    /// @dev Reverts with returndata if present. Otherwise reverts with {FailedCall}.
    function _revert(bytes memory returndata) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert FailedCall();
        }
    }
}
