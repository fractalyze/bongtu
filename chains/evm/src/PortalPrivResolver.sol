// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Ownable2Step} from "./utils/Ownable2Step.sol";

/// @notice ENSIP-10 wildcard resolver surface (the interface wallets probe
///         via ERC-165 before calling `resolve`).
interface IExtendedResolver {
    function resolve(bytes calldata name, bytes calldata data) external view returns (bytes memory);
}

/// @title PortalPrivResolver — the payment name's on-chain half.
///
/// Every resolution is answered OFFCHAIN (ERC-3668 CCIP-Read): `resolve`
/// always reverts `OffchainLookup` pointing the wallet at the gateway, the
/// gateway derives a FRESH stealth destination and records its announcement
/// BEFORE answering, and `resolveWithProof` accepts the answer only when it
/// is signed by the owner-set gateway signer and not expired. The contract
/// stores no name and no address: statelessness is what makes every lookup
/// fresh, and the signature is what keeps the gateway
/// censor-but-not-redirect (a hostile gateway or URL swap cannot fabricate
/// an answer the configured signer did not sign).
///
/// The signature preimage is the ensdomains offchain-resolver convention,
/// keccak256(0x1900 ‖ this ‖ expires ‖ keccak(request) ‖ keccak(result)),
/// re-derived here from `extraData`/`response` and pinned against the TS
/// signer by a committed parity vector (test/PortalPrivResolver.t.sol <->
/// packages/core/test/ens.test.ts).
contract PortalPrivResolver is Ownable2Step, IExtendedResolver {
    /// @notice ERC-3668: the wallet must fetch `urls` with `callData` and
    ///         call back through `callbackFunction`.
    error OffchainLookup(address sender, string[] urls, bytes callData, bytes4 callbackFunction, bytes extraData);
    error SignatureExpired(uint64 expires);
    error UntrustedSigner(address recovered);
    error MalformedSignature(uint256 length);

    event SignerChanged(address indexed signer);
    event GatewayUrlsChanged(string[] urls);

    /// @notice The gateway's response-signing address (rotated by `setSigner`,
    ///         the mainnet rotation runbook's one lever).
    address public signer;
    string[] private gatewayUrls;

    constructor(address initialOwner, address initialSigner, string[] memory initialUrls) Ownable2Step(initialOwner) {
        signer = initialSigner;
        // Element-wise: the non-via-IR codegen cannot copy nested dynamic
        // arrays to storage in one assignment.
        for (uint256 i = 0; i < initialUrls.length; i++) {
            gatewayUrls.push(initialUrls[i]);
        }
        emit SignerChanged(initialSigner);
        emit GatewayUrlsChanged(initialUrls);
    }

    function setSigner(address newSigner) external onlyOwner {
        signer = newSigner;
        emit SignerChanged(newSigner);
    }

    function setGatewayUrls(string[] calldata newUrls) external onlyOwner {
        delete gatewayUrls;
        for (uint256 i = 0; i < newUrls.length; i++) {
            gatewayUrls.push(newUrls[i]);
        }
        emit GatewayUrlsChanged(newUrls);
    }

    function urls() external view returns (string[] memory) {
        return gatewayUrls;
    }

    /// @notice ENSIP-10 entrypoint. Always offchain: the gateway is the only
    ///         party that can mint an announcement, so answering from chain
    ///         state here would break announce-before-return.
    function resolve(bytes calldata, bytes calldata) external view returns (bytes memory) {
        revert OffchainLookup(address(this), gatewayUrls, msg.data, this.resolveWithProof.selector, msg.data);
    }

    /// @notice ERC-3668 callback: verify the gateway's signed answer.
    /// @param response abi.encode(bytes result, uint64 expires, bytes sig)
    /// @param extraData the original `resolve` calldata (the signed request)
    function resolveWithProof(bytes calldata response, bytes calldata extraData)
        external
        view
        returns (bytes memory)
    {
        (bytes memory result, uint64 expires, bytes memory sig) = abi.decode(response, (bytes, uint64, bytes));
        if (expires < block.timestamp) revert SignatureExpired(expires);
        if (sig.length != 65) revert MalformedSignature(sig.length);
        bytes32 digest =
            keccak256(abi.encodePacked(hex"1900", address(this), expires, keccak256(extraData), keccak256(result)));
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != signer) revert UntrustedSigner(recovered);
        return result;
    }

    /// @dev ERC-165: ENSIP-10 wildcard support plus ERC-165 itself.
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IExtendedResolver).interfaceId || interfaceId == 0x01ffc9a7;
    }

    function _split(bytes memory sig) private pure returns (bytes32 r, bytes32 s, uint8 v) {
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
    }
}
