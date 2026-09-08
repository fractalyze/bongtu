// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PortalPrivResolver, IExtendedResolver} from "../src/PortalPrivResolver.sol";

/// The gateway-signature parity vector below is SHARED with
/// packages/core/test/ens.test.ts: both suites pin the same committed digest
/// for the same inputs, so a preimage drift on either side turns a fast
/// suite red instead of minting responses the other side rejects.
contract PortalPrivResolverTest is Test {
    uint256 constant SIGNER_KEY = 0xA11CE;
    address signer;
    address owner = address(0xB07);
    PortalPrivResolver resolver;
    string[] urls;

    // The committed TS<->Solidity parity vector (ens.test.ts PARITY).
    address constant PARITY_RESOLVER = 0x1111111111111111111111111111111111111111;
    uint64 constant PARITY_EXPIRES = 1893456000;
    bytes constant PARITY_REQUEST = hex"deadbeef";
    bytes constant PARITY_RESULT = hex"cafe";
    bytes32 constant PARITY_DIGEST = 0x0d66a888b54ad0e6696f9e7843e16d226b9a571832be789b860ed34249892636;

    function setUp() public {
        signer = vm.addr(SIGNER_KEY);
        urls.push("https://gateway.invalid/ens/{sender}/{data}.json");
        resolver = new PortalPrivResolver(owner, signer, urls);
    }

    function digestFor(bytes memory request, bytes memory result, uint64 expires) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1900", address(resolver), expires, keccak256(request), keccak256(result)));
    }

    function signedResponse(bytes memory request, bytes memory result, uint64 expires)
        internal
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digestFor(request, result, expires));
        return abi.encode(result, expires, abi.encodePacked(r, s, v));
    }

    function testParityVectorMatchesTheCommittedDigest() public pure {
        bytes32 digest = keccak256(
            abi.encodePacked(
                hex"1900", PARITY_RESOLVER, PARITY_EXPIRES, keccak256(PARITY_REQUEST), keccak256(PARITY_RESULT)
            )
        );
        assertEq(digest, PARITY_DIGEST, "TS<->Solidity signature preimage drift");
    }

    function testResolveAlwaysRevertsOffchainLookupWithTheConfiguredGateway() public {
        bytes memory name = hex"036a756e04726f6f740365746800"; // jun.root.eth, dns-encoded
        bytes memory data = abi.encodeWithSignature("addr(bytes32)", bytes32(0));
        bytes memory callData = abi.encodeCall(IExtendedResolver.resolve, (name, data));
        vm.expectRevert(
            abi.encodeWithSelector(
                PortalPrivResolver.OffchainLookup.selector,
                address(resolver),
                urls,
                callData,
                PortalPrivResolver.resolveWithProof.selector,
                callData
            )
        );
        resolver.resolve(name, data);
    }

    function testResolveWithProofAcceptsTheSignedAnswer() public {
        bytes memory request = hex"deadbeef";
        bytes memory result = abi.encode(address(0xCAFE));
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory returned = resolver.resolveWithProof(signedResponse(request, result, expires), request);
        assertEq(returned, result, "verified result returned as-is");
    }

    function testResolveWithProofRejectsExpiry() public {
        bytes memory request = hex"deadbeef";
        bytes memory result = abi.encode(address(0xCAFE));
        vm.warp(1_000_000);
        uint64 expires = uint64(block.timestamp - 1);
        bytes memory response = signedResponse(request, result, expires);
        vm.expectRevert(abi.encodeWithSelector(PortalPrivResolver.SignatureExpired.selector, expires));
        resolver.resolveWithProof(response, request);
    }

    function testResolveWithProofRejectsAForeignSigner() public {
        bytes memory request = hex"deadbeef";
        bytes memory result = abi.encode(address(0xCAFE));
        uint64 expires = uint64(block.timestamp + 300);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, digestFor(request, result, expires));
        bytes memory response = abi.encode(result, expires, abi.encodePacked(r, s, v));
        vm.expectRevert(abi.encodeWithSelector(PortalPrivResolver.UntrustedSigner.selector, vm.addr(0xBAD)));
        resolver.resolveWithProof(response, request);
    }

    function testResolveWithProofRejectsATamperedResult() public {
        bytes memory request = hex"deadbeef";
        bytes memory result = abi.encode(address(0xCAFE));
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory honest = signedResponse(request, result, expires);
        (, uint64 sigExpires, bytes memory sig) = abi.decode(honest, (bytes, uint64, bytes));
        // Reuse the honest signature over a DIFFERENT result.
        bytes memory tampered = abi.encode(abi.encode(address(0xDEAD)), sigExpires, sig);
        vm.expectRevert();
        resolver.resolveWithProof(tampered, request);
    }

    function testResolveWithProofRejectsATamperedRequest() public {
        bytes memory request = hex"deadbeef";
        bytes memory result = abi.encode(address(0xCAFE));
        uint64 expires = uint64(block.timestamp + 300);
        bytes memory response = signedResponse(request, result, expires);
        vm.expectRevert();
        resolver.resolveWithProof(response, hex"beefdead");
    }

    function testOwnerRotatesSignerAndUrls() public {
        vm.prank(owner);
        resolver.setSigner(address(0x5162));
        assertEq(resolver.signer(), address(0x5162));
        string[] memory next = new string[](2);
        next[0] = "https://a.invalid/{sender}/{data}.json";
        next[1] = "https://b.invalid/{sender}/{data}.json";
        vm.prank(owner);
        resolver.setGatewayUrls(next);
        assertEq(resolver.urls().length, 2);
        vm.expectRevert();
        resolver.setSigner(address(0xDEAD)); // non-owner
    }

    function testSupportsEnsip10Interface() public view {
        assertTrue(resolver.supportsInterface(type(IExtendedResolver).interfaceId));
        assertTrue(resolver.supportsInterface(0x01ffc9a7));
        assertFalse(resolver.supportsInterface(0xdeadbeef));
    }
}
