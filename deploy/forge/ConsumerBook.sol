// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {VmSafe} from "forge-std/Vm.sol";

/// @notice The consumer-profile deployment record — the complete field list of
///         `deploy/addresses.consumer.<chainid>.json`, declared ONCE (the
///         AddressBook rationale: merge-writes that restate fields by hand
///         silently drop the ones they forget).
///
/// The base seven fields are what `DeployConsumerOnly` produces and are
/// required on every record. The rest are ADD-ONS deployed by later scripts,
/// ABSENT until their deploy runs (a zero address here would claim a contract
/// the chain does not have): `portalPrivFactory` from `DeployPortalPriv`, and
/// the resolver triple from `DeployNameResolver` (the gateway signer and URL
/// ride with the resolver because rotating either is a resolver operation).
struct ConsumerRecord {
    uint256 chainId;
    address owner;
    uint256 batchSize;
    address poseidon;
    address token;
    address poolImpl;
    address pool;
    address portalPrivFactory; // optional add-on
    address resolver; // optional add-on (PortalPrivResolver)
    address gatewaySigner; // optional, rides with resolver
    string gatewayUrl; // optional, rides with resolver
}

/// @title ConsumerBook — read/merge-write of the consumer-profile record.
library ConsumerBook {
    VmSafe private constant vm = VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));

    function path() internal view returns (string memory) {
        return string.concat("../../deploy/addresses.consumer.", vm.toString(block.chainid), ".json");
    }

    function modulesPath() internal view returns (string memory) {
        return string.concat("../../deploy/modules.consumer.", vm.toString(block.chainid), ".json");
    }

    function exists() internal view returns (bool) {
        return vm.exists(path());
    }

    function read(string memory p) internal view returns (ConsumerRecord memory r) {
        string memory j = vm.readFile(p);
        r.chainId = vm.parseJsonUint(j, ".chainId");
        r.owner = vm.parseJsonAddress(j, ".owner");
        r.batchSize = vm.parseJsonUint(j, ".batchSize");
        r.poseidon = vm.parseJsonAddress(j, ".poseidon");
        r.token = vm.parseJsonAddress(j, ".token");
        r.poolImpl = vm.parseJsonAddress(j, ".poolImpl");
        r.pool = vm.parseJsonAddress(j, ".pool");
        if (vm.keyExists(j, ".portalPrivFactory")) r.portalPrivFactory = vm.parseJsonAddress(j, ".portalPrivFactory");
        if (vm.keyExists(j, ".resolver")) r.resolver = vm.parseJsonAddress(j, ".resolver");
        if (vm.keyExists(j, ".gatewaySigner")) r.gatewaySigner = vm.parseJsonAddress(j, ".gatewaySigner");
        if (vm.keyExists(j, ".gatewayUrl")) r.gatewayUrl = vm.parseJsonString(j, ".gatewayUrl");
    }

    function write(string memory p, ConsumerRecord memory r) internal {
        string memory o = "bongtu-consumer-book";
        vm.serializeUint(o, "chainId", r.chainId);
        vm.serializeAddress(o, "owner", r.owner);
        vm.serializeUint(o, "batchSize", r.batchSize);
        vm.serializeAddress(o, "poseidon", r.poseidon);
        vm.serializeAddress(o, "token", r.token);
        vm.serializeAddress(o, "poolImpl", r.poolImpl);
        if (r.portalPrivFactory != address(0)) vm.serializeAddress(o, "portalPrivFactory", r.portalPrivFactory);
        if (r.resolver != address(0)) {
            vm.serializeAddress(o, "resolver", r.resolver);
            vm.serializeAddress(o, "gatewaySigner", r.gatewaySigner);
            vm.serializeString(o, "gatewayUrl", r.gatewayUrl);
        }
        string memory js = vm.serializeAddress(o, "pool", r.pool);
        vm.writeJson(js, p);
    }
}
