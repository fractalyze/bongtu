// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {PortalPrivResolver} from "bongtu-src/PortalPrivResolver.sol";

import {ConsumerBook, ConsumerRecord} from "./ConsumerBook.sol";

/// @title DeployNameResolver — the payment name's CCIP resolver as an ADD-ON
///        deploy over the consumer record.
///
/// One broadcast, one contract: `PortalPrivResolver(owner, signer, [url])`
/// next to the consumer pool. The pool and factory are untouched; the
/// resolver holds no name or address state, so this deploy only pins WHO may
/// sign gateway answers and WHERE wallets fetch them. Rerun-guarded like
/// DeployPortalPriv: a second resolver would not strand funds (resolution is
/// stateless) but WOULD fork the record's signer/URL truth, so replacing one
/// is `setSigner`/`setGatewayUrls` on the recorded contract, not a redeploy.
///
/// Env: DEPLOYER_KEY (default anvil 0); GATEWAY_URL (required — the public
/// HTTPS endpoint serving /ens, with `{sender}`/`{data}` placeholders);
/// GATEWAY_SIGNER (address; default = the deployer, the demo posture where
/// one operator holds both keys); BOT (owner; default = the deployer).
contract DeployNameResolver is Script {
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run() external returns (address resolver) {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        ConsumerRecord memory r = ConsumerBook.read(ConsumerBook.path());
        require(r.resolver == address(0), "resolver already recorded for this chain");
        require(r.pool != address(0), "no pool recorded");
        require(r.portalPrivFactory != address(0), "no portalPrivFactory recorded (deploy it first: the gateway derives against it)");
        string memory url = vm.envString("GATEWAY_URL");
        address signer = vm.envOr("GATEWAY_SIGNER", vm.addr(deployerKey));
        address owner = vm.envOr("BOT", vm.addr(deployerKey));

        console2.log("== bongtu name resolver deploy (consumer profile) ==");
        console2.log("chainId:", block.chainid);
        console2.log("owner  :", owner);
        console2.log("signer :", signer);
        console2.log("url    :", url);

        string[] memory urls = new string[](1);
        urls[0] = url;
        vm.startBroadcast(deployerKey);
        PortalPrivResolver deployed = new PortalPrivResolver(owner, signer, urls);
        vm.stopBroadcast();

        require(deployed.signer() == signer, "signer not wired");
        require(deployed.owner() == owner, "owner not wired");
        require(deployed.supportsInterface(0x9061b923), "ENSIP-10 interface missing");

        r.resolver = address(deployed);
        r.gatewaySigner = signer;
        r.gatewayUrl = url;
        ConsumerBook.write(ConsumerBook.path(), r);
        console2.log("resolver:", address(deployed));
        return address(deployed);
    }
}
