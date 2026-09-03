// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {PortalFactory} from "bongtu-src/PortalFactory.sol";

import {AddressBook, AddressRecord} from "./AddressBook.sol";

/// @title DeployPortal — the portal factory as an ADD-ON deploy (slice ⑤).
///
/// One broadcast, one contract: `PortalFactory(bot)` next to the pool recorded
/// in `deploy/addresses.<chainid>.json`. The pool is not touched — deposit is
/// permissionless and the factory only ever calls it — which is why this is a
/// standalone script and not an upgrade payload.
///
/// BOT (env, address) is the sweep operator/owner; it defaults to the
/// broadcaster because on this deployment the institution runs both keys.
/// Rerun-guarded: a record that already carries a factory is refused — a
/// second factory would strand every announcement issued against the first
/// (the CREATE2 destination is a function of the factory address).
contract DeployPortal is Script {
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run() external returns (address factory) {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        AddressRecord memory r = AddressBook.read(AddressBook.path());
        require(r.portalFactory == address(0), "portal factory already recorded for this chain");
        require(r.pool != address(0), "no pool recorded");
        address bot = vm.envOr("BOT", vm.addr(deployerKey));

        console2.log("== bongtu portal factory deploy ==");
        console2.log("chainId :", block.chainid);
        console2.log("pool    :", r.pool);
        console2.log("bot     :", bot);

        vm.startBroadcast(deployerKey);
        PortalFactory f = new PortalFactory(bot);
        vm.stopBroadcast();

        require(f.owner() == bot, "factory owner != bot");
        require(f.sweeperInitCodeHash() != bytes32(0), "sweeper initcode hash empty");

        r.portalFactory = address(f);
        AddressBook.write(AddressBook.path(), r);
        console2.log("portalFactory   :", address(f));
        return address(f);
    }
}
