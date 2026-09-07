// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {PortalPrivFactory} from "bongtu-src/PortalPrivFactory.sol";

import {AddressBook, AddressRecord} from "./AddressBook.sol";

/// @title DeployPortalPriv — the consumer portal factory as an ADD-ON deploy.
///
/// One broadcast, one contract: `PortalPrivFactory(bot)` next to the pool recorded
/// in `deploy/addresses.<chainid>.json`. The pool is not touched — the factory
/// only ever drives the (already registered, permissionless) depositPriv
/// module — which is why this is a standalone script and not an upgrade
/// payload. Unlike DeployPortal it ALSO requires the consumer module set: a
/// priv factory on a chain without a recorded `depositPrivModule` could
/// never complete a sweep, so the missing record is refused at deploy time
/// rather than discovered at the first sweep.
///
/// BOT (env, address) is the sweep operator/owner; it defaults to the
/// broadcaster because on this deployment the institution runs both keys.
/// Rerun-guarded: a record that already carries a priv factory is refused —
/// a second factory would strand every announcement issued against the first
/// (the CREATE2 destination is a function of the factory address).
contract DeployPortalPriv is Script {
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run() external returns (address factory) {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        AddressRecord memory r = AddressBook.read(AddressBook.path());
        require(r.portalPrivFactory == address(0), "portalPriv factory already recorded for this chain");
        require(r.pool != address(0), "no pool recorded");
        address depositPrivModule = _depositPrivModule();
        require(depositPrivModule != address(0), "no depositPrivModule recorded (deploy the consumer module set first)");
        address bot = vm.envOr("BOT", vm.addr(deployerKey));

        console2.log("== bongtu portalPriv factory deploy ==");
        console2.log("chainId          :", block.chainid);
        console2.log("pool             :", r.pool);
        console2.log("depositPrivModule:", depositPrivModule);
        console2.log("bot              :", bot);

        vm.startBroadcast(deployerKey);
        PortalPrivFactory f = new PortalPrivFactory(bot);
        vm.stopBroadcast();

        require(f.owner() == bot, "factory owner != bot");
        require(f.sweeperInitCodeHash() != bytes32(0), "sweeper initcode hash empty");

        r.portalPrivFactory = address(f);
        AddressBook.write(AddressBook.path(), r);
        console2.log("portalPrivFactory:", address(f));
        return address(f);
    }

    /// @dev The consumer module record lives in its own file (see
    ///      ConsumerModuleKit's header for why it is not in the AddressBook);
    ///      only the one module the sweep drives is needed here.
    function _depositPrivModule() internal view returns (address) {
        string memory p = string.concat("../../deploy/modules.", vm.toString(block.chainid), ".json");
        if (!vm.exists(p)) return address(0);
        return vm.parseJsonAddress(vm.readFile(p), ".depositPrivModule");
    }
}
