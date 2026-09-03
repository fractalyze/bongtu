// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";
import {ERC1967Proxy} from "bongtu-src/utils/proxy/ERC1967Proxy.sol";
import {IPoseidon2} from "bongtu-src/interfaces/IPoseidon2.sol";
import {IERC20} from "bongtu-src/utils/IERC20.sol";
import {MockERC20} from "bongtu-test/mocks/MockERC20.sol";

import {ConsumerModuleKit, ConsumerModuleRecord} from "./ConsumerModuleKit.sol";

/// @title DeployConsumerOnly — the CONSUMER-ONLY deploy profile (OPMOD §9
///        resolved default; issue #6 acceptance: "a consumer-only profile
///        initializes with no arbiter key at all").
///
/// Deploys, in one broadcast:
///   1. Poseidon-v1 (circomlibjs creation bytecode — same artifact as Deploy.s.sol);
///   2. a mock kKRW (or TOKEN_ADDRESS);
///   3. `BongtuPool(B)` behind an ERC-1967 proxy running
///      `initializeConsumerOnly` — NO arbiter epoch, NO KEM pk hash, NO
///      enterprise verifier: no auditor key exists on this pool, and every
///      enterprise entrypoint reverts;
///   4. the five consumer verifiers + five modules (ConsumerModuleKit), each
///      registered via the event-logged onlyOwner `registerModule` — the
///      module family is the pool's whole op surface.
///
/// Deliberately NOT AddressBook-recorded: the enterprise record's field list
/// requires the six verifiers + arbiter material this profile does not have.
/// The record goes to `deploy/addresses.consumer.<chainid>.json` and the
/// module set to `deploy/modules.consumer.<chainid>.json`.
///
/// Env: DEPLOYER_KEY (default anvil 0), BATCH_SIZE (default 256),
///      TOKEN_ADDRESS (default: deploy a mock), MODULE_CHUNK_ARITY
///      (default: the OPMOD §5 chunk arity for B).
contract DeployConsumerOnly is Script {
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    /// @dev Everything one broadcast produced, gathered into a struct: the
    ///      deploy scripts are frame-budgeted under non-via-IR solc.
    struct Deployed {
        address poseidon;
        address token;
        address impl;
        BongtuPool pool;
        ConsumerModuleRecord mods;
    }

    function run() external returns (address poolAddr) {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        uint256 batchSize = vm.envOr("BATCH_SIZE", uint256(256));

        console2.log("== bongtu CONSUMER-ONLY deploy (no arbiter key exists) ==");
        console2.log("chainId  :", block.chainid);
        console2.log("deployer :", vm.addr(deployerKey));
        console2.log("batchSize:", batchSize);

        Deployed memory d = _broadcast(deployerKey, batchSize);
        _selfCheck(d, vm.addr(deployerKey), batchSize);
        _writeRecords(d, vm.addr(deployerKey), batchSize);
        _log(d);
        return address(d.pool);
    }

    function _broadcast(uint256 deployerKey, uint256 batchSize) private returns (Deployed memory d) {
        vm.startBroadcast(deployerKey);
        d.poseidon = _deployPoseidon();
        address tokenEnv = vm.envOr("TOKEN_ADDRESS", address(0));
        d.token = tokenEnv == address(0) ? address(new MockERC20()) : tokenEnv;

        BongtuPool impl = new BongtuPool();
        d.impl = address(impl);
        d.pool = BongtuPool(
            address(
                new ERC1967Proxy(
                    address(impl),
                    abi.encodeCall(
                        BongtuPool.initializeConsumerOnly, (IPoseidon2(d.poseidon), IERC20(d.token), batchSize)
                    )
                )
            )
        );

        uint256 chunkArity = vm.envOr("MODULE_CHUNK_ARITY", ConsumerModuleKit.defaultChunkArity(batchSize));
        d.mods = ConsumerModuleKit.deploySet(d.pool, chunkArity);
        address[] memory list = ConsumerModuleKit.modulesArray(d.mods);
        for (uint256 i = 0; i < list.length; i++) {
            d.pool.registerModule(list[i]);
        }
        vm.stopBroadcast();
    }

    /// @dev The profile's shape, read back from the chain.
    function _selfCheck(Deployed memory d, address deployer, uint256 batchSize) private view {
        require(d.pool.B() == batchSize, "batchSize mismatch");
        require(d.pool.owner() == deployer, "owner != deployer");
        require(d.pool.initialized(), "pool not initialized");
        require(address(d.pool.token()) == d.token, "token not wired");
        require(address(d.pool.depositVerifier()) == address(0), "an enterprise verifier exists on consumer-only");
        require(d.pool.arbiterKemPkHash(0) == bytes32(0), "KEM epoch material exists on consumer-only");
        address[] memory list = ConsumerModuleKit.modulesArray(d.mods);
        for (uint256 i = 0; i < list.length; i++) {
            require(d.pool.registeredModules(list[i]), "module not registered");
        }
    }

    function _writeRecords(Deployed memory d, address deployer, uint256 batchSize) private {
        string memory o = "bongtu-consumer-only";
        vm.serializeUint(o, "chainId", block.chainid);
        vm.serializeAddress(o, "owner", deployer);
        vm.serializeUint(o, "batchSize", batchSize);
        vm.serializeAddress(o, "poseidon", d.poseidon);
        vm.serializeAddress(o, "token", d.token);
        vm.serializeAddress(o, "poolImpl", d.impl);
        string memory js = vm.serializeAddress(o, "pool", address(d.pool));
        vm.writeJson(js, string.concat("../deploy/addresses.consumer.", vm.toString(block.chainid), ".json"));
        ConsumerModuleKit.write(
            string.concat("../deploy/modules.consumer.", vm.toString(block.chainid), ".json"), d.mods
        );
    }

    function _log(Deployed memory d) private pure {
        console2.log("poseidon:", d.poseidon);
        console2.log("token   :", d.token);
        console2.log("poolImpl:", d.impl);
        console2.log("pool    :", address(d.pool));
    }

    function _deployPoseidon() private returns (address p) {
        bytes memory code = vm.parseBytes(vm.readFile("test/fixtures/poseidon2.hex"));
        assembly {
            p := create(0, add(code, 0x20), mload(code))
        }
        require(p != address(0), "poseidon deploy failed");
    }
}
