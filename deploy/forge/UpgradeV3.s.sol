// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";

import {AddressBook, AddressRecord} from "./AddressBook.sol";
import {ConsumerModuleKit, ConsumerModuleRecord} from "./ConsumerModuleKit.sol";

/// @title UpgradeV3 — ship the op-module layer (OPMOD §7) to an EXISTING pool
///        as the UUPS upgrade the repo rules prescribe (CLAUDE.md: the live
///        pool is canonical, never redeployed).
///
/// One broadcast against the pool recorded in `deploy/addresses.<chainid>.json`:
///   1. (MODULE_PROFILE=consumer, the default) deploy the five consumer
///      verifiers + five module contracts via ConsumerModuleKit — modules are
///      inert until registered, so these deploys carry no sequencing risk;
///   2. deploy the new `BongtuPool` implementation (applyOp* + module registry
///      + reinitializeV3; the six enterprise entrypoints byte-identical);
///   3. `upgradeToAndCall(impl, reinitializeV3(modules))` — the ONE migration
///      transaction (OPMOD §7.3). Unlike UpgradeV2 there is NO verifier-swap
///      atomicity constraint: the enterprise verifiers are untouched, so
///      enterprise ops keep verifying before, during and after.
///
/// MODULE_PROFILE:
///   consumer (default)  register the five consumer modules
///   none                register nothing (audited-only posture on the new
///                       impl: reinitializeV3 runs with an empty list, so the
///                       version slot is consumed and no module can later be
///                       snuck in through a stale reinitializer — additions go
///                       through the event-logged onlyOwner registerModule)
///
/// The broadcast key must be the pool's OWNER (`_authorizeUpgrade` and
/// `reinitializeV3` are both onlyOwner) — on anvil the account-0 default IS
/// the owner `deploy_local.sh` installed, so the drill needs no env.
///
/// Post-state is read back and asserted (version slot == 3, every module
/// registered, and the storage an implementation swap must carry: tree head,
/// batch size, token, owner, arbiter key + epoch, withdraw verifier). The
/// addresses file is merge-written (only `poolImpl` changes); the module set
/// is recorded in `deploy/modules.<chainid>.json`.
contract UpgradeV3 is Script {
    // anvil account 0 (public dev key) — matches Deploy.s.sol; the live run
    // overrides with the funded owner key from .env.
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    // Initializable's ERC-7201 storage slot; low 8 bytes = uint64 _initialized.
    bytes32 constant INIT_SLOT = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    /// @dev Pre-upgrade state an implementation swap must carry untouched
    ///      (gathered into a struct: `run` is frame-budgeted under non-via-IR
    ///      solc, the deploy scripts' standing constraint).
    struct PreState {
        uint256 leaf;
        uint256 root;
        uint256 epoch;
        address withdrawVerifier;
    }

    function run() external returns (address newImpl) {
        uint256 ownerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        bool consumer = _isConsumer(vm.envOr("MODULE_PROFILE", string("consumer")));
        AddressRecord memory r = AddressBook.read(AddressBook.path());

        _guards(r, ownerKey);
        PreState memory pre = _snapshot(r);

        (ConsumerModuleRecord memory mods, address impl) = _broadcast(ownerKey, r, consumer);

        _assertPost(r, pre, mods, consumer);
        _record(r, mods, impl, consumer);
        return impl;
    }

    /// @dev Refuse a key that is not the recorded owner BEFORE broadcasting
    ///      (orphan deploys would land and pay gas, then the upgrade call
    ///      would revert), and refuse a pool already past version 2: the live
    ///      pool sits at 2 (the stealth-withdraw upgrade), a fresh anvil
    ///      deploy at 1 — both upgrade cleanly, reinitializer(3) runs once.
    function _guards(AddressRecord memory r, uint256 ownerKey) private view {
        require(vm.addr(ownerKey) == r.owner, "DEPLOYER_KEY is not the recorded pool owner");
        uint64 v = uint64(uint256(vm.load(r.pool, INIT_SLOT)));
        require(v >= 1 && v < 3, "pool already reinitialized past v2");
    }

    function _snapshot(AddressRecord memory r) private view returns (PreState memory pre) {
        BongtuPool pool = BongtuPool(r.pool);
        pre.leaf = pool.nextLeafIndex();
        pre.root = pool.root();
        pre.epoch = pool.currentEpoch();
        pre.withdrawVerifier = address(pool.withdrawVerifier());
    }

    function _broadcast(uint256 ownerKey, AddressRecord memory r, bool consumer)
        private
        returns (ConsumerModuleRecord memory mods, address impl)
    {
        BongtuPool pool = BongtuPool(r.pool);
        uint256 chunkArity = vm.envOr("MODULE_CHUNK_ARITY", ConsumerModuleKit.defaultChunkArity(pool.B()));
        vm.startBroadcast(ownerKey);
        address[] memory registerList = new address[](0);
        if (consumer) {
            mods = ConsumerModuleKit.deploySet(pool, chunkArity);
            registerList = ConsumerModuleKit.modulesArray(mods);
        }
        BongtuPool newPool = new BongtuPool();
        pool.upgradeToAndCall(address(newPool), abi.encodeCall(BongtuPool.reinitializeV3, (registerList)));
        vm.stopBroadcast();
        impl = address(newPool);
    }

    /// @dev Post-state asserts — read back from the chain, not from memory.
    function _assertPost(
        AddressRecord memory r,
        PreState memory pre,
        ConsumerModuleRecord memory mods,
        bool consumer
    ) private view {
        BongtuPool pool = BongtuPool(r.pool);
        require(uint64(uint256(vm.load(r.pool, INIT_SLOT))) == 3, "reinitializer(3) did not run");
        if (consumer) {
            address[] memory list = ConsumerModuleKit.modulesArray(mods);
            for (uint256 i = 0; i < list.length; i++) {
                require(pool.registeredModules(list[i]), "module not registered post-upgrade");
            }
        }
        require(pool.owner() == r.owner, "owner changed across upgrade");
        require(pool.B() == r.batchSize, "batchSize lost across upgrade");
        require(address(pool.token()) == r.token, "token lost across upgrade");
        require(pool.nextLeafIndex() == pre.leaf, "tree head moved across upgrade");
        require(pool.root() == pre.root, "tree root moved across upgrade");
        require(pool.currentEpoch() == pre.epoch, "arbiter epoch moved across upgrade");
        require(address(pool.withdrawVerifier()) == pre.withdrawVerifier, "withdraw verifier changed");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        require(kx == r.arbiterKeyX && ky == r.arbiterKeyY, "arbiter key lost across upgrade");
    }

    function _record(
        AddressRecord memory r,
        ConsumerModuleRecord memory mods,
        address impl,
        bool consumer
    ) private {
        r.poolImpl = impl;
        AddressBook.write(AddressBook.path(), r);
        if (consumer) {
            ConsumerModuleKit.write(ConsumerModuleKit.path(), mods);
            console2.log("modules ->", ConsumerModuleKit.path());
            console2.log("depositPrivModule      :", mods.depositPrivModule);
            console2.log("transferPrivModule     :", mods.transferPrivModule);
            console2.log("transfer10x2PrivModule :", mods.transfer10x2PrivModule);
            console2.log("withdrawPrivModule     :", mods.withdrawPrivModule);
            console2.log("consumerDisburseModule :", mods.consumerDisburseModule);
        }
        console2.log("poolImpl:", impl);
    }

    function _isConsumer(string memory profile) private pure returns (bool) {
        bytes32 h = keccak256(bytes(profile));
        if (h == keccak256("consumer")) return true;
        require(h == keccak256("none"), "MODULE_PROFILE must be 'consumer' or 'none'");
        return false;
    }
}
