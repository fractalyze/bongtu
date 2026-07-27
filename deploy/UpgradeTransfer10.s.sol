// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";
import {ITransfer10Verifier} from "bongtu-src/interfaces/IVerifiers.sol";
import {Transfer10Verifier} from "bongtu-src/verifiers/Transfer10Verifier.sol";

import {AddressBook, AddressRecord} from "./AddressBook.sol";

/// @title UpgradeTransfer10 — the UUPS migration of an ALREADY-SELF-SEND-UPGRADED
///        BongtuPool to the transfer10 (10-in / 10-out) entry point (U-Z1).
///
/// One atomic `upgradeToAndCall` per pool: deploy the Transfer10Verifier and the
/// new impl, then swap impl + install the NEW verifier via the `initializeV4`
/// payload. Unlike the two upgrades before it this is purely ADDITIVE — nothing
/// that worked before the tx behaves differently after it. `transfer10` is a new
/// entry point behind a new verifier; the 2-in `transfer` keeps its own verifier
/// and its own vkey, and deposit/withdraw/disburse are untouched. No epoch is
/// minted (no arbiter key material changes).
///
/// Atomicity still matters, for the opposite reason to the earlier scripts: a
/// bare `upgradeTo` would leave the new impl live with `transfer10Verifier` still
/// zero, so every `transfer10` would revert on a call to address(0) — a pool that
/// advertises the entry point and cannot serve it.
///
/// Ordering pre-flight (the V2/V3 lesson): `initializeV4` is `reinitializer(4)`,
/// which only requires version < 4. It would therefore run just as happily on a
/// pool that never took V2 or V3, and burning the version to 4 puts BOTH of those
/// payloads permanently out of reach — leaving the pool on its pre-PQ verifiers
/// or its pre-self-send transfer vkey with no way to swap them. BongtuPool's
/// `initializeV4` natspec names this script as where that ordering is enforced,
/// so the version is read out of the Initializable slot here and anything below
/// 3 is refused.
///
/// Reads/updates `deploy/addresses.<chainid>.json` through `AddressBook`: only
/// transfer10Verifier + poolImpl are assigned, so EVERY other field — including
/// arbiterKemPk when present — is carried over by the merge. `transfer10Verifier`
/// is an optional field of that record and this is the script that first writes
/// it; a chain that has not run this has no such key at all.
/// Env:
///   DEPLOYER_KEY  (uint256)  must be the pool OWNER; default = anvil #0
contract UpgradeTransfer10 is Script {
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    // Initializable's ERC-7201 storage slot; its first word is `uint64
    // _initialized`, i.e. the reinitializer version the proxy has reached
    // (contracts/src/utils/proxy/Initializable.sol).
    bytes32 constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    // Bundled locals: run() + the JSON round-trip together blow the EVM stack
    // in a single frame (non-via-IR build), so everything flows via memory.
    struct Up {
        address pool;
        address tv10;
        address impl;
        address dvBefore;
        address wvBefore;
        address dsvBefore;
        address tvBefore;
        uint256 epochBefore;
        uint256 axBefore;
        uint256 ayBefore;
        bytes32 kemPkHashBefore;
        uint256 rootBefore;
        uint256 nextLeafIndexBefore;
    }

    function run() external {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        string memory path = AddressBook.path();
        AddressRecord memory r = AddressBook.read(path);

        Up memory u;
        u.pool = r.pool;
        _preflight(u);

        console2.log("== bongtu transfer10 upgrade ==");
        console2.log("chainId :", block.chainid);
        console2.log("pool    :", u.pool);
        console2.log("epoch   :", u.epochBefore);

        _upgrade(deployerKey, u);
        _selfCheck(u);
        _updateAddresses(path, r, u);
        console2.log("TRANSFER10 UPGRADE OK -> transfer10Verifier", u.tv10);
    }

    /// @dev Everything asserted BEFORE the broadcast, plus the before-values the
    ///      self-check compares against. Pinning them here (not inside
    ///      `_upgrade`) is what makes "only transfer10Verifier moved" a claim
    ///      about genuine pre-upgrade state rather than a tautology.
    ///
    ///      The tree state (`root`, `nextLeafIndex`) joins the verifier and key
    ///      material this time: V4 is the first upgrade to append a storage slot
    ///      since V2's `arbiterKemPkHash`, and a mis-declared slot would re-stride
    ///      the IMT fields rather than announce itself. A moved root is what that
    ///      corruption looks like from outside.
    function _preflight(Up memory u) internal view {
        BongtuPool pool = BongtuPool(u.pool);
        u.dvBefore = address(pool.depositVerifier());
        u.wvBefore = address(pool.withdrawVerifier());
        u.dsvBefore = address(pool.disburseVerifier());
        u.tvBefore = address(pool.transferVerifier());
        u.epochBefore = pool.currentEpoch();
        (u.axBefore, u.ayBefore) = pool.currentArbiterKey();
        u.kemPkHashBefore = pool.arbiterKemPkHash(u.epochBefore);
        u.rootBefore = pool.root();
        u.nextLeafIndexBefore = pool.nextLeafIndex();

        // The version slot answers both ordering questions, and it is the only
        // thing that can: a pre-V4 pool runs an impl that predates the
        // `transfer10Verifier` getter, so READING the verifier to decide
        // "already upgraded?" reverts on exactly the pools that most need the
        // answer. `initializeV4` is the sole writer of that slot's V4 step, so
        // version < 4 IS "the verifier is still zero". Refusing here also turns
        // the already-applied case into a sentence instead of a reinitializer
        // revert deep inside `upgradeToAndCall`, after paying for two deploys.
        uint64 version = uint64(uint256(vm.load(u.pool, INITIALIZABLE_STORAGE)));
        require(version >= 3, "pool is pre-V3: run UpgradeSelfSend first");
        require(version < 4, "pool is already V4: transfer10 verifier installed");
    }

    function _upgrade(uint256 deployerKey, Up memory u) internal {
        vm.startBroadcast(deployerKey);
        u.tv10 = address(new Transfer10Verifier());
        u.impl = address(new BongtuPool());
        BongtuPool(u.pool).upgradeToAndCall(
            u.impl, abi.encodeCall(BongtuPool.initializeV4, (ITransfer10Verifier(u.tv10)))
        );
        vm.stopBroadcast();
    }

    /// @dev Post-upgrade self-check against the LIVE proxy state: transfer10 is
    ///      now served, and NOTHING else moved — the four earlier verifiers, the
    ///      arbiter bjj key, the KEM pk hash, the epoch, and the IMT root +
    ///      nextLeafIndex all read back exactly as pinned in `_preflight`.
    function _selfCheck(Up memory u) internal view {
        BongtuPool pool = BongtuPool(u.pool);
        require(address(pool.transfer10Verifier()) == u.tv10, "transfer10 verifier not installed");
        require(address(pool.depositVerifier()) == u.dvBefore, "deposit verifier must not change");
        require(address(pool.withdrawVerifier()) == u.wvBefore, "withdraw verifier must not change");
        require(address(pool.disburseVerifier()) == u.dsvBefore, "disburse verifier must not change");
        require(address(pool.transferVerifier()) == u.tvBefore, "transfer verifier must not change");
        require(pool.currentEpoch() == u.epochBefore, "no epoch may be minted");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        require(kx == u.axBefore && ky == u.ayBefore, "arbiter bjj key must not change");
        require(pool.arbiterKemPkHash(pool.currentEpoch()) == u.kemPkHashBefore, "kem pk hash must not change");
        require(pool.root() == u.rootBefore, "imt root moved: storage layout mismatch");
        require(pool.nextLeafIndex() == u.nextLeafIndexBefore, "nextLeafIndex moved: storage layout mismatch");
    }

    /// @dev Merge into the addresses record: ONLY transfer10Verifier + poolImpl
    ///      are assigned; every other field rides along in the AddressRecord read
    ///      at the top of run().
    function _updateAddresses(string memory path, AddressRecord memory r, Up memory u) internal {
        r.transfer10Verifier = u.tv10;
        r.poolImpl = u.impl;
        AddressBook.write(path, r);
        console2.log("addresses ->", path);
    }
}
