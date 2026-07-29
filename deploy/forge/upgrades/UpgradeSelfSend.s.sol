// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";
import {ITransferVerifier} from "bongtu-src/interfaces/IVerifiers.sol";
import {TransferVerifier} from "bongtu-src/verifiers/TransferVerifier.sol";

import {AddressBook, AddressRecord} from "../AddressBook.sol";

/// @title UpgradeSelfSend — the UUPS migration of an ALREADY-PQ-UPGRADED
///        BongtuPool to the self-send transfer circuit (U-X3, §11-8 v1.1
///        per-output receiver nonce).
///
/// One atomic `upgradeToAndCall` per pool: deploy the regenerated
/// TransferVerifier and the new impl, then swap impl + ONLY the transfer
/// verifier via the `initializeV3` payload. No epoch is minted (the arbiter key
/// material is unchanged — an epoch boundary would falsely signal a key change).
/// Atomicity is load-bearing: the witness shape and 37-public count are
/// identical, but the vkey differs, so an old-circuit transfer proof fails
/// against the new verifier (and vice versa) — there must be no window where
/// impl and verifier disagree. deposit/withdraw/disburse are untouched.
///
/// Reads/updates `deploy/addresses.<chainid>.json` through `AddressBook`: only
/// transferVerifier + poolImpl are assigned, so EVERY other field — including
/// arbiterKemPk when present — is carried over by the merge.
/// Env:
///   DEPLOYER_KEY  (uint256)  must be the pool OWNER; default = anvil #0
///
/// LOCAL/testnet tool. The live GIWA upgrade must land together with the
/// per-output-nonce wallet (trial-decrypt nonce+i) — running this earlier would
/// strand every wallet's transfer on InvalidProof.
contract UpgradeSelfSend is Script {
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    // Initializable's ERC-7201 storage slot; its first word is `uint64
    // _initialized`, i.e. the reinitializer version the proxy has reached
    // (contracts/src/utils/proxy/Initializable.sol).
    bytes32 constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    // Bundled locals: run() + the JSON round-trip together blow the EVM stack
    // in a single frame (non-via-IR build), so everything flows via memory.
    struct Up {
        address pool;
        address tv;
        address impl;
        address dvBefore;
        address wvBefore;
        address dsvBefore;
        uint256 epochBefore;
        uint256 axBefore;
        uint256 ayBefore;
        bytes32 kemPkHashBefore;
    }

    function run() external {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        string memory path = AddressBook.path();
        AddressRecord memory r = AddressBook.read(path);

        Up memory u;
        u.pool = r.pool;
        // Pre-upgrade state pinned BEFORE the swap, so the self-check proves
        // "only transferVerifier moved" against genuine before-values.
        u.dvBefore = address(BongtuPool(u.pool).depositVerifier());
        u.wvBefore = address(BongtuPool(u.pool).withdrawVerifier());
        u.dsvBefore = address(BongtuPool(u.pool).disburseVerifier());
        u.epochBefore = BongtuPool(u.pool).currentEpoch();
        (u.axBefore, u.ayBefore) = BongtuPool(u.pool).currentArbiterKey();
        u.kemPkHashBefore = BongtuPool(u.pool).arbiterKemPkHash(u.epochBefore);
        // initializeV3 is reinitializer(3), which only requires version < 3: it
        // would run just as happily on a pool that never took the V2 payload, and
        // burning the version to 3 puts initializeV2 permanently out of reach —
        // the pool would keep its pre-PQ deposit/withdraw/disburse verifiers with
        // no way to swap them. So the V2-then-V3 ordering that BongtuPool's
        // initializeV3 comment says "is pinned by the deploy scripts" is asserted
        // here, from the initializer version itself (the pool exposes no getter,
        // and a nonzero KEM hash is not the marker — initialize() sets one at
        // epoch 0 on a fresh deploy that is still version 1).
        uint64 version = uint64(uint256(vm.load(u.pool, INITIALIZABLE_STORAGE)));
        require(version >= 2, "pool is pre-V2: run UpgradePq first");

        console2.log("== bongtu self-send upgrade ==");
        console2.log("chainId :", block.chainid);
        console2.log("pool    :", u.pool);
        console2.log("epoch   :", u.epochBefore);

        _upgrade(deployerKey, u);
        _selfCheck(u);
        _updateAddresses(path, r, u);
        console2.log("SELF-SEND UPGRADE OK -> transferVerifier", u.tv);
    }

    function _upgrade(uint256 deployerKey, Up memory u) internal {
        vm.startBroadcast(deployerKey);
        u.tv = address(new TransferVerifier());
        u.impl = address(new BongtuPool());
        BongtuPool(u.pool).upgradeToAndCall(
            u.impl, abi.encodeCall(BongtuPool.initializeV3, (ITransferVerifier(u.tv)))
        );
        vm.stopBroadcast();
    }

    /// @dev Post-upgrade self-check against the LIVE proxy state: the transfer
    ///      verifier swapped; the other three verifiers, the arbiter bjj key,
    ///      the KEM pk hash and the epoch are all UNCHANGED (no key rotation).
    function _selfCheck(Up memory u) internal view {
        BongtuPool pool = BongtuPool(u.pool);
        require(address(pool.transferVerifier()) == u.tv, "transfer verifier not swapped");
        require(address(pool.depositVerifier()) == u.dvBefore, "deposit verifier must not change");
        require(address(pool.withdrawVerifier()) == u.wvBefore, "withdraw verifier must not change");
        require(address(pool.disburseVerifier()) == u.dsvBefore, "disburse verifier must not change");
        require(pool.currentEpoch() == u.epochBefore, "no epoch may be minted");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        require(kx == u.axBefore && ky == u.ayBefore, "arbiter bjj key must not change");
        require(pool.arbiterKemPkHash(pool.currentEpoch()) == u.kemPkHashBefore, "kem pk hash must not change");
    }

    /// @dev Merge into the addresses record: ONLY transferVerifier + poolImpl are
    ///      assigned; every other field — including the full `arbiterKemPk` bytes
    ///      the live-chain record carries — rides along in the AddressRecord that
    ///      was read at the top of run(). The UpgradePq rewrite once dropped that
    ///      field by restating the file field-by-field; there is nothing to
    ///      restate here any more.
    function _updateAddresses(string memory path, AddressRecord memory r, Up memory u) internal {
        r.transferVerifier = u.tv;
        r.poolImpl = u.impl;
        AddressBook.write(path, r);
        console2.log("addresses ->", path);
    }
}
