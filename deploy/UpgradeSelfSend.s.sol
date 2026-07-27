// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";
import {ITransferVerifier} from "bongtu-src/interfaces/IVerifiers.sol";
import {TransferVerifier} from "bongtu-src/verifiers/TransferVerifier.sol";

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
/// Reads/updates `deploy/addresses.<chainid>.json` (only transferVerifier +
/// poolImpl change; EVERY other field — including arbiterKemPk when present —
/// is carried over verbatim).
/// Env:
///   DEPLOYER_KEY  (uint256)  must be the pool OWNER; default = anvil #0
///
/// LOCAL/testnet tool. The live GIWA upgrade must land together with the
/// per-output-nonce wallet (trial-decrypt nonce+i) — running this earlier would
/// strand every wallet's transfer on InvalidProof.
contract UpgradeSelfSend is Script {
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

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
        string memory path = string.concat("../deploy/addresses.", vm.toString(block.chainid), ".json");
        string memory aj = vm.readFile(path);

        Up memory u;
        u.pool = vm.parseJsonAddress(aj, ".pool");
        // Pre-upgrade state pinned BEFORE the swap, so the self-check proves
        // "only transferVerifier moved" against genuine before-values.
        u.dvBefore = address(BongtuPool(u.pool).depositVerifier());
        u.wvBefore = address(BongtuPool(u.pool).withdrawVerifier());
        u.dsvBefore = address(BongtuPool(u.pool).disburseVerifier());
        u.epochBefore = BongtuPool(u.pool).currentEpoch();
        (u.axBefore, u.ayBefore) = BongtuPool(u.pool).currentArbiterKey();
        u.kemPkHashBefore = BongtuPool(u.pool).arbiterKemPkHash(u.epochBefore);

        console2.log("== bongtu self-send upgrade ==");
        console2.log("chainId :", block.chainid);
        console2.log("pool    :", u.pool);
        console2.log("epoch   :", u.epochBefore);

        _upgrade(deployerKey, u);
        _selfCheck(u);
        _updateAddresses(aj, path, u);
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

    /// @dev Rewrite the addresses record: ONLY transferVerifier + poolImpl move;
    ///      every other field is copied from the existing file — including the
    ///      full `arbiterKemPk` bytes when present (the live-chain record carries
    ///      it; the UpgradePq rewrite once dropped it, so it is preserved here
    ///      explicitly and guarded by keyExists).
    function _updateAddresses(string memory aj, string memory path, Up memory u) internal {
        string memory o = "bongtu-selfsend-upgrade";
        vm.serializeUint(o, "chainId", vm.parseJsonUint(aj, ".chainId"));
        vm.serializeAddress(o, "owner", vm.parseJsonAddress(aj, ".owner"));
        vm.serializeUint(o, "batchSize", vm.parseJsonUint(aj, ".batchSize"));
        vm.serializeUint(o, "arbiterKeyX", vm.parseJsonUint(aj, ".arbiterKeyX"));
        vm.serializeUint(o, "arbiterKeyY", vm.parseJsonUint(aj, ".arbiterKeyY"));
        vm.serializeBytes32(o, "arbiterKemPkHash", vm.parseJsonBytes32(aj, ".arbiterKemPkHash"));
        if (vm.keyExists(aj, ".arbiterKemPk")) {
            vm.serializeBytes(o, "arbiterKemPk", vm.parseJsonBytes(aj, ".arbiterKemPk"));
        }
        vm.serializeAddress(o, "poseidon", vm.parseJsonAddress(aj, ".poseidon"));
        vm.serializeAddress(o, "depositVerifier", vm.parseJsonAddress(aj, ".depositVerifier"));
        vm.serializeAddress(o, "withdrawVerifier", vm.parseJsonAddress(aj, ".withdrawVerifier"));
        vm.serializeAddress(o, "disburseVerifier", vm.parseJsonAddress(aj, ".disburseVerifier"));
        vm.serializeAddress(o, "transferVerifier", u.tv);
        vm.serializeAddress(o, "token", vm.parseJsonAddress(aj, ".token"));
        vm.serializeAddress(o, "poolImpl", u.impl);
        string memory js = vm.serializeAddress(o, "pool", u.pool);
        vm.writeJson(js, path);
        console2.log("addresses ->", path);
    }
}
