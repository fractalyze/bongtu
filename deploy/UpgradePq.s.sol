// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier
} from "bongtu-src/interfaces/IVerifiers.sol";
import {DepositVerifier} from "bongtu-src/verifiers/DepositVerifier.sol";
import {WithdrawVerifier} from "bongtu-src/verifiers/WithdrawVerifier.sol";
import {Disburse256Verifier} from "bongtu-src/verifiers/Disburse256Verifier.sol";
import {TransferVerifier} from "bongtu-src/verifiers/TransferVerifier.sol";

import {AddressBook, AddressRecord} from "./AddressBook.sol";

/// @title UpgradePq — the UUPS migration of an ALREADY-DEPLOYED BongtuPool to
///        the PQ hybrid-envelope implementation (design doc §4/§7).
///
/// One atomic `upgradeToAndCall` per pool: deploy the four regenerated
/// +1-public verifiers and the new impl, then swap impl + verifier addresses
/// AND mint a fresh arbiter epoch carrying BOTH keys (same bjj key by default,
/// plus the ML-KEM-768 pk hash) via the `initializeV2` payload. Atomicity is
/// load-bearing: old proofs fail against new verifiers (and vice versa) on
/// public count, so there is no partial-deploy window — a lagging wallet gets
/// InvalidProof, never a silent non-PQ op.
///
/// Reads/updates `deploy/addresses.<chainid>.json` through `AddressBook`: pool +
/// arbiter key come from the Deploy.s.sol record, and only the verifier, impl
/// and arbiter-key entries are reassigned — every other field is carried over by
/// the merge rather than restated here.
/// Env:
///   DEPLOYER_KEY         (uint256)  must be the pool OWNER; default = anvil #0
///   ARBITER_KEY_X / _Y   (uint256)  default = the recorded (current) bjj key —
///                                   the doc-preferred same-key rotation
///   ARBITER_KEM_PK_HASH  (bytes32)  default = keccak256 of the fixture arbiter
///                                   ML-KEM-768 pk (realproofs.json)
///   ARBITER_KEM_PK       (bytes)    the full encapsulation key to record beside
///                                   the hash; default = the recorded one, kept
///                                   only while it still matches the new hash
///
/// LOCAL/testnet tool. The live GIWA upgrade must land together with the
/// hybrid-witness clients and the dual-ABI indexer (design doc §7) — running
/// this earlier would strand every wallet on InvalidProof.
contract UpgradePq is Script {
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    // Bundled locals: run() + the JSON round-trip together blow the EVM stack
    // in a single frame (non-via-IR build), so everything flows via memory.
    struct Up {
        address pool;
        address dv;
        address wv;
        address dsv;
        address tv;
        address impl;
        uint256 ax;
        uint256 ay;
        bytes32 kemPkHash;
        uint256 epochBefore;
    }

    function run() external {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        string memory path = AddressBook.path();
        AddressRecord memory r = AddressBook.read(path);

        Up memory u;
        u.pool = r.pool;
        u.ax = vm.envOr("ARBITER_KEY_X", r.arbiterKeyX);
        u.ay = vm.envOr("ARBITER_KEY_Y", r.arbiterKeyY);
        // The fixture KEM keypair's seed is a PUBLIC string literal
        // (circuits/fixture_lib.ts) — anyone can derive its decapsulation key.
        // Defaulting to it is only sound on a throwaway local chain; on any
        // real chain an explicit institutional pk hash is mandatory or the
        // KEM half of every post-upgrade envelope is publicly decapsulatable.
        if (block.chainid == 31337) {
            u.kemPkHash = vm.envOr("ARBITER_KEM_PK_HASH", _fixtureKemPkHash());
        } else {
            u.kemPkHash = vm.envBytes32("ARBITER_KEM_PK_HASH");
            require(u.kemPkHash != _fixtureKemPkHash(), "fixture KEM key on a live chain");
        }
        u.epochBefore = BongtuPool(u.pool).currentEpoch();

        console2.log("== bongtu PQ upgrade ==");
        console2.log("chainId :", block.chainid);
        console2.log("pool    :", u.pool);
        console2.log("epoch   :", u.epochBefore);

        _upgrade(deployerKey, u);
        _selfCheck(u);
        _updateAddresses(path, r, u);
        console2.log("PQ UPGRADE OK -> epoch", BongtuPool(u.pool).currentEpoch());
    }

    function _upgrade(uint256 deployerKey, Up memory u) internal {
        vm.startBroadcast(deployerKey);
        u.dv = address(new DepositVerifier());
        u.wv = address(new WithdrawVerifier());
        u.dsv = address(new Disburse256Verifier());
        u.tv = address(new TransferVerifier());
        u.impl = address(new BongtuPool());
        BongtuPool(u.pool).upgradeToAndCall(
            u.impl,
            abi.encodeCall(
                BongtuPool.initializeV2,
                (
                    IDepositVerifier(u.dv),
                    IWithdrawVerifier(u.wv),
                    IDisburseVerifier(u.dsv),
                    ITransferVerifier(u.tv),
                    [u.ax, u.ay],
                    u.kemPkHash
                )
            )
        );
        vm.stopBroadcast();
    }

    /// @dev Post-upgrade self-check against the LIVE proxy state.
    function _selfCheck(Up memory u) internal view {
        BongtuPool pool = BongtuPool(u.pool);
        require(address(pool.depositVerifier()) == u.dv, "deposit verifier not swapped");
        require(address(pool.withdrawVerifier()) == u.wv, "withdraw verifier not swapped");
        require(address(pool.disburseVerifier()) == u.dsv, "disburse verifier not swapped");
        require(address(pool.transferVerifier()) == u.tv, "transfer verifier not swapped");
        require(pool.currentEpoch() == u.epochBefore + 1, "migration epoch not minted");
        require(pool.arbiterKemPkHash(pool.currentEpoch()) == u.kemPkHash, "kem pk hash not stored");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        require(kx == u.ax && ky == u.ay, "arbiter bjj key mismatch after rotation");
    }

    /// @dev keccak256 of the fixture arbiter ML-KEM-768 encapsulation key — the
    ///      keypair the committed fixture kemCiphertexts encapsulate to (the
    ///      same lockstep rule as the fixture bjj arbiter key).
    function _fixtureKemPkHash() internal view returns (bytes32) {
        return keccak256(vm.parseJsonBytes(vm.readFile("test/fixtures/realproofs.json"), ".kemPublicKey"));
    }

    /// @dev Merge the upgrade into the addresses record: same pool/token/poseidon,
    ///      new verifiers + impl + arbiter key material, so Smoke.s.sol and the TS
    ///      drivers keep reading one canonical file.
    function _updateAddresses(string memory path, AddressRecord memory r, Up memory u) internal {
        r.depositVerifier = u.dv;
        r.withdrawVerifier = u.wv;
        r.disburseVerifier = u.dsv;
        r.transferVerifier = u.tv;
        r.poolImpl = u.impl;
        r.arbiterKeyX = u.ax;
        r.arbiterKeyY = u.ay;
        r.arbiterKemPkHash = u.kemPkHash;
        // The full pk is optional metadata beside the hash. A rotation to a NEW
        // KEM key makes the recorded bytes stale, and a stale pk is worse than
        // none (clients hash-check it and would reject), so carry it only while
        // it still hashes to the epoch's value.
        bytes memory pk = vm.envOr("ARBITER_KEM_PK", r.arbiterKemPk);
        r.arbiterKemPk = keccak256(pk) == u.kemPkHash ? pk : bytes("");
        AddressBook.write(path, r);
        console2.log("addresses ->", path);
    }
}
