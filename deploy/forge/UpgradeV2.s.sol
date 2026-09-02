// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";
import {IWithdrawVerifier} from "bongtu-src/interfaces/IVerifiers.sol";
import {WithdrawVerifier} from "bongtu-src/verifiers/WithdrawVerifier.sol";

import {AddressBook, AddressRecord} from "./AddressBook.sol";

/// @title UpgradeV2 — ship the stealth-exit withdraw (proof-bound recipient) to
///        an EXISTING pool as the UUPS upgrade the repo rules prescribe
///        (CLAUDE.md: the live pool is canonical, never redeployed).
///
/// One broadcast, three txs against the pool recorded in
/// `deploy/addresses.<chainid>.json`:
///   1. deploy the regenerated `WithdrawVerifier` (uint[27] — recipient at
///      pub[26], milestone-stealth slice C);
///   2. deploy the new `BongtuPool` implementation (withdraw entry point is
///      `uint[27]` + announcement calldata; the old `uint[26]` one is REPLACED);
///   3. `upgradeToAndCall(impl, reinitializeV2(verifier))` — the verifier swap
///      rides the SAME transaction as the implementation swap, so no block ever
///      sees the new entry point paired with the old verifier (or vice versa).
///
/// The broadcast key must be the pool's OWNER (`_authorizeUpgrade` and
/// `reinitializeV2` are both onlyOwner) — on anvil the account-0 default IS the
/// owner `deploy_local.sh` installed, so the drill needs no env.
///
/// Post-state is read back and asserted (verifier wired, reinitializer version
/// consumed, and the storage that must survive an implementation swap: tree
/// head, batch size, token, arbiter epoch). The addresses file is merge-written
/// (only `withdrawVerifier` + `poolImpl` change); `packages/core/src/network.ts`
/// mirrors that file and must be updated BY FIELD NAME in the same change.
contract UpgradeV2 is Script {
    // anvil account 0 (public dev key) — matches Deploy.s.sol; the live run
    // overrides with the funded owner key from .env.
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    // Initializable's ERC-7201 storage slot; low 8 bytes = uint64 _initialized.
    bytes32 constant INIT_SLOT = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    function run() external returns (address newVerifier, address newImpl) {
        uint256 ownerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        AddressRecord memory r = AddressBook.read(AddressBook.path());
        BongtuPool pool = BongtuPool(r.pool);

        // Refuse a key that is not the recorded owner BEFORE broadcasting: the
        // verifier/impl deploys would land and pay gas, then the upgrade call
        // would revert, leaving orphan contracts on a live chain.
        require(vm.addr(ownerKey) == r.owner, "DEPLOYER_KEY is not the recorded pool owner");
        // Idempotence guard: reinitializer(2) can run once. A second invocation
        // would deploy fresh contracts and then revert on the upgrade call.
        require(uint64(uint256(vm.load(r.pool, INIT_SLOT))) == 1, "pool already reinitialized past v1");

        // Pre-state that an implementation swap must carry through untouched.
        uint256 preLeaf = pool.nextLeafIndex();
        uint256 preEpoch = pool.currentEpoch();

        console2.log("== bongtu withdraw-v2 (stealth exit) upgrade ==");
        console2.log("chainId :", block.chainid);
        console2.log("pool    :", r.pool);
        console2.log("owner   :", r.owner);

        vm.startBroadcast(ownerKey);
        WithdrawVerifier verifier = new WithdrawVerifier();
        BongtuPool impl = new BongtuPool();
        pool.upgradeToAndCall(
            address(impl), abi.encodeCall(BongtuPool.reinitializeV2, (IWithdrawVerifier(address(verifier))))
        );
        vm.stopBroadcast();

        // --- post-state asserts (read back from the chain, not from memory) ---
        require(address(pool.withdrawVerifier()) == address(verifier), "withdraw verifier not swapped");
        require(uint64(uint256(vm.load(r.pool, INIT_SLOT))) == 2, "reinitializer(2) did not run");
        require(pool.owner() == r.owner, "owner changed across upgrade");
        require(pool.B() == r.batchSize, "batchSize lost across upgrade");
        require(address(pool.token()) == r.token, "token lost across upgrade");
        require(pool.nextLeafIndex() == preLeaf, "tree head moved across upgrade");
        require(pool.currentEpoch() == preEpoch, "arbiter epoch moved across upgrade");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        require(kx == r.arbiterKeyX && ky == r.arbiterKeyY, "arbiter key lost across upgrade");

        r.withdrawVerifier = address(verifier);
        r.poolImpl = address(impl);
        AddressBook.write(AddressBook.path(), r);

        console2.log("withdrawVerifier:", address(verifier));
        console2.log("poolImpl        :", address(impl));
        console2.log("addresses merged; mirror packages/core/src/network.ts BY FIELD NAME");
        return (address(verifier), address(impl));
    }
}
