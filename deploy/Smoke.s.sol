// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";
import {IERC20} from "bongtu-src/utils/IERC20.sol";
import {MockERC20} from "bongtu-test/mocks/MockERC20.sol";

/// @title Smoke — a real broadcast tx against the DEPLOYED B=256 pool that proves
///        the instance is live and correctly wired (M1 Done#2 smoke step).
///
/// Reads the addresses `Deploy.s.sol` wrote (`deploy/addresses.<chainid>.json`),
/// then reuses the COMMITTED real deposit proof (`realproofs.json .deposit`, the
/// same one `RealProof.t.sol::testDepositAccepts` exercises) to do a genuine
/// `deposit` — a 0-in/2-out mint that needs no membership root, so it verifies
/// against the deployed REAL DepositVerifier regardless of the pool's arbiter key.
///
/// Steps (all broadcast from the deployer): mint the deposit's `out` amount of
/// mock kKRW, approve the pool, `deposit(a,b,c,pub)`. Then asserts the deployed
/// instance advanced (nextLeafIndex 0 -> 2), the tokens were custodied, and the
/// getters read back the expected production config (B=256, owner, arbiter key).
contract Smoke is Script {
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    // deposit proof calldata, loaded from the committed realproofs.json fixture.
    struct DepositProof {
        uint[2] a;
        uint[2][2] b;
        uint[2] c;
        uint[18] pub;
    }

    function run() external {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        address deployer = vm.addr(deployerKey);

        string memory aj = vm.readFile(
            string.concat("../deploy/addresses.", vm.toString(block.chainid), ".json")
        );
        BongtuPool pool = BongtuPool(vm.parseJsonAddress(aj, ".pool"));
        address tokenAddr = vm.parseJsonAddress(aj, ".token");

        _checkGetters(pool, aj, deployer);

        DepositProof memory p = _loadDeposit();
        uint256 amount = p.pub[0];
        uint256 leavesBefore = pool.nextLeafIndex();
        uint256 poolBalBefore = IERC20(tokenAddr).balanceOf(address(pool));

        // --- the smoke tx: mint -> approve -> real deposit (all broadcast) ----
        vm.startBroadcast(deployerKey);
        MockERC20(tokenAddr).mint(deployer, amount);
        IERC20(tokenAddr).approve(address(pool), type(uint256).max);
        pool.deposit(p.a, p.b, p.c, p.pub);
        vm.stopBroadcast();

        // --- assert the deployed pool advanced -------------------------------
        require(pool.nextLeafIndex() == leavesBefore + 2, "SMOKE: deposit did not append 2 leaves");
        require(
            IERC20(tokenAddr).balanceOf(address(pool)) - poolBalBefore == amount,
            "SMOKE: deposit did not custody `out` tokens"
        );
        require(pool.isKnownRoot(pool.root()), "SMOKE: post-deposit root not in history");

        console2.log("== smoke: deposit OK ==");
        console2.log("nextLeafIndex before:", leavesBefore);
        console2.log("nextLeafIndex after :", pool.nextLeafIndex());
        console2.log("pool kKRW balance   :", IERC20(tokenAddr).balanceOf(address(pool)));
        console2.log("SMOKE PASS");
    }

    /// @dev Getters prove the deployed instance is live + wired to the expected
    ///      production config recorded by Deploy.s.sol.
    function _checkGetters(BongtuPool pool, string memory aj, address deployer) internal view {
        require(pool.B() == vm.parseJsonUint(aj, ".batchSize"), "SMOKE: B() != recorded batchSize");
        require(pool.owner() == deployer, "SMOKE: owner() != deployer");
        require(pool.initialized(), "SMOKE: pool not initialized");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        require(kx == vm.parseJsonUint(aj, ".arbiterKeyX"), "SMOKE: arbiter key x mismatch");
        require(ky == vm.parseJsonUint(aj, ".arbiterKeyY"), "SMOKE: arbiter key y mismatch");
        console2.log("== smoke: getters OK (B, owner, arbiter key) ==");
        console2.log("pool.B()    :", pool.B());
        console2.log("pool.owner():", pool.owner());
    }

    /// @dev The committed real deposit proof (same loader shape as RealProof.t.sol).
    function _loadDeposit() internal view returns (DepositProof memory p) {
        string memory rj = vm.readFile("test/fixtures/realproofs.json");
        uint256[] memory av = vm.parseJsonUintArray(rj, ".deposit.a");
        uint256[] memory b0 = vm.parseJsonUintArray(rj, ".deposit.b[0]");
        uint256[] memory b1 = vm.parseJsonUintArray(rj, ".deposit.b[1]");
        uint256[] memory cv = vm.parseJsonUintArray(rj, ".deposit.c");
        uint256[] memory pv = vm.parseJsonUintArray(rj, ".deposit.pub");
        p.a = [av[0], av[1]];
        p.b = [[b0[0], b0[1]], [b1[0], b1[1]]];
        p.c = [cv[0], cv[1]];
        for (uint256 i = 0; i < 18; i++) p.pub[i] = pv[i];
    }
}
