// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";
import {IPoseidon2} from "bongtu-src/interfaces/IPoseidon2.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier
} from "bongtu-src/interfaces/IVerifiers.sol";
import {IERC20} from "bongtu-src/utils/IERC20.sol";
import {DepositVerifier} from "bongtu-src/verifiers/DepositVerifier.sol";
import {WithdrawVerifier} from "bongtu-src/verifiers/WithdrawVerifier.sol";
import {Disburse256Verifier} from "bongtu-src/verifiers/Disburse256Verifier.sol";
import {TransferVerifier} from "bongtu-src/verifiers/TransferVerifier.sol";
import {MockERC20} from "bongtu-test/mocks/MockERC20.sol";

/// @title Deploy — reusable Foundry deploy of the full PRODUCTION B=256 BongtuPool
///        stack (M1 Done#2 / U6, SPEC §5/§9).
///
/// Deploys, in one broadcast, the complete production stack to whatever node
/// `--rpc-url` points at:
///   1. Poseidon-v1 hash (circomlibjs creation bytecode, `poseidon2.hex` — the
///      byte-identical hash the circuits/SDK/tests use), via inline `create`;
///   2. the 4 REAL Groth16 verifiers — Deposit, Withdraw, **Disburse256**
///      (production 256-arity), Transfer;
///   3. a mock kKRW ERC-20 (18-dec, non-fee-on-transfer — the only shape the pool
///      supports; on GIWA swap this for the real kKRW / WETH9 address, see README);
///   4. `BongtuPool(B=256)` wired to Poseidon + the 4 verifiers + the token
///      (the token is a CONSTRUCTOR arg — the pool has no setERC20, it is
///      immutable), then `initialize(arbiterKey)` seeds arbiter epoch 0.
///
/// Owner = the broadcasting deployer (Ownable2Step sets `msg.sender`).
///
/// Config is env-driven so the SAME script targets anvil or GIWA Sepolia:
///   DEPLOYER_KEY  (uint256 privkey)  default = anvil account 0
///   BATCH_SIZE    (uint256)          default = 256 (production)
///   ARBITER_KEY_X / ARBITER_KEY_Y    default = the disburse256 fixture's
///                                    authorityPublicKey (pub[8..9]) so the
///                                    committed REAL 256 disburse proof verifies
///                                    against the deployed pool's stored key.
///
/// Records every deployed address to `deploy/addresses.<chainid>.json` (forge also
/// writes its canonical `broadcast/…/run-latest.json`).
contract Deploy is Script {
    // anvil account 0 (public dev key) — overridden by DEPLOYER_KEY on a real net.
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    struct Deployed {
        address poseidon;
        address depositVerifier;
        address withdrawVerifier;
        address disburseVerifier;
        address transferVerifier;
        address token;
        address pool;
        address owner;
        uint256 batchSize;
        uint256 arbiterKeyX;
        uint256 arbiterKeyY;
    }

    function run() external returns (Deployed memory d) {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        d.batchSize = vm.envOr("BATCH_SIZE", uint256(256));
        (uint256 defAx, uint256 defAy) = _fixtureArbiterKey();
        d.arbiterKeyX = vm.envOr("ARBITER_KEY_X", defAx);
        d.arbiterKeyY = vm.envOr("ARBITER_KEY_Y", defAy);
        d.owner = vm.addr(deployerKey);

        console2.log("== bongtu B=256 deploy ==");
        console2.log("chainId  :", block.chainid);
        console2.log("deployer :", d.owner);
        console2.log("batchSize:", d.batchSize);

        _deployStack(deployerKey, d);
        _selfCheck(d);
        _writeAddresses(d);
        _log(d);
    }

    /// @dev The full production stack, all inside one broadcast window so each
    ///      `new`/`create` is recorded as an on-chain deployment tx. Writes into
    ///      the struct directly to stay under the stack-depth limit.
    function _deployStack(uint256 deployerKey, Deployed memory d) internal {
        vm.startBroadcast(deployerKey);

        d.poseidon = address(_deployPoseidon());
        d.depositVerifier = address(new DepositVerifier());
        d.withdrawVerifier = address(new WithdrawVerifier());
        d.disburseVerifier = address(new Disburse256Verifier());
        d.transferVerifier = address(new TransferVerifier());
        // Production: point at an existing ERC-20 via TOKEN_ADDRESS (must be
        // non-fee-on-transfer / non-rebasing, SPEC §5.3). Default deploys a mock
        // kKRW so the local gate + a testnet smoke are self-contained.
        address tokenEnv = vm.envOr("TOKEN_ADDRESS", address(0));
        d.token = tokenEnv == address(0) ? address(new MockERC20()) : tokenEnv;

        BongtuPool pool = new BongtuPool(
            IPoseidon2(d.poseidon),
            IDepositVerifier(d.depositVerifier),
            IWithdrawVerifier(d.withdrawVerifier),
            IDisburseVerifier(d.disburseVerifier),
            ITransferVerifier(d.transferVerifier),
            IERC20(d.token),
            d.batchSize
        );
        pool.initialize([d.arbiterKeyX, d.arbiterKeyY]);
        d.pool = address(pool);

        vm.stopBroadcast();
    }

    /// @dev Wiring self-check against the deployed state (runs during the script's
    ///      local execution phase, reading back the just-deployed pool).
    function _selfCheck(Deployed memory d) internal view {
        BongtuPool pool = BongtuPool(d.pool);
        require(address(pool.poseidon()) == d.poseidon, "poseidon not wired");
        require(address(pool.disburseVerifier()) == d.disburseVerifier, "disburse verifier not wired");
        require(pool.B() == d.batchSize, "batchSize mismatch");
        require(pool.owner() == d.owner, "owner != deployer");
        require(pool.initialized(), "pool not initialized");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        require(kx == d.arbiterKeyX && ky == d.arbiterKeyY, "arbiter key not stored");
    }

    /// @dev Deploy Poseidon-v1 from circomlibjs creation bytecode (same artifact
    ///      the tests deploy in Base.sol). The inline `create` runs inside the
    ///      broadcast window so forge records it as a real on-chain deployment tx.
    function _deployPoseidon() internal returns (IPoseidon2) {
        bytes memory code = vm.parseBytes(vm.readFile("test/fixtures/poseidon2.hex"));
        address p;
        assembly {
            p := create(0, add(code, 0x20), mload(code))
        }
        require(p != address(0), "poseidon deploy failed");
        return IPoseidon2(p);
    }

    /// @dev The documented default arbiter key: the disburse256 fixture's
    ///      authorityPublicKey (public signals [8..9]), read straight from the
    ///      committed fixture so it stays in lockstep with the real 256 proof.
    function _fixtureArbiterKey() internal view returns (uint256 x, uint256 y) {
        uint256[] memory p = vm.parseJsonUintArray(vm.readFile("test/fixtures/disburse256.public.json"), "");
        return (p[8], p[9]);
    }

    function _writeAddresses(Deployed memory d) internal {
        string memory o = "bongtu-deployment";
        vm.serializeUint(o, "chainId", block.chainid);
        vm.serializeAddress(o, "owner", d.owner);
        vm.serializeUint(o, "batchSize", d.batchSize);
        vm.serializeUint(o, "arbiterKeyX", d.arbiterKeyX);
        vm.serializeUint(o, "arbiterKeyY", d.arbiterKeyY);
        vm.serializeAddress(o, "poseidon", d.poseidon);
        vm.serializeAddress(o, "depositVerifier", d.depositVerifier);
        vm.serializeAddress(o, "withdrawVerifier", d.withdrawVerifier);
        vm.serializeAddress(o, "disburseVerifier", d.disburseVerifier);
        vm.serializeAddress(o, "transferVerifier", d.transferVerifier);
        vm.serializeAddress(o, "token", d.token);
        string memory js = vm.serializeAddress(o, "pool", d.pool);
        string memory path = string.concat("../deploy/addresses.", vm.toString(block.chainid), ".json");
        vm.writeJson(js, path);
        console2.log("addresses ->", path);
    }

    function _log(Deployed memory d) internal pure {
        console2.log("poseidon        :", d.poseidon);
        console2.log("depositVerifier :", d.depositVerifier);
        console2.log("withdrawVerifier:", d.withdrawVerifier);
        console2.log("disburseVerifier:", d.disburseVerifier);
        console2.log("transferVerifier:", d.transferVerifier);
        console2.log("token (mock kKRW):", d.token);
        console2.log("pool (B=256)    :", d.pool);
    }
}
