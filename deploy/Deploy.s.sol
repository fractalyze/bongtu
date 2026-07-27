// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";
import {ERC1967Proxy} from "bongtu-src/utils/proxy/ERC1967Proxy.sol";
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

import {AddressBook, AddressRecord} from "./AddressBook.sol";

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
/// Owner = the broadcasting deployer: `initialize` runs through the proxy's
/// delegatecall, so `__Ownable2Step_init(msg.sender)` records the deployer.
///
/// Config is env-driven so the SAME script targets anvil or GIWA Sepolia:
///   DEPLOYER_KEY  (uint256 privkey)  default = anvil account 0
///   BATCH_SIZE    (uint256)          default = 256 (production)
///   ARBITER_KEY_X / ARBITER_KEY_Y    default = the disburse256 fixture's
///                                    authorityPublicKey (pub[9..10]) so the
///                                    committed REAL 256 disburse proof verifies
///                                    against the deployed pool's stored key.
///   ARBITER_KEM_PK_HASH (bytes32)    default = keccak256 of the fixture arbiter
///                                    ML-KEM-768 encapsulation key
///                                    (realproofs.json .kemPublicKey) — the same
///                                    keypair the committed fixtures' KEM
///                                    ciphertexts were encapsulated to.
///   ARBITER_KEM_PK      (bytes)      the FULL encapsulation key to record next
///                                    to the hash; must hash to
///                                    ARBITER_KEM_PK_HASH. Default = the fixture
///                                    key when the hash is the fixture's, and
///                                    nothing otherwise.
///
/// Records every deployed address to `deploy/addresses.<chainid>.json` — the
/// field list and the merge-write live in `deploy/AddressBook.sol`, shared with
/// the two upgrade scripts (forge also writes its canonical
/// `broadcast/…/run-latest.json`).
contract Deploy is Script {
    // anvil account 0 (public dev key) — overridden by DEPLOYER_KEY on a real net.
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    /// The deployed record is an `AddressRecord` (deploy/AddressBook.sol) — the
    /// one place the addresses-file field list is declared, shared with the two
    /// upgrade scripts.
    function run() external returns (AddressRecord memory d) {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        d.chainId = block.chainid;
        d.batchSize = vm.envOr("BATCH_SIZE", uint256(256));
        (uint256 defAx, uint256 defAy) = _fixtureArbiterKey();
        d.arbiterKeyX = vm.envOr("ARBITER_KEY_X", defAx);
        d.arbiterKeyY = vm.envOr("ARBITER_KEY_Y", defAy);
        d.arbiterKemPkHash = vm.envOr("ARBITER_KEM_PK_HASH", _fixtureKemPkHash());
        d.arbiterKemPk = _kemPk(d.arbiterKemPkHash);
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
    function _deployStack(uint256 deployerKey, AddressRecord memory d) internal {
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

        // UUPS (ERC-1967): deploy the implementation, then a proxy that runs
        // BongtuPool.initialize(...) atomically in its constructor. The PROXY
        // address is canonical + upgrade-stable (SPEC §5.2); a future
        // circuit/verifier change ships as `upgradeToAndCall`, not a redeploy.
        BongtuPool impl = new BongtuPool();
        bytes memory initData = abi.encodeCall(
            BongtuPool.initialize,
            (
                IPoseidon2(d.poseidon),
                IDepositVerifier(d.depositVerifier),
                IWithdrawVerifier(d.withdrawVerifier),
                IDisburseVerifier(d.disburseVerifier),
                ITransferVerifier(d.transferVerifier),
                IERC20(d.token),
                d.batchSize,
                [d.arbiterKeyX, d.arbiterKeyY],
                d.arbiterKemPkHash
            )
        );
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), initData);
        d.poolImpl = address(impl);
        d.pool = address(proxy);

        vm.stopBroadcast();
    }

    /// @dev Wiring self-check against the deployed state (runs during the script's
    ///      local execution phase, reading back the just-deployed pool).
    function _selfCheck(AddressRecord memory d) internal view {
        BongtuPool pool = BongtuPool(d.pool);
        require(address(pool.poseidon()) == d.poseidon, "poseidon not wired");
        require(address(pool.disburseVerifier()) == d.disburseVerifier, "disburse verifier not wired");
        require(pool.B() == d.batchSize, "batchSize mismatch");
        require(pool.owner() == d.owner, "owner != deployer");
        require(pool.initialized(), "pool not initialized");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        require(kx == d.arbiterKeyX && ky == d.arbiterKeyY, "arbiter key not stored");
        require(pool.arbiterKemPkHash(pool.currentEpoch()) == d.arbiterKemPkHash, "kem pk hash not stored");
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
    ///      authorityPublicKey (public signals [9..10] post-PQ), read straight
    ///      from the committed fixture so it stays in lockstep with the real 256 proof.
    function _fixtureArbiterKey() internal view returns (uint256 x, uint256 y) {
        uint256[] memory p = vm.parseJsonUintArray(vm.readFile("test/fixtures/disburse256.public.json"), "");
        return (p[9], p[10]);
    }

    /// @dev Default arbiter KEM pk hash: keccak256 of the fixture ML-KEM-768
    ///      encapsulation key (realproofs.json), the keypair every committed
    ///      fixture kemCiphertext was encapsulated to — same lockstep rule as
    ///      the bjj arbiter key above (design doc §3).
    function _fixtureKemPkHash() internal view returns (bytes32) {
        return keccak256(_fixtureKemPk());
    }

    function _fixtureKemPk() internal view returns (bytes memory) {
        return vm.parseJsonBytes(vm.readFile("test/fixtures/realproofs.json"), ".kemPublicKey");
    }

    /// @dev The FULL arbiter ML-KEM-768 encapsulation key to record next to the
    ///      hash (the upgraded-pool record shape — clients read the bytes and
    ///      hash-check them against the chain). An explicit ARBITER_KEM_PK must
    ///      match the recorded hash or the deploy is misconfigured; with no
    ///      override the fixture key is recorded only when the hash is the
    ///      fixture's, and a chain running some other arbiter records no bytes.
    function _kemPk(bytes32 kemPkHash) internal view returns (bytes memory) {
        bytes memory pk = vm.envOr("ARBITER_KEM_PK", bytes(""));
        if (pk.length != 0) {
            require(keccak256(pk) == kemPkHash, "ARBITER_KEM_PK does not hash to ARBITER_KEM_PK_HASH");
            return pk;
        }
        return kemPkHash == _fixtureKemPkHash() ? _fixtureKemPk() : bytes("");
    }

    function _writeAddresses(AddressRecord memory d) internal {
        string memory path = AddressBook.path();
        AddressBook.write(path, d);
        console2.log("addresses ->", path);
    }

    function _log(AddressRecord memory d) internal pure {
        console2.log("poseidon        :", d.poseidon);
        console2.log("depositVerifier :", d.depositVerifier);
        console2.log("withdrawVerifier:", d.withdrawVerifier);
        console2.log("disburseVerifier:", d.disburseVerifier);
        console2.log("transferVerifier:", d.transferVerifier);
        console2.log("token (mock kKRW):", d.token);
        console2.log("poolImpl        :", d.poolImpl);
        console2.log("pool (proxy,B256):", d.pool);
    }
}
