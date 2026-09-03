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
    ITransferVerifier,
    ITransfer10Verifier,
    ITransfer10x2Verifier
} from "bongtu-src/interfaces/IVerifiers.sol";
import {IERC20} from "bongtu-src/utils/IERC20.sol";
import {DepositVerifier} from "bongtu-src/verifiers/DepositVerifier.sol";
import {WithdrawVerifier} from "bongtu-src/verifiers/WithdrawVerifier.sol";
import {Disburse256Verifier} from "bongtu-src/verifiers/Disburse256Verifier.sol";
import {TransferVerifier} from "bongtu-src/verifiers/TransferVerifier.sol";
import {Transfer10Verifier} from "bongtu-src/verifiers/Transfer10Verifier.sol";
import {Transfer10x2Verifier} from "bongtu-src/verifiers/Transfer10x2Verifier.sol";
import {MockERC20} from "bongtu-test/mocks/MockERC20.sol";

import {AddressBook, AddressRecord} from "./AddressBook.sol";
import {ConsumerModuleKit, ConsumerModuleRecord} from "./ConsumerModuleKit.sol";

/// @title Deploy — reusable Foundry deploy of the full PRODUCTION B=256 BongtuPool
///        stack (M1 Done#2 / U6, SPEC §5/§9).
///
/// Deploys, in one broadcast, the complete production stack to whatever node
/// `--rpc-url` points at:
///   1. Poseidon-v1 hash (circomlibjs creation bytecode, `poseidon2.hex` — the
///      byte-identical hash the circuits/SDK/tests use), via inline `create`;
///   2. the 6 REAL Groth16 verifiers — Deposit, Withdraw, **Disburse256**
///      (production 256-arity), Transfer, Transfer10, Transfer10x2;
///   3. a mock kKRW ERC-20 (18-dec, non-fee-on-transfer — the only shape the pool
///      supports; on a real network swap this for the real kKRW / WETH9 address,
///      see README);
///   4. `BongtuPool(B=256)` behind an `ERC1967Proxy` whose constructor runs
///      `initialize` — one call that wires Poseidon, all six verifiers and the
///      token, derives the tree parameters, and seeds arbiter epoch 0. The pool
///      is production-shaped from its first block; there is no follow-up step.
///
/// Owner = the broadcasting deployer: `initialize` runs through the proxy's
/// delegatecall, so `__Ownable2Step_init(msg.sender)` records the deployer.
///
/// Config is env-driven so the SAME script targets anvil or the live testnet:
///   DEPLOYER_KEY  (uint256 privkey)  default = anvil account 0
///   BATCH_SIZE    (uint256)          default = 256 (production)
///   ARBITER_KEY_X / ARBITER_KEY_Y    default = the disburse256 fixture's
///                                    authorityPublicKey (pub[9..10]) so the
///                                    committed REAL 256 disburse proof verifies
///                                    against the deployed pool's stored key.
///   ARBITER_KEM_PK_HASH (bytes32)    REQUIRED off anvil, and refused if it is
///                                    the fixture's (see {_resolveKemPkHash}).
///                                    On anvil it defaults to keccak256 of the
///                                    fixture arbiter ML-KEM-768 encapsulation
///                                    key (realproofs.json .kemPublicKey) — the
///                                    same keypair the committed fixtures' KEM
///                                    ciphertexts were encapsulated to.
///   ARBITER_KEM_PK      (bytes)      the FULL encapsulation key to record next
///                                    to the hash; must hash to
///                                    ARBITER_KEM_PK_HASH. Default = the fixture
///                                    key when the hash is the fixture's, and
///                                    nothing otherwise.
///
/// Records every deployed address to `deploy/addresses.<chainid>.json` — the
/// field list and the merge-write live in `deploy/forge/AddressBook.sol` (forge
/// also writes its canonical `broadcast/…/run-latest.json`).
contract Deploy is Script {
    // anvil account 0 (public dev key) — overridden by DEPLOYER_KEY on a real net.
    uint256 constant DEFAULT_ANVIL_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    /// The deployed record is an `AddressRecord` (deploy/forge/AddressBook.sol) —
    /// the one place the addresses-file field list is declared.
    function run() external returns (AddressRecord memory d) {
        uint256 deployerKey = vm.envOr("DEPLOYER_KEY", DEFAULT_ANVIL_KEY);
        d.chainId = block.chainid;
        d.batchSize = vm.envOr("BATCH_SIZE", uint256(256));
        (uint256 defAx, uint256 defAy) = _fixtureArbiterKey();
        d.arbiterKeyX = vm.envOr("ARBITER_KEY_X", defAx);
        d.arbiterKeyY = vm.envOr("ARBITER_KEY_Y", defAy);
        d.arbiterKemPkHash = _resolveKemPkHash();
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
        _deployModuleProfile(deployerKey, d);
    }

    /// @dev MODULE_PROFILE (OPMOD §7/§9 deploy profiles):
    ///        none (default)  register no consumer modules — the audited-only
    ///                        posture, byte-identical to the pre-profile deploy;
    ///        consumer        deploy the five consumer verifiers + modules
    ///                        (ConsumerModuleKit) and register each through the
    ///                        event-logged onlyOwner registerModule.
    ///      (The no-arbiter consumer-only profile is its own script,
    ///      DeployConsumerOnly.s.sol — it needs a different initializer.)
    function _deployModuleProfile(uint256 deployerKey, AddressRecord memory d) internal {
        string memory profile = vm.envOr("MODULE_PROFILE", string("none"));
        bytes32 h = keccak256(bytes(profile));
        if (h == keccak256("none")) return;
        require(h == keccak256("consumer"), "MODULE_PROFILE must be 'consumer' or 'none'");

        BongtuPool pool = BongtuPool(d.pool);
        uint256 chunkArity = vm.envOr("MODULE_CHUNK_ARITY", ConsumerModuleKit.defaultChunkArity(d.batchSize));
        vm.startBroadcast(deployerKey);
        ConsumerModuleRecord memory mods = ConsumerModuleKit.deploySet(pool, chunkArity);
        address[] memory list = ConsumerModuleKit.modulesArray(mods);
        for (uint256 i = 0; i < list.length; i++) {
            pool.registerModule(list[i]);
        }
        vm.stopBroadcast();
        for (uint256 i = 0; i < list.length; i++) {
            require(pool.registeredModules(list[i]), "module not registered");
        }
        ConsumerModuleKit.write(ConsumerModuleKit.path(), mods);
        console2.log("consumer modules ->", ConsumerModuleKit.path());
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
        d.transfer10Verifier = address(new Transfer10Verifier());
        d.transfer10x2Verifier = address(new Transfer10x2Verifier());
        // Production: point at an existing ERC-20 via TOKEN_ADDRESS (must be
        // non-fee-on-transfer / non-rebasing, SPEC §5.3). Default deploys a mock
        // kKRW so the local gate + a testnet smoke are self-contained.
        address tokenEnv = vm.envOr("TOKEN_ADDRESS", address(0));
        d.token = tokenEnv == address(0) ? address(new MockERC20()) : tokenEnv;

        // UUPS (ERC-1967): deploy the implementation, then a proxy that runs
        // BongtuPool.initialize(...) atomically in its constructor. The PROXY
        // address is canonical + upgrade-stable (SPEC §5.2); a future
        // circuit/verifier change ships as `upgradeToAndCall`, not a redeploy.
        // `_initData` is split out to keep this function under the stack limit.
        BongtuPool impl = new BongtuPool();
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), _initData(d));
        d.poolImpl = address(impl);
        d.pool = address(proxy);

        vm.stopBroadcast();
    }

    function _initData(AddressRecord memory d) internal pure returns (bytes memory) {
        return abi.encodeCall(
            BongtuPool.initialize,
            (
                IPoseidon2(d.poseidon),
                IDepositVerifier(d.depositVerifier),
                IWithdrawVerifier(d.withdrawVerifier),
                IDisburseVerifier(d.disburseVerifier),
                ITransferVerifier(d.transferVerifier),
                ITransfer10Verifier(d.transfer10Verifier),
                ITransfer10x2Verifier(d.transfer10x2Verifier),
                IERC20(d.token),
                d.batchSize,
                [d.arbiterKeyX, d.arbiterKeyY],
                d.arbiterKemPkHash
            )
        );
    }

    /// @dev Wiring self-check against the deployed state (runs during the script's
    ///      local execution phase, reading back the just-deployed pool).
    function _selfCheck(AddressRecord memory d) internal view {
        BongtuPool pool = BongtuPool(d.pool);
        require(address(pool.poseidon()) == d.poseidon, "poseidon not wired");
        require(address(pool.depositVerifier()) == d.depositVerifier, "deposit verifier not wired");
        require(address(pool.withdrawVerifier()) == d.withdrawVerifier, "withdraw verifier not wired");
        require(address(pool.disburseVerifier()) == d.disburseVerifier, "disburse verifier not wired");
        require(address(pool.transferVerifier()) == d.transferVerifier, "transfer verifier not wired");
        require(address(pool.transfer10Verifier()) == d.transfer10Verifier, "transfer10 verifier not wired");
        require(address(pool.transfer10x2Verifier()) == d.transfer10x2Verifier, "transfer10x2 verifier not wired");
        require(pool.B() == d.batchSize, "batchSize mismatch");
        require(pool.owner() == d.owner, "owner != deployer");
        require(pool.initialized(), "pool not initialized");
        (uint256 kx, uint256 ky) = pool.currentArbiterKey();
        require(kx == d.arbiterKeyX && ky == d.arbiterKeyY, "arbiter key not stored");
        require(pool.currentEpoch() == 0, "a fresh deploy must carry exactly one arbiter epoch");
        require(pool.arbiterKemPkHash(0) == d.arbiterKemPkHash, "kem pk hash not stored");
        // The token is the one address the pool custodies against, and a wrong one
        // is as unfixable as a wrong verifier — SafeERC20 just reverts every
        // deposit. It is checked here rather than in `initialize` because the pool
        // cannot tell a wrong ERC-20 from a right one; the deploy record can.
        require(address(pool.token()) == d.token, "token not wired");
        // A live chain that records a hash but no encapsulation key leaves clients
        // with nothing to encrypt TO (they read the bytes and hash-check them).
        require(block.chainid == 31337 || d.arbiterKemPk.length != 0, "no ARBITER_KEM_PK recorded");
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

    /// @dev The arbiter KEM pk hash, gated on the chain it is being deployed to.
    ///
    ///      The whole fixture arbiter keypair is PUBLIC: its bjj scalar is a
    ///      committed literal and its ML-KEM seed is two committed sha256 strings
    ///      (`circuits/fixtures/fixture_lib.ts`). The bjj half stays the fixture
    ///      key on every chain by design — every committed proof is bound to it,
    ///      and re-proving them to swap it buys nothing, BECAUSE the envelope key
    ///      is `Poseidon(ecdhShared ++ kemSharedSecret)` (`packages/core/src/kem.ts`
    ///      {hybridEnvelopeKey}): it mixes both secrets, so one public half still
    ///      leaves the envelope sealed.
    ///
    ///      That is exactly why the KEM half must never quietly default off a
    ///      throwaway chain. Both halves public = every auditor envelope is
    ///      world-readable, and the failure is silent end to end: the pool
    ///      initializes, {_selfCheck} passes (it compares against the values it
    ///      just defaulted), {_kemPk} helpfully records the fixture encapsulation
    ///      key, and clients see a non-zero hash and encrypt to it. Nothing ever
    ///      says the confidentiality is void. So anvil may default; any other
    ///      chain must name the institutional key out loud, and is refused if it
    ///      names the fixture. `vm.envBytes32` reverts when unset — fail closed.
    function _resolveKemPkHash() internal view returns (bytes32 h) {
        if (block.chainid == 31337) return vm.envOr("ARBITER_KEM_PK_HASH", _fixtureKemPkHash());
        h = vm.envBytes32("ARBITER_KEM_PK_HASH");
        require(h != _fixtureKemPkHash(), "fixture KEM key on a live chain");
        require(h != bytes32(0), "ARBITER_KEM_PK_HASH is zero");
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
        console2.log("transfer10Verifier:", d.transfer10Verifier);
        console2.log("transfer10x2Verif:", d.transfer10x2Verifier);
        console2.log("token (mock kKRW):", d.token);
        console2.log("poolImpl        :", d.poolImpl);
        console2.log("pool (proxy,B256):", d.pool);
    }
}
