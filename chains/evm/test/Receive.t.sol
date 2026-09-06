// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {console2} from "forge-std/console2.sol";
import {Base} from "./Base.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier,
    IDepositPrivVerifier
} from "../src/interfaces/IVerifiers.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {
    StubDepositVerifier,
    StubWithdrawVerifier,
    StubDisburseVerifier,
    StubTransferVerifier
} from "./mocks/StubVerifiers.sol";
import {DepositPrivModule} from "../src/modules/DepositPrivModule.sol";
import {DepositPrivVerifier} from "../src/verifiers/DepositPrivVerifier.sol";
import {ReceiveFactory} from "../src/ReceiveFactory.sol";
import {ReceiveSweeper, IReceiveModule} from "../src/ReceiveSweeper.sol";
import {Ownable2Step} from "../src/utils/Ownable2Step.sol";

/// @notice The receive deploy-and-sweep path against the REAL depositPriv
///         verifier + the committed consumer_realproofs.json depositPriv
///         fixture — a sweep is a real CONSUMER mint (no-auditor notes,
///         tokens pulled by the pool from the sweeper), gated by the factory
///         owner (the portal v1 trust concession, see ReceiveFactory's
///         header), with both balance guards firing BEFORE the module is ever
///         called, and the sweep-time `Announced` event carrying the exact
///         announcement tuple. The pool's enterprise verifier slots are
///         always-accept stubs (the ConsumerModules.t.sol pattern): consumer
///         proof validity is the thing under test here.
contract ReceiveTest is Base {
    MockERC20 token;
    IPoseidon2 poseidon;
    string j;

    address constant BOT = address(0xB07);
    address constant STRANGER = address(0xBAD);

    function setUp() public {
        poseidon = deployPoseidon();
        j = vm.readFile("test/fixtures/consumer_realproofs.json");
    }

    // Fresh pool with the REAL depositPriv verifier behind its module (the
    // sweep must mint via a real consumer proof) + a fresh factory owned by BOT.
    function _fresh() internal returns (BongtuPool pool, DepositPrivModule mod, ReceiveFactory factory) {
        token = new MockERC20();
        pool = deployPoolWithBatch(
            poseidon,
            IDepositVerifier(address(new StubDepositVerifier())),
            IWithdrawVerifier(address(new StubWithdrawVerifier())),
            IDisburseVerifier(address(new StubDisburseVerifier())),
            ITransferVerifier(address(new StubTransferVerifier())),
            IERC20(address(token)),
            B,
            [uint256(101), uint256(202)],
            DUMMY_KEM_PK_HASH
        );
        mod = new DepositPrivModule(pool, IDepositPrivVerifier(address(new DepositPrivVerifier())));
        pool.registerModule(address(mod));
        factory = new ReceiveFactory(BOT);
    }

    // --- committed depositPriv fixture (the ConsumerModules.t.sol loaders) ---
    function _depositPrivArgs()
        internal
        view
        returns (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[16] memory pub, bytes[] memory kemCts)
    {
        uint256[] memory av = vm.parseJsonUintArray(j, ".depositPriv.a");
        uint256[] memory b0 = vm.parseJsonUintArray(j, ".depositPriv.b[0]");
        uint256[] memory b1 = vm.parseJsonUintArray(j, ".depositPriv.b[1]");
        uint256[] memory cv = vm.parseJsonUintArray(j, ".depositPriv.c");
        uint256[] memory p = vm.parseJsonUintArray(j, ".depositPriv.pub");
        a = [av[0], av[1]];
        b = [[b0[0], b0[1]], [b1[0], b1[1]]];
        c = [cv[0], cv[1]];
        for (uint256 i = 0; i < 16; i++) pub[i] = p[i];
        kemCts = vm.parseJsonBytesArray(j, ".depositPriv.kemCiphertexts");
    }

    // The salt convention (ReceiveFactory header): the DKSAP stealth address,
    // bytes32-left-padded. A fixed placeholder EOA stands in for a derived one —
    // the derivation itself is TS-side; the contract only ever sees the salt.
    address constant STEALTH = address(0x2222222222222222222222222222222222222222);
    bytes32 constant SALT = bytes32(uint256(uint160(STEALTH)));

    // The announcement tuple the bot passes through — arbitrary here; the test
    // asserts the event carries these EXACT values.
    bytes32 constant EPHEMERAL_PUB = bytes32(uint256(0xE9E9E9));
    uint8 constant VIEW_TAG = 0x42;

    event Swept(bytes32 indexed salt, address indexed sweeper, uint256 amount);
    event Announced(bytes32 indexed salt, bytes32 ephemeralPub, uint8 viewTag);

    function _sweep(ReceiveFactory factory, DepositPrivModule mod) internal {
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[16] memory pub, bytes[] memory kemCts) =
            _depositPrivArgs();
        factory.sweep(SALT, IReceiveModule(address(mod)), a, b, c, pub, kemCts, EPHEMERAL_PUB, VIEW_TAG);
    }

    // ============================ happy path =================================

    function testSweepMintsConsumerNotes() public {
        (BongtuPool pool, DepositPrivModule mod, ReceiveFactory factory) = _fresh();
        (,,, uint[16] memory pub,) = _depositPrivArgs();
        uint256 rootAfter = vm.parseJsonUint(j, ".depositPriv.rootAfter");

        // The payer path: a plain transfer (here: faucet mint) to the
        // NOT-YET-DEPLOYED CREATE2 address, exactly the proof-bound amount.
        address predicted = factory.addressOf(SALT);
        assertEq(predicted.code.length, 0, "sweeper must not exist before the first sweep");
        token.mint(predicted, pub[0]);

        // Both events, in emit order, from the factory — Announced must carry
        // the exact tuple the bot passed (the chain-only recovery path).
        vm.expectEmit(true, true, false, true, address(factory));
        emit Swept(SALT, predicted, pub[0]);
        vm.expectEmit(true, false, false, true, address(factory));
        emit Announced(SALT, EPHEMERAL_PUB, VIEW_TAG);
        vm.prank(BOT);
        _sweep(factory, mod);

        // addressOf matches the actually-deployed sweeper, and the sweep IS a
        // real consumer mint: two leaves appended, root == oracle, tokens
        // pulled INTO the pool (applyOpWithPull from the sweeper).
        assertGt(predicted.code.length, 0, "sweeper not deployed at addressOf(salt)");
        assertEq(ReceiveSweeper(predicted).factory(), address(factory), "sweeper must be bound to this factory");
        assertEq(pool.nextLeafIndex(), 2, "sweep must append the 2 proof-bound notes");
        assertEq(pool.root(), rootAfter, "sweep root != depositPriv oracle");
        assertEq(token.balanceOf(address(pool)), pub[0], "pool did not receive the swept tokens");
        assertEq(token.balanceOf(predicted), 0, "sweeper must be emptied");
    }

    /// A second payment to the same address is legal: the sweeper is already
    /// deployed, so the repeat sweep must SKIP the deploy and still mint.
    /// The committed depositPriv proof itself serves as the "second valid
    /// proof": depositPriv is a 0-in mint with no nullifier, so replaying it
    /// is a fresh, contract-valid deposit (the duplicate-commitment self-burn
    /// foot-gun is documented in docs/contracts.md, irrelevant to the
    /// deploy-skip + re-sweep mechanics under test).
    function testRepeatSweepOnDeployedSweeper() public {
        (BongtuPool pool, DepositPrivModule mod, ReceiveFactory factory) = _fresh();
        (,,, uint[16] memory pub,) = _depositPrivArgs();
        address predicted = factory.addressOf(SALT);

        token.mint(predicted, pub[0]);
        vm.prank(BOT);
        _sweep(factory, mod);
        assertEq(pool.nextLeafIndex(), 2);

        // second funding, second sweep — deploy skipped (code already there)
        token.mint(predicted, pub[0]);
        vm.prank(BOT);
        _sweep(factory, mod);

        assertEq(pool.nextLeafIndex(), 4, "repeat sweep must mint again");
        assertEq(token.balanceOf(address(pool)), 2 * pub[0], "both fundings must be escrowed");
        assertEq(token.balanceOf(predicted), 0, "sweeper must be emptied again");
    }

    // ============================ access gates ===============================

    function testNonOwnerSweepReverts() public {
        (, DepositPrivModule mod, ReceiveFactory factory) = _fresh();
        (,,, uint[16] memory pub,) = _depositPrivArgs();
        token.mint(factory.addressOf(SALT), pub[0]);

        vm.expectRevert(abi.encodeWithSelector(Ownable2Step.OwnableUnauthorized.selector, STRANGER));
        vm.prank(STRANGER);
        _sweep(factory, mod);
    }

    /// The sweeper itself refuses everyone but its factory — the factory's
    /// onlyOwner would otherwise be bypassable by calling the deployed sweeper
    /// directly.
    function testDirectSweeperCallReverts() public {
        (, DepositPrivModule mod, ReceiveFactory factory) = _fresh();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[16] memory pub, bytes[] memory kemCts) =
            _depositPrivArgs();
        address predicted = factory.addressOf(SALT);
        token.mint(predicted, pub[0]);
        vm.prank(BOT);
        _sweep(factory, mod);

        token.mint(predicted, pub[0]);
        vm.expectRevert(abi.encodeWithSelector(ReceiveSweeper.NotFactory.selector, STRANGER));
        vm.prank(STRANGER);
        ReceiveSweeper(predicted).sweep(IReceiveModule(address(mod)), a, b, c, pub, kemCts);
    }

    // ============================ balance guards =============================

    /// pub[0] > balance must revert BEFORE the module call: the proof here is
    /// genuine (it would be ACCEPTED, as the happy-path test shows), so seeing
    /// SweepExceedsBalance proves the sweeper's own guard fired first — the
    /// pool's pull would have failed later with SafeERC20FailedOperation.
    function testBalanceShortSweepRevertsBeforeModule() public {
        (, DepositPrivModule mod, ReceiveFactory factory) = _fresh();
        (,,, uint[16] memory pub,) = _depositPrivArgs();
        token.mint(factory.addressOf(SALT), pub[0] - 1);

        vm.expectRevert(abi.encodeWithSelector(ReceiveSweeper.SweepExceedsBalance.selector, pub[0], pub[0] - 1));
        vm.prank(BOT);
        _sweep(factory, mod);
    }

    function testZeroBalanceSweepReverts() public {
        (, DepositPrivModule mod, ReceiveFactory factory) = _fresh();
        // no funding at all — nothing to shield
        vm.expectRevert(ReceiveSweeper.NothingToSweep.selector);
        vm.prank(BOT);
        _sweep(factory, mod);
    }

    // ======================= TS<->sol CREATE2 parity =========================

    // THE PARITY VECTOR GENERATOR + PIN — this pair's OWN vector: the
    // ReceiveSweeper initcode differs from PortalSweeper's, so the hash and
    // every derived address differ. The factory is etched at a FIXED address
    // (CREATE2 addresses depend on the deployer), then addressOf(SALT) and the
    // sweeper initcode hash are pinned to the committed constants below.
    // `packages/core/test/stealth.test.ts` pins `create2Address` to the SAME
    // three constants — no side hand-computes anything. After any
    // ReceiveSweeper source or compiler-config change, regenerate with
    //   forge test --match-test testReceiveCreate2ParityVectorPinned -vv
    // and copy the logged values into BOTH files.
    address constant VECTOR_FACTORY = address(uint160(0xC0FFEE02));
    bytes32 constant VECTOR_INITCODE_HASH =
        0xe1cbdf009697cb9492969ca8f0534dbab59c3b06659ae5ef3838bb64c3e73cc2;
    address constant VECTOR_ADDRESS = 0x717Ad979a80944A58f600F3E002F085502622De1;

    function testReceiveCreate2ParityVectorPinned() public {
        deployCodeTo("ReceiveFactory.sol:ReceiveFactory", abi.encode(BOT), VECTOR_FACTORY);
        ReceiveFactory f = ReceiveFactory(VECTOR_FACTORY);
        console2.log("factory:", VECTOR_FACTORY);
        console2.log("sweeperInitCodeHash:");
        console2.logBytes32(f.sweeperInitCodeHash());
        console2.log("addressOf(SALT):", f.addressOf(SALT));
        assertEq(f.sweeperInitCodeHash(), VECTOR_INITCODE_HASH, "initcode hash drifted - regen the parity vector");
        assertEq(f.addressOf(SALT), VECTOR_ADDRESS, "CREATE2 vector drifted - regen the parity vector");
    }
}
