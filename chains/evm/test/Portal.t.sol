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
    ITransferVerifier
} from "../src/interfaces/IVerifiers.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";
import {DisburseVerifier} from "../src/verifiers/DisburseVerifier.sol";
import {TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {PortalFactory} from "../src/PortalFactory.sol";
import {PortalSweeper, IPortalPool} from "../src/PortalSweeper.sol";
import {Ownable2Step} from "../src/utils/Ownable2Step.sol";

/// @notice Slice ⑤ U-P1: the portal deploy-and-sweep path against the REAL
///         deposit verifier + the committed realproofs.json deposit fixture —
///         a sweep is a real deposit (notes minted by the proof), gated by the
///         factory owner (the v1 trust concession, see PortalFactory's header),
///         with both balance guards firing BEFORE the pool is ever called.
contract PortalTest is Base {
    MockERC20 token;
    IPoseidon2 poseidon;
    string j;
    uint256[2] arbiterKey;

    address constant BOT = address(0xB07);
    address constant STRANGER = address(0xBAD);

    function setUp() public {
        poseidon = deployPoseidon();
        j = vm.readFile("test/fixtures/realproofs.json");
        uint256[] memory k = vm.parseJsonUintArray(j, ".arbiterKey");
        arbiterKey = [k[0], k[1]];
    }

    // Fresh pool with the REAL deposit verifier (the sweep must mint via a real
    // proof, mirroring RealProof.t.sol's deposit-accept path) + a fresh factory
    // owned by BOT.
    function _fresh() internal returns (BongtuPool pool, PortalFactory factory) {
        token = new MockERC20();
        pool = deployPool(
            poseidon,
            IDepositVerifier(address(new DepositVerifier())),
            IWithdrawVerifier(address(new WithdrawVerifier())),
            IDisburseVerifier(address(new DisburseVerifier())),
            ITransferVerifier(address(new TransferVerifier())),
            IERC20(address(token)),
            arbiterKey
        );
        factory = new PortalFactory(BOT);
    }

    // --- committed deposit fixture (same JSON helpers as RealProof.t.sol) ----
    function _depositArgs()
        internal
        view
        returns (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[19] memory pub, bytes memory kemCt)
    {
        uint256[] memory av = vm.parseJsonUintArray(j, ".deposit.a");
        uint256[] memory b0 = vm.parseJsonUintArray(j, ".deposit.b[0]");
        uint256[] memory b1 = vm.parseJsonUintArray(j, ".deposit.b[1]");
        uint256[] memory cv = vm.parseJsonUintArray(j, ".deposit.c");
        uint256[] memory p = vm.parseJsonUintArray(j, ".deposit.pub");
        a = [av[0], av[1]];
        b = [[b0[0], b0[1]], [b1[0], b1[1]]];
        c = [cv[0], cv[1]];
        for (uint256 i = 0; i < 19; i++) pub[i] = p[i];
        kemCt = vm.parseJsonBytes(j, ".deposit.kemCiphertext");
    }

    // The salt convention (PortalFactory header): the DKSAP stealth address,
    // bytes32-left-padded. A fixed placeholder EOA stands in for a derived one —
    // the derivation itself is TS-side; the contract only ever sees the salt.
    address constant STEALTH = address(0x1111111111111111111111111111111111111111);
    bytes32 constant SALT = bytes32(uint256(uint160(STEALTH)));

    event Swept(bytes32 indexed salt, address indexed sweeper, uint256 amount);

    // ============================ happy path =================================

    function testSweepMintsRealNotes() public {
        (BongtuPool pool, PortalFactory factory) = _fresh();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[19] memory pub, bytes memory kemCt) =
            _depositArgs();
        uint256 rootAfter = vm.parseJsonUint(j, ".deposit.rootAfter");

        // The payer path: a plain transfer (here: faucet mint) to the
        // NOT-YET-DEPLOYED CREATE2 address, exactly the proof-bound amount.
        address predicted = factory.addressOf(SALT);
        assertEq(predicted.code.length, 0, "sweeper must not exist before the first sweep");
        token.mint(predicted, pub[0]);

        vm.expectEmit(true, true, false, true, address(factory));
        emit Swept(SALT, predicted, pub[0]);
        vm.prank(BOT);
        factory.sweep(SALT, IPortalPool(address(pool)), a, b, c, pub, kemCt);

        // addressOf matches the actually-deployed sweeper, and the sweep IS a
        // real deposit: two leaves appended, root == oracle, tokens escrowed.
        assertGt(predicted.code.length, 0, "sweeper not deployed at addressOf(salt)");
        assertEq(PortalSweeper(predicted).factory(), address(factory), "sweeper must be bound to this factory");
        assertEq(pool.nextLeafIndex(), 2, "sweep must append the 2 proof-bound notes");
        assertEq(pool.root(), rootAfter, "sweep root != deposit oracle");
        assertEq(token.balanceOf(address(pool)), pub[0], "pool did not receive the swept tokens");
        assertEq(token.balanceOf(predicted), 0, "sweeper must be emptied");
    }

    /// A second payment to the same address is legal: the sweeper is already
    /// deployed, so the repeat sweep must SKIP the deploy and still mint.
    /// The committed deposit proof itself serves as the "second valid proof":
    /// deposit carries no nullifier (a mint, not a spend), so replaying it is a
    /// fresh, contract-valid deposit — the duplicate output commitments it
    /// appends are the recipient-side self-burn foot-gun documented in
    /// docs/contracts.md, irrelevant to the deploy-skip + re-sweep mechanics
    /// under test. No assertion is weakened: the full second sweep executes
    /// against the SAME factory and pool.
    function testRepeatSweepOnDeployedSweeper() public {
        (BongtuPool pool, PortalFactory factory) = _fresh();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[19] memory pub, bytes memory kemCt) =
            _depositArgs();
        address predicted = factory.addressOf(SALT);

        token.mint(predicted, pub[0]);
        vm.prank(BOT);
        factory.sweep(SALT, IPortalPool(address(pool)), a, b, c, pub, kemCt);
        assertEq(pool.nextLeafIndex(), 2);

        // second funding, second sweep — deploy skipped (code already there)
        token.mint(predicted, pub[0]);
        vm.prank(BOT);
        factory.sweep(SALT, IPortalPool(address(pool)), a, b, c, pub, kemCt);

        assertEq(pool.nextLeafIndex(), 4, "repeat sweep must mint again");
        assertEq(token.balanceOf(address(pool)), 2 * pub[0], "both fundings must be escrowed");
        assertEq(token.balanceOf(predicted), 0, "sweeper must be emptied again");
    }

    // ============================ access gates ===============================

    function testNonOwnerSweepReverts() public {
        (BongtuPool pool, PortalFactory factory) = _fresh();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[19] memory pub, bytes memory kemCt) =
            _depositArgs();
        token.mint(factory.addressOf(SALT), pub[0]);

        vm.expectRevert(abi.encodeWithSelector(Ownable2Step.OwnableUnauthorized.selector, STRANGER));
        vm.prank(STRANGER);
        factory.sweep(SALT, IPortalPool(address(pool)), a, b, c, pub, kemCt);
    }

    /// The sweeper itself refuses everyone but its factory — the factory's
    /// onlyOwner would otherwise be bypassable by calling the deployed sweeper
    /// directly.
    function testDirectSweeperCallReverts() public {
        (BongtuPool pool, PortalFactory factory) = _fresh();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[19] memory pub, bytes memory kemCt) =
            _depositArgs();
        address predicted = factory.addressOf(SALT);
        token.mint(predicted, pub[0]);
        vm.prank(BOT);
        factory.sweep(SALT, IPortalPool(address(pool)), a, b, c, pub, kemCt);

        token.mint(predicted, pub[0]);
        vm.expectRevert(abi.encodeWithSelector(PortalSweeper.NotFactory.selector, STRANGER));
        vm.prank(STRANGER);
        PortalSweeper(predicted).sweep(IPortalPool(address(pool)), a, b, c, pub, kemCt);
    }

    // ============================ balance guards =============================

    /// pub[0] > balance must revert BEFORE the pool call: the proof here is
    /// genuine (it would be ACCEPTED by the pool, as the happy-path test shows),
    /// so seeing SweepExceedsBalance proves the sweeper's own guard fired first
    /// — the pool would have failed later with SafeERC20FailedOperation instead.
    function testBalanceShortSweepRevertsBeforePool() public {
        (BongtuPool pool, PortalFactory factory) = _fresh();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[19] memory pub, bytes memory kemCt) =
            _depositArgs();
        token.mint(factory.addressOf(SALT), pub[0] - 1);

        vm.expectRevert(abi.encodeWithSelector(PortalSweeper.SweepExceedsBalance.selector, pub[0], pub[0] - 1));
        vm.prank(BOT);
        factory.sweep(SALT, IPortalPool(address(pool)), a, b, c, pub, kemCt);
    }

    function testZeroBalanceSweepReverts() public {
        (BongtuPool pool, PortalFactory factory) = _fresh();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c, uint[19] memory pub, bytes memory kemCt) =
            _depositArgs();
        // no funding at all — nothing to shield
        vm.expectRevert(PortalSweeper.NothingToSweep.selector);
        vm.prank(BOT);
        factory.sweep(SALT, IPortalPool(address(pool)), a, b, c, pub, kemCt);
    }

    // ======================= TS<->sol CREATE2 parity =========================

    // THE PARITY VECTOR GENERATOR + PIN. The factory is etched at a FIXED
    // address (CREATE2 addresses depend on the deployer, so the vector must fix
    // it), then addressOf(SALT) and the sweeper initcode hash are pinned to the
    // committed constants below. `packages/core/test/stealth.test.ts` pins
    // `create2Address` / `portalAddress` to the SAME three constants — no side
    // hand-computes anything. After any PortalSweeper source or compiler-config
    // change, regenerate with
    //   forge test --match-test testCreate2ParityVectorPinned -vv
    // and copy the logged values into BOTH files.
    address constant VECTOR_FACTORY = address(uint160(0xC0FFEE01));
    bytes32 constant VECTOR_INITCODE_HASH =
        0xe70cc154569870971ebc21f0d436f960dbd217315e69c3c102d47536293eeb3f;
    address constant VECTOR_ADDRESS = 0xDdF8577C4Bd01a287dEA1bc3cFe4c9e7D5c2343A;

    function testCreate2ParityVectorPinned() public {
        deployCodeTo("PortalFactory.sol:PortalFactory", abi.encode(BOT), VECTOR_FACTORY);
        PortalFactory f = PortalFactory(VECTOR_FACTORY);
        console2.log("factory:", VECTOR_FACTORY);
        console2.log("sweeperInitCodeHash:");
        console2.logBytes32(f.sweeperInitCodeHash());
        console2.log("addressOf(SALT):", f.addressOf(SALT));
        assertEq(f.sweeperInitCodeHash(), VECTOR_INITCODE_HASH, "initcode hash drifted - regen the parity vector");
        assertEq(f.addressOf(SALT), VECTOR_ADDRESS, "CREATE2 vector drifted - regen the parity vector");
    }
}
