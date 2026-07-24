// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Vm} from "forge-std/Vm.sol";
import {Base} from "./Base.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {
    StubDepositVerifier,
    StubWithdrawVerifier,
    StubDisburseVerifier,
    StubTransferVerifier
} from "./mocks/StubVerifiers.sol";

/// @notice M0 Done#3-(i): THE differential gate. Drives BongtuPool through the
///         mandated interleaved sequence
///           deposit(2) -> transfer(2) -> disburse(pad+attach 16) -> withdraw(1)
///         and asserts `contract root == ImtTree oracle root AFTER EVERY insert`
///         (the roots emitted by Appended/SubtreeAppended, compared 1:1 against
///         the JS-generated reference). Tree logic is isolated with always-accept
///         stub verifiers (root correctness is independent of proof validity).
///         The withdraw step exercises a PADDED single-input spend (nullifier[1]
///         = 0 => contract-derived enabled[1] = 0).
contract DifferentialTest is Base {
    BongtuPool pool;
    MockERC20 token;

    // fixture (test/fixtures/differential.json)
    uint256[] depositLeaves;
    uint256[] transferLeaves;
    uint256 subtreeRoot;
    uint256 withdrawChange;
    uint256[] expectedRoots; // reference root after each real insert

    bytes32 constant APPENDED_SIG = keccak256("Appended(uint256,uint256,uint256)");
    bytes32 constant SUBTREE_SIG = keccak256("SubtreeAppended(uint256,uint256,uint256)");

    function setUp() public {
        IPoseidon2 poseidon = deployPoseidon();
        token = new MockERC20();
        // non-zero arbiter key (§5.3); irrelevant to stub verification.
        pool = deployPool(
            poseidon,
            new StubDepositVerifier(),
            new StubWithdrawVerifier(),
            new StubDisburseVerifier(),
            new StubTransferVerifier(),
            IERC20(address(token)),
            [uint256(11), uint256(22)]
        );

        token.mint(address(this), 1_000_000 ether);
        token.approve(address(pool), type(uint256).max);

        string memory j = vm.readFile("test/fixtures/differential.json");
        depositLeaves = vm.parseJsonUintArray(j, ".deposit");
        transferLeaves = vm.parseJsonUintArray(j, ".transfer");
        subtreeRoot = vm.parseJsonUint(j, ".subtreeRoot");
        withdrawChange = vm.parseJsonUint(j, ".withdrawChange");
        expectedRoots = vm.parseJsonUintArray(j, ".roots");
    }

    function testDifferentialRootMatchesOracleAtEveryInsert() public {
        vm.recordLogs();

        // deposit(2): out=1000 (pulls tokens), appends the two output notes.
        {
            uint[18] memory pub;
            pub[0] = 1000;
            pub[13] = depositLeaves[0];
            pub[14] = depositLeaves[1];
            (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
            pool.deposit(a, b, c, pub);
        }

        // transfer(2): 2 real nullifiers, appends the two output notes.
        {
            uint[36] memory pub;
            pub[26] = 111; // nullifier[0] (nonzero => enabled[0]=1)
            pub[27] = 222; // nullifier[1]
            pub[28] = pool.root(); // membership root (known: the live root)
            pub[31] = transferLeaves[0];
            pub[32] = transferLeaves[1];
            (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
            pool.transfer(a, b, c, pub);
        }

        // disburse: pad the partial block to a B boundary, attach the subtree.
        // The plain disburse() is removed (§6b v2); publish a length-correct blob
        // (content unchecked on-chain — the differential test only cares about roots).
        {
            uint[10] memory pub;
            pub[3] = subtreeRoot;
            pub[4] = 333; // nullifier (nonzero => enabled=1)
            pub[5] = pool.root(); // membership root
            (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
            pool.disburseWithCiphertexts(a, b, c, pub, new uint256[](pool.disburseCiphertextLen()));
        }

        // withdraw(1) with a PADDED slot: nullifier[1]=0 => enabled[1]=0.
        {
            uint[25] memory pub;
            pub[0] = 50; // withdrawn amount (pushes tokens)
            pub[16] = 444; // real nullifier
            pub[17] = 0; // padded input (enabled derived to 0)
            pub[18] = pool.root();
            pub[21] = withdrawChange;
            (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
            pool.withdraw(a, b, c, pub);
        }

        // Collect every emitted insert root, in order, and compare 1:1.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256[] memory got = new uint256[](expectedRoots.length);
        uint256 n;
        for (uint256 i = 0; i < logs.length; i++) {
            bytes32 sig = logs[i].topics[0];
            if (sig == APPENDED_SIG || sig == SUBTREE_SIG) {
                (, uint256 r) = abi.decode(logs[i].data, (uint256, uint256));
                require(n < expectedRoots.length, "more inserts than expected");
                got[n++] = r;
            }
        }
        assertEq(n, expectedRoots.length, "insert count != oracle root count");

        for (uint256 i = 0; i < expectedRoots.length; i++) {
            assertEq(got[i], expectedRoots[i], "contract root != ImtTree oracle root at an insert");
        }

        // Final state: live root == last oracle root; tree advanced d2+t2+B+1.
        assertEq(pool.root(), expectedRoots[expectedRoots.length - 1], "final root mismatch");
        assertEq(pool.nextLeafIndex(), 33, "nextLeafIndex != 2+2+16(+12 pad from idx4)+1 = 33");
        assertTrue(pool.nullifierUsed(444), "real withdraw nullifier not spent");
        assertTrue(!pool.nullifierUsed(0), "zero (padded) nullifier must never be marked");
    }
}
