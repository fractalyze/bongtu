// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

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

/// @notice §6b v2 self-burn defense (audit finding): every output-commitment
///         append path — deposit, transfer, withdraw — rejects a zero output
///         commitment with ZeroOutputCommitment. A zero commitment is a non-note;
///         appending it would burn value into a permanently-unspendable leaf.
///
///         The guard runs AFTER the Groth16 verify, so it is exercised here with
///         always-accept stub verifiers: the proof "passes", and the pure
///         contract-side guard is what reverts. (With a real verifier a zero
///         commitment could never satisfy a valid proof, so verify would reject
///         first and the guard would never run — the guard is the belt against a
///         forged/edge proof that nonetheless carries a zero commitment.)
contract EnforcementTest is Base {
    BongtuPool pool;

    // A fresh, initialized, all-stub pool. The empty-tree root is already a known
    // root (set in the constructor), so a membership-checking op passes its root
    // guard with pub[root] = pool.root().
    function _stubPool() internal returns (BongtuPool p) {
        IPoseidon2 poseidon = deployPoseidon();
        MockERC20 token = new MockERC20();
        p = deployPool(
            poseidon,
            new StubDepositVerifier(),
            new StubWithdrawVerifier(),
            new StubDisburseVerifier(),
            new StubTransferVerifier(),
            IERC20(address(token)),
            [uint256(101), uint256(202)]
        );
    }

    /// deposit appends oc0=pub[14], oc1=pub[15]; a zero in either reverts.
    function testZeroOutputCommitmentDepositReverts() public {
        pool = _stubPool();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[19] memory pub;
        pub[14] = 0; // zero output commitment
        pub[15] = 7; // the other output is a normal note

        vm.expectRevert(BongtuPool.ZeroOutputCommitment.selector);
        pool.deposit(a, b, c, pub, dummyKemCt());
        assertEq(pool.nextLeafIndex(), 0, "no leaf must be appended on a rejected deposit");
    }

    /// transfer appends oc0=pub[32], oc1=pub[33]; a zero in either reverts (after
    /// the root guard + nullifier spend, satisfied with the empty root and two
    /// fresh nonzero nullifiers).
    function testZeroOutputCommitmentTransferReverts() public {
        pool = _stubPool();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[37] memory pub;
        pub[29] = pool.root(); // known (empty-tree) root => passes root guard
        pub[27] = 111; // fresh real nullifiers
        pub[28] = 222;
        pub[32] = 0; // zero output commitment
        pub[33] = 9;

        vm.expectRevert(BongtuPool.ZeroOutputCommitment.selector);
        pool.transfer(a, b, c, pub, dummyKemCt());
        assertEq(pool.nextLeafIndex(), 0, "no leaf must be appended on a rejected transfer");
    }

    /// withdraw appends change=pub[22]; a zero reverts (after root guard + spend).
    function testZeroOutputCommitmentWithdrawReverts() public {
        pool = _stubPool();
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[26] memory pub;
        pub[19] = pool.root(); // known (empty-tree) root
        pub[17] = 333; // fresh real nullifiers
        pub[18] = 444;
        pub[22] = 0; // zero change commitment

        vm.expectRevert(BongtuPool.ZeroOutputCommitment.selector);
        pool.withdraw(a, b, c, pub, dummyKemCt());
        assertEq(pool.nextLeafIndex(), 0, "no leaf must be appended on a rejected withdraw");
    }
}
