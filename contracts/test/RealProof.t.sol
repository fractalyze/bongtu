// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

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
import {StubDepositVerifier} from "./mocks/StubVerifiers.sol";
import {DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";
import {DisburseVerifier} from "../src/verifiers/DisburseVerifier.sol";
import {TransferVerifier} from "../src/verifiers/TransferVerifier.sol";

/// @notice M0 Done#3 (ii)-(v) with the REAL Groth16 verifiers:
///   (v)  each circuit's committed proof is accepted + advances state (root ==
///        oracle, nullifier marked);
///   (ii) an enabled=0 proof on a value-carrying (nonzero-nullifier) input is
///        REJECTED because the contract injects enabled=1 (§5.2) — and a genuine
///        padded slot (nullifier=0,enabled=0) is ACCEPTED;
///   (iii) replaying a real proof reverts on nullifier reuse;
///   (iv) flipping one bit of a public signal fails Groth16 verification.
contract RealProofTest is Base {
    MockERC20 token;
    IPoseidon2 poseidon;
    string j;
    uint256[2] arbiterKey;

    function setUp() public {
        poseidon = deployPoseidon();
        j = vm.readFile("test/fixtures/realproofs.json");
        uint256[] memory k = vm.parseJsonUintArray(j, ".arbiterKey");
        arbiterKey = [k[0], k[1]];
    }

    // Deploy a fresh, initialized, well-funded pool. `realDeposit` picks the real
    // deposit verifier (deposit-accept test) vs a stub (so other tests can seed
    // the tree with specific commitments via a 2-leaf mint).
    function _freshPool(bool realDeposit) internal returns (BongtuPool pool) {
        token = new MockERC20();
        IDepositVerifier dv =
            realDeposit ? IDepositVerifier(address(new DepositVerifier())) : IDepositVerifier(address(new StubDepositVerifier()));
        pool = deployPool(
            poseidon,
            dv,
            IWithdrawVerifier(address(new WithdrawVerifier())),
            IDisburseVerifier(address(new DisburseVerifier())),
            ITransferVerifier(address(new TransferVerifier())),
            IERC20(address(token))
        );
        pool.initialize(arbiterKey);
        token.mint(address(pool), 1_000_000);
        token.mint(address(this), 1_000_000);
        token.approve(address(pool), type(uint256).max);
    }

    // --- JSON helpers ---------------------------------------------------------
    function _abc(string memory key)
        internal
        view
        returns (uint[2] memory a, uint[2][2] memory b, uint[2] memory c)
    {
        uint256[] memory av = vm.parseJsonUintArray(j, string.concat(key, ".a"));
        uint256[] memory b0 = vm.parseJsonUintArray(j, string.concat(key, ".b[0]"));
        uint256[] memory b1 = vm.parseJsonUintArray(j, string.concat(key, ".b[1]"));
        uint256[] memory cv = vm.parseJsonUintArray(j, string.concat(key, ".c"));
        a = [av[0], av[1]];
        b = [[b0[0], b0[1]], [b1[0], b1[1]]];
        c = [cv[0], cv[1]];
    }

    function _pub(string memory key) internal view returns (uint256[] memory) {
        return vm.parseJsonUintArray(j, string.concat(key, ".pub"));
    }

    // Seed the tree via a stub 2-leaf mint so the proof's membership root becomes
    // a known root (§5.3 any-historical-root).
    function _seed(BongtuPool pool, string memory key) internal {
        uint256[] memory seed = vm.parseJsonUintArray(j, string.concat(key, ".seedLeaves"));
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        // deposit publics (18): out=pub[0], oc0=pub[13], oc1=pub[14]. A stub
        // deposit verifier accepts, so only the appended leaves matter for seeding.
        uint[18] memory pub;
        pub[13] = seed[0];
        pub[14] = seed[1];
        pool.deposit(a, b, c, pub);
    }

    // Build a disburse ciphertext blob of exactly the enforced length (content is
    // unchecked on-chain — the proof's disclosureHash binds it off-chain, §6b).
    function _ctBlob(BongtuPool pool) internal view returns (uint256[] memory) {
        return new uint256[](pool.disburseCiphertextLen());
    }

    // ======================= (v) REAL-PROOF ACCEPT ===========================

    function testDepositAccepts() public {
        BongtuPool pool = _freshPool(true);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".deposit");
        uint256[] memory p = _pub(".deposit");
        uint[18] memory pub;
        for (uint256 i = 0; i < 18; i++) pub[i] = p[i];
        uint256 rootAfter = vm.parseJsonUint(j, ".deposit.rootAfter");

        uint256 balBefore = token.balanceOf(address(pool));
        pool.deposit(a, b, c, pub);

        assertEq(pool.nextLeafIndex(), 2, "deposit appends 2 leaves");
        assertEq(pool.root(), rootAfter, "deposit root != oracle");
        assertEq(token.balanceOf(address(pool)) - balBefore, p[0], "deposit did not pull `out` tokens");
    }

    function testDisburseAccepts() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".disburse");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disburse");
        uint256[] memory p = _pub(".disburse");
        uint[10] memory pub;
        for (uint256 i = 0; i < 10; i++) pub[i] = p[i];
        uint256 rootAfter = vm.parseJsonUint(j, ".disburse.rootAfter");

        pool.disburseWithCiphertexts(a, b, c, pub, _ctBlob(pool));

        assertEq(pool.root(), rootAfter, "disburse root != oracle");
        assertEq(pool.nextLeafIndex(), 32, "disburse pad(2->16)+attach(16) => 32");
        assertTrue(pool.nullifierUsed(p[4]), "disburse nullifier not marked");
    }

    function testTransferAccepts() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".transfer");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer");
        uint256[] memory p = _pub(".transfer");
        uint[36] memory pub;
        for (uint256 i = 0; i < 36; i++) pub[i] = p[i];
        uint256 rootAfter = vm.parseJsonUint(j, ".transfer.rootAfter");

        pool.transfer(a, b, c, pub);

        assertEq(pool.nextLeafIndex(), 4, "transfer appends 2 outputs (seed 2 + 2)");
        assertEq(pool.root(), rootAfter, "transfer root != oracle");
        assertTrue(pool.nullifierUsed(p[26]) && pool.nullifierUsed(p[27]), "transfer nullifiers not marked");
    }

    function testWithdrawAccepts() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".withdraw");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".withdraw");
        uint256[] memory p = _pub(".withdraw");
        uint[25] memory pub;
        for (uint256 i = 0; i < 25; i++) pub[i] = p[i];
        uint256 rootAfter = vm.parseJsonUint(j, ".withdraw.rootAfter");

        uint256 balBefore = token.balanceOf(address(this));
        pool.withdraw(a, b, c, pub);

        assertEq(pool.nextLeafIndex(), 3, "withdraw appends 1 change leaf (seed 2 + 1)");
        assertEq(pool.root(), rootAfter, "withdraw root != oracle");
        assertTrue(pool.nullifierUsed(p[16]) && pool.nullifierUsed(p[17]), "withdraw nullifiers not marked");
        assertEq(token.balanceOf(address(this)) - balBefore, p[0], "withdraw did not push `out` tokens");
    }

    // ============== (ii) MINT-FROM-NOTHING CLOSED + PADDED ACCEPT ============

    /// The load-bearing soundness fix. The mint-from-nothing vector — a fabricated
    /// input {nullifier=0, commitment=0, value=X, enabled=0} that passes
    /// CheckNullifiers/CheckHashes/CheckIMTProof yet inflates `out` via CheckSum —
    /// is now UNPROVABLE at the CIRCUIT level thanks to the value-belt
    /// `(1-enabled[i])*inputValues[i]===0` (SPEC §5.2). The old contract-derived
    /// enabled=(nullifier!=0) alone did NOT catch it, because for a zero nullifier
    /// the contract injects enabled=0 — AGREEING with the malicious proof.
    ///
    /// There is therefore no attack calldata to submit: `circuits/gen_realproofs.ts`
    /// no longer emits a `withdraw_attack` entry, and both the pure mint
    /// (nullifier=0/value!=0/enabled=0) and the value-carrying forgery
    /// (nullifier!=0/value!=0/enabled=0) FAIL `generate_witness` on the belt —
    /// proven verbatim by `circuits/assert_attacks_throw.ts`. This test pins that
    /// closure: the fixture generator refuses to produce an attack proof.
    function testMintFromNothingUnprovableAtCircuitLevel() public view {
        // The circuit belt makes the attack witness unsatisfiable, so the fixture
        // pipeline emits no proof for it. `.withdraw_attack.pub` therefore does not
        // exist in realproofs.json (parseJsonUintArray reverts / returns empty on a
        // missing key) — the contract can never be handed such a proof.
        bool present = vm.keyExistsJson(j, ".withdraw_attack");
        assertFalse(present, "attack vector must be unprovable => no withdraw_attack fixture");
    }

    /// Belt-and-suspenders: even for a legitimately-provable proof, the contract
    /// IGNORES calldata `enabled` and injects enabled[i]=(nullifier[i]!=0) (§5.2).
    /// We submit the genuine padded proof (nullifier[1]=0, enabled[1]=0) but LIE in
    /// calldata (enabled[1]=1); the contract overwrites it back to 0, so the proof
    /// still matches and ACCEPTS — demonstrating calldata `enabled` is never trusted.
    function testContractInjectionIgnoresCalldataEnabled() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".withdraw_padded");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".withdraw_padded");
        uint256[] memory p = _pub(".withdraw_padded");
        uint[25] memory pub;
        for (uint256 i = 0; i < 25; i++) pub[i] = p[i];

        assertEq(p[17], 0, "padded fixture must have nullifier[1]=0");
        pub[20] = 1; // adversarial calldata lie: claim enabled[1]=1

        // Contract injects injected[20]=(nullifier[1]!=0)=0, overriding the lie, so
        // the vector matches the proof and verification passes.
        pool.withdraw(a, b, c, pub);
        assertTrue(pool.nullifierUsed(p[16]), "real nullifier[0] must be marked");
    }

    /// A genuine padded slot (nullifier[1]=0, enabled[1]=0) is accepted: the
    /// contract injects enabled[1]=0, matching the proof.
    function testPaddedSlotAccepts() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".withdraw_padded");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".withdraw_padded");
        uint256[] memory p = _pub(".withdraw_padded");
        uint[25] memory pub;
        for (uint256 i = 0; i < 25; i++) pub[i] = p[i];
        uint256 rootAfter = vm.parseJsonUint(j, ".withdraw_padded.rootAfter");

        assertEq(p[17], 0, "padded fixture must have nullifier[1]=0");
        assertEq(p[20], 0, "padded fixture must have enabled[1]=0");

        pool.withdraw(a, b, c, pub);

        assertEq(pool.root(), rootAfter, "padded withdraw root != oracle");
        assertTrue(pool.nullifierUsed(p[16]), "real nullifier[0] not marked");
        assertTrue(!pool.nullifierUsed(0), "zero nullifier must never be marked");
    }

    // ======================= (iii) REPLAY REVERT =============================

    function testReplayReverts() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".withdraw");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".withdraw");
        uint256[] memory p = _pub(".withdraw");
        uint[25] memory pub;
        for (uint256 i = 0; i < 25; i++) pub[i] = p[i];

        pool.withdraw(a, b, c, pub); // first spend OK

        // The proof's membership root is still known, so it re-verifies; the
        // second spend must revert on nullifier reuse.
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NullifierAlreadyUsed.selector, p[16]));
        pool.withdraw(a, b, c, pub);
    }

    // ======================= (iv) TAMPER REVERT ==============================

    function testTamperedPublicSignalReverts() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".withdraw");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".withdraw");
        uint256[] memory p = _pub(".withdraw");
        uint[25] memory pub;
        for (uint256 i = 0; i < 25; i++) pub[i] = p[i];

        // Flip one bit of the change-commitment public signal (pub[21]); the root
        // (pub[18]) is untouched so the known-root guard still passes and the
        // failure is isolated to the Groth16 verify.
        pub[21] = pub[21] ^ 1;

        vm.expectRevert(BongtuPool.InvalidProof.selector);
        pool.withdraw(a, b, c, pub);
    }

    // ============ §6b v2 enforced disclosure: WRONG AUTHORITY KEY =============

    /// §6b v2 load-bearing enforcement: deposit() injects the STORED arbiter key
    /// into the authority-envelope public signals (pub[16..17]) before verify, so a
    /// proof encrypted to a DIFFERENT arbiter key cannot verify. We rotate the
    /// stored key to a fresh value, then submit the committed real deposit proof
    /// (encrypted to the epoch-0 key); the injected key no longer matches the
    /// proof's commitment and Groth16 rejects. Control = testDepositAccepts(),
    /// which submits the same proof against the un-rotated key and it accepts, so
    /// this revert is attributable to the arbiter-key injection, not the proof.
    function testWrongAuthorityKeyDepositReverts() public {
        BongtuPool pool = _freshPool(true);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".deposit");
        uint256[] memory p = _pub(".deposit");
        uint[18] memory pub;
        for (uint256 i = 0; i < 18; i++) pub[i] = p[i];

        // Rotate the arbiter key away from the one the proof was encrypted to.
        pool.rotateArbiter([uint256(0x1234), uint256(0x5678)]);

        vm.expectRevert(BongtuPool.InvalidProof.selector);
        pool.deposit(a, b, c, pub);
    }

    /// Same enforcement on the withdraw path: the stored arbiter key is injected at
    /// pub[23..24]. Seeding makes the membership root known, and both fixture
    /// nullifiers are nonzero so the injected enabled[i] match the proof — the
    /// failure therefore isolates to the arbiter-key injection. Control =
    /// testWithdrawAccepts() (same proof, un-rotated key, accepts).
    function testWrongAuthorityKeyWithdrawReverts() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".withdraw");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".withdraw");
        uint256[] memory p = _pub(".withdraw");
        uint[25] memory pub;
        for (uint256 i = 0; i < 25; i++) pub[i] = p[i];

        pool.rotateArbiter([uint256(0x1234), uint256(0x5678)]);

        vm.expectRevert(BongtuPool.InvalidProof.selector);
        pool.withdraw(a, b, c, pub);
    }

    // ================= disburse access control (§5.3) ========================

    /// An allowlisted (non-owner) operator may disburse.
    function testDisburseAllowlistedSucceeds() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".disburse");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disburse");
        uint256[] memory p = _pub(".disburse");
        uint[10] memory pub;
        for (uint256 i = 0; i < 10; i++) pub[i] = p[i];

        address operator = address(0xB0B);
        pool.setDisburseAllowed(operator, true);
        uint256[] memory ct = _ctBlob(pool);
        vm.prank(operator);
        pool.disburseWithCiphertexts(a, b, c, pub, ct);

        assertTrue(pool.nullifierUsed(p[4]), "allowlisted disburse nullifier not marked");
    }

    /// A caller who is neither owner nor allowlisted is rejected before any proof
    /// work (the access check precedes the known-root/verify path).
    function testDisburseUnauthorizedReverts() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".disburse");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disburse");
        uint256[] memory p = _pub(".disburse");
        uint[10] memory pub;
        for (uint256 i = 0; i < 10; i++) pub[i] = p[i];

        address stranger = address(0xBAD);
        uint256[] memory ct = _ctBlob(pool);
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(BongtuPool.NotDisburseAuthorized.selector, stranger));
        pool.disburseWithCiphertexts(a, b, c, pub, ct);
    }

    // ================= root / init negative controls =========================

    /// A proof whose membership root was never seeded reverts UnknownRoot before
    /// the Groth16 verify (§5.3 any-historical-root guard).
    function testUnknownRootReverts() public {
        BongtuPool pool = _freshPool(false); // deliberately NOT seeded
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".withdraw");
        uint256[] memory p = _pub(".withdraw");
        uint[25] memory pub;
        for (uint256 i = 0; i < 25; i++) pub[i] = p[i];

        vm.expectRevert(abi.encodeWithSelector(BongtuPool.UnknownRoot.selector, p[18]));
        pool.withdraw(a, b, c, pub);
    }

    /// Operations revert NotInitialized until initialize() seeds arbiter epoch 0.
    function testNotInitializedReverts() public {
        token = new MockERC20();
        BongtuPool pool = deployPool(
            poseidon,
            IDepositVerifier(address(new StubDepositVerifier())),
            IWithdrawVerifier(address(new WithdrawVerifier())),
            IDisburseVerifier(address(new DisburseVerifier())),
            ITransferVerifier(address(new TransferVerifier())),
            IERC20(address(token))
        ); // no initialize()

        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[18] memory pub;
        pub[13] = 1;
        pub[14] = 2;
        vm.expectRevert(BongtuPool.NotInitialized.selector);
        pool.deposit(a, b, c, pub);
    }
}
