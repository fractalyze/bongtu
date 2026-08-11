// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier,
    ITransfer10Verifier,
    ITransfer10x2Verifier
} from "../src/interfaces/IVerifiers.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {ERC1967Proxy} from "../src/utils/proxy/ERC1967Proxy.sol";
import {StubTransfer10Verifier, StubTransfer10x2Verifier} from "./mocks/StubVerifiers.sol";

/// @dev Shared setup: deploy the circomlibjs Poseidon(2) from creation bytecode
///      (same pattern as the reusable PoC), a mock kKRW token, and the pool
///      behind a UUPS ERC-1967 proxy (SPEC §5.2) — the same shape as the live
///      deploy, so tests exercise the pool through its real proxy path.
abstract contract Base is Test {
    uint256 constant B = 16; // M0 disburse batch size

    // Non-zero placeholder KEM pk hash for suites where the KEM epoch material
    // is irrelevant (stub-verifier tree/enforcement tests); initialize rejects
    // bytes32(0) — the pre-KEM marker is reserved for pre-upgrade epochs.
    bytes32 constant DUMMY_KEM_PK_HASH = bytes32(uint256(1));

    /// @dev A length-correct (1088-byte) KEM ciphertext blob: content is
    ///      unchecked on-chain (design doc §2 — binding is arbiter-enforced),
    ///      so stub-verifier suites can pass zeros.
    function dummyKemCt() internal pure returns (bytes memory) {
        return new bytes(1088);
    }

    function deployPoseidon() internal returns (IPoseidon2) {
        bytes memory code = vm.parseBytes(vm.readFile("test/fixtures/poseidon2.hex"));
        address p;
        assembly {
            p := create(0, add(code, 0x20), mload(code))
        }
        require(p != address(0), "poseidon deploy failed");
        return IPoseidon2(p);
    }

    /// @dev Pool impl behind a UUPS proxy, initialized in one tx with batch size
    ///      B and the placeholder KEM pk hash (suites asserting real KEM epoch
    ///      material pass an explicit hash via {deployPoolWithBatch}).
    ///
    ///      `initialize` rejects a zero address for every verifier, so the two
    ///      arity-10 slots are filled with always-accept stubs here. Suites whose
    ///      subject IS an arity-10 path pass their own via {deployPoolWith10}.
    function deployPool(
        IPoseidon2 poseidon,
        IDepositVerifier dv,
        IWithdrawVerifier wv,
        IDisburseVerifier dsv,
        ITransferVerifier tv,
        IERC20 token,
        uint256[2] memory arbiterKey
    ) internal returns (BongtuPool) {
        return deployPoolWithBatch(poseidon, dv, wv, dsv, tv, token, B, arbiterKey, DUMMY_KEM_PK_HASH);
    }

    /// @dev Same as {deployPool} but with an explicit batch size (e.g. B=256)
    ///      and an explicit arbiter KEM pk hash.
    function deployPoolWithBatch(
        IPoseidon2 poseidon,
        IDepositVerifier dv,
        IWithdrawVerifier wv,
        IDisburseVerifier dsv,
        ITransferVerifier tv,
        IERC20 token,
        uint256 batchSize,
        uint256[2] memory arbiterKey,
        bytes32 kemPkHash
    ) internal returns (BongtuPool) {
        return deployPoolFrom(
            InitArgs({
                poseidon: poseidon,
                dv: dv,
                wv: wv,
                dsv: dsv,
                tv: tv,
                tv10: ITransfer10Verifier(address(new StubTransfer10Verifier())),
                tv10x2: ITransfer10x2Verifier(address(new StubTransfer10x2Verifier())),
                token: token,
                batchSize: batchSize,
                arbiterKey: arbiterKey,
                kemPkHash: kemPkHash
            })
        );
    }

    /// @dev {deployPool} with the two arity-10 verifiers named explicitly — the
    ///      Transfer10 / Transfer10x2 suites swap in the real Groth16 verifiers.
    function deployPoolWith10(
        IPoseidon2 poseidon,
        IDepositVerifier dv,
        IWithdrawVerifier wv,
        IDisburseVerifier dsv,
        ITransferVerifier tv,
        ITransfer10Verifier tv10,
        ITransfer10x2Verifier tv10x2,
        IERC20 token,
        uint256[2] memory arbiterKey
    ) internal returns (BongtuPool) {
        return deployPoolFrom(
            InitArgs({
                poseidon: poseidon,
                dv: dv,
                wv: wv,
                dsv: dsv,
                tv: tv,
                tv10: tv10,
                tv10x2: tv10x2,
                token: token,
                batchSize: B,
                arbiterKey: arbiterKey,
                kemPkHash: DUMMY_KEM_PK_HASH
            })
        );
    }

    /// @dev The full 11-argument `initialize` call, gathered into a struct so the
    ///      helpers above stay readable and a suite can build one field at a time
    ///      (the zero-verifier rejection tests do exactly that).
    struct InitArgs {
        IPoseidon2 poseidon;
        IDepositVerifier dv;
        IWithdrawVerifier wv;
        IDisburseVerifier dsv;
        ITransferVerifier tv;
        ITransfer10Verifier tv10;
        ITransfer10x2Verifier tv10x2;
        IERC20 token;
        uint256 batchSize;
        uint256[2] arbiterKey;
        bytes32 kemPkHash;
    }

    function deployPoolFrom(InitArgs memory p) internal returns (BongtuPool) {
        return deployPoolOn(new BongtuPool(), p);
    }

    /// @dev Proxy-only half of {deployPoolFrom}. Tests that assert `initialize`
    ///      REVERTS must deploy the implementation first and call this: a CREATE
    ///      counts as the "next call" for `vm.expectRevert`, so an inline
    ///      `new BongtuPool()` would swallow the expectation.
    function deployPoolOn(BongtuPool impl, InitArgs memory p) internal returns (BongtuPool) {
        return BongtuPool(address(new ERC1967Proxy(address(impl), initCalldata(p))));
    }

    function initCalldata(InitArgs memory p) internal pure returns (bytes memory) {
        return abi.encodeCall(
            BongtuPool.initialize,
            (
                p.poseidon,
                p.dv,
                p.wv,
                p.dsv,
                p.tv,
                p.tv10,
                p.tv10x2,
                p.token,
                p.batchSize,
                p.arbiterKey,
                p.kemPkHash
            )
        );
    }

    /// @dev Pool impl behind a UUPS proxy with EMPTY init data (UNINITIALIZED) —
    ///      for tests that drive initialize() themselves (arbiter-key validation,
    ///      the pre-init NotInitialized guard).
    function deployUninitializedPool() internal returns (BongtuPool) {
        BongtuPool impl = new BongtuPool();
        return BongtuPool(address(new ERC1967Proxy(address(impl), "")));
    }

    // dummy Groth16 args (ignored by stub verifiers)
    function dummyABC() internal pure returns (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) {
        a = [uint256(1), 2];
        b = [[uint256(3), 4], [uint256(5), 6]];
        c = [uint256(7), 8];
    }
}
