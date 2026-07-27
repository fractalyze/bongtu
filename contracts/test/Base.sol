// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IPoseidon2} from "../src/interfaces/IPoseidon2.sol";
import {IDepositVerifier, IWithdrawVerifier, IDisburseVerifier, ITransferVerifier} from "../src/interfaces/IVerifiers.sol";
import {IERC20} from "../src/utils/IERC20.sol";
import {BongtuPool} from "../src/BongtuPool.sol";
import {ERC1967Proxy} from "../src/utils/proxy/ERC1967Proxy.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

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
        BongtuPool impl = new BongtuPool();
        bytes memory initData =
            abi.encodeCall(BongtuPool.initialize, (poseidon, dv, wv, dsv, tv, token, batchSize, arbiterKey, kemPkHash));
        return BongtuPool(address(new ERC1967Proxy(address(impl), initData)));
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
