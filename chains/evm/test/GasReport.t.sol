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

/// @notice Clean per-operation gas: gasleft() delta around the single pool call,
///         measured in a NORMAL run (forge --gas-report inflates via metering, and
///         mixes arities/revert paths in Min/Avg). B=16 arities here; the 1x256
///         disburse is measured in Disburse256.t.sol (aligned 1.03M / partial 2.0M).
contract GasReportTest is Base {
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

    function _freshPool(bool realDeposit) internal returns (BongtuPool pool) {
        token = new MockERC20();
        IDepositVerifier dv = realDeposit
            ? IDepositVerifier(address(new DepositVerifier()))
            : IDepositVerifier(address(new StubDepositVerifier()));
        pool = deployPool(
            poseidon,
            dv,
            IWithdrawVerifier(address(new WithdrawVerifier())),
            IDisburseVerifier(address(new DisburseVerifier())),
            ITransferVerifier(address(new TransferVerifier())),
            IERC20(address(token)),
            arbiterKey
        );
        token.mint(address(pool), 1_000_000);
        token.mint(address(this), 1_000_000);
        token.approve(address(pool), type(uint256).max);
    }

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

    function _kemCt(string memory key) internal view returns (bytes memory) {
        return vm.parseJsonBytes(j, string.concat(key, ".kemCiphertext"));
    }

    function _seed(BongtuPool pool, string memory key) internal {
        uint256[] memory seed = vm.parseJsonUintArray(j, string.concat(key, ".seedLeaves"));
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = dummyABC();
        uint[19] memory pub;
        pub[14] = seed[0];
        pub[15] = seed[1];
        pool.deposit(a, b, c, pub, dummyKemCt());
    }

    function _pub19(string memory key) internal view returns (uint[19] memory p) {
        uint256[] memory pv = _pub(key);
        for (uint256 i = 0; i < 19; i++) p[i] = pv[i];
    }

    function _pub11(string memory key) internal view returns (uint[11] memory p) {
        uint256[] memory pv = _pub(key);
        for (uint256 i = 0; i < 11; i++) p[i] = pv[i];
    }

    function _pub27(string memory key) internal view returns (uint[27] memory p) {
        uint256[] memory pv = _pub(key);
        for (uint256 i = 0; i < 27; i++) p[i] = pv[i];
    }

    function _pub37(string memory key) internal view returns (uint[37] memory p) {
        uint256[] memory pv = _pub(key);
        for (uint256 i = 0; i < 37; i++) p[i] = pv[i];
    }

    function testGasDeposit() public {
        BongtuPool pool = _freshPool(true);
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".deposit");
        uint[19] memory pub = _pub19(".deposit");
        bytes memory kemCt = _kemCt(".deposit");
        uint256 g = gasleft();
        pool.deposit(a, b, c, pub, kemCt);
        emit log_named_uint("gas deposit (0-in/2-out, +authority envelope, +KEM ct)", g - gasleft());
    }

    function testGasTransfer() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".transfer");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".transfer");
        uint[37] memory pub = _pub37(".transfer");
        bytes memory kemCt = _kemCt(".transfer");
        uint256 g = gasleft();
        pool.transfer(a, b, c, pub, kemCt);
        emit log_named_uint("gas transfer (2-in/2-out, +KEM ct)", g - gasleft());
    }

    function testGasWithdraw() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".withdraw");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".withdraw");
        uint[27] memory pub = _pub27(".withdraw");
        bytes memory kemCt = _kemCt(".withdraw");
        uint256 g = gasleft();
        pool.withdraw(a, b, c, pub, kemCt, bytes32(uint256(1)), 7);
        emit log_named_uint("gas withdraw (2-in/1-out, +authority envelope, +KEM ct, +announcement)", g - gasleft());
    }

    function testGasDisburse16() public {
        BongtuPool pool = _freshPool(false);
        _seed(pool, ".disburse");
        (uint[2] memory a, uint[2][2] memory b, uint[2] memory c) = _abc(".disburse");
        uint[11] memory pub = _pub11(".disburse");
        uint256[] memory ct = new uint256[](pool.disburseCiphertextLen());
        bytes memory kemCt = _kemCt(".disburse");
        uint256 g = gasleft();
        pool.disburseWithCiphertexts(a, b, c, pub, ct, kemCt);
        emit log_named_uint("gas disburse (1-in/16-out, partial block, full ciphertext, +KEM ct)", g - gasleft());
    }
}
