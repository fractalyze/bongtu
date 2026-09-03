// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {VmSafe} from "forge-std/Vm.sol";

import {BongtuPool} from "bongtu-src/BongtuPool.sol";
import {
    IDepositPrivVerifier,
    ITransferPrivVerifier,
    ITransfer10x2PrivVerifier,
    IWithdrawPrivVerifier,
    IDisbursePrivVerifier
} from "bongtu-src/interfaces/IVerifiers.sol";
import {DepositPrivVerifier} from "bongtu-src/verifiers/DepositPrivVerifier.sol";
import {TransferPrivVerifier} from "bongtu-src/verifiers/TransferPrivVerifier.sol";
import {Transfer10x2PrivVerifier} from "bongtu-src/verifiers/Transfer10x2PrivVerifier.sol";
import {WithdrawPrivVerifier} from "bongtu-src/verifiers/WithdrawPrivVerifier.sol";
import {DisbursePrivVerifier} from "bongtu-src/verifiers/DisbursePrivVerifier.sol";
import {DisbursePriv256Verifier} from "bongtu-src/verifiers/DisbursePriv256Verifier.sol";
import {DepositPrivModule} from "bongtu-src/modules/DepositPrivModule.sol";
import {TransferPrivModule} from "bongtu-src/modules/TransferPrivModule.sol";
import {Transfer10x2PrivModule} from "bongtu-src/modules/Transfer10x2PrivModule.sol";
import {WithdrawPrivModule} from "bongtu-src/modules/WithdrawPrivModule.sol";
import {ConsumerDisburseModule} from "bongtu-src/modules/ConsumerDisburseModule.sol";

/// @notice One deployed consumer module set: five verifiers + five modules,
///         each module constructed over (pool, its verifier). The disburse
///         verifier is picked by the POOL's batch size — 256 => the production
///         DisbursePriv256Verifier, 16 => the 1x16 dev twin. Those are the ONLY
///         two shipped disbursePriv circuit instantiations, so `deploySet`
///         refuses any other B loudly rather than wiring a disburse module no
///         circuit can ever satisfy (a born-bricked, permanently rejecting
///         surface).
struct ConsumerModuleRecord {
    uint256 chainId;
    address pool;
    uint256 chunkArity;
    address depositPrivVerifier;
    address transferPrivVerifier;
    address transfer10x2PrivVerifier;
    address withdrawPrivVerifier;
    address disbursePrivVerifier;
    address depositPrivModule;
    address transferPrivModule;
    address transfer10x2PrivModule;
    address withdrawPrivModule;
    address consumerDisburseModule;
}

/// @title ConsumerModuleKit — the ONE declaration of the consumer module-set
///        deploy (OPMOD §7.3) + its record writer, shared by every script that
///        registers the family (`Deploy.s.sol` MODULE_PROFILE=consumer,
///        `UpgradeV3.s.sol`, `DeployConsumerOnly.s.sol`).
///
/// Module addresses live in their own `deploy/modules.<chainid>.json` (not the
/// AddressBook record): the pool record's field list is enterprise-shaped and
/// consumed field-by-field by `packages/core/src/network.ts`; the module set is
/// an add-on whose canonical on-chain source is the ModuleRegistered event
/// stream (OPMOD §1.4) — this file is the deploy-time convenience mirror.
library ConsumerModuleKit {
    VmSafe private constant vm = VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @dev OPMOD §5/§9 defaults: 86 at B=256 (K=3, each chunk under the
    ///      op-geth txpool byte cap with margin); 6 at B=16 (the 1x16 dev twin
    ///      keeps the same MULTI-chunk K=3 shape so the chunk transport is
    ///      exercised). Only the two shipped batch sizes reach a deploy —
    ///      `deploySet` refuses every other B. Override with MODULE_CHUNK_ARITY.
    function defaultChunkArity(uint256 b) internal pure returns (uint256) {
        return b == 256 ? 86 : 6;
    }

    /// @notice Deploy the five consumer verifiers + five modules against
    ///         `pool`. MUST be called inside an active broadcast window.
    ///         Modules are inert until registered (a pre-registration call
    ///         reverts at applyOp's ModuleNotRegistered), so this deploy is
    ///         unsequenced and safely retryable.
    function deploySet(BongtuPool pool, uint256 chunkArity) internal returns (ConsumerModuleRecord memory r) {
        r.chainId = block.chainid;
        r.pool = address(pool);
        r.chunkArity = chunkArity;

        // Only B ∈ {16, 256} have shipped disbursePriv circuit instantiations;
        // any other pool would get a disburse module whose proofs no circuit
        // can produce — refuse the whole set deploy instead.
        uint256 b = pool.B();
        require(
            b == 16 || b == 256,
            "ConsumerModuleKit: no shipped disbursePriv verifier for this batch size (shipped circuit instantiations: disbursePriv 1x16 dev twin, disbursePriv256 production)"
        );

        DepositPrivVerifier dpv = new DepositPrivVerifier();
        TransferPrivVerifier tpv = new TransferPrivVerifier();
        Transfer10x2PrivVerifier t10x2pv = new Transfer10x2PrivVerifier();
        WithdrawPrivVerifier wpv = new WithdrawPrivVerifier();
        // The disburse verifier is B-selected: the module reads pool.B() and
        // attaches at the pool's LOG_B level (OPMOD §2).
        address dspv = b == 256 ? address(new DisbursePriv256Verifier()) : address(new DisbursePrivVerifier());

        r.depositPrivVerifier = address(dpv);
        r.transferPrivVerifier = address(tpv);
        r.transfer10x2PrivVerifier = address(t10x2pv);
        r.withdrawPrivVerifier = address(wpv);
        r.disbursePrivVerifier = dspv;

        r.depositPrivModule = address(new DepositPrivModule(pool, IDepositPrivVerifier(address(dpv))));
        r.transferPrivModule = address(new TransferPrivModule(pool, ITransferPrivVerifier(address(tpv))));
        r.transfer10x2PrivModule =
            address(new Transfer10x2PrivModule(pool, ITransfer10x2PrivVerifier(address(t10x2pv))));
        r.withdrawPrivModule = address(new WithdrawPrivModule(pool, IWithdrawPrivVerifier(address(wpv))));
        r.consumerDisburseModule =
            address(new ConsumerDisburseModule(pool, IDisbursePrivVerifier(dspv), chunkArity));
    }

    /// @notice The five module addresses in registration order — the
    ///         `reinitializeV3` / `registerModule` payload.
    function modulesArray(ConsumerModuleRecord memory r) internal pure returns (address[] memory mods) {
        mods = new address[](5);
        mods[0] = r.depositPrivModule;
        mods[1] = r.transferPrivModule;
        mods[2] = r.transfer10x2PrivModule;
        mods[3] = r.withdrawPrivModule;
        mods[4] = r.consumerDisburseModule;
    }

    /// @dev The modules record path for the current chain (scripts run from
    ///      `contracts/`, mirroring AddressBook.path()).
    function path() internal view returns (string memory) {
        return string.concat("../deploy/modules.", vm.toString(block.chainid), ".json");
    }

    /// @notice Write the record (full rewrite: the whole set deploys together).
    function write(string memory p, ConsumerModuleRecord memory r) internal {
        string memory o = "bongtu-consumer-modules";
        vm.serializeUint(o, "chainId", r.chainId);
        vm.serializeAddress(o, "pool", r.pool);
        vm.serializeUint(o, "chunkArity", r.chunkArity);
        vm.serializeAddress(o, "depositPrivVerifier", r.depositPrivVerifier);
        vm.serializeAddress(o, "transferPrivVerifier", r.transferPrivVerifier);
        vm.serializeAddress(o, "transfer10x2PrivVerifier", r.transfer10x2PrivVerifier);
        vm.serializeAddress(o, "withdrawPrivVerifier", r.withdrawPrivVerifier);
        vm.serializeAddress(o, "disbursePrivVerifier", r.disbursePrivVerifier);
        vm.serializeAddress(o, "depositPrivModule", r.depositPrivModule);
        vm.serializeAddress(o, "transferPrivModule", r.transferPrivModule);
        vm.serializeAddress(o, "transfer10x2PrivModule", r.transfer10x2PrivModule);
        vm.serializeAddress(o, "withdrawPrivModule", r.withdrawPrivModule);
        string memory js = vm.serializeAddress(o, "consumerDisburseModule", r.consumerDisburseModule);
        vm.writeJson(js, p);
    }
}
