// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {VmSafe} from "forge-std/Vm.sol";

/// @notice One deployment record — the complete field list of
///         `deploy/addresses.<chainid>.json`, declared ONCE.
///
/// Every deploy/upgrade script used to hand-serialize the whole field list, so a
/// script that only changed two entries still had to restate all the others; the
/// PQ upgrade's rewrite once dropped `arbiterKemPk` that way. Scripts now read
/// the record, assign the fields they actually change, and write it back.
///
/// Two fields are OPTIONAL, and for the same reason: a chain can legitimately
/// predate them, and writing a zero would claim the pool holds one when it does
/// not. Both are therefore absent from the file rather than empty.
///   - `arbiterKemPk` — the full 1184-byte ML-KEM-768 encapsulation key,
///     convenience metadata next to the hash the pool actually stores. Absent on
///     a chain whose arbiter predates the hybrid envelope.
///   - `transfer10Verifier` — absent until `UpgradeTransfer10.s.sol` runs. A
///     pre-V4 pool's `transfer10Verifier` really is `address(0)` (which is why
///     `transfer10` reverts there), so the field appearing at all is the marker
///     that the V4 payload landed.
struct AddressRecord {
    uint256 chainId;
    address owner;
    uint256 batchSize;
    uint256 arbiterKeyX;
    uint256 arbiterKeyY;
    bytes32 arbiterKemPkHash;
    bytes arbiterKemPk; // optional — absent on a pre-KEM chain
    address poseidon;
    address depositVerifier;
    address withdrawVerifier;
    address disburseVerifier;
    address transferVerifier;
    address transfer10Verifier; // optional — absent on a pre-V4 chain
    address token;
    address poolImpl;
    address pool;
}

/// @title AddressBook — read/merge-write of `deploy/addresses.<chainid>.json`.
///
/// A library rather than a base contract: the deploy scripts already extend
/// `Script`, and this is data plumbing, not behaviour they specialize. It talks
/// to the cheatcode address directly (the forge-std `VM_ADDRESS` constant) so it
/// needs no inheritance at all.
///
/// Usage from a script — name only what you change:
///
///     AddressRecord memory r = AddressBook.read(AddressBook.path());
///     r.transferVerifier = tv;
///     r.poolImpl = impl;
///     AddressBook.write(AddressBook.path(), r);
///
/// forge serializes JSON with sorted keys, so the field order here does not
/// affect the file's shape.
library AddressBook {
    VmSafe private constant vm = VmSafe(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// @dev The record for the chain the script is running against. Scripts run
    ///      from `contracts/`, hence the `../deploy` prefix (matching the
    ///      `fs_permissions` grant in contracts/foundry.toml).
    function path() internal view returns (string memory) {
        return string.concat("../deploy/addresses.", vm.toString(block.chainid), ".json");
    }

    /// @notice Load the existing record. Every field except the two optional ones
    ///         is required — a record missing one is corrupt, and defaulting it to
    ///         zero would write that zero back on the next merge.
    function read(string memory p) internal view returns (AddressRecord memory r) {
        string memory j = vm.readFile(p);
        r.chainId = vm.parseJsonUint(j, ".chainId");
        r.owner = vm.parseJsonAddress(j, ".owner");
        r.batchSize = vm.parseJsonUint(j, ".batchSize");
        r.arbiterKeyX = vm.parseJsonUint(j, ".arbiterKeyX");
        r.arbiterKeyY = vm.parseJsonUint(j, ".arbiterKeyY");
        r.arbiterKemPkHash = vm.parseJsonBytes32(j, ".arbiterKemPkHash");
        if (vm.keyExists(j, ".arbiterKemPk")) r.arbiterKemPk = vm.parseJsonBytes(j, ".arbiterKemPk");
        r.poseidon = vm.parseJsonAddress(j, ".poseidon");
        r.depositVerifier = vm.parseJsonAddress(j, ".depositVerifier");
        r.withdrawVerifier = vm.parseJsonAddress(j, ".withdrawVerifier");
        r.disburseVerifier = vm.parseJsonAddress(j, ".disburseVerifier");
        r.transferVerifier = vm.parseJsonAddress(j, ".transferVerifier");
        if (vm.keyExists(j, ".transfer10Verifier")) {
            r.transfer10Verifier = vm.parseJsonAddress(j, ".transfer10Verifier");
        }
        r.token = vm.parseJsonAddress(j, ".token");
        r.poolImpl = vm.parseJsonAddress(j, ".poolImpl");
        r.pool = vm.parseJsonAddress(j, ".pool");
    }

    /// @notice Write the record back. An unset optional field stays ABSENT: a
    ///         zero there would claim material the pool does not hold, and the
    ///         next merge-read would carry that claim forward as truth.
    /// @dev The recorded key and the recorded hash must describe the SAME
    ///      arbiter: a rotation that changes the hash and carries the old bytes
    ///      forward would publish a key clients hash-check and reject. Callers
    ///      that rotate clear the field; this require is the belt that keeps the
    ///      two fields from ever disagreeing on disk.
    function write(string memory p, AddressRecord memory r) internal {
        require(
            r.arbiterKemPk.length == 0 || keccak256(r.arbiterKemPk) == r.arbiterKemPkHash,
            "arbiterKemPk does not hash to arbiterKemPkHash"
        );
        string memory o = "bongtu-address-book";
        vm.serializeUint(o, "chainId", r.chainId);
        vm.serializeAddress(o, "owner", r.owner);
        vm.serializeUint(o, "batchSize", r.batchSize);
        vm.serializeUint(o, "arbiterKeyX", r.arbiterKeyX);
        vm.serializeUint(o, "arbiterKeyY", r.arbiterKeyY);
        vm.serializeBytes32(o, "arbiterKemPkHash", r.arbiterKemPkHash);
        if (r.arbiterKemPk.length != 0) vm.serializeBytes(o, "arbiterKemPk", r.arbiterKemPk);
        vm.serializeAddress(o, "poseidon", r.poseidon);
        vm.serializeAddress(o, "depositVerifier", r.depositVerifier);
        vm.serializeAddress(o, "withdrawVerifier", r.withdrawVerifier);
        vm.serializeAddress(o, "disburseVerifier", r.disburseVerifier);
        vm.serializeAddress(o, "transferVerifier", r.transferVerifier);
        if (r.transfer10Verifier != address(0)) {
            vm.serializeAddress(o, "transfer10Verifier", r.transfer10Verifier);
        }
        vm.serializeAddress(o, "token", r.token);
        vm.serializeAddress(o, "poolImpl", r.poolImpl);
        string memory js = vm.serializeAddress(o, "pool", r.pool);
        vm.writeJson(js, p);
    }
}
