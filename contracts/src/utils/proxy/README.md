# Vendored UUPS (ERC-1967) proxy set

A minimal, faithful copy of the OpenZeppelin Contracts **v5.0** UUPS machinery,
vendored here so `BongtuPool` can ship future circuit/verifier changes as an
**upgrade** (preserving the pool address + IMT tree state) instead of a forced
redeploy (SPEC §5.2, `docs/zeto-derivation.md` "Upgradeability").

## Why vendored (not `forge install`)

This repo deliberately carries **plain vendored checkouts** — `lib/forge-std` is a
plain directory, there is **no `.gitmodules` anywhere**, and every file under
`src/utils/` documents a "self-contained / no OpenZeppelin dependency" invariant.
`forge install` would introduce git-submodule machinery foreign to the repo. So
the UUPS set is vendored the same way, matching SPEC §5.1 ("BongtuPool vendors
Zeto's proven patterns — UUPS, ERC-7201 storage …").

## Faithfulness

The ERC-1967 slot math and the ERC-7201 initializer storage are copied
**byte-for-byte** from OZ v5.0 — these must not be hand-improvised:

- `Initializable.INITIALIZABLE_STORAGE = 0xf0c57e16…6a00`
  (`keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~0xff`).
- `ERC1967Utils.IMPLEMENTATION_SLOT = 0x360894a1…82bbc`
  (`keccak256("eip1967.proxy.implementation") - 1`).

`ERC1967Utils` is trimmed to the **implementation-slot** helpers a UUPS proxy
needs; the admin/beacon slots and `IBeacon` are dropped (UUPS keeps upgrade
authority in the implementation via `_authorizeUpgrade`, not a separate admin).
`StorageSlot` / `Address` are trimmed to the members the above pull in. All logic
inside the copied functions is unchanged.

## Files

| file | role |
|------|------|
| `Initializable.sol` | `initializer` / `reinitializer` / `_disableInitializers` (ERC-7201 storage) |
| `ERC1967Utils.sol` | impl slot + `upgradeToAndCall` |
| `UUPSUpgradeable.sol` | `proxiableUUID` + `upgradeToAndCall` + abstract `_authorizeUpgrade` |
| `ERC1967Proxy.sol` + `Proxy.sol` | the ERC-1967 proxy (delegatecall fallback) |
| `IERC1822Proxiable.sol` | ERC-1822 `proxiableUUID` interface |
| `StorageSlot.sol` / `Address.sol` | slot typing + delegatecall bubbling helpers |

`../Ownable2StepUpgradeable.sol` is the initializer-pattern twin of the repo's
own `../Ownable2Step.sol` (regular-storage owner set by `__Ownable2Step_init`).
