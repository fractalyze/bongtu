# bongtu review style guide

Rules a reviewer should enforce beyond generic best practice. Full context
lives in README.md and docs/; decision history in .dev/.

## TypeScript

- `let` is banned in source code: loops and accumulation are expressed with
  `for (const ... of ...)`, `reduce`, or a const IIFE. Flag any `let`.
- Comments explain WHY, not what. Flag comments that restate the code, and
  flag deleted comments that carried rationale.
- Tests are interface-level (node:test, no DOM): state machines, copy
  tables, wire shapes. Flag tests that pin implementation details or change
  existing assertions during a refactor.
- Public import surfaces are the package exports maps (noun subpaths).
  Flag deep relative imports across packages or new cross-package
  re-export layers.

## Consensus-critical code (packages/core crypto, chains/*)

- Crypto folds keep their iteration order; moved crypto files must be
  content-identical. Flag any reshaping of hash/fold/limb logic, changed
  endianness, or a hand-written constant that should be generated from
  circuit artifacts (verification keys, poseidon vectors).
- Byte layouts (instruction wires, envelope layouts, PDA seeds) are frozen
  contracts: flag any change that is not accompanied by a spec note and a
  regenerated fixture.

## Money and custody

- The bjj private key never enters React state, browser storage, or logs.
- A balance must never render a fabricated zero: loading and
  empty-after-scan are distinct states.
- Failure copy comes from the shared classifier tables; flag raw
  `e.message` rendering in app code.

## Tests and gates

- Every behavior change needs a test in the same PR.
- Gate scripts never pipe through `tail` (exit code loss); flag it.
