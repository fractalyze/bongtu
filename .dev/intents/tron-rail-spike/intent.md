# Tron rail feasibility spike and design document

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

The consumer product's end state spans Maroo, Solana, and Tron, but the Tron rail is
entirely unbuilt and its feasibility is unvalidated. TVM is EVM-derived, so the pool
contract might port, but the load-bearing unknowns are unmeasured: whether TVM exposes the
BN254 pairing precompiles our Groth16 verifiers need, what verification costs in energy at
our public-vector sizes (up to uint[141]), how event ingestion and discovery work against
Tron nodes, and what the deploy/upgrade story is. Building the rail before answering these
risks a campaign against an infeasible target.

## Proposed outcome

A feasibility spike whose deliverable is a design document (.dev/tron-rail-design.md) with
MEASURED answers, not speculation:

- Groth16 verification on TVM: precompile availability, a real verify transaction of a
  committed fixture proof on a Tron testnet, and its energy cost per verifier size.
- The pool-contract port shape (what changes vs chains/evm), the event/discovery model for
  the indexer, and the client/key-derivation domain (the signMessage analogue).
- A go/no-go recommendation; on go, the campaign slicing for follow-up build intents.

Falsifiable: the document exists with the measurements attached, and it ends in an explicit
recommendation.

## Affected users and systems

None in production. Output is a .dev design document plus disposable spike artifacts;
no production code path changes.

## Constraints

- No changes to shipped apps, packages, chains, or deploy paths.
- Spike contracts/scripts stay out of the production tree (scratch or clearly-marked spike
  directory, removed or archived at the end).
- Circuit artifacts must be reused byte-identical (same BN254 curve); if Tron verification
  demands any circuit change, that is a no-go finding, not a workaround.

## Open questions

- Testnet choice (Shasta vs Nile) and faucet/tooling reliability.
- Toolchain: tronbox vs porting the foundry flow; tronweb vs a viem-style client.
- Whether Tron's fee model (energy/bandwidth, fee limits) fits the relayer pattern or
  needs its own sponsorship design.
