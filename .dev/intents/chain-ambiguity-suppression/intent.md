# Chain-ambiguous name answers stop leaking cross-chain destinations

Author: JunBeom Lee. Status: draft.
Origin: incident

## Problem

Observed live on the demo topology (resolver on mainnet, funds on
Sepolia): the legacy addr(bytes32) form and coinType 60 answer a
Sepolia-only destination to a mainnet-selected wallet. The wallet renders
it as an ordinary mainnet recipient, and any mainnet asset sent there is
permanently stranded - the C1 hazard class, one mistaken send away from
real loss once real value is nearby. The demo survives only by posture
("resolve to view and copy, then send on Sepolia"), which no runbook
sentence can enforce on a sender. The gateway currently has no notion of
"the chain this answer implies" vs "the chain I can actually sweep".

## Proposed outcome

The gateway never serves a destination whose implied chain it cannot
sweep: when the queried form names a chain (explicitly via ENSIP-11
coinType, or implicitly - the legacy form means the resolution chain) that
has no recorded funds stack, the answer is empty and no row is minted. The
demo's deliberate cross-chain override, if kept at all, becomes an
explicit opt-in flag defaulting to off. Falsifiable: on a split-chain
deployment with the flag off, coinType 60 and the legacy form answer
empty and mint nothing; on a same-chain deployment both answer normally;
the name_leg gate asserts both postures.

## Affected users and systems

Sender (protected from stranding), operator. Components: indexer /ens
gateway routing; the name_leg gate. Interacts with the multichain
cointype map intent, which makes "the set of chains with a recorded funds
stack" an explicit structure this rule can consult.

## Constraints

Same-chain deployments must keep answering the legacy form: it is what a
native-chain MetaMask actually asks (measured), so suppression keyed on
anything but a real chain mismatch breaks the main path. The live demo
depends on the unsafe behavior today, so rollout needs the opt-in flag or
the mainnet funds promotion to land first. Suppression must mint nothing:
an empty answer that still creates a row would reintroduce the
unfunded-row cost the detection intent removes.

## Open questions

Empty answer vs explicit error for a suppressed form, and what each
renders as in real wallets (a wrong "name not found" is better than a
strandable address, but worth measuring). Whether the opt-in override is
worth keeping once mainnet funds exist, or the split topology dies with
the demo. Whether text records and other resolution forms need the same
rule.
