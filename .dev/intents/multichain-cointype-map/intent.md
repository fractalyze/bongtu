# One name answers every served chain

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

The name gateway serves exactly one funds chain: ENS_GATEWAY_CHAIN_ID picks
the single ENSIP-11 coinType answered with destinations, everything else
answers empty. Measured live: senders resolving with Base and Base-Sepolia
selected asked for coinTypes 8453 and 84532 and got nothing, and the demo
had to steer every sender onto one specific network. The product frame is a
chain-aware payment name (the name resolves on the recipient's chosen
receive chain, with Arbitrum and Maroo as the growth path), and today's
one-chain switch cannot express it.

## Proposed outcome

The gateway holds a coinType-to-stack map: each served chain has its own
recorded consumer stack (factory, pool, sweeper), an ENSIP-11 query for a
served coinType derives against that chain's factory, and every answer
keeps the invariant that its implied chain equals the chain whose sweeper
serves the destination. Unserved coinTypes still answer empty and mint
nothing. Falsifiable: with two chains configured, resolving each chain's
coinType yields a destination that a payment on that chain gets swept from
into that chain's pool; a third, unconfigured coinType answers empty and
mints no row.

## Affected users and systems

Sender (multi-chain wallets), recipient, operator. Components: indexer
/ens gateway (config and routing), announce store (rows gain a chain),
deploy records (one consumer pair per chain), one sweeper bot per chain.
The resolver contract is stateless and unchanged.

## Constraints

Per-chain addresses come from that chain's record pair by field name.
Every added chain needs a funded bot key and an RPC, so the map's size is
an operational commitment, not just config. The legacy addr(bytes32) form
carries no chain field; its semantics interact with the chain-ambiguity
suppression intent and the two specs must agree. The live Sepolia demo
keeps working as the map's one-entry case.

## Open questions

Config shape: an env list vs discovering deploy record files. Whether one
indexer instance serves all chains or one instance per chain fronted by
one gateway URL. How announce and feed routes partition by chain. Maroo's
coinType under ENSIP-11 (0x80000000 | chainId) and whether wallets ever
ask for it unprompted. Whether per-chain registration is per-name opt-in
(a recipient serves only chains they can spend from).
