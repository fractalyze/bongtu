# Multi-rail consumer wallet: Maroo and Solana in wallet-web

Author: JunBeom Lee. Status: draft.
Origin: conversation

## Problem

The multi-chain privacy wallet exists only at the library level. packages/client-solana
proves the full consumer path (signMessage key derivation, deposit, self-scan, transfer,
withdraw) in the validator gates, but wallet-web is Maroo/EVM-only: no rail selection, no
Solana transaction path in the UI, and no Solana pool a consumer could point at — the rail
has never been deployed to a public cluster. A consumer cannot actually use the Solana rail
today.

## Proposed outcome

- wallet-web offers rail selection between the live Maroo pool and a Solana pool, with the
  architecture shaped for a third rail later (the Tron slot).
- Login, balance via self-scan, transfer, and withdraw work end to end on BOTH rails from
  the UI: Maroo against the live 450815 pool, Solana against a **devnet** pool.
- A committed per-cluster devnet record exists under deploy/solana (the broadcast itself is
  a human-executed step; the repo contains everything so it is one command).
- Falsifiable: the devnet record is committed, and gates prove the wallet flows on both
  rails (local-validator acceptance for CI; the devnet pool for the human check).

## Affected users and systems

Consumer. Components: apps/wallet-web, packages/client-solana and the shared client
engine, deploy/solana (records + runbook), apps/indexer (serving the wallet on the Solana
backend — read paths only), docs.

## Constraints

- Per-rail key derivation is by design: the Solana signing domain (genesis hash + program
  id) yields a DIFFERENT bjj identity than the EVM domain — the UI must present per-rail
  accounts honestly, not pretend one balance.
- No circuit changes; the live Maroo pool and its records untouched.
- The devnet broadcast is a live-chain action: auto mode stops there, the human runs it.
- Overlaps with `consumer-wallet-split` on wallet-web files; whichever runs second rebases.

## Open questions

- Rail selector UX: how per-rail accounts/balances present (tabs, switcher, unified list).
- Which Solana wallet adapters ship at done (Phantom baseline; Ledger's off-chain-message
  format is already handled at the derivation layer).
- Fee UX on Solana (SOL for fees vs the relayer pattern the EVM rail has).
- Whether one indexer instance serves both rails to the wallet or the wallet targets two.
