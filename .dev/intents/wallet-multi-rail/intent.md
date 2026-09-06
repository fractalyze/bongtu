# Global multi-rail consumer wallet

Author: JunBeom Lee. Status: accepted.
Origin: conversation

## Problem

The product direction (2026-09-06) is a GLOBAL privacy wallet: the user thinks in assets,
not networks, and the ultimate flow is "send this asset to that recipient privately" with
the chain as an implementation detail. Today the opposite exists: wallet-web is
Maroo/EVM-only, the proven Solana consumer path (packages/client-solana: signMessage key
derivation, deposit, self-scan, transfer, withdraw) has no UI and no public-cluster pool,
and the obvious quick fix — a MetaMask-style network switcher — would train users on
exactly the wrong mental model and shape the component tree around a paradigm the end goal
(cross-chain private send) contradicts. UI paradigms are the most expensive thing to
retrofit; the multi-rail shell is being built fresh now, so building it global-shaped
costs nothing extra.

## Proposed outcome

- wallet-web is a **global wallet shell**: one unified asset view across rails, the chain
  appearing as a badge on an asset, not as a mode the user switches. No network switcher.
- A login session holds the user's per-rail identities simultaneously; connecting only one
  chain wallet degrades gracefully to that rail's assets.
- Login, balance via self-scan, transfer, and withdraw work end to end on BOTH rails from
  the UI: Maroo against the live 450815 pool, Solana against a **devnet** pool. Sends
  target same-chain recipients for now.
- A committed per-cluster devnet record exists under deploy/solana (the broadcast itself
  is a human-executed step; the repo contains everything so it is one command).
- The rail leaks into the surface only where it must: fee payment, receive addresses, and
  send-target scoping. The architecture leaves a third-rail slot (Tron).
- Falsifiable: the devnet record is committed, gates prove the wallet flows on both rails,
  and the shipped UI contains no network-switch affordance.

## Affected users and systems

Consumer. Components: apps/wallet-web, packages/client-solana and the shared client
engine, deploy/solana (records + runbook), apps/indexer (read paths for the Solana
backend), docs.

## Constraints

- Per-rail key derivation is by design: the Solana signing domain (genesis hash + program
  id) yields a DIFFERENT bjj identity than the EVM domain. The global shell may unify the
  PRESENTATION (one asset list) but must not imply one account: per-rail identities stay
  honest in receive/security surfaces.
- **Cross-chain send is an explicit non-goal**: it requires a protocol mechanism that does
  not exist (captured as the `crosschain-private-send` design intent); this intent builds
  the shell that mechanism will later plug into.
- No circuit changes; the live Maroo pool and its records untouched.
- The devnet broadcast is a live-chain action: auto mode stops there, the human runs it.
- Overlaps with `consumer-wallet-split` on wallet-web files; whichever runs second rebases.

## Open questions

- **Login identity — the load-bearing spec decision**: (a) per-rail chain-wallet
  signatures (MetaMask + Phantom each sign; one-wallet users see one rail), vs (b) a
  single signature deriving every rail's keys (true one-login; requires revisiting the
  Solana derivation decision, whose user veto is still open per
  .dev/solana-rail-design.md OPEN-2). Security-model implications either way — spec gate.
- Which Solana wallet adapters ship at done (Phantom baseline; Ledger's
  off-chain-message format is already handled at the derivation layer).
- Fee UX on Solana (SOL for fees vs the relayer pattern the EVM rail has), and how fees
  surface in a global shell without reintroducing a network mode.
- Whether one indexer instance serves both rails to the wallet or the wallet targets two.
