// The pay console — the single main page behind the service login, framed as a
// TESTNET TOOL for trying batch transfers (USER-APPROVED mock, U-P7):
//
//   header      brand "Bongtu Payroll Tool" + TESTNET badge | [Sign out]
//   session card ONE in-content region: connect prompt, or the connected
//               wallet's eth account · bongtu address · kKRW balance · [Deposit]
//               ([Deposit] opens the deposit DIALOG — with the sheet short, the
//               button wears the warn palette and the total row says by how much)
//   payees      only once the wallet is connected: ONE centered
//               [Generate random recipients] button, or the generated worksheet
//               (255 editable/deletable rows) with a [Regenerate] affordance
//   total row   attached under the payees table: total + [Send]
//
// One click on [Send] (after a confirmation that names the random-recipient
// framing) runs the WHOLE chain — transfer10x2 merges until one note covers the
// total (@bongtu/client runMergeChain), then the 1-in/256-out disburse (this
// app's builder, seed randomization intact) — with a wallet-style progress rail
// and a done screen. Every proof goes to the prover service.
//
// The WALLET session lives here (not on the login page): the session card offers
// [Connect wallet] while none exists. The connect chain is unchanged: injected
// provider → ensureChain → EIP-712 sign (the shared KDF) → keyCache seed →
// indexer view token. The idle wipe and an account switch drop the wallet
// session exactly as before; the service session stands. Sign out is the
// reverse coupling (lib/signOut.ts): it ends the service session AND locks the
// key cache — the unmount clears every piece of transient state (nothing here
// is persisted; there is no draft).
//
// All decisions the views render are pure and tested (lib/worksheet.ts,
// lib/randomRecipients.ts, lib/statusBar.ts): this component only wires them to
// React state and the engine flows.

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Banner } from "@bongtu/ui/Banner";
import { KEY_DERIVATION, deriveLoginIdentity } from "@bongtu/client/identity";
import { ensureChain, type Connection } from "@bongtu/client/connection";
import { runDeposit } from "@bongtu/client/depositFlow";
import type { LegProgress, SpendStage } from "@bongtu/client/spendFlow";
import { sumUnspent } from "@bongtu/client/balance";
import { formatKkrw, groupAmountInput } from "@bongtu/client/money";
import { encodeAddress } from "@bongtu/core/pubkey";
import {
  buildNotesTokenUrl,
  buildNotesUrl,
  fetchNotes,
  obtainViewToken,
  type OwnerNote,
} from "@bongtu/client/indexerClient";
import { DEFAULTS } from "../config.js";
import { errorDetails, payrollErrorMessage } from "../lib/errors.js";
import { openInjectedConnection, watchInjectedAccount } from "../lib/connect.js";
import {
  DEPOSIT_MODAL_DEPS,
  depositModalView,
  mintTestKkrw,
  mintView,
  NO_GAS_MESSAGE,
  openDepositModal,
  openMint,
  readDepositAccount,
  readGas,
  type DepositModalState,
  type MintState,
} from "../lib/depositModal.js";
import { keyCache } from "../lib/keyCache.js";
import { proveViaService } from "../lib/proverClient.js";
import { runPayRun, type PayRunResult } from "../lib/payRun.js";
import { generateRecipientsChunked, plannedRowCount } from "../lib/randomRecipients.js";
import { statusBarState } from "../lib/statusBar.js";
import { toastError, toasts } from "../lib/toasts.js";
import {
  MAX_ROWS,
  checkWorksheet,
  removeRow,
  sendReadiness,
  type RowIssue,
  type WorksheetRow,
} from "../lib/worksheet.js";
import { Button, CellInput, Spinner, TestnetBadge, shortHex } from "./controls.js";
import { DepositModal } from "./DepositModal.js";

const INDEXER_URL = DEFAULTS.indexerUrl;
const AUTO_REFRESH_MS = 3000;

/** What every balance-shaped slot says before the first read lands. */
const BALANCE_LOADING = "Loading";

const prove = (request: Parameters<typeof proveViaService>[1]) =>
  proveViaService(DEFAULTS.proverUrl, request);

/** base58 display form: enough head to eyeball-compare, tail to disambiguate. */
function shortB58(b58: string): string {
  return b58.length <= 16 ? b58 : `${b58.slice(0, 8)}…${b58.slice(-6)}`;
}

const STAGE_LABEL: Record<SpendStage, string> = {
  unlock: "Waiting for wallet signature",
  assemble: "Assembling the transaction",
  prove: "Generating the zero-knowledge proof (GPU server)",
  submit: "Waiting for the wallet to send",
  waiting: "Waiting for network confirmation",
};

interface WalletSession {
  connection: Connection;
  /** the employer's compressed bjj pubkey — what every note read/spend is keyed on. */
  pubkey: string;
  /** the indexer's view token, or null when the indexer has no /auth — then the
   *  console signs its reads with the held key instead. In-memory only, like
   *  everything else about the wallet session. */
  viewToken: string | null;
}

type PayPhase =
  | { phase: "idle" }
  | { phase: "running"; stage: SpendStage; leg: LegProgress }
  | { phase: "done"; result: PayRunResult; paid: { address: string; amount: string }[] };

export function Console({ onSignOut }: { onSignOut: () => void }): ReactNode {
  const [rows, setRows] = useState<WorksheetRow[]>([]);
  const [wallet, setWallet] = useState<WalletSession | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [notes, setNotes] = useState<OwnerNote[] | null>(null);
  const [dataError, setDataError] = useState<string | null>(null);

  const [pay, setPay] = useState<PayPhase>({ phase: "idle" });
  const [confirmOpen, setConfirmOpen] = useState(false);
  // The deposit dialog: ONE piece of state, null when closed — a typed amount or a
  // read balance cannot outlive the dialog that collected it.
  const [deposit, setDeposit] = useState<DepositModalState | null>(null);

  const disconnectWallet = useCallback((): void => {
    keyCache.lock();
    toasts.clear();
    setWallet(null);
    setNotes(null);
    setDataError(null);
    setRows([]);
    // The dialogs are wallet-session state too: a switched account must not inherit
    // the previous session's open deposit (its balance readout is that account's).
    setDeposit(null);
    setConfirmOpen(false);
  }, []);

  // The wallet session lives exactly as long as the lock holds the key: the
  // idle wipe (or an explicit lock — Sign out included) drops the console back
  // to its connect affordance — it must not keep rendering balances or a
  // generated sheet for a key it no longer holds.
  useEffect(() => {
    return keyCache.subscribe(() => {
      if (!keyCache.isUnlocked()) disconnectWallet();
    });
  }, [disconnectWallet]);

  // A held spending key belongs to ONE wallet account; a switch ends the session.
  useEffect(() => watchInjectedAccount(disconnectWallet), [disconnectWallet]);

  const connectWallet = useCallback(async (): Promise<void> => {
    setConnecting(true);
    try {
      const connection = await openInjectedConnection();
      // The derivation's typed data pins domain.chainId to the live chain, and wallets
      // reject a v4 request whose domain chain differs from the active one — so
      // the add/switch prompt must come BEFORE the signature.
      await ensureChain(connection);
      // Injected wallets are MetaMask-class deterministic signers — no
      // double-sign check needed (loginGuard's rule for the injected transport).
      const identity = await deriveLoginIdentity(connection, { doubleSign: false }, KEY_DERIVATION);
      // The connect popup already paid for the key: hand it to the lock so the
      // whole session runs on it (idle-wiped, memory-only).
      keyCache.seed(identity, connection.address, identity.compressedPubkey);
      // Trade the key for a view token while it is in hand, so background
      // balance reads never need it again. An indexer without /auth just means
      // key-signed reads (the read paths below handle both).
      let viewToken: string | null = null;
      try {
        const view = await obtainViewToken(
          INDEXER_URL,
          identity.compressedPubkey,
          identity.keypair.formattedPrivateKey,
        );
        viewToken = view.token;
      } catch {
        viewToken = null;
      }
      setWallet({ connection, pubkey: identity.compressedPubkey, viewToken });
    } catch (e) {
      // A declined signature is the most common outcome here; the toast keeps
      // the raw thrown value behind Copy details.
      toastError(payrollErrorMessage(e), errorDetails(e));
    } finally {
      setConnecting(false);
    }
  }, []);

  /** The BACKGROUND read of the employer's notes. Token-authed when the indexer
   *  issued a token; otherwise signed with a key the lock already holds — peeked,
   *  not unlocked, so a 3-second poll neither raises a popup nor postpones the
   *  10-minute idle wipe (@bongtu/client keyCache.peek). Null means no wallet or
   *  an empty lock: there is nothing to read with. */
  const readNotes = useCallback(async (): Promise<OwnerNote[] | null> => {
    if (!wallet) return null;
    if (wallet.viewToken) return fetchNotes(buildNotesTokenUrl(INDEXER_URL, wallet.pubkey, wallet.viewToken));
    const identity = keyCache.peek(wallet.pubkey);
    if (!identity) return null;
    return fetchNotes(buildNotesUrl(INDEXER_URL, wallet.pubkey, identity.keypair.formattedPrivateKey));
  }, [wallet]);

  /** The same read for a user ACTION, which may open the lock (and push its
   *  deadline out) because a person is waiting on the answer. */
  const loadNotes = useCallback(async (): Promise<OwnerNote[]> => {
    if (!wallet) throw new Error("Connect your wallet first.");
    if (wallet.viewToken) return fetchNotes(buildNotesTokenUrl(INDEXER_URL, wallet.pubkey, wallet.viewToken));
    const identity = await keyCache.unlock(wallet.connection, wallet.pubkey);
    return fetchNotes(buildNotesUrl(INDEXER_URL, wallet.pubkey, identity.keypair.formattedPrivateKey));
  }, [wallet]);

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const fresh = await readNotes();
      if (fresh === null) return; // no wallet / locked — nothing to read with
      setNotes(fresh);
      setDataError(null);
    } catch (e) {
      setDataError(`Could not load the balance. Check the indexer connection. (${payrollErrorMessage(e)})`);
    }
  }, [readNotes]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Money disbursed TO or BY this account must appear unprompted; a tick never
  // overlaps itself or a run, and a tokenless session reads only while unlocked.
  const busy = pay.phase === "running" || deposit?.stage != null || deposit?.mint?.pending === true;
  useEffect(() => {
    if (!wallet) return;
    let inflight = false;
    const id = setInterval(() => {
      if (document.visibilityState !== "visible" || inflight || busy) return;
      if (!wallet.viewToken && !keyCache.isUnlocked()) return;
      inflight = true;
      void refresh().finally(() => {
        inflight = false;
      });
    }, AUTO_REFRESH_MS);
    return () => clearInterval(id);
  }, [refresh, busy, wallet]);

  // The session's own address is handed to validation so a row paying it is caught
  // in the cell, not deep inside the terminal assemble after every merge is signed.
  const check = useMemo(() => checkWorksheet(rows, wallet?.pubkey), [rows, wallet]);
  // `notes` is null until a wallet is connected and the first read lands — passed
  // through as null, because "not loaded" is a state of its own and must never be
  // read as an empty balance.
  const readiness = useMemo(() => sendReadiness(check, notes), [check, notes]);
  const balance = notes === null ? null : sumUnspent(notes);
  const bar = statusBarState(
    wallet === null ? null : { ethAccount: wallet.connection.address, bongtuAddress: wallet.pubkey },
    balance,
  );
  // The generate/regenerate gate: 0 rows plannable = disabled + "Deposit first".
  // An unknown balance also plans 0 — the tool never generates against a guess.
  const plannedRows = plannedRowCount(balance);
  const issueFor = (index: number, field: RowIssue["field"]): RowIssue | undefined =>
    check.issues.find((i) => i.index === index && i.field === field);

  const setCell = (i: number, patch: Partial<WorksheetRow>): void =>
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  const [generating, setGenerating] = useState(false);
  const generate = (): void => {
    if (balance === null || plannedRows === 0 || generating) return;
    setGenerating(true);
    setRows([]);
    // Chunked so the event loop keeps painting through 255 scalar mults, but
    // revealed ONCE at the end — streaming rows into the table re-rendered a
    // growing 255-row list eight times and read as UI jank (user feedback).
    const acc: WorksheetRow[] = [];
    void generateRecipientsChunked(balance, (chunk) => acc.push(...chunk))
      .then(() => setRows(acc))
      .finally(() => setGenerating(false));
  };

  const startPay = async (): Promise<void> => {
    if (!wallet) return;
    if (readiness.kind !== "ready" && readiness.kind !== "ready-fragmented") return;
    const recipients = check.recipients;
    setPay({ phase: "running", stage: "assemble", leg: { index: 0, count: readiness.kind === "ready" ? 1 : readiness.mergeCount + 1 } });
    try {
      // Plan against the freshest balance, not the 3s-old screen state.
      const fresh = await loadNotes();
      setNotes(fresh);
      const result = await runPayRun(
        {
          connection: wallet.connection,
          indexerUrl: INDEXER_URL,
          pool: DEFAULTS.pool,
          explorer: DEFAULTS.explorer,
          notes: fresh,
          sessionPubkey: wallet.pubkey,
          reloadNotes: loadNotes,
        },
        recipients,
        (stage, leg) => setPay({ phase: "running", stage, leg }),
        { prove, keyCache },
      );
      setPay({
        phase: "done",
        result,
        paid: rows
          .filter((r) => r.address.trim() !== "" || r.amount.trim() !== "")
          .map((r) => ({ address: r.address.trim(), amount: r.amount.trim() })),
      });
    } catch (e) {
      toastError(payrollErrorMessage(e), errorDetails(e));
      setPay({ phase: "idle" });
      void refresh();
    }
  };

  const closeDone = (): void => {
    // The sheet was paid: back to the empty state — the next test run generates
    // a fresh random sheet against the fresh balance.
    setRows([]);
    setPay({ phase: "idle" });
    void refresh();
  };

  const shortfall = readiness.kind === "insufficient" ? readiness.shortfallWei : null;
  const sendable = readiness.kind === "ready" || readiness.kind === "ready-fragmented";
  // A background refresh can flip the sheet DEFINITIVELY unsendable while the
  // confirm is up (insufficient/blocked) — close it then. A transient "loading"
  // tick must not eat the dialog mid-click.
  useEffect(() => {
    if (readiness.kind === "insufficient" || readiness.kind === "blocked") setConfirmOpen(false);
  }, [readiness.kind]);
  // A background refresh can flip the sheet unsendable while the confirm is up;
  // close it then, so it cannot silently reappear when sendability returns.
  useEffect(() => {
    if (!sendable) setConfirmOpen(false);
  }, [sendable]);

  // --- the deposit dialog ----------------------------------------------------------

  /** Patch the OPEN dialog. A no-op once it is closed, so a late read or a
   *  finally-block cannot resurrect a dialog the operator dismissed. */
  const patchDeposit = (patch: Partial<DepositModalState>): void =>
    setDeposit((d) => (d === null ? null : { ...d, ...patch }));

  /** Read the account's public kKRW + gas into the open dialog. Both edges are
   *  best-effort inside readDepositAccount, so this never throws at the caller. */
  const readDepositBalances = async (connection: Connection): Promise<void> => {
    patchDeposit(await readDepositAccount(connection, DEFAULTS.token, DEFAULTS.pool, DEPOSIT_MODAL_DEPS));
  };

  const openDeposit = (): void => {
    // A deposit signs with the wallet, so the action prompts for the connect when
    // none exists (the session card's [Connect wallet] is the same chain).
    if (!wallet) {
      void connectWallet();
      return;
    }
    // Opened against the CURRENT shortfall: the operator who came here from a short
    // sheet starts with the gap already typed in.
    setDeposit(openDepositModal(shortfall));
    void readDepositBalances(wallet.connection);
  };

  /** The gas belt both actions run first. A ZERO-gas account fails inside the wallet
   *  with an opaque provider object, so it is caught here and said plainly (the
   *  dialog's notice + faucet link) with nothing signed. Returns false = stop. */
  const gasOk = async (connection: Connection): Promise<boolean> => {
    const gas = await readGas(connection, DEPOSIT_MODAL_DEPS);
    patchDeposit({ gas });
    return gas !== "none";
  };

  const startDeposit = async (): Promise<void> => {
    if (!wallet || deposit === null) return;
    const amountWei = depositModalView(deposit).amountWei;
    if (amountWei === null) return;
    patchDeposit({ error: null });
    if (!(await gasOk(wallet.connection))) return;
    patchDeposit({ stage: "approve" });
    try {
      await runDeposit(
        {
          connection: wallet.connection,
          pool: DEFAULTS.pool,
          token: DEFAULTS.token,
          explorer: DEFAULTS.explorer,
          sessionPubkey: wallet.pubkey,
        },
        { amount: amountWei.toString() },
        (stage) => patchDeposit({ stage }),
        { keyCache, prove },
      );
      // The note lands in the pool, not in this dialog: close it and let the 3s
      // refresh show the new private balance where the balance lives.
      setDeposit(null);
      void refresh();
    } catch (e) {
      patchDeposit({ error: payrollErrorMessage(e), stage: null });
    }
  };

  /** Patch the OPEN mint popup — a no-op once it (or the dialog) is closed, the
   *  same late-write rule patchDeposit follows. */
  const patchMint = (patch: Partial<MintState>): void =>
    setDeposit((d) => (d?.mint == null ? d : { ...d, mint: { ...d.mint, ...patch } }));

  const startMint = async (): Promise<void> => {
    if (!wallet || deposit?.mint == null) return;
    const amountWei = mintView(deposit.mint).amountWei;
    if (amountWei === null) return;
    patchMint({ error: null });
    if (!(await gasOk(wallet.connection))) {
      // The dialog's gas notice (with the faucet link) is BEHIND the popup — the
      // popup has to say it too, or the operator watches a dead Mint button.
      patchMint({ error: NO_GAS_MESSAGE });
      return;
    }
    patchMint({ pending: true });
    try {
      const tx = await mintTestKkrw(wallet.connection, DEFAULTS.token, amountWei, DEPOSIT_MODAL_DEPS);
      patchMint({ tx });
      // The minted kKRW is public and sits in the wallet — the dialog's own readout
      // is what changed, so re-read it here (the private balance did not move).
      await readDepositBalances(wallet.connection);
    } catch (e) {
      patchMint({ error: payrollErrorMessage(e) });
    } finally {
      patchMint({ pending: false });
    }
  };

  return (
    <div className="min-h-full flex flex-col">
      <header className="sticky top-0 z-10 bg-surface border-b border-border">
        <div className="max-w-[1100px] mx-auto px-5 py-3 flex items-center gap-2">
          <span className="text-lg font-bold text-primary">Bongtu</span>
          <span className="text-lg font-semibold">Payroll Tool</span>
          <TestnetBadge />
          <div className="ml-auto">
            <Button variant="ghost" onClick={onSignOut}>
              Sign out
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-[1100px] mx-auto w-full px-5 py-5 flex flex-col gap-4 flex-1">
        {/* session card — ONE region for both states: the connect prompt swaps
            to the wallet's account/address/balance/[Deposit] in place */}
        <div className="bg-surface border border-border rounded-xl px-5 py-3.5 flex items-center gap-4 flex-wrap min-h-[58px]">
          {bar.kind === "disconnected" ? (
            <>
              <span className="text-[13.5px] font-medium">Please connect your wallet</span>
              <div className="ml-auto">
                <Button disabled={connecting} onClick={() => void connectWallet()}>
                  {connecting && <Spinner />}
                  {connecting ? "Connecting…" : "Connect wallet"}
                </Button>
              </div>
            </>
          ) : (
            <>
              <span className="font-mono text-[12px]" title={bar.ethAccount}>
                {shortHex(bar.ethAccount)}
              </span>
              <span className="text-muted">·</span>
              {/* the bongtu address is DISPLAYED base58 like every other surface;
                  the state keeps canonical hex */}
              <span className="font-mono text-[12px]" title={encodeAddress(bar.bongtuAddress)}>
                {shortB58(encodeAddress(bar.bongtuAddress))}
              </span>
              <span className="text-muted">·</span>
              <span className="text-[13px] font-semibold tabular-nums">
                {/* an unread balance is Loading — never a false zero */}
                {bar.balanceWei === null ? BALANCE_LOADING : `${formatKkrw(bar.balanceWei)} kKRW`}
              </span>
              <div className="ml-auto">
                {/* while the sheet is short, the ONE affordance that fixes it wears
                    the warn palette — the total row says by how much */}
                <Button variant={shortfall !== null ? "warn" : "secondary"} onClick={openDeposit}>
                  Deposit
                </Button>
              </div>
            </>
          )}
        </div>
        {dataError && <Banner message={dataError} onRetry={() => void refresh()} retryLabel="Retry" />}

        {/* payees — only once the wallet is connected */}
        {wallet !== null &&
          (rows.length === 0 ? (
            /* empty state: ONE centered generate button — or, mid-generation,
               the whole area as a loading panel until the sheet reveals at once */
            <div className="bg-surface border border-border rounded-xl flex-1 flex flex-col items-center justify-center gap-3 py-16">
              {generating ? (
                <div className="flex flex-col items-center gap-2 text-muted">
                  <span className="w-6 h-6 rounded-full border-[3px] border-border border-t-primary animate-spin" />
                  <span className="text-[13px]">Generating {plannedRows} recipients…</span>
                </div>
              ) : (
                <Button disabled={plannedRows === 0} onClick={generate}>
                  Generate random recipients
                </Button>
              )}
              {plannedRows === 0 && (
                <div className="text-[12px] text-muted">
                  {balance === null ? BALANCE_LOADING : "Deposit first"}
                </div>
              )}
            </div>
          ) : (
            <div className="bg-surface border border-border rounded-xl overflow-hidden flex flex-col">
              <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border">
                <span className="text-[13px] font-semibold">Payees</span>
                <span className="text-[12px] text-muted tabular-nums">
                  {check.filledCount}/{MAX_ROWS}
                </span>
                <div className="ml-auto">
                  {/* replaces the WHOLE list with a fresh random sheet */}
                  <Button variant="secondary" disabled={plannedRows === 0 || generating} onClick={generate}>
                    {generating && <Spinner />}
                    {generating ? "Generating…" : "Regenerate"}
                  </Button>
                </div>
              </div>
              <div className="overflow-y-auto max-h-[60vh]">
                <table className="w-full text-[13px] border-collapse">
                  <thead>
                    <tr className="text-left text-muted text-[12px]">
                      <th className="px-4 py-2 w-[52px] font-medium">#</th>
                      <th className="px-2 py-2 font-medium">Recipient address</th>
                      <th className="px-2 py-2 w-[180px] font-medium text-right">Amount (kKRW)</th>
                      <th className="px-2 py-2 w-[48px]" />
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map((r, i) => {
                      const addrIssue = issueFor(i, "address");
                      const amtIssue = issueFor(i, "amount");
                      return (
                        <tr key={i} className="border-t border-border align-top">
                          <td className="px-4 py-1.5 text-muted tabular-nums">{i + 1}</td>
                          <td className="px-2 py-1.5">
                            <CellInput
                              mono
                              ariaLabel={`Recipient address ${i + 1}`}
                              value={r.address}
                              placeholder="bongtu address (3… base58 or 0x… hex)"
                              invalid={addrIssue !== undefined}
                              onChange={(v) => setCell(i, { address: v })}
                            />
                            {addrIssue && <div className="text-[11.5px] text-err mt-0.5">{addrIssue.message}</div>}
                          </td>
                          <td className="px-2 py-1.5">
                            <CellInput
                              align="right"
                              ariaLabel={`Amount ${i + 1}`}
                              value={r.amount}
                              placeholder="0"
                              invalid={amtIssue !== undefined}
                              onChange={(v) => setCell(i, { amount: groupAmountInput(v) })}
                            />
                            {amtIssue && <div className="text-[11.5px] text-err mt-0.5 text-right">{amtIssue.message}</div>}
                          </td>
                          <td className="px-2 py-1.5">
                            <Button variant="ghost" aria-label={`Delete row ${i + 1}`} onClick={() => setRows((rs) => removeRow(rs, i))}>
                              ✕
                            </Button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {/* total + send — attached under the table, not a fixed footer
                  (sendReadiness keeps the messaging truthful) */}
              <div className="border-t border-border px-4 py-3.5 flex items-center gap-4 flex-wrap bg-surface">
                <div className="text-[14px] font-semibold tabular-nums">
                  Total outgoing: {formatKkrw(check.totalWei)} kKRW ({check.filledCount} recipient
                  {check.filledCount === 1 ? "" : "s"})
                </div>
                <div className="text-[12.5px] text-muted flex-1 min-w-[200px]">
                  {readiness.kind === "loading" &&
                    (dataError !== null ? "The balance could not be read. See the notice above." : "Loading the balance…")}
                  {readiness.kind === "blocked" && "Fix the highlighted cells to send."}
                  {readiness.kind === "ready" && "Balance covers the sheet. One payout transaction will be sent."}
                  {readiness.kind === "ready-fragmented" &&
                    `Your balance is split across notes: ${readiness.mergeCount} merge${readiness.mergeCount === 1 ? "" : "s"}, then the payout — ${readiness.mergeCount + 1} signatures in total.`}
                  {readiness.kind === "insufficient" && shortfall !== null && (
                    <span className="text-err font-medium">
                      Balance is short by {formatKkrw(shortfall)} kKRW. Use Deposit at the top,
                      then send.
                    </span>
                  )}
                </div>
                <Button disabled={!sendable || generating} onClick={() => setConfirmOpen(true)}>
                  Send
                </Button>
              </div>
            </div>
          ))}
      </main>

      {confirmOpen && (
        <ConfirmSend
          totalWei={check.totalWei}
          recipientCount={check.filledCount}
          mergeCount={readiness.kind === "ready-fragmented" ? readiness.mergeCount : 0}
          onCancel={() => setConfirmOpen(false)}
          onConfirm={() => {
            setConfirmOpen(false);
            void startPay();
          }}
        />
      )}
      {deposit !== null && (
        <DepositModal
          state={deposit}
          onAmountChange={(amount) => patchDeposit({ amount })}
          onClose={() => setDeposit(null)}
          onDeposit={() => void startDeposit()}
          onOpenMint={() => patchDeposit({ mint: openMint() })}
          onCloseMint={() => patchDeposit({ mint: null })}
          onMintAmountChange={(amount) => patchMint({ amount })}
          onMint={() => void startMint()}
        />
      )}
      {pay.phase === "running" && <ProgressRail stage={pay.stage} leg={pay.leg} />}
      {pay.phase === "done" && <DoneScreen result={pay.result} paid={pay.paid} onClose={closeDone} />}
    </div>
  );
}

/** The send confirmation. One line is REQUIRED by the testnet framing: the
 *  operator is reminded the payees are random test addresses, not people. */
function ConfirmSend({
  totalWei,
  recipientCount,
  mergeCount,
  onCancel,
  onConfirm,
}: {
  totalWei: bigint;
  recipientCount: number;
  mergeCount: number;
  onCancel: () => void;
  onConfirm: () => void;
}): ReactNode {
  return (
    <div className="fixed inset-0 z-20 bg-backdrop flex items-center justify-center p-6">
      <div className="w-full max-w-[420px] bg-surface border border-border rounded-2xl p-6 flex flex-col gap-4">
        <div className="text-[15px] font-semibold">Send the payout?</div>
        <div className="text-[13.5px]">
          {formatKkrw(totalWei)} kKRW to {recipientCount} recipient{recipientCount === 1 ? "" : "s"} in one
          private transaction
          {mergeCount > 0 ? ` (after ${mergeCount} merge transaction${mergeCount === 1 ? "" : "s"})` : ""}.
        </div>
        <div className="text-[12.5px] text-muted">Recipients are randomly generated for this testnet run.</div>
        <div className="flex gap-2 justify-end">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button onClick={onConfirm}>Send</Button>
        </div>
      </div>
    </div>
  );
}

/** The wallet-style progress rail, over the whole chain: merge legs then the
 *  terminal disburse, one row per transaction, the active row narrating its
 *  stage. */
function ProgressRail({ stage, leg }: { stage: SpendStage; leg: LegProgress }): ReactNode {
  const labels = Array.from({ length: leg.count }, (_, i) =>
    i < leg.count - 1 ? `Merge notes ${i + 1}` : "Send the payout",
  );
  return (
    <div className="fixed inset-0 z-20 bg-backdrop flex items-center justify-center p-6">
      <div className="w-full max-w-[420px] bg-surface border border-border rounded-2xl p-6 flex flex-col gap-4">
        <div className="text-[15px] font-semibold">Running the payout</div>
        <ol className="flex flex-col gap-2.5">
          {labels.map((label, i) => {
            const state = i < leg.index ? "done" : i === leg.index ? "active" : "todo";
            return (
              <li key={i} className="flex items-start gap-2.5">
                <span
                  className={`mt-0.5 w-5 h-5 rounded-full flex items-center justify-center text-[11px] font-semibold shrink-0 ${
                    state === "done"
                      ? "bg-pos-bg text-pos animate-check-pop"
                      : state === "active"
                        ? "bg-primary text-primary-ink animate-pulse-soft"
                        : "bg-surface-2 text-muted"
                  }`}
                >
                  {state === "done" ? "✓" : i + 1}
                </span>
                <div className="min-w-0 flex-1">
                  <div className={`text-[13.5px] ${state === "todo" ? "text-muted" : "font-medium"}`}>{label}</div>
                  {state === "active" && <StageChecklist stage={stage} />}
                </div>
              </li>
            );
          })}
        </ol>
        <div className="text-[12px] text-muted">
          Each transaction needs one wallet confirmation. Keep this window open.
        </div>
      </div>
    </div>
  );
}

/** The active leg's inner stages as their own checklist — a single-leg payout
 *  would otherwise read as one opaque step while proving/waiting runs. `unlock`
 *  renders as a transient first row only while it is happening. */
const STAGE_ORDER: SpendStage[] = ["assemble", "prove", "submit", "waiting"];
function StageChecklist({ stage }: { stage: SpendStage }): ReactNode {
  const activeAt = stage === "unlock" ? -1 : STAGE_ORDER.indexOf(stage);
  return (
    <ol className="mt-1.5 flex flex-col gap-1">
      {stage === "unlock" && (
        <li className="flex items-center gap-2 text-[12px] font-medium">
          <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse-soft shrink-0" />
          {STAGE_LABEL.unlock}
        </li>
      )}
      {STAGE_ORDER.map((st, i) => {
        const state = i < activeAt ? "done" : i === activeAt ? "active" : "todo";
        return (
          <li
            key={st}
            className={`flex items-center gap-2 text-[12px] ${
              state === "done" ? "text-pos" : state === "active" ? "font-medium" : "text-muted"
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full shrink-0 ${
                state === "done" ? "bg-pos" : state === "active" ? "bg-primary animate-pulse-soft" : "bg-border-strong"
              }`}
            />
            {STAGE_LABEL[st]}
          </li>
        );
      })}
    </ol>
  );
}


/** The done screen: one check per paid row + the explorer link of the terminal
 *  disburse (merge legs listed under it). No receipts download, by design. */
function DoneScreen({
  result,
  paid,
  onClose,
}: {
  result: PayRunResult;
  paid: { address: string; amount: string }[];
  onClose: () => void;
}): ReactNode {
  return (
    <div className="fixed inset-0 z-20 bg-backdrop flex items-center justify-center p-6">
      <div className="w-full max-w-[480px] max-h-[80vh] bg-surface border border-border rounded-2xl p-6 flex flex-col gap-4">
        <div className="flex items-center gap-2.5">
          <span className="w-8 h-8 rounded-full bg-pos-bg text-pos flex items-center justify-center text-[15px] animate-check-pop">
            ✓
          </span>
          <div>
            <div className="text-[15px] font-semibold">Payout complete</div>
            <div className="text-[12.5px] text-muted">
              {result.recipientCount} recipient{result.recipientCount === 1 ? "" : "s"} paid.
            </div>
          </div>
        </div>
        <ul className="flex-1 overflow-y-auto flex flex-col gap-1.5 border border-border rounded-xl p-3">
          {paid.map((row, i) => (
            <li key={i} className="flex items-center gap-2 text-[12.5px]">
              <span className="text-pos">✓</span>
              <span className="font-mono truncate flex-1" title={row.address}>
                {shortHex(row.address, 10, 6)}
              </span>
              <span className="tabular-nums">{row.amount} kKRW</span>
            </li>
          ))}
        </ul>
        <div className="text-[12.5px]">
          <a className="text-primary underline" href={result.explorerUrl} target="_blank" rel="noreferrer">
            View the payout transaction ({shortHex(result.txHash, 8, 6)})
          </a>
          {result.mergeTxs.length > 0 && (
            <div className="text-muted mt-1">
              {result.mergeTxs.length} merge transaction{result.mergeTxs.length === 1 ? "" : "s"}:{" "}
              {result.mergeTxs.map((t, i) => (
                <a key={t.txHash} className="underline mr-2" href={t.explorerUrl} target="_blank" rel="noreferrer">
                  #{i + 1}
                </a>
              ))}
            </div>
          )}
        </div>
        <Button onClick={onClose}>Close</Button>
      </div>
    </div>
  );
}
