// The pay console — the single main page behind the login (LOCKED design,
// 2026-07-29): sticky header (brand, pool, account, balance), a full-width
// worksheet of {받는 주소, 금액} rows, a compact stat bar, and a 3-state footer
// (covered / covered-but-fragmented / insufficient-with-deposit-CTA). One click
// on [전송] runs the WHOLE chain — transfer10x2 merges until one note covers the
// total (@bongtu/client runMergeChain), then the 1-in/256-out disburse (this
// app's builder, seed randomization intact) — with a wallet-style progress rail
// and a per-row done screen. Every proof goes to the prover service.
//
// All decisions the table renders are pure and tested (lib/worksheet.ts): this
// component only wires them to React state and the engine flows.

import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Banner } from "@bongtu/ui/Banner";
import type { Connection } from "@bongtu/client/connection";
import { runDeposit, type DepositStage } from "@bongtu/client/depositFlow";
import type { LegProgress, SpendStage } from "@bongtu/client/spendFlow";
import { sumUnspent } from "@bongtu/client/balance";
import { formatKkrw, groupAmountInput } from "@bongtu/client/money";
import {
  buildNotesTokenUrl,
  buildNotesUrl,
  fetchNotes,
  type OwnerNote,
} from "@bongtu/client/indexerClient";
import { DEFAULTS } from "../config.js";
import { errorDetails, parseDepositAmount, payrollErrorMessage } from "../lib/errors.js";
import { keyCache } from "../lib/keyCache.js";
import { proveViaService } from "../lib/proverClient.js";
import { runPayRun, type PayRunResult } from "../lib/payRun.js";
import { toastError } from "../lib/toasts.js";
import {
  MAX_ROWS,
  addRow,
  blankRow,
  checkWorksheet,
  clearDraft,
  loadDraft,
  removeRow,
  rowsFromCsv,
  saveDraft,
  sendReadiness,
  type RowIssue,
  type WorksheetRow,
} from "../lib/worksheet.js";
import { Button, CellInput, Stat, shortHex } from "./controls.js";

const INDEXER_URL = DEFAULTS.indexerUrl;
const AUTO_REFRESH_MS = 3000;

/** What every balance-shaped slot says before the first read lands. */
const BALANCE_LOADING = "확인 중";

const prove = (request: Parameters<typeof proveViaService>[1]) =>
  proveViaService(DEFAULTS.proverUrl, request);

const STAGE_LABEL: Record<SpendStage, string> = {
  unlock: "지갑 서명 대기 중",
  assemble: "트랜잭션 구성 중",
  prove: "영지식 증명 생성 중 (GPU 서버)",
  submit: "체인 전송 대기 중",
  waiting: "네트워크 반영 대기 중",
};

const DEPOSIT_STAGE_LABEL: Record<DepositStage, string> = {
  unlock: "지갑 서명 대기 중",
  approve: "kKRW 사용 승인 중",
  prove: "영지식 증명 생성 중 (GPU 서버)",
  submit: "체인 전송 대기 중",
};

type PayPhase =
  | { phase: "idle" }
  | { phase: "running"; stage: SpendStage; leg: LegProgress }
  | { phase: "done"; result: PayRunResult; paid: { address: string; amount: string }[] };

export function Console({
  connection,
  pubkey,
  viewToken,
  onLogout,
}: {
  connection: Connection;
  /** the logged-in session's compressed bjj pubkey (the employer's receive id). */
  pubkey: string;
  /** the indexer's view token from login, or null for an indexer without /auth —
   *  then reads sign with the held key instead (and pause while locked). */
  viewToken: string | null;
  onLogout: () => void;
}): ReactNode {
  const storage = typeof localStorage === "undefined" ? null : localStorage;
  const [rows, setRows] = useState<WorksheetRow[]>(() => loadDraft(storage));
  const [notes, setNotes] = useState<OwnerNote[] | null>(null);
  const [dataError, setDataError] = useState<string | null>(null);

  const [pay, setPay] = useState<PayPhase>({ phase: "idle" });
  const [depositOpen, setDepositOpen] = useState(false);
  const [depositAmount, setDepositAmount] = useState("");
  const [depositStage, setDepositStage] = useState<DepositStage | null>(null);
  const [depositError, setDepositError] = useState<string | null>(null);

  // Draft-persist what the employer types — the login never survives a reload,
  // the half-built sheet should (injectable-storage seam, tested).
  useEffect(() => saveDraft(rows, storage), [rows, storage]);

  /** The BACKGROUND read of the employer's notes. Token-authed when the indexer
   *  issued a token; otherwise signed with a key the lock already holds — peeked,
   *  not unlocked, so a 3-second poll neither raises a popup nor postpones the
   *  10-minute idle wipe (@bongtu/client keyCache.peek). Null means the lock is
   *  empty: there is nothing to read with, and App is already dropping to Login. */
  const readNotes = useCallback(async (): Promise<OwnerNote[] | null> => {
    if (viewToken) return fetchNotes(buildNotesTokenUrl(INDEXER_URL, pubkey, viewToken));
    const identity = keyCache.peek(pubkey);
    if (!identity) return null;
    return fetchNotes(buildNotesUrl(INDEXER_URL, pubkey, identity.keypair.formattedPrivateKey));
  }, [viewToken, pubkey]);

  /** The same read for a user ACTION, which may open the lock (and push its
   *  deadline out) because a person is waiting on the answer. */
  const loadNotes = useCallback(async (): Promise<OwnerNote[]> => {
    if (viewToken) return fetchNotes(buildNotesTokenUrl(INDEXER_URL, pubkey, viewToken));
    const identity = await keyCache.unlock(connection, pubkey);
    return fetchNotes(buildNotesUrl(INDEXER_URL, pubkey, identity.keypair.formattedPrivateKey));
  }, [viewToken, pubkey, connection]);

  const refresh = useCallback(async (): Promise<void> => {
    try {
      const fresh = await readNotes();
      if (fresh === null) return; // locked — the session is ending, not failing
      setNotes(fresh);
      setDataError(null);
    } catch (e) {
      setDataError(`잔고를 불러오지 못했습니다. 인덱서 연결을 확인하세요. (${payrollErrorMessage(e)})`);
    }
  }, [readNotes]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // Money disbursed TO or BY this account must appear unprompted; a tick never
  // overlaps itself or a run, and a tokenless session reads only while unlocked.
  const busy = pay.phase === "running" || depositStage !== null;
  useEffect(() => {
    let inflight = false;
    const id = setInterval(() => {
      if (document.visibilityState !== "visible" || inflight || busy) return;
      if (!viewToken && !keyCache.isUnlocked()) return;
      inflight = true;
      void refresh().finally(() => {
        inflight = false;
      });
    }, AUTO_REFRESH_MS);
    return () => clearInterval(id);
  }, [refresh, busy, viewToken]);

  // The session's own address is handed to validation so a row paying it is caught
  // in the cell, not deep inside the terminal assemble after every merge is signed.
  const check = useMemo(() => checkWorksheet(rows, pubkey), [rows, pubkey]);
  // `notes` is null until the first read lands — passed through as null, because
  // "not loaded" is a state of its own and must never be read as an empty balance.
  const readiness = useMemo(() => sendReadiness(check, notes), [check, notes]);
  const balance = notes === null ? null : sumUnspent(notes);
  const issueFor = (index: number, field: RowIssue["field"]): RowIssue | undefined =>
    check.issues.find((i) => i.index === index && i.field === field);

  const setCell = (i: number, patch: Partial<WorksheetRow>): void =>
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  // CSV paste fill: a whole-sheet replace, so a payroll export IS the worksheet.
  const [csvOpen, setCsvOpen] = useState(false);
  const [csvText, setCsvText] = useState("");
  const applyCsv = (): void => {
    try {
      setRows(rowsFromCsv(csvText));
      setCsvText("");
      setCsvOpen(false);
    } catch (e) {
      toastError((e as Error).message);
    }
  };

  const startPay = async (): Promise<void> => {
    if (readiness.kind !== "ready" && readiness.kind !== "ready-fragmented") return;
    const recipients = check.recipients;
    setPay({ phase: "running", stage: "assemble", leg: { index: 0, count: readiness.kind === "ready" ? 1 : readiness.mergeCount + 1 } });
    try {
      // Plan against the freshest balance, not the 3s-old screen state.
      const fresh = await loadNotes();
      setNotes(fresh);
      const result = await runPayRun(
        {
          connection,
          indexerUrl: INDEXER_URL,
          pool: DEFAULTS.pool,
          explorer: DEFAULTS.explorer,
          notes: fresh,
          sessionPubkey: pubkey,
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
    // The sheet was paid: a fresh worksheet greets the next payroll.
    setRows([blankRow()]);
    clearDraft(storage);
    setPay({ phase: "idle" });
    void refresh();
  };

  const startDeposit = async (): Promise<void> => {
    const parsed = parseDepositAmount(depositAmount);
    if (!parsed.ok) {
      setDepositError(parsed.error);
      return;
    }
    setDepositError(null);
    setDepositStage("approve");
    try {
      await runDeposit(
        {
          connection,
          pool: DEFAULTS.pool,
          token: DEFAULTS.token,
          explorer: DEFAULTS.explorer,
          sessionPubkey: pubkey,
        },
        { amount: parsed.wei.toString() },
        (stage) => setDepositStage(stage),
        { keyCache, prove },
      );
      setDepositAmount("");
      setDepositOpen(false);
      void refresh();
    } catch (e) {
      setDepositError(payrollErrorMessage(e));
    } finally {
      setDepositStage(null);
    }
  };

  const shortfall = readiness.kind === "insufficient" ? readiness.shortfallWei : null;

  return (
    <div className="min-h-full flex flex-col">
      <header className="sticky top-0 z-10 bg-surface border-b border-border">
        <div className="max-w-[1100px] mx-auto px-5 py-3 flex items-center gap-4 flex-wrap">
          <div className="flex items-baseline gap-1.5">
            <span className="text-lg font-bold text-primary">봉투</span>
            <span className="font-semibold">페이롤</span>
          </div>
          <span className="font-mono text-[11px] text-muted bg-surface-2 rounded-lg px-2 py-1">
            pool {shortHex(DEFAULTS.pool)}
          </span>
          <div className="ml-auto flex items-center gap-3">
            <div className="text-right">
              <div className="text-[11px] text-muted">잔고</div>
              <div className="text-[15px] font-semibold tabular-nums">
                {balance === null ? BALANCE_LOADING : `${formatKkrw(balance)} kKRW`}
              </div>
            </div>
            <span
              className="w-8 h-8 rounded-full bg-primary text-primary-ink text-[11px] font-semibold flex items-center justify-center"
              title={connection.address}
            >
              {connection.address.slice(2, 4).toUpperCase()}
            </span>
            <span className="font-mono text-[12px] text-muted">{shortHex(connection.address)}</span>
            <Button variant="ghost" onClick={onLogout}>
              로그아웃
            </Button>
          </div>
        </div>
      </header>

      <main className="max-w-[1100px] mx-auto w-full px-5 py-5 flex flex-col gap-4 flex-1">
        {dataError && <Banner message={dataError} onRetry={() => void refresh()} retryLabel="다시 시도" />}

        {/* stat bar */}
        <div className="bg-surface border border-border rounded-xl px-5 py-3 grid grid-cols-2 sm:grid-cols-4 gap-4">
          <Stat label="잔고" value={balance === null ? BALANCE_LOADING : formatKkrw(balance)} />
          <Stat label="행 수" value={`${check.filledCount} / ${MAX_ROWS}`} />
          <Stat label="총액" value={formatKkrw(check.totalWei)} />
          {/* 충분성 goes red ONLY on a real shortfall — an unread balance is 확인 중,
              never 부족: the employer may well be funded. */}
          <Stat
            label="충분성"
            tone={
              readiness.kind === "insufficient"
                ? "err"
                : readiness.kind === "blocked" || readiness.kind === "loading"
                  ? "ink"
                  : "pos"
            }
            value={
              readiness.kind === "insufficient"
                ? "부족"
                : readiness.kind === "ready"
                  ? "충분"
                  : readiness.kind === "ready-fragmented"
                    ? "충분 · 통합 필요"
                    : readiness.kind === "loading"
                      ? BALANCE_LOADING
                      : "—"
            }
          />
        </div>

        {/* worksheet */}
        <div className="bg-surface border border-border rounded-xl overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border">
            <span className="text-[13px] font-semibold">지급 명세</span>
            <span className="text-[12px] text-muted tabular-nums">
              {check.filledCount}/{MAX_ROWS}명
            </span>
            <div className="ml-auto flex gap-2">
              <Button variant="secondary" onClick={() => setCsvOpen((v) => !v)}>
                CSV 붙여넣기
              </Button>
              <Button
                variant="secondary"
                disabled={rows.length >= MAX_ROWS}
                onClick={() => setRows(addRow)}
                title={rows.length >= MAX_ROWS ? `최대 ${MAX_ROWS}행` : undefined}
              >
                {rows.length >= MAX_ROWS ? `+ 행 추가 (${MAX_ROWS}/${MAX_ROWS})` : "+ 행 추가"}
              </Button>
            </div>
          </div>
          {csvOpen && (
            <div className="px-4 py-3 border-b border-border bg-surface-2 flex flex-col gap-2">
              <textarea
                className="w-full bg-surface border border-border rounded-lg px-2.5 py-2 text-[12.5px] font-mono resize-y focus:outline-none focus:border-border-strong"
                rows={4}
                spellCheck={false}
                placeholder={"주소,금액 형식으로 한 줄에 한 명씩 붙여넣으세요\n예) 3xk…주소,1000"}
                value={csvText}
                onChange={(e) => setCsvText(e.target.value)}
              />
              <div className="flex gap-2 justify-end">
                <Button variant="ghost" onClick={() => setCsvOpen(false)}>
                  닫기
                </Button>
                <Button variant="secondary" onClick={applyCsv}>
                  표에 채우기
                </Button>
              </div>
            </div>
          )}
          <table className="w-full text-[13px] border-collapse">
            <thead>
              <tr className="text-left text-muted text-[12px]">
                <th className="px-4 py-2 w-[52px] font-medium">#</th>
                <th className="px-2 py-2 font-medium">받는 주소</th>
                <th className="px-2 py-2 w-[180px] font-medium text-right">금액 (kKRW)</th>
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
                        ariaLabel={`받는 주소 ${i + 1}`}
                        value={r.address}
                        placeholder="bongtu 주소 (3… base58 또는 0x… hex)"
                        invalid={addrIssue !== undefined}
                        onChange={(v) => setCell(i, { address: v })}
                      />
                      {addrIssue && <div className="text-[11.5px] text-err mt-0.5">{addrIssue.message}</div>}
                    </td>
                    <td className="px-2 py-1.5">
                      <CellInput
                        align="right"
                        ariaLabel={`금액 ${i + 1}`}
                        value={r.amount}
                        placeholder="0"
                        invalid={amtIssue !== undefined}
                        onChange={(v) => setCell(i, { amount: groupAmountInput(v) })}
                      />
                      {amtIssue && <div className="text-[11.5px] text-err mt-0.5 text-right">{amtIssue.message}</div>}
                    </td>
                    <td className="px-2 py-1.5">
                      <Button variant="ghost" aria-label={`${i + 1}행 삭제`} onClick={() => setRows((rs) => removeRow(rs, i))}>
                        ✕
                      </Button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* footer: the 3-state send bar */}
        <div className="bg-surface border border-border rounded-xl px-5 py-4 flex items-center gap-4 flex-wrap">
          <div className="text-[13px] text-muted flex-1 min-w-[240px]">
            {/* Neutral, muted, no CTA: until the balance is known there is nothing
                to promise and nothing to blame the employer for. A read that
                actually FAILED is already named by the banner above. */}
            {readiness.kind === "loading" &&
              (dataError !== null
                ? "잔고를 확인하지 못했습니다. 위 안내를 확인하세요."
                : "잔고를 불러오는 중입니다.")}
            {readiness.kind === "blocked" &&
              (check.issues.length > 0 ? "빨간 항목을 수정하면 전송할 수 있습니다." : "받는 주소와 금액을 입력하세요.")}
            {readiness.kind === "ready" && "잔고가 충분합니다. 1건의 지급 트랜잭션으로 전송됩니다."}
            {readiness.kind === "ready-fragmented" &&
              `잔고가 여러 조각으로 나뉘어 있어, 통합 ${readiness.mergeCount}회 후 지급까지 총 ${readiness.mergeCount + 1}건을 서명합니다.`}
            {readiness.kind === "insufficient" && shortfall !== null && (
              <span className="text-err font-medium">
                잔고가 {formatKkrw(shortfall)} kKRW 부족합니다. 아래에서 입금 후 전송하세요.
              </span>
            )}
          </div>
          {/* deposit stays reachable but quiet while the balance covers the sheet */}
          {readiness.kind !== "insufficient" && (
            <Button variant="ghost" onClick={() => setDepositOpen((v) => !v)}>
              입금
            </Button>
          )}
          <Button
            disabled={readiness.kind !== "ready" && readiness.kind !== "ready-fragmented"}
            onClick={() => void startPay()}
          >
            전송
          </Button>
        </div>

        {/* deposit: a highlighted CTA when the sheet cannot be covered, a quiet
            panel behind the 입금 button otherwise (wallet-web grammar) */}
        {(readiness.kind === "insufficient" || depositOpen) && (
          <div
            className={`rounded-xl px-5 py-4 border flex flex-col gap-3 ${
              readiness.kind === "insufficient" ? "bg-warn-bg border-warn-border" : "bg-surface border-border"
            }`}
          >
            <div className="text-[13px] font-semibold">
              {readiness.kind === "insufficient" ? "입금이 필요합니다" : "입금"}
            </div>
            <div className="flex items-end gap-2 flex-wrap">
              <label className="flex flex-col gap-1">
                <span className="text-[11px] text-muted">입금액 (kKRW)</span>
                <input
                  type="text"
                  className="bg-surface border border-border rounded-lg px-2.5 py-1.5 text-[13px] text-right tabular-nums w-[200px] focus:outline-none focus:border-border-strong"
                  value={depositAmount}
                  placeholder={shortfall !== null ? formatKkrw(shortfall) : "0"}
                  onChange={(e) => setDepositAmount(groupAmountInput(e.target.value))}
                />
              </label>
              {shortfall !== null && (
                <Button variant="secondary" onClick={() => setDepositAmount(groupAmountInput(formatKkrw(shortfall)))}>
                  부족분 채우기
                </Button>
              )}
              <Button disabled={depositStage !== null} onClick={() => void startDeposit()}>
                {depositStage !== null ? DEPOSIT_STAGE_LABEL[depositStage] : "입금"}
              </Button>
            </div>
            {depositError && <div className="text-[12.5px] text-err">{depositError}</div>}
            <div className="text-[12px] text-muted">
              공개 kKRW를 풀에 넣어 비공개 잔고로 바꿉니다. 승인(필요 시)과 입금, 두 번까지 지갑
              확인이 뜹니다.
            </div>
          </div>
        )}
      </main>

      {pay.phase === "running" && <ProgressRail stage={pay.stage} leg={pay.leg} />}
      {pay.phase === "done" && <DoneScreen result={pay.result} paid={pay.paid} onClose={closeDone} />}
    </div>
  );
}

/** The wallet-style progress rail, over the whole chain: merge legs then the
 *  terminal disburse, one row per transaction, the active row narrating its
 *  stage. */
function ProgressRail({ stage, leg }: { stage: SpendStage; leg: LegProgress }): ReactNode {
  const labels = Array.from({ length: leg.count }, (_, i) =>
    i < leg.count - 1 ? `노트 통합 ${i + 1}` : "지급 전송",
  );
  return (
    <div className="fixed inset-0 z-20 bg-backdrop flex items-center justify-center p-6">
      <div className="w-full max-w-[420px] bg-surface border border-border rounded-2xl p-6 flex flex-col gap-4">
        <div className="text-[15px] font-semibold">지급 실행 중</div>
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
                <div className="min-w-0">
                  <div className={`text-[13.5px] ${state === "todo" ? "text-muted" : "font-medium"}`}>{label}</div>
                  {state === "active" && <div className="text-[12px] text-muted">{STAGE_LABEL[stage]}</div>}
                </div>
              </li>
            );
          })}
        </ol>
        <div className="text-[12px] text-muted">
          트랜잭션마다 지갑 확인이 한 번씩 필요합니다. 이 창을 닫지 마세요.
        </div>
      </div>
    </div>
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
            <div className="text-[15px] font-semibold">지급 완료</div>
            <div className="text-[12.5px] text-muted">{result.recipientCount}명에게 전송되었습니다.</div>
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
            지급 트랜잭션 보기 ({shortHex(result.txHash, 8, 6)})
          </a>
          {result.mergeTxs.length > 0 && (
            <div className="text-muted mt-1">
              통합 트랜잭션 {result.mergeTxs.length}건:{" "}
              {result.mergeTxs.map((t, i) => (
                <a key={t.txHash} className="underline mr-2" href={t.explorerUrl} target="_blank" rel="noreferrer">
                  #{i + 1}
                </a>
              ))}
            </div>
          )}
        </div>
        <Button onClick={onClose}>닫기</Button>
      </div>
    </div>
  );
}
