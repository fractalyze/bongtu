// The DOM shell over src/lib/pay.ts: parse /p/{label}, run the one issuance,
// render (design canvas "Stealth Receive Screens", Main artboard). Every
// failure renders its message and nothing else — the address never shows
// without a recorded announcement and a passed parity check (lib ordering).

import QRCode from "qrcode";

import { INDEXER_URL, PORTAL_PRIV_FACTORY, SWEEPER_INITCODE_HASH, CHAIN_NAME, TOKEN_SYMBOL } from "./config.js";
import { issuePayment, labelFromPath, shortAddress, type IssuedPayment } from "./lib/pay.js";

const app = document.getElementById("app") as HTMLElement;

const LOCK_ICON =
  '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#123a5c" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="10" rx="2"></rect><path d="M7 11V7a5 5 0 0 1 10 0v4"></path></svg>';
const INFO_ICON =
  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2a4a66" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;margin-top:1px"><circle cx="12" cy="12" r="10"></circle><path d="M12 16v-4"></path><path d="M12 8h.01"></path></svg>';

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function shell(inner: string): string {
  return `
    <div class="page">
      <div class="topbar">
        <span class="brand">${LOCK_ICON}<span>pay</span></span>
        <span class="topbar-note">비공개 결제 수신</span>
      </div>
      <div class="stack">${inner}</div>
      <div class="footer">결제 내역은 체인에서 서로 연결되지 않아요</div>
    </div>`;
}

function renderMessage(kind: "error-card" | "spinner-card", message: string): void {
  app.innerHTML = shell(`<div class="${kind}">${esc(message)}</div>`);
}

async function renderIssued(issued: IssuedPayment): Promise<void> {
  const label = esc(issued.label);
  app.innerHTML = shell(`
    <div class="card">
      <div class="who">
        <div class="avatar">${label.slice(0, 1)}</div>
        <div class="who-title">${label}님에게 보내기</div>
        <div class="who-sub">아래 주소로 보내면 ${label}님이 받아요</div>
      </div>
      <div class="qr-frame" id="qr"></div>
      <div class="addr-row">
        <div class="addr-chip"><span id="addr-short"></span></div>
        <button class="copy-btn" id="copy">주소 복사</button>
      </div>
    </div>
    <div class="facts">
      <div class="fact"><span class="fact-k">네트워크</span><span class="fact-v">${CHAIN_NAME}</span></div>
      <div class="fact-sep"></div>
      <div class="fact"><span class="fact-k">받는 자산</span><span class="fact-v">${TOKEN_SYMBOL}</span></div>
    </div>
    <div class="notice">${INFO_ICON}
      <p>이 주소는 이번 결제 전용이에요. 페이지를 새로 열면 새 주소가 나와요.
      어떤 지갑이나 거래소에서 보내도 ${label}님이 비공개로 받아요.</p>
    </div>`);

  (document.getElementById("addr-short") as HTMLElement).textContent = shortAddress(issued.destination);
  const svg = await QRCode.toString(issued.destination, { type: "svg", margin: 0 });
  (document.getElementById("qr") as HTMLElement).innerHTML = svg;

  const copy = document.getElementById("copy") as HTMLButtonElement;
  copy.addEventListener("click", () => {
    void navigator.clipboard.writeText(issued.destination).then(() => {
      copy.textContent = "복사했어요";
      setTimeout(() => (copy.textContent = "주소 복사"), 1500);
    });
  });
}

async function boot(): Promise<void> {
  const label = labelFromPath(window.location.pathname);
  if (!label) {
    renderMessage("error-card", "결제 링크가 아니에요. /p/{이름} 링크로 열어 주세요.");
    return;
  }
  renderMessage("spinner-card", "새 주소를 만들고 있어요…");
  try {
    const issued = await issuePayment(label, {
      indexerUrl: INDEXER_URL,
      portalPrivFactory: PORTAL_PRIV_FACTORY,
      sweeperInitCodeHash: SWEEPER_INITCODE_HASH,
    });
    await renderIssued(issued);
  } catch (e) {
    renderMessage("error-card", (e as Error).message);
  }
}

void boot();
