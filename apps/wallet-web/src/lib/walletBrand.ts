// PURE identification of the connected wallet (framework-free, unit-tested headlessly):
// which brand it is, what to call it in a sentence, and which icon to draw.
//
// Two sources feed it. The injected EIP-1193 object carries vendor flags, and the
// EIP-6963 discovery event carries the wallet's OWN name and icon (see eip6963.ts) —
// the only way to name a wallet this app has never heard of. The flags decide the
// brand; the announcement, when there is one, supplies the display name and icon.

export type WalletBrand =
  | "metamask"
  | "rabby"
  | "coinbase"
  | "okx"
  | "bitget"
  | "trust"
  | "phantom"
  | "brave"
  | "rainbow"
  | "zerion"
  | "frame"
  | "unknown";

// ORDER IS THE WHOLE POINT: nearly every injected wallet ALSO sets `isMetaMask: true`
// so that dapps written against MetaMask keep working, so a vendor's own flag has to
// win. Testing isMetaMask first is what showed the fox to Rabby/OKX/Trust users.
const VENDOR_FLAGS: ReadonlyArray<readonly [string, WalletBrand]> = [
  ["isRabby", "rabby"],
  ["isCoinbaseWallet", "coinbase"],
  ["isOkxWallet", "okx"],
  ["isOKExWallet", "okx"],
  ["isBitKeep", "bitget"],
  ["isBitgetWallet", "bitget"],
  ["isTrust", "trust"],
  ["isTrustWallet", "trust"],
  ["isPhantom", "phantom"],
  ["isBraveWallet", "brave"],
  ["isRainbow", "rainbow"],
  ["isZerion", "zerion"],
  ["isFrame", "frame"],
  ["isMetaMask", "metamask"],
];

const BRAND_NAMES: Record<WalletBrand, string | null> = {
  metamask: "MetaMask",
  rabby: "Rabby",
  coinbase: "Coinbase Wallet",
  okx: "OKX Wallet",
  bitget: "Bitget Wallet",
  trust: "Trust Wallet",
  phantom: "Phantom",
  brave: "Brave Wallet",
  rainbow: "Rainbow",
  zerion: "Zerion",
  frame: "Frame",
  unknown: null,
};

/** What the copy says when the wallet cannot be identified — never a guess. */
export const NEUTRAL_WALLET_NAME = "your wallet";

/**
 * Classify the raw injected EIP-1193 provider object (ethers v5 keeps it at
 * `web3Provider.provider`). Every flag is matched STRICTLY against `true`: several
 * wallets spoof compatibility flags with truthy non-boolean values, and an
 * absent/foreign provider must degrade to "unknown", never throw.
 */
export function walletBrand(injected: unknown): WalletBrand {
  if (typeof injected !== "object" || injected === null) return "unknown";
  const flags = injected as Record<string, unknown>;
  for (const [flag, brand] of VENDOR_FLAGS) {
    if (flags[flag] === true) return brand;
  }
  return "unknown";
}

/**
 * The raw EIP-1193 object to identify: the one behind an ethers connection, else the
 * page's own injected wallet. A silently-restored session goes through the same
 * ethers Web3Provider over the same injected object as a fresh connect, so the wallet
 * re-identifies itself on restore and nothing about it has to be persisted.
 */
export function injectedFrom(connection: unknown, pageInjected: unknown): unknown {
  const behind = (connection as { provider?: { provider?: unknown } } | null)?.provider?.provider;
  return behind ?? pageInjected ?? null;
}

/** What the EIP-6963 announcement told us about this provider (eip6963.ts). */
export interface AnnouncedWallet {
  name?: unknown;
  icon?: unknown;
}

export interface WalletDescription {
  brand: WalletBrand;
  /** What to call it in a sentence: its announced name, our brand name, or the
   *  neutral fallback. Always safe to interpolate into copy. */
  name: string;
  /** false when `name` is the neutral fallback — i.e. we do not actually know. */
  named: boolean;
  /** The wallet's own announced icon, as a data: URL; null when it announced none. */
  iconUrl: string | null;
}

// The announced name is a string from a browser extension, rendered inside our UI:
// flatten control characters and cap the length so a hostile or broken announcement
// cannot reflow a screen.
function safeName(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const clean = raw.replace(/\p{C}/gu, " ").replace(/\s+/g, " ").trim().slice(0, 24);
  return clean.length > 0 ? clean : null;
}

// EIP-6963 requires the icon to be a data URI, and we enforce it: a remote URL here
// would fetch from the wallet vendor on every render, telling them who is using us.
function safeIcon(raw: unknown): string | null {
  return typeof raw === "string" && /^data:image\/(png|jpeg|gif|webp|svg\+xml);/i.test(raw)
    ? raw
    : null;
}

/** Everything the UI needs to show the connected wallet: brand for the built-in mark,
 *  name for the copy, icon when the wallet supplied its own. */
export function describeWallet(
  injected: unknown,
  announced?: AnnouncedWallet | null,
): WalletDescription {
  const brand = walletBrand(injected);
  const name = safeName(announced?.name) ?? BRAND_NAMES[brand];
  return {
    brand,
    name: name ?? NEUTRAL_WALLET_NAME,
    named: name !== null,
    iconUrl: safeIcon(announced?.icon),
  };
}
