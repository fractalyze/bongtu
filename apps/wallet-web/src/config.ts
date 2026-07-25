// Live GIWA Sepolia defaults (deploy/addresses.91342.json). Everything here is
// PUBLIC. The arbiter *public* key is the pool's stored authority pubkey — the
// wallet encrypts every transfer/withdraw authority envelope to it (non-repudiation
// on every op, SPEC §2 Q2), so it must ship in the client. No PRIVATE key ever
// lives in the public wallet: the user's bjj spending key is DERIVED from a
// MetaMask signature at runtime (src/lib/derive.ts) and never persisted.

export const DEFAULTS = {
  chainId: 91342,
  rpc: "https://sepolia-rpc.giwa.io",
  explorer: "https://sepolia-explorer.giwa.io",
  pool: "0x93365980784ef504613EF5822ce1289CF858Fc10",
  token: "0x17A89cC5FF3395Bb01464c9E422749CcDbFa8C3f",
  batchSize: 256,
  // The pool's stored arbiter PUBLIC key (addresses.91342.json arbiterKeyX/Y). The
  // transfer/withdraw circuits encrypt an authority envelope to this key; the
  // contract injects the SAME key from storage before verifying, so a mismatch fails.
  arbiterPubKey: [
    "3913862942419584217034784582196041949017644467033355253711012199317627839810",
    "9603702957807229873011073182281683387900303214140383090738501285426490726765",
  ] as [string, string],
  // KDF domain version (SPEC §6): part of the EIP-712 domain, so bumping it rotates
  // every derived key. Pinned per deployment; never silently changed.
  keyVersion: "1",
  // The arbiter-mode indexer for the signed `GET /notes` balance path; public-mode
  // indexers additionally serve `/events` + `/nullifiers` for the trial-decrypt fallback.
  indexerUrl: "http://localhost:8600",
  // Where the transfer/withdraw circuit assets (wasm + zkey) are served for browser
  // snarkjs proving. Static assets under the app, or a configured CDN/helper URL.
  // Files: `${circuitBaseUrl}/{transfer,withdraw}.wasm` and `.zkey`.
  circuitBaseUrl: "/circuits",
} as const;

export const H = 32; // IMT height (SPEC §4)
export const B = 256; // production disburse batch size (unused by the wallet; here for parity)
