// Live GIWA Sepolia defaults (deploy/addresses.91342.json). Everything here is
// PUBLIC: the arbiter *public* key is the pool's stored authority pubkey, safe to
// ship in employer-mode. The arbiter PRIVATE key is entered only in auditor-mode
// and never lives in this file.

export const DEFAULTS = {
  chainId: 91342,
  rpc: "https://sepolia-rpc.giwa.io",
  explorer: "https://sepolia-explorer.giwa.io",
  pool: "0x93365980784ef504613EF5822ce1289CF858Fc10",
  token: "0x17A89cC5FF3395Bb01464c9E422749CcDbFa8C3f",
  batchSize: 256,
  // The pool's stored arbiter PUBLIC key (addresses.91342.json arbiterKeyX/Y).
  arbiterPubKey: [
    "3913862942419584217034784582196041949017644467033355253711012199317627839810",
    "9603702957807229873011073182281683387900303214140383090738501285426490726765",
  ] as [string, string],
  // A local prover-cli helper (apps/admin/prover-helper.ts) on the employer's GPU box.
  proverUrl: "http://localhost:8700/prove",
  // A public-mode indexer for /head + /path; auditor-mode points at an arbiter indexer.
  indexerUrl: "http://localhost:8600",
} as const;

export const H = 32; // IMT height (SPEC §4)
export const B = 256; // production disburse batch size
