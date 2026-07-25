// The ONE home for the deployment-coupled chain facts of the LIVE GIWA Sepolia
// BongtuPool. Everything here is PUBLIC (the arbiter key below is the pool's
// stored authority PUBLIC key; no private key ever lives in this module).
//
// Canonical record: deploy/addresses.91342.json (CLAUDE.md "live pool is
// canonical" — the deployed pool is reused, no redeploys for new work).
// test/network.test.ts asserts these values equal that JSON field-for-field
// and byte-pins the facts the JSON does not carry, so a transcription slip
// fails in milliseconds instead of at on-chain proof rejection. On a redeploy
// or arbiter epoch rotation, edit THIS file (the test convicts stale fields);
// app config.ts files import from here and keep only app-specific knobs.
//
// DATA-ONLY by design: no ethers (or any other) import — wallet-web bundles
// the sdk and must stay ethers-free at the sdk boundary. Consumers that need
// a BigNumber gas price call ethers.utils.parseUnits(GIWA_GAS_FLOOR_GWEI,
// "gwei") themselves.

/** GIWA Sepolia chain id (also the EIP-712 KDF domain chainId, SPEC §6). */
export const CHAIN_ID = 91342;

/** GIWA Sepolia public RPC. */
export const RPC_URL = "https://sepolia-rpc.giwa.io";

/** GIWA Sepolia Blockscout explorer base (no trailing slash). */
export const EXPLORER_BASE = "https://sepolia-explorer.giwa.io";

/** The live BongtuPool UUPS proxy (deploy/addresses.91342.json `pool`). */
export const POOL_ADDRESS = "0x93365980784ef504613EF5822ce1289CF858Fc10";

/** The wrapped mock kKRW ERC-20 the pool escrows (`token`). */
export const TOKEN_ADDRESS = "0x17A89cC5FF3395Bb01464c9E422749CcDbFa8C3f";

// The pool's stored arbiter PUBLIC key (addresses.91342.json arbiterKeyX/Y).
// Every op's circuit encrypts its authority envelope to this key and the
// contract injects the SAME key from storage before verifying — a stale copy
// here means a wasted proof rejected on-chain. Decimal strings (bjj field
// elements do not fit JS numbers).
export const ARBITER_PUBKEY_X =
  "3913862942419584217034784582196041949017644467033355253711012199317627839810";
export const ARBITER_PUBKEY_Y =
  "9603702957807229873011073182281683387900303214140383090738501285426490726765";
/** [x, y] tuple form of the arbiter public key. */

/** IMT height (SPEC §4) — the deployed pool + all circuits are built for depth 32. */
export const H = 32;

/** Production disburse batch size (`batchSize`) — the live pool is a B=256 stack. */
export const B = 256;

// GIWA wants ~0.001 gwei; ethers' auto-estimate overpays ~1500x (drains the
// faucet grant). 0.005 gwei is a safe 5x floor. Kept as the parseUnits ARG
// (a decimal-gwei string) so this module stays ethers-free.
export const GIWA_GAS_FLOOR_GWEI = "0.005";

// Minimal hand-written BongtuPool ABI fragments (avoids importing the Foundry
// artifact JSON into browser bundles) — ONE string per function, shared by
// both apps. transfer/withdraw take (a,b,c,pub) only: their ciphertext rides
// in `pub` as circuit outputs. disburseWithCiphertexts is the §6b v2
// enforced-length form — the 2054-element receiver++authority ciphertext is a
// separate calldata arg the contract length-checks.
export const POOL_ABI_FRAGMENTS = {
  // deposit (0-in/2-out mint): permissionless (external, whenInitialized, nonReentrant,
  // NO onlyOwner), pulls V of the ERC-20 from msg.sender. pub is length 18, pub[0] == V;
  // its single authority envelope rides in pub, so no separate ciphertext arg.
  deposit:
    "function deposit(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[18] pub)",
  transfer:
    "function transfer(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[36] pub)",
  withdraw:
    "function withdraw(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[25] pub)",
  disburseWithCiphertexts:
    "function disburseWithCiphertexts(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[10] pub, uint256[] receiverCiphertexts)",
  root: "function root() view returns (uint256)",
  nextLeafIndex: "function nextLeafIndex() view returns (uint256)",
  B: "function B() view returns (uint256)",
} as const;

// Minimal ERC-20 fragments the public wallet needs for the deposit/shield flow: the
// depositor approves the pool to pull exactly V (skipped when the current allowance
// already covers V), and the Home/Deposit screens read the raw kKRW balance + pool
// allowance. Raw-integer token units everywhere (no decimal conversion).
export const ERC20_ABI_FRAGMENTS = {
  approve: "function approve(address spender, uint256 amount) returns (bool)",
  allowance: "function allowance(address owner, address spender) view returns (uint256)",
  balanceOf: "function balanceOf(address owner) view returns (uint256)",
  // Mock-token dev faucet: the deployed kKRW is MockERC20, whose mint(to, amount) is
  // FULLY permissionless (no onlyOwner, no cap) — so a user self-mints test kKRW from
  // their own MetaMask and pays their own GIWA gas. NOT present on a production token.
  mint: "function mint(address to, uint256 amount)",
} as const;

/** Explorer link for a tx hash; `base` defaults to the live GIWA explorer. */
export function explorerTxUrl(txHash: string, base: string = EXPLORER_BASE): string {
  return `${base.replace(/\/$/, "")}/tx/${txHash}`;
}
