// The ONE home for the deployment-coupled chain facts of the LIVE BongtuPool.
// Everything here is PUBLIC (the arbiter key below is the pool's stored
// authority PUBLIC key; no private key ever lives in this module).
//
// The CHAIN IS SWAPPABLE and has moved before, so nothing here is named after
// it: every export is a role ("the chain id", "the gas price pin"), the chain's own
// name is the single CHAIN_NAME string below, and downstream code says
// `ensureChain` / `CHAIN_HEX` / `GAS_PRICE_PIN_GWEI` rather than embedding a brand.
// A future move is then this file plus the deploy record, not a repo sweep.
//
// Canonical record: deploy/addresses.84532.json (CLAUDE.md "live pool is
// canonical" — the deployed pool is reused, no redeploys for new work).
// test/network.test.ts asserts these values equal that JSON field-for-field
// and byte-pins the facts the JSON does not carry, so a transcription slip
// fails in milliseconds instead of at on-chain proof rejection. On a redeploy
// or arbiter epoch rotation, edit THIS file (the test convicts stale fields);
// app config.ts files import from here and keep only app-specific knobs.
//
// NEVER transcribe an address by pattern-matching the old value: the Base
// deployment replayed the SAME deployer CREATE nonces the previous chain used,
// so several addresses collide ACROSS chains while naming DIFFERENT contracts
// (0x93365980… was the old pool and is this chain's token). Copy every address
// from the record BY FIELD NAME.
//
// DATA-ONLY by design: no chain-library import — this stays a plain-data
// boundary. Consumers turn GAS_PRICE_PIN_GWEI into a wei gas price with their
// own client (viem `parseGwei(GAS_PRICE_PIN_GWEI)`).

/** The live chain's id (also the EIP-712 KDF domain chainId, SPEC §6). */
export const CHAIN_ID = 84532;

/** The live chain's display name — the ONE place a screen, an error message or
 *  a wallet_addEthereumChain payload gets the chain's name from. */
export const CHAIN_NAME = "Base Sepolia";

/** The live chain's gas token, in the shape both viem `defineChain` and an
 *  EIP-3085 `wallet_addEthereumChain` payload want. One home like every other
 *  chain fact: it was the last field still transcribed per client. */
export const NATIVE_CURRENCY = { name: "Sepolia Ether", symbol: "ETH", decimals: 18 };

/** The live chain's public RPC. */
export const RPC_URL = "https://sepolia.base.org";

/** The live chain's block-explorer base (no trailing slash). */
export const EXPLORER_BASE = "https://sepolia.basescan.org";

/** Where a user with no gas ETH on this chain gets some. Surfaced from the
 *  zero-gas errors in both apps, so it lives with the other chain facts. */
export const GAS_FAUCET_URL = "https://portal.cdp.coinbase.com/products/faucet";

/** The phrase every "this account cannot pay gas" message contains. The error
 *  banner decides whether to hang the faucet link off a message by looking for
 *  it, so message and matcher must not drift — before, both hardcoded the chain
 *  name and a rename would have silently dropped the link. */
export const GAS_TOKEN_PHRASE = `${CHAIN_NAME} ETH`;

/** The live BongtuPool UUPS proxy (deploy/addresses.84532.json `pool`). */
export const POOL_ADDRESS = "0x2a72fea8e97fF79069B3D0165A5DB1Fef7F9322C";

/** The wrapped mock kKRW ERC-20 the pool escrows (`token`). */
export const TOKEN_ADDRESS = "0x93365980784ef504613EF5822ce1289CF858Fc10";

/**
 * The (chainId, pool) pair as ONE opaque string — the identity of this
 * deployment.
 *
 * WHY IT EXISTS: the EIP-712 KDF domain is exactly (chainId, verifyingContract)
 * (SPEC §6), so the bjj spending key an account derives is a function of THIS
 * pair. Move either half and every user legitimately derives a different key.
 * Anything persisted under a derived identity — a browser session record, the
 * account→key binding — is therefore meaningful only for one pair, and must be
 * stored under a key that carries it: a record from another deployment has to
 * read as ABSENT, not as a contradiction (packages/client/src/session.ts).
 */
export const DEPLOYMENT_TAG = `${CHAIN_ID}:${POOL_ADDRESS.toLowerCase()}`;

// The pool's stored arbiter PUBLIC key (addresses.84532.json arbiterKeyX/Y).
// Every op's circuit encrypts its authority envelope to this key and the
// contract injects the SAME key from storage before verifying — a stale copy
// here means a wasted proof rejected on-chain. Decimal strings (bjj field
// elements do not fit JS numbers).
export const ARBITER_PUBKEY_X =
  "3913862942419584217034784582196041949017644467033355253711012199317627839810";
export const ARBITER_PUBKEY_Y =
  "9603702957807229873011073182281683387900303214140383090738501285426490726765";
/** [x, y] tuple form of the arbiter public key. */

// The institutional arbiter ML-KEM-768 encapsulation key (1184 B, FIPS 203) —
// the PQ half of the hybrid authority envelope (.dev/pq-envelope-design.md §2).
// Clients encapsulate every op's kemCiphertext against THIS key; the chain
// stores only its keccak256 (arbiterKemPkHash per epoch, §4), so the full key
// is a deployment fact distributed here + deploy/addresses.84532.json (both
// equality-tested against deploy/arbiter-kem-pk.84532.hex's material). The
// arbiter did NOT rotate when the chain moved — same institutional key, same
// hash, so every previously-issued envelope stays decryptable. PUBLIC:
// the decapsulation key exists only in the arbiter's env (AUTHORITY_KEM_KEY).
export const ARBITER_KEM_PK = "0x" +
  "1206b1b3894761e20bbdf5679ed1cec2e91d1839ab74146f469c142ac50f5548bb7cc6ae9cf3b0113b925c49" +
  "c6897734036b791d65c413545cb1b387810a3f2727ae7d0073b7237e7ac4a5c19b8213b867746c1303a7c69d" +
  "7787aff7c42e3658b7c3469d6386a64132e039511a71755fa64b62d60d34285c9aea8b02d98043fbc6fe850a" +
  "f9fb4c5c281744da6e84903d1d64ae9eb01246447c41d18d676aae5195bce12135ea142d3ba472edf86666d3" +
  "0e488246ed788ec1ab4abc794f062776e2670d2db38ffc0aba74caaac3333b90973da5b9881b662d6f22b177" +
  "813c63203b15f451156ac299fccb0b857df0a57c0f98acff870b6de72c095277bc394a6e008dc5a0b26312bc" +
  "928b7e46cb1050b4a4426559c5846027b44326b566df1821c6c10034fc99fba0237170bb8f58b994b9985c74" +
  "8af556488a3c49d8c9333d896e95ab32e2c3365752986ef7080704c54b1801401c27bc096cd1198120e8bd99" +
  "41339e2ba00a788a6f0442971a58c6c01c8dcb4822166de367539298a457f5b11dd46185a59151e83ea5e523" +
  "f6d77bd12c496c7105c0a30a4f95469c2bc523f59333898898525e13109d7cb425f3584f92bc4be10668fd46" +
  "1f05330672c29fa782067975ab34f16e7518c494dcb14427223ad244fcb9c0bc092192da078e704b2d47c486" +
  "a7cad187adcf129ac1274e7c21c5d5fa033ea146d58b2e97a36863a36486d3993f21502cf8bde2eb770a5b29" +
  "6fe7a84f78b276373656801a3f4c8ce369937d962eefd30dea99ccecf30185088a21434a11d7373aac140625" +
  "ca9a83b72e0ab453353a1be05e3c0a6103341790d355abe58ba60610e88bc7c6760624318a3698a87d68cca3" +
  "796a2c11072509b15ff65bba845c2e08a949455f18f05a1ceb1b53a1198fca7fe0425ad75a3377d86cb61acd" +
  "3bcc53029b2cf1b8c08e6362009c8c4f38156f306acd052e89ac4ba0867b6686aaaadb940506369fc0cedd72" +
  "19bcfa95121880f7e03174902b9c46082a0cb661b7a4476915bea637104700fc185dac875d9839b46ed00194" +
  "081f9f2368be4a4ffe3880948462f4121dcb6bb7d6a6970a5a75edab5934e2baacdac0415087203ab5e2c144" +
  "e985cdd1772306570bb9d6b2787a7b8dc6a1546178b0910b5ae3874954a1774ca092ac857fab1a86f135a22a" +
  "15293c06747a0906752d4b2a6e04b0b043f93e48f5840559b5fde5a06c3193dad9a905d9ccf6f56a4b81549d" +
  "a3bf4b3b42378731c5d07c018c897fea008fc9942f251e6fc88ddd891c1de2a9e3687f1804b2df87a0a19aac" +
  "65f38bc368766d373d58b6b825983ea0f89970e4a46128cce317469752b3845477f90a5b7316717d4b2588f4" +
  "7c6baa964c3a2f724c9b3ff342ada7a71f0807d836ca47f012d3137fa2f6bacbfca116cbbc02008afd45246a" +
  "e75af79947194a3e6dd95d2a224256d370275200565676b568158df3264de341d0347c2882bca3735180081d" +
  "71621f2281aa0c2a807b54b4fa965c622927334049e0964223fccdc37634cc198f91073c457419b4a7937232" +
  "784c1352b8365e2076c170c72df8e897595621a21157983c79f4965728d1a9ae5721728985ae074796e9042a" +
  "33c4a2e4c86194b6e330e5598ed9773aab85a05b65c053b94b83860b7bc8105a23113c2bd8e424e2";

/** keccak256 of ARBITER_KEM_PK — what the pool stores per epoch
 *  (`arbiterKemPkHash(currentEpoch())`); clients verify the full key against it
 *  before encapsulating. */
export const ARBITER_KEM_PK_HASH =
  "0x0403c92bcdb56d0369c0981754a6f4af6719395d59eef32370dcfad9bb332314";

/**
 * Classify a failed `arbiterKemPkHash(currentEpoch())` probe: ethers raises
 * CALL_EXCEPTION when the getter is missing/reverts — the pre-KEM (V1) pool
 * marker. Anything else (network, timeout, server) is a real failure the caller
 * must surface: folding it into "V1 pool" would fail the guard OPEN on a
 * transient RPC hiccup.
 */
export function isPreKemProbeError(e: unknown): boolean {
  return (e as { code?: string } | null)?.code === "CALL_EXCEPTION";
}

/**
 * The client-side arbiter-KEM-key guard (design doc §4/§5): given the pool's
 * `arbiterKemPkHash(currentEpoch())` — or null when the probe hit a pre-KEM V1
 * pool — return the fatal message when encapsulating to ARBITER_KEM_PK would be
 * wrong, else null. Clients call this BEFORE drawing KEM material so the
 * bundled key never substitutes for the chain's.
 */
export function arbiterKemPkGuardError(onchainHash: string | null): string | null {
  if (onchainHash === null) {
    return "the pool has no KEM epoch (pre-PQ V1 pool) but this build only produces hybrid PQ proofs — the pool upgrade has not landed yet";
  }
  if (onchainHash.toLowerCase() !== ARBITER_KEM_PK_HASH) {
    return `on-chain arbiter KEM key hash ${onchainHash} does not match this build's ARBITER_KEM_PK — refusing to encapsulate to an unverified key`;
  }
  return null;
}

/** IMT height (SPEC §4) — the deployed pool + all circuits are built for depth 32. */
export const H = 32;

/** Production disburse batch size (`batchSize`) — the live pool is a B=256 stack. */
export const B = 256;

// WHAT IT IS: a HARD PIN, not a floor anything raises from. The deploy/live
// drivers build their viem rig with `gasPrice: parseGwei(GAS_PRICE_PIN_GWEI)`, which
// bakes this exact price into EVERY write and deploy they send, with no
// estimation anywhere in the path. (The browser apps stopped using it: their
// submits ask the node for eth_gasPrice and take 3x. Only the live drivers pin.)
//
// WHY A PIN AT ALL: client-side fee estimation once overpaid ~1500x on a
// cheap L2 and drained a whole faucet grant, so the drivers name the price.
//
// WHAT GOES WRONG IF IT IS WRONG, and it is asymmetric:
//   too LOW  — the tx is under the block base fee, the node rejects it
//              ("max fee per gas less than block base fee") or it sits pending
//              forever. A live e2e run just stops.
//   too HIGH — the run overpays testnet ETH. On a 2.5M-gas op, 0.05 gwei is
//              ~0.000125 ETH.
// So this is set high, deliberately.
//
// THE NUMBER: Base Sepolia measured 0.006 gwei (`cast gas-price`) over a
// 0.005 gwei base fee on 2026-08-11. 0.05 gwei is ~8x that quote — headroom for
// a congestion spike between reading this constant and the tx landing, which a
// pinned price cannot otherwise absorb. Re-measure on a chain move; a value at
// or just above the base fee is the failure mode, not the safe choice.
//
// Kept as the parseGwei ARG (a decimal-gwei string) so this module stays
// chain-library-free.
export const GAS_PRICE_PIN_GWEI = "0.05";

// Minimal hand-written BongtuPool ABI fragments (avoids importing the Foundry
// artifact JSON into browser bundles) — ONE string per function, shared by
// both apps. transfer/withdraw take (a,b,c,pub) only for the envelope: their
// Poseidon ciphertext rides in `pub` as circuit outputs, while the raw
// ML-KEM-768 `kemCiphertext` (1088 B, length-checked on-chain) is a separate
// bytes arg on EVERY op (.dev/pq-envelope-design.md §4 — the hybrid V2 pool;
// these fragments do NOT match the pre-KEM V1 pool by design, see §7 cutover).
// disburseWithCiphertexts is the §6b v2 enforced-length form — the
// 2054-element receiver++authority ciphertext is a separate calldata arg the
// contract length-checks.
export const POOL_ABI_FRAGMENTS = {
  // deposit (0-in/2-out mint): permissionless (external, whenInitialized, nonReentrant,
  // NO onlyOwner), pulls V of the ERC-20 from msg.sender. pub is length 19, pub[0] == V;
  // its single authority envelope rides in pub, so no separate Poseidon-ct arg.
  deposit:
    "function deposit(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[19] pub, bytes kemCiphertext)",
  transfer:
    "function transfer(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[37] pub, bytes kemCiphertext)",
  // withdraw pays the proof-bound pub[26] recipient (never msg.sender), so it is
  // relayable; the trailing pair is the stealth announcement (zero when none).
  withdraw:
    "function withdraw(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[27] pub, bytes kemCiphertext, bytes32 stealthEphemeralPub, uint8 stealthViewTag)",
  disburseWithCiphertexts:
    "function disburseWithCiphertexts(uint256[2] a, uint256[2][2] b, uint256[2] c, uint256[11] pub, uint256[] receiverCiphertexts, bytes kemCiphertext)",
  root: "function root() view returns (uint256)",
  nextLeafIndex: "function nextLeafIndex() view returns (uint256)",
  B: "function B() view returns (uint256)",
  // KEM epoch marker (design doc §4/§7): nonzero == the pool expects hybrid
  // envelopes; clients verify ARBITER_KEM_PK's keccak256 against it and the
  // indexer's boot guard refuses a V1-ABI/keyless-arbiter build on it.
  currentEpoch: "function currentEpoch() view returns (uint256)",
  arbiterKemPkHash: "function arbiterKemPkHash(uint256 epoch) view returns (bytes32)",
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
  // their own MetaMask and pays their own gas. NOT present on a production token.
  mint: "function mint(address to, uint256 amount)",
} as const;

/** Explorer link for a tx hash; `base` defaults to the live chain's explorer. */
export function explorerTxUrl(txHash: string, base: string = EXPLORER_BASE): string {
  return `${base.replace(/\/$/, "")}/tx/${txHash}`;
}
