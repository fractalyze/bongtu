// connection/keypair.ts — a SolanaConnection over a local ed25519 keypair: the
// headless wallet the validator acceptance gate and tests drive the REAL
// client path with (the wallet-standard browser bridge is the app layer's
// sibling of this file). signMessage is WebCrypto Ed25519 — RFC 8032, so it
// lands in the deterministic wallet class the identity.ts guard admits.

import {
  createKeyPairFromBytes,
  getAddressFromPublicKey,
  getBase64EncodedWireTransaction,
  signBytes,
  signTransaction,
  type Transaction,
} from "@solana/kit";
import type { SolanaConnection } from "./edge.js";
import { rpcCall } from "./edge.js";

/**
 * Build a keypair-backed connection. `secretKey` is the 64-byte Solana
 * secret-key form (32-byte seed || 32-byte public key). Never persist it —
 * gate/test material only.
 */
export async function keypairConnection(rpcUrl: string, secretKey: Uint8Array): Promise<SolanaConnection> {
  const keyPair = await createKeyPairFromBytes(secretKey);
  const address = await getAddressFromPublicKey(keyPair.publicKey);
  return {
    address,
    // A local extension-class signer: the stricter Solana first-derivation
    // rule in identity.ts ignores the transport anyway.
    transport: "injected",
    rpcUrl,
    signMessage: async (bytes: Uint8Array): Promise<Uint8Array> =>
      Uint8Array.from(await signBytes(keyPair.privateKey, bytes)),
    signAndSendTransaction: async (tx: Transaction): Promise<string> => {
      const signed = await signTransaction([keyPair], tx);
      const wire = getBase64EncodedWireTransaction(signed);
      return rpcCall<string>(rpcUrl, "sendTransaction", [
        wire,
        { encoding: "base64", preflightCommitment: "confirmed" },
      ]);
    },
  };
}
