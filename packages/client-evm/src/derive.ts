// The EIP-712 derivation seed (issue #40): the domain-separated typed-data
// struct the wallet asks MetaMask to sign, split out of @bongtu/client
// keys/derive.ts when the KDF core stayed rail-agnostic. The signature this
// struct produces IS the seed of every derived key (SPEC §6), so the exact
// bytes here are consensus-critical; the KDF that turns the signature into the
// bjj/view/KEM identity stays in @bongtu/client/derive, and the signing edge
// that submits this payload is @bongtu/client-evm/connection signKeyDerivation.

/** An EIP-712 typed-data payload ready for `signer._signTypedData(domain, types, message)`
 *  / `eth_signTypedData_v4`. */
export interface KeyDerivationTypedData {
  domain: {
    name: string;
    version: string;
    chainId: number;
    verifyingContract: string;
  };
  types: Record<string, { name: string; type: string }[]>;
  primaryType: string;
  message: Record<string, string>;
}

/**
 * The domain-separated struct the wallet asks MetaMask to sign (SPEC §6). The
 * spending key is a pure function of this payload + the signing account, so the
 * exact bytes here are consensus-critical: changing `name`/`version`/the message
 * text rotates every user's key. `verifyingContract` = the pool, `chainId` +
 * `version` complete the separation.
 */
export function keyDerivationTypedData(
  chainId: number,
  poolAddress: string,
  version: string,
): KeyDerivationTypedData {
  return {
    domain: {
      name: "bongtu",
      version,
      chainId,
      verifyingContract: poolAddress,
    },
    types: {
      // EIP712Domain is filled in by the wallet / ethers automatically.
      BongtuSpendingKey: [
        { name: "statement", type: "string" },
        { name: "warning", type: "string" },
      ],
    },
    primaryType: "BongtuSpendingKey",
    message: {
      statement: "Derive my bongtu BabyJubJub spending key for this pool.",
      warning:
        "Signing this message reveals your bongtu spending key to whoever requested it. " +
        "Only sign inside the official bongtu wallet.",
    },
  };
}
