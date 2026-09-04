//! OPEN-3 recipient binding for `withdraw_priv` — DECIDED: **truncate-253**
//! (S2 security review; the user can still veto, which is why the entire
//! binding lives in this one module and nowhere else).
//!
//! The circuit binds `recipient` as ONE BN254 field element (pub[15] of
//! withdrawPriv; the EVM module range-checks it to uint160). A Solana token
//! account address is 32 bytes and does not fit a field element, so this rail
//! binds the LOW 253 BITS of the address: interpret the `Pubkey` bytes as a
//! big-endian 256-bit integer and clear the top 3 bits of byte 0. Every
//! 253-bit value is < r (r ~ 1.36 * 2^253), so the bound value is always a
//! canonical field element, and a prover-side value >= 2^253 can never match
//! any real account (funds stay unspent — no burn, failed verify/compare is
//! no state change).
//!
//! Security: substitution needs an attacker-controlled token account whose
//! address matches 253 chosen bits — ~2^250 keygens (keypair accounts) or
//! ~2^250 sha256 evaluations (PDA/ATA grinding), 93 bits MORE margin than the
//! EVM rail's whole 160-bit address space. Poseidon-of-limbs buys nothing
//! above the field's own ~2^253 level while adding a consensus-critical
//! limb-split spec, a sol_poseidon dependency on the withdraw path, and an
//! opaque pub[15]. The zero-guard mirrors WithdrawPrivModule.sol's
//! `InvalidRecipient(0)` belt (unreachable for real accounts).
//!
//! `withdraw_priv` (not yet on the dispatch) MUST: (1) run the normal SPL
//! owner/mint checks on the recipient token account, (2) compute
//! `bound_recipient_be(account.key)`, (3) require it nonzero and byte-equal
//! to public input pub[15] in its 32-byte big-endian encoding — one mask plus
//! one compare, ~0 CU, no new crypto surface.

use solana_program::pubkey::Pubkey;

/// Clear-top-3-bits mask for byte 0 of the big-endian address (2^253 truncation).
pub const RECIPIENT_MASK_HIGH_BYTE: u8 = 0x1F;

/// The 32-byte big-endian field-element encoding of the bound recipient:
/// `addr mod 2^253` over the raw `Pubkey` bytes read big-endian. This is the
/// exact byte string that must equal the withdrawPriv public input pub[15].
pub fn bound_recipient_be(recipient_token_account: &Pubkey) -> [u8; 32] {
    let mut bound = recipient_token_account.to_bytes();
    bound[0] &= RECIPIENT_MASK_HIGH_BYTE;
    bound
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_only_the_top_three_bits() {
        let addr = Pubkey::new_from_array([0xFF; 32]);
        let bound = bound_recipient_be(&addr);
        assert_eq!(bound[0], 0x1F);
        assert!(bound[1..].iter().all(|b| *b == 0xFF));
    }

    #[test]
    fn low_253_bits_pass_through() {
        let mut raw = [0xAB; 32];
        raw[0] = 0x1C; // already < 2^253
        let addr = Pubkey::new_from_array(raw);
        assert_eq!(bound_recipient_be(&addr), raw);
    }

    #[test]
    fn bound_value_is_always_canonical() {
        // 2^253 - 1 (the mask's maximum) < r: the bound encoding is a valid
        // scalar for every possible address, so no account is unbindable.
        let max = {
            let mut b = [0xFF; 32];
            b[0] = RECIPIENT_MASK_HIGH_BYTE;
            b
        };
        assert!(crate::groth16::is_canonical_scalar(&max));
    }
}
