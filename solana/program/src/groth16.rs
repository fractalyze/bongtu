//! Groth16 verification over the alt_bn128 syscalls (SOLR §2.3: verify is an
//! in-program syscall sequence against baked-in generated VK constants).
//!
//! Byte conventions (EIP-197, the syscall's native encoding): 32-byte
//! big-endian field elements; G1 = x || y; G2 limbs imaginary-first
//! (x_c1 || x_c0 || y_c1 || y_c0). The committed EVM fixtures already carry
//! proof `b` in this limb order (the snarkjs exportSolidityCallData swap), so
//! proof bytes go from wire to syscall untouched; only A is negated here.
//!
//! Verification equation, as one 4-pair product check:
//!   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
//! with vk_x = IC[0] + sum(pub[i] * IC[i+1]).

use {
    crate::{error::PoolError, generated::fields},
    solana_bn254::prelude::{
        alt_bn128_g1_addition_be, alt_bn128_g1_multiplication_be, alt_bn128_pairing_be,
    },
};

pub const PROOF_LEN: usize = 256;

/// One circuit's verifying key, assembled from the generated per-circuit
/// constants (generated/vk_*.rs) — the same shape for every op family.
pub struct Vk {
    pub alpha_g1: &'static [u8; 64],
    pub beta_g2: &'static [u8; 128],
    pub gamma_g2: &'static [u8; 128],
    pub delta_g2: &'static [u8; 128],
    /// IC[0..=nPublic]: vk_x = IC[0] + sum(pub[i] * IC[i+1]).
    pub ic: &'static [[u8; 64]],
}

/// `a < b` over 32-byte big-endian unsigned integers.
fn lt_be(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

pub fn is_canonical_scalar(v: &[u8; 32]) -> bool {
    lt_be(v, &fields::SCALAR_FIELD_R_BE)
}

pub fn is_zero(v: &[u8; 32]) -> bool {
    v.iter().all(|b| *b == 0)
}

/// q - y over big-endian bytes (y == 0 maps to 0: the point at infinity's y
/// stays 0). Callers pass y < q; a y >= q is a malformed point the syscall
/// itself rejects later, so no range check is duplicated here.
fn negate_fq_be(y: &[u8; 32]) -> [u8; 32] {
    if is_zero(y) {
        return [0u8; 32];
    }
    let q = &fields::BASE_FIELD_Q_BE;
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = q[i] as i16 - y[i] as i16 - borrow;
        if d < 0 {
            out[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            out[i] = d as u8;
            borrow = 0;
        }
    }
    out
}

/// Verify a Groth16 proof against a generated verifying key.
///
/// `proof` = A(64) || B(128, EVM limb order) || C(64). `publics` must be the
/// FULL reconstructed public vector (carried + program-injected signals),
/// each already checked canonical (< r) by the caller.
pub fn verify(vk: &Vk, proof: &[u8; PROOF_LEN], publics: &[[u8; 32]]) -> Result<bool, PoolError> {
    // A wrong-arity call is a program bug, not a prover input — fail hard.
    if publics.len() + 1 != vk.ic.len() {
        return Err(PoolError::SyscallFailed);
    }

    // vk_x = IC[0] + sum(pub[i] * IC[i+1])
    let mut vk_x: [u8; 64] = vk.ic[0];
    for (i, public) in publics.iter().enumerate() {
        let mut mul_in = [0u8; 96];
        mul_in[..64].copy_from_slice(&vk.ic[i + 1]);
        mul_in[64..].copy_from_slice(public);
        let term = alt_bn128_g1_multiplication_be(&mul_in).map_err(|_| PoolError::SyscallFailed)?;
        let mut add_in = [0u8; 128];
        add_in[..64].copy_from_slice(&vk_x);
        add_in[64..].copy_from_slice(&term);
        let sum = alt_bn128_g1_addition_be(&add_in).map_err(|_| PoolError::SyscallFailed)?;
        vk_x.copy_from_slice(&sum);
    }

    // -A: negate the y coordinate.
    let mut neg_a = [0u8; 64];
    neg_a[..32].copy_from_slice(&proof[..32]);
    let mut a_y = [0u8; 32];
    a_y.copy_from_slice(&proof[32..64]);
    neg_a[32..].copy_from_slice(&negate_fq_be(&a_y));

    // Pairing input: (-A, B), (alpha, beta), (vk_x, gamma), (C, delta).
    let mut pairing_in = [0u8; 4 * 192];
    pairing_in[0..64].copy_from_slice(&neg_a);
    pairing_in[64..192].copy_from_slice(&proof[64..192]);
    pairing_in[192..256].copy_from_slice(vk.alpha_g1);
    pairing_in[256..384].copy_from_slice(vk.beta_g2);
    pairing_in[384..448].copy_from_slice(&vk_x);
    pairing_in[448..576].copy_from_slice(vk.gamma_g2);
    pairing_in[576..640].copy_from_slice(&proof[192..256]);
    pairing_in[640..768].copy_from_slice(vk.delta_g2);

    let out = alt_bn128_pairing_be(&pairing_in).map_err(|_| PoolError::SyscallFailed)?;
    // Success = big-endian 1 (31 zero bytes then 0x01).
    Ok(out.len() == 32 && out[31] == 1 && out[..31].iter().all(|b| *b == 0))
}
