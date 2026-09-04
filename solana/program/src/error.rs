//! Program error codes — the Solana mapping of the EVM pool/module error
//! surface (BongtuPool.sol + ConsumerOpModule.sol), pinned by the gate-5
//! invariant conformance table (SOLR §3.1.3 #5). Codes are part of the test
//! contract: the mollusk harness asserts `ProgramError::Custom(code)`.

use solana_program::program_error::ProgramError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PoolError {
    /// Op family flag is off in `PoolConfig` — the `ModuleNotRegistered`
    /// analogue (SOLR §2.1: family-enable flags replace the module registry).
    FamilyDisabled = 1,
    /// Instruction payload does not carry exactly the fixed wire shape
    /// (proof + non-derivable publics + N × 1088 B kem cts) — covers both the
    /// EVM `WrongKemCiphertextCount` and `WrongKemCiphertextLength`.
    WrongKemCiphertextLength = 2,
    /// A carried public signal is >= the BN254 scalar field modulus r.
    PublicInputNotCanonical = 3,
    /// Groth16 verification failed.
    InvalidProof = 4,
    /// Spend root has no `KnownRoot` PDA (or a spend-free op carried a
    /// nonzero root) — `UnknownRoot`.
    UnknownRoot = 5,
    /// Nullifier PDA already exists (spent), or the same nullifier appears
    /// twice in one instruction — `NullifierAlreadyUsed`.
    NullifierAlreadyUsed = 6,
    /// A zero nullifier crossed the state boundary — `ZeroNullifier`
    /// (padded slots are skipped before this point; belt only).
    ZeroNullifier = 7,
    /// A zero output commitment would burn value into an unspendable leaf —
    /// `ZeroOutputCommitment` (§6b self-burn defense).
    ZeroOutputCommitment = 8,
    /// Internal IMT insert misalignment — `MisalignedInsert`.
    MisalignedInsert = 9,
    /// The IMT is full — `TreeFull`.
    TreeFull = 10,
    /// An account has the wrong owner, tag, or config linkage.
    InvalidAccount = 11,
    /// A passed PDA does not match the program-derived address for its value.
    PdaMismatch = 12,
    /// Fewer nullifier PDA accounts than nonzero nullifiers.
    MissingNullifierAccount = 13,
    /// The event self-CPI authority is not the expected PDA signer.
    InvalidEventAuthority = 14,
    /// An alt_bn128 / poseidon syscall rejected its input (malformed curve
    /// point or hash input) — distinct from a well-formed proof that fails
    /// the pairing check (`InvalidProof`).
    SyscallFailed = 15,
    /// Unknown instruction discriminator.
    InvalidDiscriminator = 16,
    /// The withdraw recipient token account binds to zero under the OPEN-3
    /// truncate-253 rule — the `InvalidRecipient(0)` belt of
    /// WithdrawPrivModule.sol (unreachable for real accounts).
    InvalidRecipient = 17,
    /// A proof-bound escrow amount (pub[0]) exceeds u64 — SPL token amounts
    /// are u64, a per-rail narrowing of the 2^100 value belt (README
    /// consensus conventions).
    AmountOverflow = 18,
    /// The SPL token CPI (escrow pull or push) rejected — wrong mint,
    /// insufficient balance, frozen account, or a bad authority.
    TokenTransferFailed = 19,
}

impl From<PoolError> for ProgramError {
    fn from(e: PoolError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
