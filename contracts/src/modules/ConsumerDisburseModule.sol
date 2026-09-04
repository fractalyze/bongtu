// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {BongtuPool} from "../BongtuPool.sol";
import {IDisbursePrivVerifier} from "../interfaces/IVerifiers.sol";
import {ConsumerOpModule} from "./ConsumerOpModule.sol";

/// @title ConsumerDisburseModule — disbursePriv256 (1-in / B-out public
///        batch), OPMOD §4/§5. Parameterized over B like the pool itself: one
///        code path serves the 1x16 dev twin and the 1x256 production batch
///        via the constructor-wired verifier and the pool's B.
///
/// publics (8): [0..1]=ecdhPub [2]=disclosureHash [3]=subtreeRoot
///              [4]=nullifier [5]=root [6]=enabled [7]=nonce
///
/// The 256 output commitments, receiver cts and viewTags travel in the
/// `disclosure` calldata array (receiverCts[4B] ++ viewTags[B] ++
/// outputCommitments[B]), totally ordered and bound by the proof's extended
/// disclosureHash fold — so a PUBLIC indexer can fill batch-interior merkle
/// paths (OPMOD §4.4). Kem ct bytes ride in K separate permissionless chunk
/// transactions keccak-bound to the batch tx (Option A-chunked, §5): a single
/// tx would carry ~330 KB of calldata, ~2.5x the op-geth txpool byte cap.
contract ConsumerDisburseModule is ConsumerOpModule {
    /// @dev BN254 scalar field modulus p — the canonical-form bound (§4.4).
    uint256 private constant SNARK_SCALAR_FIELD =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    IDisbursePrivVerifier public immutable verifier;
    /// @notice Batch size, read from the pool at construction: the subtree
    ///         attaches at the POOL's LOG_B level, so any other B would be a
    ///         wiring bug — reading it makes the mismatch unrepresentable.
    uint256 public immutable batchSize;
    /// @notice Outputs per kem-ct chunk tx (86 at B=256 => K=3, each chunk
    ///         <= ~94 KB — under the txpool byte cap with margin).
    uint256 public immutable chunkArity;
    /// @notice K = ceil(batchSize / chunkArity).
    uint256 public immutable chunkCount;

    /// @dev batchId (= startLeafIndex, unique forever in an append-only tree)
    ///      => the keccak256 of each pending chunk's bytes. Discovery-
    ///      transport state, not consensus state — and note that
    ///      {submitDisburseKemChunk} never crosses the pool's applyOp gate, so
    ///      a REMOVED module still accepts chunk submissions and emits
    ///      DisburseKemChunkAccepted from its deregistered address. That is
    ///      consensus-contained (chunks touch no pool state) but real for
    ///      discovery: indexers must keep watching removed disburse-module
    ///      addresses until every one of their batches' chunks is accepted.
    mapping(uint256 => bytes32[]) private _chunkHashes;
    /// @notice batchId => chunkIndex => accepted.
    mapping(uint256 => mapping(uint256 => bool)) public kemChunkAccepted;

    error ZeroNullifier();
    error WrongCiphertextLength(uint256 got, uint256 want);
    error NonCanonicalDisclosureElement(uint256 index, uint256 value);
    error WrongKemChunkHashCount(uint256 got, uint256 want);
    error BadChunkArity(uint256 arity, uint256 batchSize);
    error UnknownBatch(uint256 batchId);
    error BadChunkIndex(uint256 chunkIndex);
    error ChunkAlreadyAccepted(uint256 batchId, uint256 chunkIndex);
    error ChunkHashMismatch(uint256 batchId, uint256 chunkIndex);

    /// @notice `batchId` is the startLeafIndex applyOp returned; everything
    ///         consensus-relevant is FINAL in this event's transaction — only
    ///         the kem ct bytes are deferred to the chunk txs.
    event DisbursedPriv(
        uint256 indexed batchId,
        uint256 nullifier,
        uint256 subtreeRoot,
        uint256 disclosureHash,
        uint256[2] ecdhPublicKey,
        uint256 encryptionNonce,
        uint256 root,
        bytes32[] kemChunkHashes
    );
    /// @notice The batch-fill material, bound off-chain by the proof's
    ///         disclosureHash fold (re-hashing 6B elements on-chain is the
    ///         same non-starter as the enterprise 2054).
    event DisbursePrivDisclosure(uint256 indexed startLeafIndex, uint256[] disclosure);
    /// @notice Chunk DATA stays calldata-only (no re-emit): the public indexer
    ///         fetches the chunk tx via eth_getTransactionByHash — the
    ///         documented deviation from the logs-only rule, saving the ~2.2M
    ///         gas event copy (OPMOD §5).
    event DisburseKemChunkAccepted(uint256 indexed batchId, uint256 chunkIndex);

    constructor(BongtuPool _pool, IDisbursePrivVerifier _verifier, uint256 _chunkArity) ConsumerOpModule(_pool) {
        if (address(_verifier) == address(0)) revert ZeroVerifier();
        verifier = _verifier;
        uint256 b = _pool.B();
        if (_chunkArity == 0 || _chunkArity > b) revert BadChunkArity(_chunkArity, b);
        batchSize = b;
        chunkArity = _chunkArity;
        chunkCount = (b + _chunkArity - 1) / _chunkArity;
    }

    /// @notice The batch entrypoint. Order (OPMOD §4.3 + the §2.1 disburse
    ///         exception): disclosure length + canonical-form + chunk-hash
    ///         count checks, ZeroNullifier revert, THEN the unconditional
    ///         `enabled = 1` injection, then verify. The disburse base omits
    ///         the enabled boolean + value belt, so injecting 1 without the
    ///         zero-nullifier revert would hand a zero-leaf spend full trust —
    ///         the revert-then-inject sequence is this module's load-bearing
    ///         obligation.
    function disbursePriv256(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[8] calldata pub,
        uint256[] calldata disclosure,
        bytes32[] calldata kemChunkHashes_
    ) external {
        if (disclosure.length != 6 * batchSize) revert WrongCiphertextLength(disclosure.length, 6 * batchSize);
        // Canonical-form binding (OPMOD §4.4): poseidon folds reduce mod p
        // silently, so an element x + p would pass the off-chain fold while
        // its raw bytes disagree with the proven element — a byte-comparing
        // scanner would silently drop the event. Rejecting >= p upgrades the
        // fold's elementwise equality from mod-p equivalence to byte equality.
        for (uint256 i = 0; i < disclosure.length; i++) {
            if (disclosure[i] >= SNARK_SCALAR_FIELD) revert NonCanonicalDisclosureElement(i, disclosure[i]);
        }
        if (kemChunkHashes_.length != chunkCount) {
            revert WrongKemChunkHashCount(kemChunkHashes_.length, chunkCount);
        }
        if (pub[4] == 0) revert ZeroNullifier();

        uint[8] memory injected = pub;
        injected[6] = 1;
        if (!verifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        uint256[] memory nfs = new uint256[](1);
        nfs[0] = pub[4];
        uint256 start = pool.applyOp(
            BongtuPool.OpEffects({root: pub[5], nullifiers: nfs, leaves: _none(), subtreeRoot: pub[3]})
        );

        _chunkHashes[start] = kemChunkHashes_;
        _emitDisbursedPriv(pub, kemChunkHashes_, start);
        emit DisbursePrivDisclosure(start, disclosure);
    }

    /// @notice Permissionless kem-ct chunk delivery: anyone holding the bytes
    ///         can complete a batch. The hash was committed at batch time, so
    ///         a late chunk is verifiably THE bytes the sender chose. A
    ///         missing chunk leaves its outputs hash-committed but
    ///         undiscoverable-by-scan — the sender-self-sabotage class; funds
    ///         are intact and spendable.
    function submitDisburseKemChunk(uint256 batchId, uint256 chunkIndex, bytes calldata chunkData) external {
        bytes32[] storage hashes = _chunkHashes[batchId];
        // A real batch always stores K >= 1 hashes, so empty == never minted.
        if (hashes.length == 0) revert UnknownBatch(batchId);
        if (chunkIndex >= hashes.length) revert BadChunkIndex(chunkIndex);
        if (kemChunkAccepted[batchId][chunkIndex]) revert ChunkAlreadyAccepted(batchId, chunkIndex);
        uint256 want = chunkArityOf(chunkIndex) * KEM_CIPHERTEXT_LEN;
        if (chunkData.length != want) revert WrongKemCiphertextLength(chunkIndex, chunkData.length, want);
        if (keccak256(chunkData) != hashes[chunkIndex]) revert ChunkHashMismatch(batchId, chunkIndex);

        kemChunkAccepted[batchId][chunkIndex] = true;
        emit DisburseKemChunkAccepted(batchId, chunkIndex);
    }

    /// @notice Outputs carried by chunk `chunkIndex`: `chunkArity` for every
    ///         chunk but the last, which carries the remainder (84 at B=256).
    function chunkArityOf(uint256 chunkIndex) public view returns (uint256) {
        return chunkIndex == chunkCount - 1 ? batchSize - (chunkCount - 1) * chunkArity : chunkArity;
    }

    /// @notice The stored per-chunk keccak commitments for `batchId` (empty
    ///         array == unknown batch).
    function kemChunkHashes(uint256 batchId) external view returns (bytes32[] memory) {
        return _chunkHashes[batchId];
    }

    /// @dev Own frame: the 8-field emit plus the applyOp locals overflows the
    ///      EVM stack under non-via-IR solc (the pool's `_emit*` precedent).
    function _emitDisbursedPriv(uint[8] calldata pub, bytes32[] calldata kemChunkHashes_, uint256 start) private {
        emit DisbursedPriv(start, pub[4], pub[3], pub[2], [pub[0], pub[1]], pub[7], pool.root(), kemChunkHashes_);
    }
}
