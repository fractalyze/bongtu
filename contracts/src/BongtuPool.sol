// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IPoseidon2} from "./interfaces/IPoseidon2.sol";
import {
    IDepositVerifier,
    IWithdrawVerifier,
    IDisburseVerifier,
    ITransferVerifier,
    ITransfer10Verifier,
    ITransfer10x2Verifier
} from "./interfaces/IVerifiers.sol";
import {IERC20} from "./utils/IERC20.sol";
import {SafeERC20} from "./utils/SafeERC20.sol";
import {Ownable2StepUpgradeable} from "./utils/Ownable2StepUpgradeable.sol";
import {Initializable} from "./utils/proxy/Initializable.sol";
import {UUPSUpgradeable} from "./utils/proxy/UUPSUpgradeable.sol";

/// @title BongtuPool — unified single-frontier IMT shielded pool (SPEC §5).
///
/// One height-`H` Poseidon-v1 Incremental Merkle Tree holds BOTH incremental
/// single-leaf inserts (deposit / transfer / withdraw outputs) AND B-leaf batch
/// subtrees (disburse), sharing one `nextLeafIndex` and one `filledSubtrees`
/// frontier, so a batch-inserted note is spendable by transfer/withdraw against
/// the same root (§5.1). The tree is byte-identical to the JS reference
/// `packages/core/src/imt.ts` — the Foundry differential test asserts `root() ==
/// ImtTree.getRoot()` after every insert.
///
/// The load-bearing soundness fix (§5.2): for every verifier call the contract
/// DERIVES `enabled[i] = (nullifier[i] != 0)` from its own view and injects it
/// into the public-signal vector, and injects the arbiter pubkey from storage —
/// `enabled` and the authority key are NEVER read from calldata. A proof made
/// with `enabled=0` on a value-carrying (nonzero-nullifier) input therefore
/// fails verification (mint-from-nothing is closed).
///
/// Lifecycle (SPEC §5.2, `docs/zeto-derivation.md` "Upgradeability"): the pool is
/// deployed behind a **UUPS (ERC-1967) proxy** so a future circuit/verifier change
/// ships as an `upgradeToAndCall` — preserving the pool address + the whole IMT
/// tree state — instead of a forced redeploy. Every former immutable/constructor
/// value is set once in {initialize}; the implementation constructor only calls
/// `_disableInitializers()` so a bare impl can never be initialized/hijacked.
contract BongtuPool is Initializable, Ownable2StepUpgradeable, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    // --- IMT (single-frontier, Poseidon-v1) -----------------------------------
    // Everything below was `immutable` in the pre-proxy pool; behind a proxy the
    // implementation constructor never runs against the proxy's storage, so these
    // are now regular storage, set exactly once in {initialize}.
    uint256 public constant H = 32; // tree height (2^32 leaf capacity)
    uint256 public B; // disburse batch size (M0 = 16, prod = 256)
    uint256 public LOG_B; // level at which a disburse subtree attaches
    // §6b v2 enforced disclosure: the ONLY disburse entry point must publish the
    // FULL ciphertext = 4*B receiver elements ++ the authority envelope. For
    // B=256 this is 1024 + 1030 = 2054. Precomputed from B in {initialize}.
    uint256 public disburseCiphertextLen;

    IPoseidon2 public poseidon;

    uint256[33] public zeros; // zeros[0]=0, zeros[k]=H(zeros[k-1],zeros[k-1]); k in 0..H
    uint256[32] public filledSubtrees; // Tornado frontier, level 0..H-1
    uint256 public root;
    uint256 public nextLeafIndex;

    // --- verifiers (fixed per impl; a circuit change ships via a UUPS upgrade) -
    // All six are wired by {initialize}; the two transfer10* slots sit at the
    // tail of storage (see the tail-slots block at the bottom of the contract).
    IDepositVerifier public depositVerifier;
    IWithdrawVerifier public withdrawVerifier;
    IDisburseVerifier public disburseVerifier;
    ITransferVerifier public transferVerifier;

    // --- roots / nullifiers / custody -----------------------------------------
    mapping(uint256 => bool) public knownRoots; // §5.3 any-historical-root (no ring)
    mapping(uint256 => bool) public nullifierUsed;
    IERC20 public token;

    // --- arbiter epochs (§5.3) -------------------------------------------------
    struct ArbiterEpoch {
        uint256 keyX;
        uint256 keyY;
        uint256 activatedBlock;
    }

    ArbiterEpoch[] public arbiterEpochs;
    bool public initialized;

    // --- retired storage (slot kept for layout continuity) ---------------------
    // Was the disburse caller-allowlist (§5.3). RETIRED 2026-07-28 (user
    // decision): disburse is permissionless — the event payload is ciphertext,
    // so batch contents are already readable only by each recipient and the
    // arbiter, and value conservation is proven in-circuit. Nothing reads or
    // writes this mapping anymore; it stays declared so V1-era slots keep
    // their positions under the UUPS proxy.
    mapping(address => bool) public disburseAllowed;

    /// @notice ML-KEM-768 ciphertext wire size (FIPS 203) — the only on-chain
    ///         check possible on `kemCiphertext` (content is bound off-chain via
    ///         the proof's `kemBinding` + arbiter decapsulation, design doc §2).
    uint256 public constant KEM_CIPHERTEXT_LEN = 1088;

    // --- public-signal indices (derived from out/<name>.public.json + .sym) ----
    // The PQ hybrid envelope (.dev/pq-envelope-design.md §3) declares `kemBinding`
    // as the LAST circuit output, so all pre-existing output indices are unchanged
    // and every public-INPUT index shifts by exactly +1.
    // deposit  (19): [0]=out [1..2]=ecdhPub [3..12]=cipherTextAuthority[10]
    //                [13]=kemBinding [14..15]=oc [16]=nonce [17..18]=authorityPubKey
    // withdraw (26): [0]=out [1..2]=ecdhPub [3..15]=cipherTextAuthority[13]
    //                [16]=kemBinding [17..18]=nf [19]=root [20..21]=enabled
    //                [22]=oc0(change) [23]=nonce [24..25]=authorityPubKey
    // disburse (11): [0..1]=ecdhPub [2]=disclosureHash [3]=subtreeRoot
    //                [4]=kemBinding [5]=nf [6]=root [7]=enabled [8]=nonce
    //                [9..10]=authorityPubKey
    // transfer (37): [0..1]=ecdhPub [2..9]=cipherTexts[2][4]
    //                [10..25]=cipherTextAuthority[16] [26]=kemBinding [27..28]=nf
    //                [29]=root [30..31]=enabled [32..33]=oc [34]=nonce
    //                [35..36]=authorityPubKey
    // transfer10 (141): the same vector at arity 10 —
    //                [0..1]=ecdhPub [2..41]=cipherTexts[10][4]
    //                [42..105]=cipherTextAuthority[64] [106]=kemBinding
    //                [107..116]=nf [117]=root [118..127]=enabled
    //                [128..137]=oc [138]=nonce [139..140]=authorityPubKey
    // transfer10x2 (68): transfer10's input side, 2 outputs —
    //                [0..1]=ecdhPub [2..9]=cipherTexts[2][4]
    //                [10..40]=cipherTextAuthority[31] [41]=kemBinding
    //                [42..51]=nf [52]=root [53..62]=enabled
    //                [63..64]=oc [65]=nonce [66..67]=authorityPubKey

    // --- events (all ciphertext copied from verified publicSignals) -----------
    event Appended(uint256 indexed leafIndex, uint256 leaf, uint256 root);
    event SubtreeAppended(uint256 indexed startLeafIndex, uint256 subtreeRoot, uint256 root);
    // §6b v2: Deposited carries the authority (auditor) envelope so the minted
    // output notes are decryptable from on-chain data alone. ecdhPublicKey +
    // encryptionNonce + encryptedValuesForAuthority are copied from the proof's
    // public signals (the contract injected the arbiter key before verify).
    // PQ hybrid envelope (.dev/pq-envelope-design.md §4): every op event carries
    // the proof's `kemBinding` public signal AND the raw ML-KEM-768 ciphertext,
    // so the arbiter decapsulates + binding-checks from event data alone (it must
    // never need tx calldata). `kemCiphertext` content is NOT verifiable on-chain
    // (only its 1088-byte length is enforced); a junk-wrapped ct surfaces at the
    // arbiter as a kemBinding mismatch = first-class alarm.
    event Deposited(
        uint256 indexed epoch,
        uint256 firstLeafIndex,
        uint256 oc0,
        uint256 oc1,
        uint256 amount,
        uint256[2] ecdhPublicKey,
        uint256[10] encryptedValuesForAuthority,
        uint256 encryptionNonce,
        uint256 root,
        uint256 kemBinding,
        bytes kemCiphertext
    );
    event Transferred(
        uint256 indexed epoch,
        uint256[2] nullifiers,
        uint256[2] outputCommitments,
        uint256[2] ecdhPublicKey,
        uint256[4] encryptedValuesForReceiver0,
        uint256[4] encryptedValuesForReceiver1,
        uint256[16] encryptedValuesForAuthority,
        uint256 encryptionNonce,
        uint256 root,
        uint256 kemBinding,
        bytes kemCiphertext
    );
    /// @notice transfer10 (10-in / 10-out). A SEPARATE event, not a widened
    ///         `Transferred`: the 2-in shape stays on the live wire (an indexer
    ///         spanning the upgrade block must keep parsing it), and the arity-10
    ///         receiver ciphertexts arrive as ONE flat `uint256[40]` rather than
    ///         ten named fields — ingest slices it at `i*4` in leaf order, which
    ///         is the same loop it already runs over a disburse batch, and
    ///         `encryptedValuesForReceiverN` x10 would be neither.
    event Transferred10(
        uint256 indexed epoch,
        uint256[10] nullifiers,
        uint256[10] outputCommitments,
        uint256[2] ecdhPublicKey,
        uint256[40] encryptedValuesForReceivers,
        uint256[64] encryptedValuesForAuthority,
        uint256 encryptionNonce,
        uint256 root,
        uint256 kemBinding,
        bytes kemCiphertext
    );
    /// @notice transfer10x2 (10-in / 2-out). Its own event for the same reason
    ///         {Transferred10} is not a widened `Transferred`: both older shapes
    ///         stay on the live wire across the upgrade block, and the array
    ///         widths here (10 nullifiers, 2 commitments, 8 receiver elements,
    ///         31 authority elements) match no existing event.
    event Transferred10x2(
        uint256 indexed epoch,
        uint256[10] nullifiers,
        uint256[2] outputCommitments,
        uint256[2] ecdhPublicKey,
        uint256[8] encryptedValuesForReceivers,
        uint256[31] encryptedValuesForAuthority,
        uint256 encryptionNonce,
        uint256 root,
        uint256 kemBinding,
        bytes kemCiphertext
    );
    event Disbursed(
        uint256 indexed epoch,
        uint256 nullifier,
        uint256 subtreeRoot,
        uint256 disclosureHash,
        uint256[2] ecdhPublicKey,
        uint256 encryptionNonce,
        uint256 root,
        uint256 kemBinding,
        bytes kemCiphertext
    );
    /// @notice Raw receiver ciphertext bytes for a disburse batch (SPEC §5.3 /
    ///         §4 disburse note): 4 field elements per output note
    ///         (`SymmetricEncrypt(2)` of [value, salt]), flattened in leaf order
    ///         from `startLeafIndex`. Free calldata bound only by the proof's
    ///         `disclosureHash` (indexer/recipient duty, §6b) — the chain does not
    ///         re-hash it (2,054 Poseidons, infeasible §4). Without these bytes
    ///         (plus `ecdhPublicKey`+`encryptionNonce` from Disbursed) a recipient
    ///         cannot derive its note by trial-decrypt.
    event DisburseCiphertexts(uint256 indexed startLeafIndex, uint256[] receiverCiphertexts);
    // §6b v2: Withdrawn carries the authority (auditor) envelope — the spent
    // inputs' owner + values/salts and the change note — decryptable on-chain.
    event Withdrawn(
        uint256 indexed epoch,
        uint256[2] nullifiers,
        uint256 amount,
        uint256 changeCommitment,
        uint256[2] ecdhPublicKey,
        uint256[13] encryptedValuesForAuthority,
        uint256 encryptionNonce,
        uint256 root,
        uint256 kemBinding,
        bytes kemCiphertext
    );
    /// @notice Stealth payout surface, paired 1:1 with a Withdrawn in the same
    ///         tx: the proof-bound payout address plus the announcement a
    ///         recipient's wallet scans for (ephemeralPub/viewTag zero when the
    ///         caller withdrew to a plainly-known address and announced
    ///         nothing). A separate event so Withdrawn keeps its historical
    ///         shape — one fragment decodes the whole chain. The announcement
    ///         halves are calldata-carried, NOT proof-bound: tampering them can
    ///         only break discovery; funds still reach the proof-bound
    ///         recipient.
    event WithdrawAnnouncement(uint256 recipient, bytes32 stealthEphemeralPub, uint8 stealthViewTag);
    event ArbiterRotated(uint256 indexed epoch, uint256 keyX, uint256 keyY, uint256 activatedBlock);
    /// @notice The keccak256 of the epoch's 1184-byte ML-KEM-768 encapsulation
    ///         key (the full pk is distributed off-chain; clients verify it
    ///         against this hash before encapsulating). Emitted alongside
    ///         ArbiterRotated for the same epoch.
    event ArbiterKemPkHashSet(uint256 indexed epoch, bytes32 kemPkHash);

    // --- op-module layer events (OPMOD §1.5) ----------------------------------
    event ModuleRegistered(address indexed module);
    event ModuleRemoved(address indexed module);
    /// @notice One per applyOp*: the audit trail tying a tree mutation to the
    ///         module that caused it. Carries the resulting root so the
    ///         indexer's per-insert mirror assertion has the same anchor the
    ///         low-level Appended/SubtreeAppended events give it (which keep
    ///         firing unchanged — the tree feed is family-blind).
    event OpApplied(
        address indexed module,
        uint256 startLeafIndex,
        uint256 nullifierCount,
        uint256 leafCount, // 0 for a subtree attach
        uint256 subtreeRoot, // 0 for single-leaf appends
        uint256 root
    );

    // --- errors ---------------------------------------------------------------
    // (re-init reverts via Initializable.InvalidInitialization, not a local error)
    error NotInitialized();
    error ZeroArbiterKey();
    error UnknownRoot(uint256 root);
    error NullifierAlreadyUsed(uint256 nullifier);
    error ZeroNullifier();
    error InvalidProof();
    error Reentrancy();
    error BatchSizeNotPowerOfTwo(uint256 batchSize);
    error MisalignedInsert();
    error TreeFull();
    error WrongCiphertextLength(uint256 got, uint256 want);
    error WrongKemCiphertextLength(uint256 got, uint256 want);
    error ZeroKemPkHash();
    error ZeroVerifier();
    error ZeroOutputCommitment();
    error InvalidRecipient(uint256 recipient);
    // --- op-module layer (OPMOD §1) ---
    error ModuleNotRegistered(address module);
    error ModuleAlreadyRegistered(address module);
    error MixedAppendShape();
    error ZeroModule();
    error EmptyOp();

    // --- reentrancy guard -----------------------------------------------------
    // Behind a proxy the inline default does not reach the proxy's storage, so
    // {initialize} also arms `_locked = 1`; `whenInitialized` runs before
    // `nonReentrant` on every op so a pre-init call reverts NotInitialized.
    uint256 private _locked = 1;

    modifier nonReentrant() {
        if (_locked != 1) revert Reentrancy();
        _locked = 2;
        _;
        _locked = 1;
    }

    modifier whenInitialized() {
        if (!initialized) revert NotInitialized();
        _;
    }

    /// @dev The implementation constructor only locks the bare impl (a UUPS impl
    ///      must never be initializable on its own — that is the classic
    ///      implementation-takeover footgun). ALL former constructor state now
    ///      lives in {initialize}, run exactly once through the proxy.
    constructor() {
        _disableInitializers();
    }

    /// @notice The pool's ONLY initializer, run through the ERC-1967 proxy
    ///         (SPEC §5.2). It brings the pool up in its complete production
    ///         shape in a single run-once call: Poseidon / token wiring, ALL SIX
    ///         verifiers, the IMT parameters (B, LOG_B, the enforced disburse
    ///         ciphertext length, the zeros ladder, the frontier, the empty-tree
    ///         root), the reentrancy latch, the owner, and arbiter epoch 0
    ///         carrying both halves of the hybrid authority key.
    ///
    ///         There is deliberately no second entry point. A pool is deployed
    ///         with every op it will ever serve already wired, so no operation is
    ///         ever reachable-but-unbacked and no deploy needs sequencing. A
    ///         later circuit change ships as `upgradeToAndCall` carrying its own
    ///         one-shot migration payload, written then against the state it
    ///         actually has to move; nothing is reserved for it here.
    ///
    ///         The `initializer` modifier (ERC-7201 storage) enforces run-once;
    ///         the caller (the deployer, via the proxy) becomes owner — this is
    ///         not `onlyOwner` because there is no owner until it runs. Rejects a
    ///         zero address for any verifier (a zeroed one bricks its op until an
    ///         upgrade), a non-power-of-two batch size, a (0,0) arbiter key
    ///         (§5.3 Q9) and a zero KEM pk hash: a zero in `arbiterKemPkHash`
    ///         must mean "epoch never minted" and nothing else, so every epoch
    ///         this pool mints — epoch 0 included — carries a real hash (design
    ///         doc §4).
    function initialize(
        IPoseidon2 _poseidon,
        IDepositVerifier _depositVerifier,
        IWithdrawVerifier _withdrawVerifier,
        IDisburseVerifier _disburseVerifier,
        ITransferVerifier _transferVerifier,
        ITransfer10Verifier _transfer10Verifier,
        ITransfer10x2Verifier _transfer10x2Verifier,
        IERC20 _token,
        uint256 _batchSize,
        uint256[2] calldata arbiterKey,
        bytes32 arbiterKemPkHash_
    ) external initializer {
        if (_batchSize <= 1 || (_batchSize & (_batchSize - 1)) != 0) revert BatchSizeNotPowerOfTwo(_batchSize);
        if (arbiterKey[0] == 0 || arbiterKey[1] == 0) revert ZeroArbiterKey();
        if (arbiterKemPkHash_ == bytes32(0)) revert ZeroKemPkHash();

        __Ownable2Step_init(msg.sender);
        __UUPSUpgradeable_init();

        // Behind a proxy the impl constructor never ran against THIS storage, so
        // the inline `_locked = 1` default did not take — arm the latch here
        // (NOT_ENTERED == 1) or the first nonReentrant op would revert Reentrancy.
        _locked = 1;

        // The verifier wiring and the tree/param derivation are split into
        // helpers to keep this function under the stack-depth limit.
        _initVerifiers(
            _depositVerifier,
            _withdrawVerifier,
            _disburseVerifier,
            _transferVerifier,
            _transfer10Verifier,
            _transfer10x2Verifier
        );
        poseidon = _poseidon;
        token = _token;
        B = _batchSize;
        _initTreeAndParams(_batchSize);

        // §5.3 Q9. Epoch 0 carries the KEM hash too — a zero would be
        // indistinguishable from an index that was never minted (design doc §4).
        initialized = true;
        arbiterEpochs.push(ArbiterEpoch({keyX: arbiterKey[0], keyY: arbiterKey[1], activatedBlock: block.number}));
        arbiterKemPkHash[0] = arbiterKemPkHash_;
        emit ArbiterRotated(0, arbiterKey[0], arbiterKey[1], block.number);
        emit ArbiterKemPkHashSet(0, arbiterKemPkHash_);
    }

    /// @dev Wire every verifier the pool will ever call, rejecting the zero
    ///      address on each: a zeroed verifier turns its entry point into a call
    ///      into nothing — reachable, always reverting, and unfixable short of an
    ///      upgrade. The deploy script constructs all six inline, so a zero here
    ///      is always a misconfiguration rather than an intended "not yet".
    function _initVerifiers(
        IDepositVerifier _depositVerifier,
        IWithdrawVerifier _withdrawVerifier,
        IDisburseVerifier _disburseVerifier,
        ITransferVerifier _transferVerifier,
        ITransfer10Verifier _transfer10Verifier,
        ITransfer10x2Verifier _transfer10x2Verifier
    ) private {
        if (
            address(_depositVerifier) == address(0) || address(_withdrawVerifier) == address(0)
                || address(_disburseVerifier) == address(0) || address(_transferVerifier) == address(0)
                || address(_transfer10Verifier) == address(0) || address(_transfer10x2Verifier) == address(0)
        ) revert ZeroVerifier();
        depositVerifier = _depositVerifier;
        withdrawVerifier = _withdrawVerifier;
        disburseVerifier = _disburseVerifier;
        transferVerifier = _transferVerifier;
        transfer10Verifier = _transfer10Verifier;
        transfer10x2Verifier = _transfer10x2Verifier;
    }

    /// @dev The tree + param derivation: LOG_B, the enforced disburse ciphertext
    ///      length, the zeros ladder, the frontier and the empty-tree root.
    ///      Reads the just-wired `poseidon` storage.
    function _initTreeAndParams(uint256 _batchSize) private {
        uint256 logB = 0;
        while ((uint256(1) << logB) < _batchSize) logB++;
        LOG_B = logB;

        // §6b v2: authority plaintext = 2 + 2*nInputs(=1) + 4*B = 4 + 4*B;
        // Poseidon-sponge ct = pad plaintext to a multiple of 3, then +1. The
        // enforced disburse ciphertext = 4*B receiver elements ++ that envelope.
        uint256 authPlain = 4 + 4 * _batchSize;
        uint256 authPad = (3 - (authPlain % 3)) % 3;
        disburseCiphertextLen = 4 * _batchSize + (authPlain + authPad + 1);

        // zeros ladder — identical to ImtTree: zeros[0]=0, zeros[k]=H(z,z).
        zeros[0] = 0;
        for (uint256 k = 1; k <= H; k++) {
            zeros[k] = poseidon.poseidon([zeros[k - 1], zeros[k - 1]]);
        }
        for (uint256 i = 0; i < H; i++) {
            filledSubtrees[i] = zeros[i];
        }
        root = zeros[H];
        knownRoots[root] = true; // the empty-tree root is a known root
    }

    /// @dev UUPS upgrade authorization — only the owner may swap the impl (a
    ///      circuit/verifier change ships as `upgradeToAndCall`, SPEC §5.2/§5.3).
    ///      On mainnet the owner is a multisig/timelock (docs/zeto-derivation.md).
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}

    /// @notice One-shot migration payload for the stealth-withdraw upgrade:
    ///         swaps in the verifier for the 27-public withdraw circuit
    ///         (recipient bound at pub[26]). Ridden by `upgradeToAndCall` so the
    ///         implementation and its verifier change atomically — a pool
    ///         serving the new `withdraw(uint[27],…)` ABI with the old
    ///         26-public verifier (or vice versa) would reject every proof.
    ///         `onlyOwner` because `reinitializer(2)` alone is first-come:
    ///         after a bare `upgradeTo` anyone could otherwise claim the slot
    ///         and wire a forged verifier.
    function reinitializeV2(IWithdrawVerifier _withdrawVerifier) external onlyOwner reinitializer(2) {
        if (address(_withdrawVerifier) == address(0)) revert ZeroVerifier();
        withdrawVerifier = _withdrawVerifier;
    }

    /// @notice One-shot migration payload for the op-module upgrade (OPMOD §7.2):
    ///         registers the initial consumer module set. No verifier swap rides
    ///         in it — the six enterprise verifiers are untouched, so unlike
    ///         {reinitializeV2} there is no atomicity constraint between old
    ///         proofs and new verifiers. `onlyOwner` for the same reason
    ///         reinitializeV2 is — `reinitializer(3)` alone is first-come after
    ///         a bare `upgradeTo`.
    function reinitializeV3(address[] calldata modules) external onlyOwner reinitializer(3) {
        for (uint256 i = 0; i < modules.length; i++) {
            if (modules[i] == address(0)) revert ZeroModule();
            // A duplicate entry would double-emit ModuleRegistered — the same
            // unbalanced-log hazard the setter guards close: the event stream
            // is the canonical registry reconstruction source.
            if (registeredModules[modules[i]]) revert ModuleAlreadyRegistered(modules[i]);
            registeredModules[modules[i]] = true;
            emit ModuleRegistered(modules[i]);
        }
    }

    /// @notice Append an epoch and emit its index; the arbiter pubkey is read
    ///         from storage at execution (never calldata) so a sender cannot
    ///         encrypt to their own key and silently kill non-repudiation.
    ///         There is no bjj-only overload: every epoch must carry a KEM pk
    ///         hash, or a rotation could mint a zero-hash epoch a client could
    ///         not tell from an index that was never minted (design doc §4).
    function rotateArbiter(uint256[2] calldata newKey, bytes32 newKemPkHash) external onlyOwner whenInitialized {
        _rotateArbiter(newKey, newKemPkHash);
    }

    /// @dev The epoch append itself, private so a future `upgradeToAndCall`
    ///      payload can mint a rotation epoch in the same transaction as an
    ///      implementation swap — the external {rotateArbiter} is unreachable
    ///      from there without changing msg.sender.
    function _rotateArbiter(uint256[2] calldata newKey, bytes32 newKemPkHash) private {
        if (newKey[0] == 0 || newKey[1] == 0) revert ZeroArbiterKey();
        if (newKemPkHash == bytes32(0)) revert ZeroKemPkHash();
        uint256 e = arbiterEpochs.length;
        arbiterEpochs.push(ArbiterEpoch({keyX: newKey[0], keyY: newKey[1], activatedBlock: block.number}));
        arbiterKemPkHash[e] = newKemPkHash;
        emit ArbiterRotated(e, newKey[0], newKey[1], block.number);
        emit ArbiterKemPkHashSet(e, newKemPkHash);
    }

    function currentEpoch() public view returns (uint256) {
        return arbiterEpochs.length - 1;
    }

    function currentArbiterKey() public view returns (uint256 x, uint256 y) {
        ArbiterEpoch storage ep = arbiterEpochs[arbiterEpochs.length - 1];
        return (ep.keyX, ep.keyY);
    }

    function isKnownRoot(uint256 r) public view returns (bool) {
        return knownRoots[r];
    }

    // ==========================================================================
    //                               OPERATIONS
    // ==========================================================================

    /// @notice deposit (0-in / 2-out mint): inject the stored arbiter key into the
    ///         authority envelope's public key (§6b v2 enforced disclosure — a
    ///         deposit not encrypted to the current arbiter key FAILS), verify,
    ///         append the two output notes, then pull `out` tokens (SafeERC20, CEI).
    ///         `kemCiphertext` = the ML-KEM-768 encapsulation to the arbiter KEM
    ///         key: length-checked + emitted only (design doc §2 trade-off — the
    ///         ECDH half keeps proof-fails-on-wrong-key, the KEM half is
    ///         alarm-enforced via the arbiter's kemBinding check).
    function deposit(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[19] calldata pub,
        bytes calldata kemCiphertext
    ) external whenInitialized nonReentrant {
        _checkKemCiphertext(kemCiphertext);
        uint[19] memory injected = pub;
        (injected[17], injected[18]) = currentArbiterKey();
        if (!depositVerifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        uint256 oc0 = pub[14];
        uint256 oc1 = pub[15];
        // A zero output commitment is a non-note (self-burn foot-gun); never append it.
        if (oc0 == 0 || oc1 == 0) revert ZeroOutputCommitment();

        uint256 first = nextLeafIndex;
        _appendLeaf(oc0);
        _appendLeaf(oc1);

        _emitDeposited(pub, kemCiphertext, first);
        token.safeTransferFrom(msg.sender, address(this), pub[0]);
    }

    /// @dev Split out of {deposit}: the 11-field event plus the verify locals
    ///      overflows the EVM stack in a single frame (non-via-IR build).
    function _emitDeposited(uint[19] calldata pub, bytes calldata kemCiphertext, uint256 first) private {
        uint256[10] memory cta;
        for (uint256 i = 0; i < 10; i++) cta[i] = pub[3 + i];
        emit Deposited(
            currentEpoch(), first, pub[14], pub[15], pub[0], [pub[1], pub[2]], cta, pub[16], root, pub[13], kemCiphertext
        );
    }

    /// @dev The ONLY on-chain check possible on the KEM ciphertext: FIPS 203
    ///      pins the ML-KEM-768 ct at exactly 1088 bytes; content is bound
    ///      off-chain by the proof's kemBinding + arbiter decapsulation.
    function _checkKemCiphertext(bytes calldata kemCiphertext) private pure {
        if (kemCiphertext.length != KEM_CIPHERTEXT_LEN) {
            revert WrongKemCiphertextLength(kemCiphertext.length, KEM_CIPHERTEXT_LEN);
        }
    }

    /// @notice disburse (1-in / B-out): the ONLY disburse entry point (§6b v2 —
    ///         the plain, ciphertext-free `disburse()` is removed so publication is
    ///         enforced on-chain, not by convention). Requires the FULL ciphertext
    ///         (4*B receiver elements ++ the authority envelope) so a recipient AND
    ///         the auditor can discover + decrypt from chain data alone. The chain
    ///         checks LENGTH only (gas ≈ free); content stays bound off-chain by the
    ///         proof's `disclosureHash` (§4/§6b — 2,054 Poseidons are infeasible to
    ///         re-hash on-chain). A length-padded junk publish still tx-succeeds but
    ///         yields a provable `mismatch` alarm + undecryptable notes. Pads the
    ///         frontier to a B boundary and attaches the in-circuit subtreeRoot;
    ///         permissionless like every spend (allowlist retired 2026-07-28 —
    ///         contents are ciphertext, so openness costs no privacy); injects
    ///         enabled=1 and the arbiter key (§5.2/§5.3).
    function disburseWithCiphertexts(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[11] calldata pub,
        uint256[] calldata receiverCiphertexts,
        bytes calldata kemCiphertext
    ) external whenInitialized nonReentrant {
        if (receiverCiphertexts.length != disburseCiphertextLen) {
            revert WrongCiphertextLength(receiverCiphertexts.length, disburseCiphertextLen);
        }
        _checkKemCiphertext(kemCiphertext);
        uint256 start = _disburseCore(a, b, c, pub, kemCiphertext);
        emit DisburseCiphertexts(start, receiverCiphertexts);
    }

    /// @dev disburse verification + subtree attach. Caller-gated (§5.3); contract
    ///      injects enabled=1 and the arbiter key from storage (§5.2). Returns
    ///      the batch's start leaf index.
    function _disburseCore(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[11] calldata pub,
        bytes calldata kemCiphertext
    ) private returns (uint256 start) {
        if (!knownRoots[pub[6]]) revert UnknownRoot(pub[6]);

        uint256 nf = pub[5];
        if (nf == 0) revert ZeroNullifier(); // 1-in disburse is always real
        if (nullifierUsed[nf]) revert NullifierAlreadyUsed(nf);

        // §5.2 contract-derived enabled + §5.3 arbiter-key-from-storage injection.
        // disburse has a single input and reverts above on nf==0, so enabled is
        // unconditionally 1 (membership on the sole input is always required).
        // kemBinding (pub[4]) is read from the proof, never injected — the
        // contract has nothing to check it against (design doc §4).
        uint[11] memory injected = pub;
        injected[7] = 1;
        (injected[9], injected[10]) = currentArbiterKey();
        if (!disburseVerifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        nullifierUsed[nf] = true;
        start = _attachSubtree(pub[3]);

        emit Disbursed(
            currentEpoch(), nf, pub[3], pub[2], [pub[0], pub[1]], pub[8], root, pub[4], kemCiphertext
        );
        emit SubtreeAppended(start, pub[3], root);
    }

    /// @notice transfer (2-in / 2-out): permissionless. Contract injects
    ///         enabled[i]=(nullifier[i]!=0) and the arbiter key from storage,
    ///         spends the real (nonzero) nullifiers, appends the 2 outputs.
    function transfer(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[37] calldata pub,
        bytes calldata kemCiphertext
    ) external whenInitialized nonReentrant {
        _checkKemCiphertext(kemCiphertext);
        if (!knownRoots[pub[29]]) revert UnknownRoot(pub[29]);

        uint[37] memory injected = pub;
        injected[30] = pub[27] != 0 ? 1 : 0;
        injected[31] = pub[28] != 0 ? 1 : 0;
        (injected[35], injected[36]) = currentArbiterKey();
        if (!transferVerifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        _spendNullifier(pub[27]);
        _spendNullifier(pub[28]);

        // A zero output commitment is a non-note (self-burn foot-gun); never append it.
        if (pub[32] == 0 || pub[33] == 0) revert ZeroOutputCommitment();
        _appendLeaf(pub[32]);
        _appendLeaf(pub[33]);

        _emitTransferred(pub, kemCiphertext);
    }

    /// @dev Split out of {transfer}: the 11-field event plus the verify locals
    ///      overflows the EVM stack in a single frame (non-via-IR build).
    function _emitTransferred(uint[37] calldata pub, bytes calldata kemCiphertext) private {
        uint256[4] memory ct0 = [pub[2], pub[3], pub[4], pub[5]];
        uint256[4] memory ct1 = [pub[6], pub[7], pub[8], pub[9]];
        uint256[16] memory cta;
        for (uint256 i = 0; i < 16; i++) {
            cta[i] = pub[10 + i];
        }
        emit Transferred(
            currentEpoch(),
            [pub[27], pub[28]],
            [pub[32], pub[33]],
            [pub[0], pub[1]],
            ct0,
            ct1,
            cta,
            pub[34],
            root,
            pub[26],
            kemCiphertext
        );
    }

    // --- transfer10 public-signal bases (the index map at the top) ------------
    // Named because the arity-10 vector is four 10-wide runs plus two 40/64-wide
    // ciphertext runs, and a bare `pub[118 + i]` says nothing about which run it
    // indexes. Constants live in bytecode, not storage — no upgrade impact.
    uint256 public constant TRANSFER10_ARITY = 10;
    uint256 private constant T10_RECEIVER_CT = 2; // cipherTexts[10][4] -> 40 elements
    uint256 private constant T10_AUTHORITY_CT = 42; // cipherTextAuthority[64]
    uint256 private constant T10_KEM_BINDING = 106;
    uint256 private constant T10_NULLIFIER = 107; // nullifiers[10]
    uint256 private constant T10_ROOT = 117;
    uint256 private constant T10_ENABLED = 118; // enabled[10] (contract-derived)
    uint256 private constant T10_OUTPUT_COMMITMENT = 128; // outputCommitments[10]
    uint256 private constant T10_NONCE = 138;
    uint256 private constant T10_AUTHORITY_KEY = 139; // authorityPublicKey[2]

    /// @notice transfer10 (10-in / 10-out): permissionless, and the SAME rules as
    ///         {transfer} at arity 10 — contract-derived
    ///         `enabled[i] = (nullifier[i] != 0)`, the arbiter key injected from
    ///         storage, an any-historical-root membership check, all ten
    ///         nullifiers spent and all ten outputs appended.
    ///
    ///         The circuit does NOT check that the ten nullifiers are DISTINCT
    ///         (it never did at arity 2 either), so in-transaction double-spend
    ///         safety rests entirely on {_spendNullifier} being run over every
    ///         slot in order: the duplicate hits an already-marked nullifier and
    ///         reverts `NullifierAlreadyUsed`. Skipping even one slot would let a
    ///         single note be spent ten times in one call.
    ///
    ///         There is no ciphertext ARGUMENT to length-check the way
    ///         {disburseWithCiphertexts} has one: like {transfer}, transfer10's
    ///         receiver ciphertexts (40 elements) and authority envelope (64)
    ///         ride INSIDE the public-signal vector, so the fixed `uint[141]`
    ///         calldata type and the verifier itself bind them — strictly
    ///         stronger than a length rule on free calldata. The one free
    ///         argument, `kemCiphertext`, is length-checked like every other op.
    function transfer10(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[141] calldata pub,
        bytes calldata kemCiphertext
    ) external whenInitialized nonReentrant {
        _checkKemCiphertext(kemCiphertext);
        if (!knownRoots[pub[T10_ROOT]]) revert UnknownRoot(pub[T10_ROOT]);

        uint[141] memory injected = pub;
        for (uint256 i = 0; i < TRANSFER10_ARITY; i++) {
            injected[T10_ENABLED + i] = pub[T10_NULLIFIER + i] != 0 ? 1 : 0;
        }
        (injected[T10_AUTHORITY_KEY], injected[T10_AUTHORITY_KEY + 1]) = currentArbiterKey();
        if (!transfer10Verifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        // Sequential and complete: the second occurrence of a repeated nullifier
        // reverts here (see the note above). Padded slots carry 0 and are skipped.
        for (uint256 i = 0; i < TRANSFER10_ARITY; i++) {
            _spendNullifier(pub[T10_NULLIFIER + i]);
        }

        for (uint256 i = 0; i < TRANSFER10_ARITY; i++) {
            uint256 oc = pub[T10_OUTPUT_COMMITMENT + i];
            // A zero output commitment is a non-note (self-burn foot-gun); never
            // append it. An UNUSED transfer10 output slot is still a real note —
            // a value-0 note with a salt — so its commitment is nonzero too.
            if (oc == 0) revert ZeroOutputCommitment();
            _appendLeaf(oc);
        }

        _emitTransferred10(pub, kemCiphertext);
    }

    /// @dev Split out of {transfer10} for the same reason as {_emitTransferred}:
    ///      the 10-field event plus the verify locals overflows the EVM stack in
    ///      a single frame (non-via-IR build).
    function _emitTransferred10(uint[141] calldata pub, bytes calldata kemCiphertext) private {
        uint256[10] memory nfs;
        uint256[10] memory ocs;
        for (uint256 i = 0; i < TRANSFER10_ARITY; i++) {
            nfs[i] = pub[T10_NULLIFIER + i];
            ocs[i] = pub[T10_OUTPUT_COMMITMENT + i];
        }
        uint256[40] memory rct;
        for (uint256 i = 0; i < 40; i++) rct[i] = pub[T10_RECEIVER_CT + i];
        uint256[64] memory cta;
        for (uint256 i = 0; i < 64; i++) cta[i] = pub[T10_AUTHORITY_CT + i];
        emit Transferred10(
            currentEpoch(),
            nfs,
            ocs,
            [pub[0], pub[1]],
            rct,
            cta,
            pub[T10_NONCE],
            root,
            pub[T10_KEM_BINDING],
            kemCiphertext
        );
    }

    // --- transfer10x2 public-signal bases (the index map at the top) ----------
    // Named for the same reason as the T10_* set: a bare `pub[53 + i]` says
    // nothing about which run it indexes. Constants live in bytecode, not
    // storage — no upgrade impact.
    uint256 private constant T10X2_RECEIVER_CT = 2; // cipherTexts[2][4] -> 8 elements
    uint256 private constant T10X2_AUTHORITY_CT = 10; // cipherTextAuthority[31]
    uint256 private constant T10X2_KEM_BINDING = 41;
    uint256 private constant T10X2_NULLIFIER = 42; // nullifiers[10]
    uint256 private constant T10X2_ROOT = 52;
    uint256 private constant T10X2_ENABLED = 53; // enabled[10] (contract-derived)
    uint256 private constant T10X2_OUTPUT_COMMITMENT = 63; // outputCommitments[2]
    uint256 private constant T10X2_NONCE = 65;
    uint256 private constant T10X2_AUTHORITY_KEY = 66; // authorityPublicKey[2]

    /// @notice transfer10x2 (10-in / 2-out): permissionless, and the SAME rules
    ///         as {transfer10} — contract-derived `enabled[i] = (nullifier[i] != 0)`,
    ///         the arbiter key injected from storage, an any-historical-root
    ///         membership check, all ten nullifiers spent — but only TWO outputs
    ///         appended (payment + change, or merged note + zero change), which
    ///         is the whole point: an output is a depth-32 IMT append, and
    ///         transfer10 pays for eight zero-value pads this arity sheds.
    ///
    ///         The circuit does NOT check that the ten nullifiers are DISTINCT
    ///         (no arity of this base does), so in-transaction double-spend
    ///         safety rests entirely on {_spendNullifier} being run over every
    ///         slot in order — same defense, same test vector as {transfer10}.
    ///
    ///         Like {transfer10}, there is no ciphertext ARGUMENT to
    ///         length-check: the 8 receiver elements and 31-element authority
    ///         envelope ride INSIDE the fixed `uint[68]` the verifier binds.
    ///         The one free argument, `kemCiphertext`, is length-checked like
    ///         every other op.
    function transfer10x2(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[68] calldata pub,
        bytes calldata kemCiphertext
    ) external whenInitialized nonReentrant {
        _checkKemCiphertext(kemCiphertext);
        if (!knownRoots[pub[T10X2_ROOT]]) revert UnknownRoot(pub[T10X2_ROOT]);

        uint[68] memory injected = pub;
        for (uint256 i = 0; i < TRANSFER10_ARITY; i++) {
            injected[T10X2_ENABLED + i] = pub[T10X2_NULLIFIER + i] != 0 ? 1 : 0;
        }
        (injected[T10X2_AUTHORITY_KEY], injected[T10X2_AUTHORITY_KEY + 1]) = currentArbiterKey();
        if (!transfer10x2Verifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        // Sequential and complete: the second occurrence of a repeated nullifier
        // reverts here (see the note above). Padded slots carry 0 and are skipped.
        for (uint256 i = 0; i < TRANSFER10_ARITY; i++) {
            _spendNullifier(pub[T10X2_NULLIFIER + i]);
        }

        for (uint256 i = 0; i < 2; i++) {
            uint256 oc = pub[T10X2_OUTPUT_COMMITMENT + i];
            // A zero output commitment is a non-note (self-burn foot-gun); never
            // append it. An UNUSED output slot is still a real note — a value-0
            // note with a salt — so its commitment is nonzero too.
            if (oc == 0) revert ZeroOutputCommitment();
            _appendLeaf(oc);
        }

        _emitTransferred10x2(pub, kemCiphertext);
    }

    /// @dev Split out of {transfer10x2} for the same reason as {_emitTransferred}:
    ///      the 10-field event plus the verify locals overflows the EVM stack in
    ///      a single frame (non-via-IR build).
    function _emitTransferred10x2(uint[68] calldata pub, bytes calldata kemCiphertext) private {
        uint256[10] memory nfs;
        for (uint256 i = 0; i < TRANSFER10_ARITY; i++) {
            nfs[i] = pub[T10X2_NULLIFIER + i];
        }
        uint256[8] memory rct;
        for (uint256 i = 0; i < 8; i++) rct[i] = pub[T10X2_RECEIVER_CT + i];
        uint256[31] memory cta;
        for (uint256 i = 0; i < 31; i++) cta[i] = pub[T10X2_AUTHORITY_CT + i];
        emit Transferred10x2(
            currentEpoch(),
            nfs,
            [pub[T10X2_OUTPUT_COMMITMENT], pub[T10X2_OUTPUT_COMMITMENT + 1]],
            [pub[0], pub[1]],
            rct,
            cta,
            pub[T10X2_NONCE],
            root,
            pub[T10X2_KEM_BINDING],
            kemCiphertext
        );
    }

    /// @notice withdraw (2-in / 1-out): permissionless — and RELAYABLE: the
    ///         tokens go to the proof-bound `pub[26]` recipient, never to
    ///         msg.sender, so anyone may submit a withdraw without being able
    ///         to redirect it (stealth exits ride a relayer so the recipient's
    ///         own wallet never appears on-chain). Contract injects
    ///         enabled[i]=(nullifier[i]!=0) (§5.2) AND the stored arbiter key into
    ///         the authority envelope (§6b v2 — a withdraw not encrypted to the
    ///         current arbiter key FAILS), spends the real nullifiers, appends the
    ///         change output, pushes `out` tokens to the recipient.
    ///         `stealthEphemeralPub`/`stealthViewTag` are the recipient-discovery
    ///         announcement (zero when withdrawing to a plainly-known address);
    ///         they are event-carried, not proof-bound — see the event comment.
    function withdraw(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[27] calldata pub,
        bytes calldata kemCiphertext,
        bytes32 stealthEphemeralPub,
        uint8 stealthViewTag
    ) external whenInitialized nonReentrant {
        _checkKemCiphertext(kemCiphertext);
        if (!knownRoots[pub[19]]) revert UnknownRoot(pub[19]);
        // The payout address must be a real uint160 image: the circuit binds the
        // field element but cannot range-check an address, and truncating here
        // would let two field values alias one address (payout confusion).
        if (pub[26] == 0 || pub[26] > type(uint160).max) revert InvalidRecipient(pub[26]);

        uint[27] memory injected = pub;
        injected[20] = pub[17] != 0 ? 1 : 0;
        injected[21] = pub[18] != 0 ? 1 : 0;
        (injected[24], injected[25]) = currentArbiterKey();
        if (!withdrawVerifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        _spendNullifier(pub[17]);
        _spendNullifier(pub[18]);

        uint256 change = pub[22];
        // A zero output commitment is a non-note (self-burn foot-gun); never append it.
        if (change == 0) revert ZeroOutputCommitment();
        _appendLeaf(change);

        _emitWithdrawn(pub, kemCiphertext, stealthEphemeralPub, stealthViewTag);
        token.safeTransfer(address(uint160(pub[26])), pub[0]);
    }

    /// @dev Both withdraw emits in their own frame: the widened signature (two
    ///      announcement params on top of the proof args) leaves the main body
    ///      no stack headroom for the 10-argument Withdrawn emit under non-IR
    ///      solc. `pub[22]` is the change commitment (nonzero — guarded before
    ///      this runs).
    function _emitWithdrawn(
        uint[27] calldata pub,
        bytes calldata kemCiphertext,
        bytes32 stealthEphemeralPub,
        uint8 stealthViewTag
    ) private {
        uint256[13] memory cta;
        for (uint256 i = 0; i < 13; i++) cta[i] = pub[3 + i];
        emit Withdrawn(
            currentEpoch(), [pub[17], pub[18]], pub[0], pub[22], [pub[1], pub[2]], cta, pub[23], root, pub[16], kemCiphertext
        );
        emit WithdrawAnnouncement(pub[26], stealthEphemeralPub, stealthViewTag);
    }

    // ==========================================================================
    //                        OP-MODULE LAYER (OPMOD §1)
    // ==========================================================================
    // The core's module-only external surface. The six enterprise entrypoints
    // above are byte-untouched and never route through applyOp; a consumer op
    // family ships as a plain (non-proxied) module contract that checks its
    // own Groth16 proof, arranges its public-signal layout, and calls one
    // applyOp* per user op. The core re-derives NOTHING from proofs — it
    // enforces the OPMOD §1.3 invariant list on whatever a REGISTERED module
    // passes, which is why registration is onlyOwner and upgrade-equivalent
    // power (a hostile module is a hostile implementation).

    /// @notice The tree/nullifier effects of one op (OPMOD §1.2), copied by
    ///         the MODULE out of the public-signal vector its verifier
    ///         accepted — the core never sees the proof itself.
    struct OpEffects {
        /// Membership root the proof was made against. MUST be a known root
        /// when `nullifiers` is non-empty; MUST be 0 when it is empty (a
        /// rootless mint may not smuggle a root claim).
        uint256 root;
        /// Nullifiers to spend. Every entry MUST be nonzero and unused —
        /// modules strip padded (zero) slots before calling; unlike
        /// {_spendNullifier}, the core does NOT skip zeros here.
        uint256[] nullifiers;
        /// Output commitments to append as single leaves, in order. Every
        /// entry MUST be nonzero. MUST be empty when subtreeRoot != 0.
        uint256[] leaves;
        /// Nonzero => attach ONE B-leaf subtree at level LOG_B instead of
        /// appending leaves (the disburse shape). Zero => single-leaf appends.
        uint256 subtreeRoot;
    }

    /// @dev The whole applyOp access story: users never call applyOp*; they
    ///      call a module, and the module is msg.sender here.
    modifier onlyRegisteredModule() {
        if (!registeredModules[msg.sender]) revert ModuleNotRegistered(msg.sender);
        _;
    }

    /// @notice Register `module` as an applyOp* caller. Upgrade-equivalent
    ///         power (OPMOD §1.3 #6): a registered module can spend any
    ///         approval made to the core and mint into the shared tree, so the
    ///         trust boundary is the owner key, same as {_authorizeUpgrade}.
    ///         Reverts on a no-op re-register: the ModuleRegistered/
    ///         ModuleRemoved event stream is the canonical registry
    ///         reconstruction source, so it must stay a balanced add/remove
    ///         log — never spurious.
    function registerModule(address module) external onlyOwner whenInitialized {
        if (module == address(0)) revert ZeroModule();
        if (registeredModules[module]) revert ModuleAlreadyRegistered(module);
        registeredModules[module] = true;
        emit ModuleRegistered(module);
    }

    /// @notice Deregister `module`, effective immediately. Strands nothing:
    ///         notes are untyped, and a pending user tx re-proves against a
    ///         replacement module unchanged (proofs bind no module address).
    ///         Reverts when `module` is not registered, for the same reason
    ///         {registerModule} rejects a re-register: the event stream is the
    ///         canonical registry reconstruction source and must stay a
    ///         balanced add/remove log — never spurious.
    function removeModule(address module) external onlyOwner whenInitialized {
        if (!registeredModules[module]) revert ModuleNotRegistered(module);
        registeredModules[module] = false;
        emit ModuleRemoved(module);
    }

    /// @notice Apply one op's tree/nullifier effects with NO escrow motion.
    ///         Returns the leaf index of the first appended leaf (or the batch
    ///         start for a subtree attach) — modules need it for their events.
    function applyOp(OpEffects calldata fx)
        external
        whenInitialized
        nonReentrant
        onlyRegisteredModule
        returns (uint256 startLeafIndex)
    {
        return _applyOp(fx);
    }

    /// @notice {applyOp} + pull exactly `amount` from `from` (the deposit
    ///         shape). CEI: the pull runs AFTER all tree/nullifier writes,
    ///         mirroring {deposit}. That `amount` equals the module's
    ///         proof-bound public is a module obligation reviewed at
    ///         registration — the core never sees the proof.
    function applyOpWithPull(OpEffects calldata fx, address from, uint256 amount)
        external
        whenInitialized
        nonReentrant
        onlyRegisteredModule
        returns (uint256 startLeafIndex)
    {
        startLeafIndex = _applyOp(fx);
        token.safeTransferFrom(from, address(this), amount);
    }

    /// @notice {applyOp} + push exactly `amount` to `to` (the withdraw shape).
    ///         CEI as above; the module has already range-checked the
    ///         proof-bound recipient the way {withdraw} does.
    function applyOpWithPush(OpEffects calldata fx, address to, uint256 amount)
        external
        whenInitialized
        nonReentrant
        onlyRegisteredModule
        returns (uint256 startLeafIndex)
    {
        if (to == address(0)) revert InvalidRecipient(0);
        startLeafIndex = _applyOp(fx);
        token.safeTransfer(to, amount);
    }

    /// @dev The OPMOD §1.3 invariant gate, in execution order: known-root iff
    ///      nullifiers present (a mint claims no membership); every nullifier
    ///      nonzero + unused, marked sequentially and completely (an in-tx
    ///      duplicate reverts on its second occurrence); shape exclusivity
    ///      (subtree attach XOR single-leaf appends); every leaf nonzero.
    ///      {_appendLeaf}/{_attachSubtree} keep the Appended/SubtreeAppended
    ///      feed identical to the in-core ops' — the indexer is family-blind.
    function _applyOp(OpEffects calldata fx) private returns (uint256 startLeafIndex) {
        // A zero-effect op (no nullifiers, no leaves, no subtree) has no
        // legitimate module use and would emit an ambiguous OpApplied.
        if (fx.nullifiers.length == 0 && fx.leaves.length == 0 && fx.subtreeRoot == 0) revert EmptyOp();
        if (fx.nullifiers.length > 0) {
            if (!knownRoots[fx.root]) revert UnknownRoot(fx.root);
        } else if (fx.root != 0) {
            revert UnknownRoot(fx.root);
        }

        for (uint256 i = 0; i < fx.nullifiers.length; i++) {
            uint256 nf = fx.nullifiers[i];
            if (nf == 0) revert ZeroNullifier();
            if (nullifierUsed[nf]) revert NullifierAlreadyUsed(nf);
            nullifierUsed[nf] = true;
        }

        if (fx.subtreeRoot != 0) {
            if (fx.leaves.length != 0) revert MixedAppendShape();
            startLeafIndex = _attachSubtree(fx.subtreeRoot);
            emit SubtreeAppended(startLeafIndex, fx.subtreeRoot, root);
        } else {
            startLeafIndex = nextLeafIndex;
            for (uint256 i = 0; i < fx.leaves.length; i++) {
                if (fx.leaves[i] == 0) revert ZeroOutputCommitment();
                _appendLeaf(fx.leaves[i]);
            }
        }

        emit OpApplied(msg.sender, startLeafIndex, fx.nullifiers.length, fx.leaves.length, fx.subtreeRoot, root);
    }

    // ==========================================================================
    //                              IMT INTERNALS
    // ==========================================================================

    /// @dev Mark a nullifier used; a zero nullifier is a padded/disabled input
    ///      (enabled injected to 0) and is skipped, never marked.
    function _spendNullifier(uint256 nf) private {
        if (nf == 0) return;
        if (nullifierUsed[nf]) revert NullifierAlreadyUsed(nf);
        nullifierUsed[nf] = true;
    }

    /// @dev Standard Tornado single-leaf insert at nextLeafIndex — byte-identical
    ///      to ImtTree._insertNode(node, 0). Emits Appended for the differential
    ///      test + the indexer.
    function _appendLeaf(uint256 leaf) private {
        uint256 index = nextLeafIndex;
        _insertNode(leaf, 0);
        knownRoots[root] = true;
        emit Appended(index, leaf, root);
    }

    /// @dev disburse batch attach — ImtTree.attachSubtree: close the pending
    ///      partial block up to a B boundary with dead zero leaves, then attach
    ///      subtreeRoot at level LOG_B.
    ///
    ///      The close is done in O(LOG_B) folds, NOT O(B) individual zero-leaf
    ///      inserts: at B=256 the naive loop pads up to 255 leaves x 32 hashes
    ///      (~248M gas, over any block limit), so a disburse right after a deposit
    ///      would be unexecutable on-chain. Instead we compute the partial block's
    ///      level-LOG_B node treating positions rem..B-1 as zeros — bit i of rem
    ///      selects the real left sibling filledSubtrees[i] (when the path node is a
    ///      right child) or an empty right sibling zeros[i]. Root-identical to
    ///      padding one leaf at a time (the differential test pins contract==oracle
    ///      across the interleaved sequence). The sub-LOG_B frontier is left stale,
    ///      which is safe: nextLeafIndex is now B-aligned, so a fresh block
    ///      overwrites filledSubtrees[i] (i<LOG_B) as a left child before any read.
    function _attachSubtree(uint256 subtreeRoot) private returns (uint256 start) {
        uint256 rem = nextLeafIndex % B;
        if (rem != 0) {
            uint256 node = zeros[0];
            for (uint256 i = 0; i < LOG_B; i++) {
                if (((rem >> i) & 1) == 1) {
                    node = poseidon.poseidon([filledSubtrees[i], node]);
                } else {
                    node = poseidon.poseidon([node, zeros[i]]);
                }
            }
            nextLeafIndex -= rem; // back to the B-aligned block start
            _insertNode(node, LOG_B); // place the closed partial block, advance by B
        }
        start = nextLeafIndex;
        _insertNode(subtreeRoot, LOG_B);
        knownRoots[root] = true;
    }

    /// @dev Fold `node` (at level startLevel, position nextLeafIndex/2^startLevel)
    ///      up to the root, updating filledSubtrees + root, then advance
    ///      nextLeafIndex by 2^startLevel. Mirrors ImtTree._insertNode exactly.
    function _insertNode(uint256 node, uint256 startLevel) private {
        uint256 stride = uint256(1) << startLevel;
        if (nextLeafIndex % stride != 0) revert MisalignedInsert();
        if (nextLeafIndex + stride > (uint256(1) << H)) revert TreeFull();

        uint256 currentIndex = nextLeafIndex / stride;
        uint256 current = node;
        for (uint256 i = startLevel; i < H; i++) {
            uint256 left;
            uint256 right;
            if (currentIndex % 2 == 0) {
                left = current;
                right = zeros[i];
                filledSubtrees[i] = current;
            } else {
                left = filledSubtrees[i];
                right = current;
            }
            current = poseidon.poseidon([left, right]);
            currentIndex = currentIndex / 2;
        }
        root = current;
        nextLeafIndex += stride;
    }

    // --- tail slots -----------------------------------------------------------
    // Everything below sits AFTER every slot declared above, taking words off the
    // trailing __gap. That is the pool's standing storage rule under the UUPS
    // proxy: state is only ever APPENDED at the tail, never inserted next to a
    // logically-related slot, because an insert re-strides every slot below it
    // and would silently move a live pool's IMT root, nullifier set and arbiter
    // epochs when the implementation is swapped. Read the grouping as chronology,
    // not as topic — {transfer10Verifier} belongs with the other verifiers in
    // meaning and lives here in layout, and both facts are load-bearing.

    // Per-epoch ML-KEM-768 encapsulation-key hash. The 3-word ArbiterEpoch struct
    // is frozen — growing a field would re-stride the dynamic array — so the hash
    // lives in a sibling mapping keyed by epoch (design doc §4). keccak256 of the
    // epoch's 1184-byte encapsulation key; {initialize} and {rotateArbiter} both
    // refuse a zero, so a zero here can only mean "epoch never minted".
    mapping(uint256 => bytes32) public arbiterKemPkHash;

    // The 10-in/10-out {transfer10} verifier, wired by {initialize}.
    ITransfer10Verifier public transfer10Verifier;

    // The 10-in/2-out {transfer10x2} verifier, wired by {initialize}.
    ITransfer10x2Verifier public transfer10x2Verifier;

    /// OPMOD §1.4: the module registry. True => the address may call applyOp*.
    /// Registration is onlyOwner and upgrade-equivalent power. One mapping, one
    /// word — module addresses are recoverable from ModuleRegistered/
    /// ModuleRemoved events, so no enumerable array.
    mapping(address => bool) public registeredModules;

    /// @dev Reserved trailing storage so a future implementation can add state
    ///      without colliding with any slot introduced here (upgrade-safety).
    ///      Shrink it by exactly one word for each word appended above.
    uint256[46] private __gap;
}
