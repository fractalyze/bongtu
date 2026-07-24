// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

import {IPoseidon2} from "./interfaces/IPoseidon2.sol";
import {IDepositVerifier, IWithdrawVerifier, IDisburseVerifier, ITransferVerifier} from "./interfaces/IVerifiers.sol";
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
/// `sdk/src/imt.ts` — the Foundry differential test asserts `root() ==
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

    // --- disburse access control (caller-gated, §5.3) -------------------------
    mapping(address => bool) public disburseAllowed;

    // --- public-signal indices (derived from out/<name>.public.json + .sym) ----
    // deposit  (18): [0]=out [1..2]=ecdhPub [3..12]=cipherTextAuthority[10]
    //                [13..14]=oc [15]=nonce [16..17]=authorityPubKey
    // withdraw (25): [0]=out [1..2]=ecdhPub [3..15]=cipherTextAuthority[13]
    //                [16..17]=nf [18]=root [19..20]=enabled [21]=oc0(change)
    //                [22]=nonce [23..24]=authorityPubKey
    // disburse (10): [0..1]=ecdhPub [2]=disclosureHash [3]=subtreeRoot [4]=nf
    //                [5]=root [6]=enabled [7]=nonce [8..9]=authorityPubKey
    // transfer (36): [0..1]=ecdhPub [2..9]=cipherTexts[2][4]
    //                [10..25]=cipherTextAuthority[16] [26..27]=nf [28]=root
    //                [29..30]=enabled [31..32]=oc [33]=nonce [34..35]=authorityPubKey

    // --- events (all ciphertext copied from verified publicSignals) -----------
    event Appended(uint256 indexed leafIndex, uint256 leaf, uint256 root);
    event SubtreeAppended(uint256 indexed startLeafIndex, uint256 subtreeRoot, uint256 root);
    // §6b v2: Deposited carries the authority (auditor) envelope so the minted
    // output notes are decryptable from on-chain data alone. ecdhPublicKey +
    // encryptionNonce + encryptedValuesForAuthority are copied from the proof's
    // public signals (the contract injected the arbiter key before verify).
    event Deposited(
        uint256 indexed epoch,
        uint256 firstLeafIndex,
        uint256 oc0,
        uint256 oc1,
        uint256 amount,
        uint256[2] ecdhPublicKey,
        uint256[10] encryptedValuesForAuthority,
        uint256 encryptionNonce,
        uint256 root
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
        uint256 root
    );
    event Disbursed(
        uint256 indexed epoch,
        uint256 nullifier,
        uint256 subtreeRoot,
        uint256 disclosureHash,
        uint256[2] ecdhPublicKey,
        uint256 encryptionNonce,
        uint256 root
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
        uint256 root
    );
    event ArbiterRotated(uint256 indexed epoch, uint256 keyX, uint256 keyY, uint256 activatedBlock);
    event DisburseAllowlist(address indexed account, bool allowed);

    // --- errors ---------------------------------------------------------------
    // (re-init reverts via Initializable.InvalidInitialization, not a local error)
    error NotInitialized();
    error ZeroArbiterKey();
    error UnknownRoot(uint256 root);
    error NullifierAlreadyUsed(uint256 nullifier);
    error ZeroNullifier();
    error InvalidProof();
    error NotDisburseAuthorized(address caller);
    error Reentrancy();
    error BatchSizeNotPowerOfTwo(uint256 batchSize);
    error MisalignedInsert();
    error TreeFull();
    error WrongCiphertextLength(uint256 got, uint256 want);
    error ZeroOutputCommitment();

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

    /// @notice One-shot initializer, run through the ERC-1967 proxy (SPEC §5.2).
    ///         Folds the OLD constructor (Poseidon/verifier/token wiring, the IMT
    ///         zeros ladder + frontier + empty-tree root, B / LOG_B / the enforced
    ///         disburse ciphertext length) AND the OLD `initialize(arbiterKey)`
    ///         (non-zero arbiter key check + arbiter epoch 0) into a single
    ///         run-once call. The `initializer` modifier (ERC-7201 storage)
    ///         enforces run-once; the caller (the deployer, via the proxy) becomes
    ///         owner. REQUIRES a non-zero arbiter key (§5.3, Q9) — kills the (0,0)
    ///         footgun. Not `onlyOwner`: there is no owner until this call sets one.
    function initialize(
        IPoseidon2 _poseidon,
        IDepositVerifier _depositVerifier,
        IWithdrawVerifier _withdrawVerifier,
        IDisburseVerifier _disburseVerifier,
        ITransferVerifier _transferVerifier,
        IERC20 _token,
        uint256 _batchSize,
        uint256[2] calldata arbiterKey
    ) external initializer {
        if (_batchSize <= 1 || (_batchSize & (_batchSize - 1)) != 0) revert BatchSizeNotPowerOfTwo(_batchSize);
        if (arbiterKey[0] == 0 || arbiterKey[1] == 0) revert ZeroArbiterKey();

        __Ownable2Step_init(msg.sender);
        __UUPSUpgradeable_init();

        // Behind a proxy the impl constructor never ran against THIS storage, so
        // the inline `_locked = 1` default did not take — arm the latch here
        // (NOT_ENTERED == 1) or the first nonReentrant op would revert Reentrancy.
        _locked = 1;

        poseidon = _poseidon;
        depositVerifier = _depositVerifier;
        withdrawVerifier = _withdrawVerifier;
        disburseVerifier = _disburseVerifier;
        transferVerifier = _transferVerifier;
        token = _token;
        B = _batchSize;

        // Split out to keep the 8-arg initializer under the stack-depth limit
        // (all former-constructor tree/param derivation lives here).
        _initTreeAndParams(_batchSize);

        // Seed arbiter epoch 0 (§5.3, Q9) and mark the pool live.
        initialized = true;
        arbiterEpochs.push(ArbiterEpoch({keyX: arbiterKey[0], keyY: arbiterKey[1], activatedBlock: block.number}));
        emit ArbiterRotated(0, arbiterKey[0], arbiterKey[1], block.number);
    }

    /// @dev The former-constructor tree + param derivation: LOG_B, the enforced
    ///      disburse ciphertext length, the zeros ladder, the frontier and the
    ///      empty-tree root. Reads the just-wired `poseidon` storage.
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

    /// @notice Append an epoch and emit its index; the arbiter pubkey is read
    ///         from storage at execution (never calldata) so a sender cannot
    ///         encrypt to their own key and silently kill non-repudiation.
    function rotateArbiter(uint256[2] calldata newKey) external onlyOwner whenInitialized {
        if (newKey[0] == 0 || newKey[1] == 0) revert ZeroArbiterKey();
        uint256 e = arbiterEpochs.length;
        arbiterEpochs.push(ArbiterEpoch({keyX: newKey[0], keyY: newKey[1], activatedBlock: block.number}));
        emit ArbiterRotated(e, newKey[0], newKey[1], block.number);
    }

    function currentEpoch() public view returns (uint256) {
        return arbiterEpochs.length - 1;
    }

    function currentArbiterKey() public view returns (uint256 x, uint256 y) {
        ArbiterEpoch storage ep = arbiterEpochs[arbiterEpochs.length - 1];
        return (ep.keyX, ep.keyY);
    }

    function setDisburseAllowed(address account, bool allowed) external onlyOwner {
        disburseAllowed[account] = allowed;
        emit DisburseAllowlist(account, allowed);
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
    function deposit(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[18] calldata pub)
        external
        whenInitialized
        nonReentrant
    {
        uint[18] memory injected = pub;
        (injected[16], injected[17]) = currentArbiterKey();
        if (!depositVerifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        uint256 oc0 = pub[13];
        uint256 oc1 = pub[14];
        // A zero output commitment is a non-note (self-burn foot-gun); never append it.
        if (oc0 == 0 || oc1 == 0) revert ZeroOutputCommitment();

        uint256 first = nextLeafIndex;
        _appendLeaf(oc0);
        _appendLeaf(oc1);

        uint256[10] memory cta;
        for (uint256 i = 0; i < 10; i++) cta[i] = pub[3 + i];
        emit Deposited(currentEpoch(), first, oc0, oc1, pub[0], [pub[1], pub[2]], cta, pub[15], root);
        token.safeTransferFrom(msg.sender, address(this), pub[0]);
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
    ///         caller-gated (§5.3); injects enabled=1 and the arbiter key (§5.2/§5.3).
    function disburseWithCiphertexts(
        uint[2] calldata a,
        uint[2][2] calldata b,
        uint[2] calldata c,
        uint[10] calldata pub,
        uint256[] calldata receiverCiphertexts
    ) external whenInitialized nonReentrant {
        if (receiverCiphertexts.length != disburseCiphertextLen) {
            revert WrongCiphertextLength(receiverCiphertexts.length, disburseCiphertextLen);
        }
        uint256 start = _disburseCore(a, b, c, pub);
        emit DisburseCiphertexts(start, receiverCiphertexts);
    }

    /// @dev disburse verification + subtree attach, shared by both entry points.
    ///      Caller-gated (§5.3); contract injects enabled=1 and the arbiter key
    ///      from storage (§5.2). Returns the batch's start leaf index.
    function _disburseCore(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[10] calldata pub)
        private
        returns (uint256 start)
    {
        if (msg.sender != owner() && !disburseAllowed[msg.sender]) revert NotDisburseAuthorized(msg.sender);
        if (!knownRoots[pub[5]]) revert UnknownRoot(pub[5]);

        uint256 nf = pub[4];
        if (nf == 0) revert ZeroNullifier(); // 1-in disburse is always real
        if (nullifierUsed[nf]) revert NullifierAlreadyUsed(nf);

        // §5.2 contract-derived enabled + §5.3 arbiter-key-from-storage injection.
        // disburse has a single input and reverts above on nf==0, so enabled is
        // unconditionally 1 (membership on the sole input is always required).
        uint[10] memory injected = pub;
        injected[6] = 1;
        (injected[8], injected[9]) = currentArbiterKey();
        if (!disburseVerifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        nullifierUsed[nf] = true;
        start = _attachSubtree(pub[3]);

        emit Disbursed(
            currentEpoch(), nf, pub[3], pub[2], [pub[0], pub[1]], pub[7], root
        );
        emit SubtreeAppended(start, pub[3], root);
    }

    /// @notice transfer (2-in / 2-out): permissionless. Contract injects
    ///         enabled[i]=(nullifier[i]!=0) and the arbiter key from storage,
    ///         spends the real (nonzero) nullifiers, appends the 2 outputs.
    function transfer(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[36] calldata pub)
        external
        whenInitialized
        nonReentrant
    {
        if (!knownRoots[pub[28]]) revert UnknownRoot(pub[28]);

        uint[36] memory injected = pub;
        injected[29] = pub[26] != 0 ? 1 : 0;
        injected[30] = pub[27] != 0 ? 1 : 0;
        (injected[34], injected[35]) = currentArbiterKey();
        if (!transferVerifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        _spendNullifier(pub[26]);
        _spendNullifier(pub[27]);

        // A zero output commitment is a non-note (self-burn foot-gun); never append it.
        if (pub[31] == 0 || pub[32] == 0) revert ZeroOutputCommitment();
        _appendLeaf(pub[31]);
        _appendLeaf(pub[32]);

        uint256[4] memory ct0 = [pub[2], pub[3], pub[4], pub[5]];
        uint256[4] memory ct1 = [pub[6], pub[7], pub[8], pub[9]];
        uint256[16] memory cta;
        for (uint256 i = 0; i < 16; i++) {
            cta[i] = pub[10 + i];
        }
        emit Transferred(
            currentEpoch(),
            [pub[26], pub[27]],
            [pub[31], pub[32]],
            [pub[0], pub[1]],
            ct0,
            ct1,
            cta,
            pub[33],
            root
        );
    }

    /// @notice withdraw (2-in / 1-out): permissionless. Contract injects
    ///         enabled[i]=(nullifier[i]!=0) (§5.2) AND the stored arbiter key into
    ///         the authority envelope (§6b v2 — a withdraw not encrypted to the
    ///         current arbiter key FAILS), spends the real nullifiers, appends the
    ///         change output, pushes `out` tokens.
    function withdraw(uint[2] calldata a, uint[2][2] calldata b, uint[2] calldata c, uint[25] calldata pub)
        external
        whenInitialized
        nonReentrant
    {
        if (!knownRoots[pub[18]]) revert UnknownRoot(pub[18]);

        uint[25] memory injected = pub;
        injected[19] = pub[16] != 0 ? 1 : 0;
        injected[20] = pub[17] != 0 ? 1 : 0;
        (injected[23], injected[24]) = currentArbiterKey();
        if (!withdrawVerifier.verifyProof(a, b, c, injected)) revert InvalidProof();

        _spendNullifier(pub[16]);
        _spendNullifier(pub[17]);

        uint256 change = pub[21];
        // A zero output commitment is a non-note (self-burn foot-gun); never append it.
        if (change == 0) revert ZeroOutputCommitment();
        _appendLeaf(change);

        uint256[13] memory cta;
        for (uint256 i = 0; i < 13; i++) cta[i] = pub[3 + i];
        emit Withdrawn(currentEpoch(), [pub[16], pub[17]], pub[0], change, [pub[1], pub[2]], cta, pub[22], root);
        token.safeTransfer(msg.sender, pub[0]);
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

    /// @dev Reserved trailing storage so a future BongtuPoolV2 can add state
    ///      without colliding with any slot introduced here (upgrade-safety).
    uint256[50] private __gap;
}
