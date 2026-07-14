// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/Bns.sol";

/// Minimal subset of the Foundry cheatcode interface so the §1 suites stay
/// dependency-free (no forge-std checkout required on CI). The cheatcode
/// precompile lives at the well-known hevm address.
interface Vm {
    struct Log {
        bytes32[] topics;
        bytes data;
        address emitter;
    }

    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function warp(uint256) external;
    function chainId(uint256) external;
    function expectRevert() external;
    function expectRevert(bytes4) external;
    function expectRevert(bytes calldata) external;
    /// Matches only the 4-byte selector — use for errors that carry args.
    function expectPartialRevert(bytes4) external;
    function expectEmit(bool, bool, bool, bool) external;
    function expectEmit(bool, bool, bool, bool, address) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
    function label(address, string calldata) external;
    function snapshotState() external returns (uint256);
    function revertToState(uint256) external returns (bool);
    function assume(bool) external pure;
}

/// Shared fixtures + builders for the BNS contract test suites. Concrete suites
/// inherit this and add `test*` functions.
contract BnsTestBase {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    Bns internal bns;

    /// Reusable owner-doc body + its pre-hashed ref (built in setUp so no
    /// sha256 precompile call happens inside a pranked/expectRevert section).
    bytes internal constant DOC_OWNER_BODY = "{\"id\":\"did:bns:x\"}";
    DocumentRef internal ownerRef;

    bytes32 internal constant ZERO = bytes32(0);
    bytes32 internal constant KID =
        0x6d61696e00000000000000000000000000000000000000000000000000000000; // "main"
    bytes32 internal constant KID2 =
        0x6d61696e32000000000000000000000000000000000000000000000000000000; // "main2"
    bytes32 internal constant STORAGE_INLINE =
        0x696e6c696e650000000000000000000000000000000000000000000000000000; // "inline"
    bytes32 internal constant STORAGE_IPFS =
        0x6970667300000000000000000000000000000000000000000000000000000000; // "ipfs" (non-inline)
    bytes32 internal constant METHOD_EIP155_ACCOUNT =
        0x6569703135352d6163636f756e74000000000000000000000000000000000000; // "eip155-account"

    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);
    address internal constant CAROL = address(0xCA401);
    address internal constant CTRL = address(0xC0417401);
    address internal constant CTRL2 = address(0xC0417402);

    // --- Redeclared events so suites can `emit` them for vm.expectEmit matching.
    event ProtocolEvent(
        uint64 indexed seq,
        bytes32 indexed eventType,
        address indexed actor,
        bytes32 previousLogRoot,
        bytes32 logRoot
    );
    event NameRegistered(
        bytes32 indexed nameHash,
        string name,
        address indexed assetOwner,
        address indexed actor,
        uint64 expireAt,
        uint64 lineageEpoch,
        uint64 nameSeq
    );
    event NameRenewed(
        bytes32 indexed nameHash, string name, address indexed actor, uint64 expireAt, uint64 nameSeq
    );
    event NameAssetTransferred(
        bytes32 indexed nameHash,
        string name,
        address indexed oldAssetOwner,
        address indexed newAssetOwner,
        bool standardTransfer,
        uint64 nameSeq
    );
    event NameOwnerUpdated(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        PrincipalKind ownerKind,
        bytes ownerValue,
        OwnerSource ownerSource,
        bool standardTransferEnabled,
        uint64 nameSeq
    );
    event AuthorityKeysUpdated(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        uint64 authoritySeq,
        bytes32 authorityRoot
    );
    event NameReleased(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        ReleaseMode mode,
        bytes32 reasonHash,
        uint64 nameSeq
    );
    event DocumentPublished(
        bytes32 indexed nameHash,
        string name,
        string docType,
        uint64 indexed version,
        address indexed actor,
        bytes32 contentHash,
        bytes32 documentStateHash
    );
    event DocumentRevoked(
        bytes32 indexed nameHash,
        string name,
        string docType,
        address indexed actor,
        uint64 previousVersion,
        uint64 newVersion,
        bytes32 reasonHash
    );
    event OwnerDocumentIatFloorUpdated(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        uint64 previousMinDocumentIat,
        uint64 newMinDocumentIat,
        uint64 ownerPolicySeq,
        uint64 nameSeq,
        bytes32 reasonHash
    );
    event ControllerPolicyUpdated(
        bytes32 indexed nameHash, string name, address indexed actor, bytes32 policyHash, uint64 nameSeq
    );
    event NamespacePolicyUpdated(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        bool allowDelegatedSubnames,
        bytes32 namespacePolicyHash,
        uint64 nameSeq
    );
    event DidAliasSet(
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        string targetDid,
        AliasKind kind,
        bytes32 proofHash,
        uint64 nameSeq
    );
    event PaymentTargetUpdated(
        bytes32 indexed nameHash,
        string name,
        string docType,
        address indexed actor,
        address paymentTarget,
        bytes32 paymentPolicyHash,
        uint64 version
    );
    event LogCheckpointPublished(
        bytes32 indexed logRoot,
        address indexed actor,
        uint64 lastSeq,
        uint64 issuedAt,
        bytes32 externalAnchor
    );

    function setUp() public virtual {
        bns = new Bns();
        ownerRef = _inlineDoc(DOC_OWNER_BODY);
    }

    // --- assertion helpers (forge-std-free) -------------------------------

    function assertTrue(bool cond, string memory reason) internal pure {
        require(cond, reason);
    }

    function assertEqUint(uint256 a, uint256 b, string memory reason) internal pure {
        require(a == b, reason);
    }

    function assertEqBytes32(bytes32 a, bytes32 b, string memory reason) internal pure {
        require(a == b, reason);
    }

    // --- principal / authority builders -----------------------------------

    function _unset() internal pure returns (Principal memory) {
        return Principal({ kind: PrincipalKind.Unset, value: "" });
    }

    function _chain(address account) internal pure returns (Principal memory) {
        return Principal({ kind: PrincipalKind.ChainAccount, value: abi.encodePacked(account) });
    }

    function _bnsName(string memory name) internal pure returns (Principal memory) {
        return Principal({ kind: PrincipalKind.BnsName, value: bytes(name) });
    }

    function _ownerAuth(address owner) internal pure returns (CallAuthority memory) {
        return CallAuthority({ role: AuthorityRole.Owner, actor: _chain(owner), kid: ZERO });
    }

    function _ownerAuthName(string memory name, bytes32 kid)
        internal
        pure
        returns (CallAuthority memory)
    {
        return CallAuthority({ role: AuthorityRole.Owner, actor: _bnsName(name), kid: kid });
    }

    function _controllerAuth(address controller) internal pure returns (CallAuthority memory) {
        return CallAuthority({ role: AuthorityRole.Controller, actor: _chain(controller), kid: ZERO });
    }

    function _noneAuth() internal pure returns (CallAuthority memory) {
        return CallAuthority({ role: AuthorityRole.None, actor: _unset(), kid: ZERO });
    }

    function _guard(uint64 nameSeq) internal pure returns (MutationGuard memory) {
        return MutationGuard({ expectedNameSeq: nameSeq, expectedParentNameSeq: 0 });
    }

    function _guard(uint64 nameSeq, uint64 parentSeq) internal pure returns (MutationGuard memory) {
        return MutationGuard({ expectedNameSeq: nameSeq, expectedParentNameSeq: parentSeq });
    }

    function _noOwnerPolicyUpdate() internal pure returns (OwnerPolicyUpdate memory) {
        return OwnerPolicyUpdate({
            updateMinDocumentIat: false,
            minDocumentIat: 0,
            reasonHash: ZERO
        });
    }

    // --- document builders -------------------------------------------------

    function _inlineDoc(bytes memory body) internal pure returns (DocumentRef memory) {
        return DocumentRef({
            storageType: STORAGE_INLINE,
            uri: "",
            inlineDocument: body,
            contentHash: sha256(body),
            schema: ZERO,
            codec: ZERO,
            extraHash: ZERO
        });
    }

    function _refDoc(string memory uri, bytes32 contentHash) internal pure returns (DocumentRef memory) {
        return DocumentRef({
            storageType: STORAGE_IPFS,
            uri: uri,
            inlineDocument: "",
            contentHash: contentHash,
            schema: ZERO,
            codec: ZERO,
            extraHash: ZERO
        });
    }

    function _defaultOptions(Principal memory semanticOwner)
        internal
        pure
        returns (RegisterOptions memory)
    {
        return RegisterOptions({
            duration: 365 days,
            gracePeriod: 30 days,
            renewable: true,
            transferable: true,
            initialSemanticOwner: semanticOwner,
            allowDelegatedSubnames: true,
            initialPaymentTarget: address(0),
            initialPaymentPolicyHash: ZERO,
            initialNamespacePolicyHash: ZERO
        });
    }

    function _options(uint64 duration, uint64 gracePeriod, bool renewable, bool transferable)
        internal
        pure
        returns (RegisterOptions memory)
    {
        return RegisterOptions({
            duration: duration,
            gracePeriod: gracePeriod,
            renewable: renewable,
            transferable: transferable,
            initialSemanticOwner: _unset(),
            allowDelegatedSubnames: true,
            initialPaymentTarget: address(0),
            initialPaymentPolicyHash: ZERO,
            initialNamespacePolicyHash: ZERO
        });
    }

    // --- common flows ------------------------------------------------------

    function _registerName(
        string memory name,
        address owner,
        RegisterOptions memory options,
        DocumentUpdate[] memory initialDocuments,
        CallAuthority memory authority,
        MutationGuard memory guard
    ) internal returns (uint64) {
        AuthorityKeyUpdate[] memory noKeys = new AuthorityKeyUpdate[](0);
        ControllerRule[] memory noRules = new ControllerRule[](0);
        (uint64 nameSeq,,) = bns.registerName(
            name, owner, options, noKeys, _unset(), noRules, ZERO, initialDocuments, authority, guard
        );
        return nameSeq;
    }

    /// Register a root name (asset-owner fallback ownership). Root registration
    /// is permissionless (authority must be None), so the caller doesn't matter.
    function _registerRoot(string memory name, address owner) internal returns (uint64) {
        DocumentUpdate[] memory emptyDocs = new DocumentUpdate[](0);
        return _registerName(
            name, owner, _defaultOptions(_unset()), emptyDocs, _noneAuth(), _guard(0)
        );
    }

    /// Publish a document via the full external entrypoint, using the current
    /// msg.sender (prank before calling to drive a specific signer).
    ///
    /// IMPORTANT: the `DocumentRef` must be built BEFORE any `vm.prank` /
    /// `vm.expectRevert`, because `_inlineDoc` runs `sha256` — a precompile
    /// *call* that would otherwise consume the single-shot cheatcode.
    function _publishDoc(
        string memory name,
        string memory docType,
        uint64 expectedVersion,
        DocumentRef memory document,
        CallAuthority memory authority,
        MutationGuard memory guard
    ) internal returns (uint64) {
        return bns.publishDocument(
            name,
            docType,
            expectedVersion,
            document,
            _unset(),
            _unset(),
            address(0),
            0,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            authority,
            guard
        );
    }

    /// Install a single authority key (address-backed) on `name`, owned by
    /// `ownerAddr` (asset-owner). Returns the new name seq.
    function _installAuthorityKey(
        string memory name,
        bytes32 kid,
        address keyAddr,
        address ownerAddr,
        uint64 validFrom,
        uint64 validUntil,
        uint64 currentSeq
    ) internal returns (uint64) {
        AuthorityKeyUpdate[] memory updates = new AuthorityKeyUpdate[](1);
        updates[0] = AuthorityKeyUpdate({
            key: AuthorityKey({
                kid: kid,
                verificationMethod: METHOD_EIP155_ACCOUNT,
                keyData: abi.encodePacked(keyAddr),
                purposes: bns.KEY_PURPOSE_AUTHENTICATION(),
                validFrom: validFrom,
                validUntil: validUntil,
                status: AuthorityKeyStatus.Active,
                metadataHash: ZERO
            }),
            active: true
        });
        vm.prank(ownerAddr);
        (uint64 authoritySeq,) = bns.updateAuthorityKeys(name, updates, _ownerAuth(ownerAddr), _guard(currentSeq));
        authoritySeq; // silence unused
        return bns.queryNameState(name).nameSeq;
    }

    function _singleRule(
        Principal memory controller,
        string memory docType,
        uint32 permissions,
        uint64 validFrom,
        uint64 validUntil
    ) internal pure returns (ControllerRule[] memory) {
        ControllerRule[] memory rules = new ControllerRule[](1);
        rules[0] = ControllerRule({
            controller: controller,
            docType: docType,
            permissions: permissions,
            namespaceScopeHash: ZERO,
            validFrom: validFrom,
            validUntil: validUntil,
            constraintHash: ZERO
        });
        return rules;
    }
}
