// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

enum NameStatus {
    Available,
    Active,
    Expired,
    Released,
    Tombstoned
}

enum DocumentStatus {
    Missing,
    Active,
    Revoked,
    Expired,
    Migrated,
    Tombstoned
}

enum AliasKind {
    None,
    Alias,
    MigratedTo,
    Canonical
}

enum ReleaseMode {
    ReleaseAfterGrace,
    TombstoneForever
}

enum PrincipalKind {
    Unset,
    ChainAccount,
    BnsName
}

enum OwnerSource {
    None,
    AssetOwnerFallback,
    ExplicitSemanticOwner,
    ParentInherited
}

enum AuthorityRole {
    None,
    Owner,
    Controller
}

enum AuthorityKeyStatus {
    Missing,
    Active,
    Revoked,
    Expired
}

struct Principal {
    PrincipalKind kind;
    bytes value;
}

struct CallAuthority {
    AuthorityRole role;
    Principal actor;
    bytes32 kid;
}

struct MutationGuard {
    uint64 expectedNameSeq;
    uint64 expectedParentNameSeq;
}

struct AuthorityKey {
    bytes32 kid;
    bytes32 verificationMethod;
    bytes keyData;
    uint32 purposes;
    uint64 validFrom;
    uint64 validUntil;
    AuthorityKeyStatus status;
    bytes32 metadataHash;
}

struct AuthorityKeyUpdate {
    AuthorityKey key;
    bool active;
}

struct AuthoritySetState {
    string name;
    uint64 authoritySeq;
    bytes32 authorityRoot;
    uint32 activeKeyCount;
}

struct DocumentRef {
    bytes32 storageType;
    string uri;
    bytes inlineDocument;
    bytes32 contentHash;
    bytes32 schema;
    bytes32 codec;
    bytes32 extraHash;
}

struct NameState {
    string name;
    address assetOwner;
    Principal semanticOwner;
    Principal effectiveOwner;
    OwnerSource ownerSource;
    bool standardTransferEnabled;
    NameStatus status;
    uint64 registeredAt;
    uint64 expireAt;
    uint64 graceUntil;
    uint64 updatedAt;
    uint64 nameSeq;
    uint64 ownerDocumentVersion;
    uint64 minDocumentIat;
    uint64 ownerPolicySeq;
    uint64 lineageEpoch;
    bool renewable;
    bool transferable;
    bool allowDelegatedSubnames;
    bytes32 namespacePolicyHash;
    bytes32 paymentPolicyHash;
    bytes32 aliasStateHash;
}

struct DocumentState {
    string name;
    string docType;
    uint64 version;
    uint64 previousVersion;
    DocumentStatus status;
    DocumentRef document;
    Principal controller;
    Principal beneficiary;
    address paymentTarget;
    uint64 validFrom;
    uint64 expireAt;
    uint64 revokedAt;
    bytes32 controllerPolicyHash;
    bytes32 paymentPolicyHash;
    bytes32 splitPolicyHash;
    bytes32 pricePolicyHash;
    bytes32 rightsPolicyHash;
    bytes32 documentStateHash;
}

struct ControllerRule {
    Principal controller;
    string docType;
    uint32 permissions;
    bytes32 namespaceScopeHash;
    uint64 validFrom;
    uint64 validUntil;
    bytes32 constraintHash;
}

struct RegisterOptions {
    uint64 duration;
    uint64 gracePeriod;
    bool renewable;
    bool transferable;
    Principal initialSemanticOwner;
    bool allowDelegatedSubnames;
    address initialPaymentTarget;
    bytes32 initialPaymentPolicyHash;
    bytes32 initialNamespacePolicyHash;
}

struct DocumentUpdate {
    string docType;
    uint64 expectedVersion;
    DocumentRef document;
    Principal controller;
    Principal beneficiary;
    address paymentTarget;
    uint64 expireAt;
    bytes32 controllerPolicyHash;
    bytes32 paymentPolicyHash;
    bytes32 splitPolicyHash;
    bytes32 pricePolicyHash;
    bytes32 rightsPolicyHash;
}

struct OwnerPolicyUpdate {
    bool updateMinDocumentIat;
    uint64 minDocumentIat;
    bytes32 reasonHash;
}

struct OwnerResolution {
    Principal effectiveOwner;
    OwnerSource source;
    bytes32 authorityRoot;
    uint64 authoritySeq;
}

struct ResolveResult {
    NameState nameState;
    DocumentState documentState;
    OwnerResolution owner;
    Principal effectiveController;
    DocumentStatus status;
    AliasKind aliasKind;
    string aliasTargetDid;
    bytes32 proofRoot;
}

struct AliasState {
    string name;
    AliasKind kind;
    string targetDid;
    bytes32 proofHash;
    uint64 setAt;
    uint64 nameSeq;
}

struct PurchaseContext {
    string name;
    string docType;
    uint64 documentVersion;
    Principal beneficiary;
    address paymentTarget;
    bytes32 paymentPolicyHash;
    bytes32 splitPolicyHash;
    bytes32 pricePolicyHash;
    bytes32 rightsPolicyHash;
    DocumentStatus status;
    bytes32 proofRoot;
}

struct LogCheckpoint {
    bytes32 logRoot;
    uint64 lastSeq;
    uint64 issuedAt;
    Principal issuer;
    bytes32 externalAnchor;
}

error InvalidName(string name);
error InvalidDocType(string docType);
error InvalidPrincipal();
error InvalidKid(bytes32 kid);
error NameAlreadyExists(string name);
error NameNotFound(string name);
error DocumentNotFound(string name, string docType);
error StaleNameSeq(string name, uint64 expected, uint64 actual);
error StaleParentNameSeq(string name, uint64 expected, uint64 actual);
error StaleDocumentVersion(string name, string docType, uint64 expected, uint64 actual);
error NotEffectiveOwner(string name);
error ControllerScopeDenied(string name, string docType, bytes32 operation);
error StandardTransferDisabled(string name);
error OwnerGraphCycle();
error NoConcreteSigner();
error OwnerGraphTooDeep(uint256 maxDepth);
error InlineDocumentTooLarge(uint256 len, uint256 max);
error InvalidMutation(bytes32 reason);

contract Bns {
    uint64 public constant MAX_INLINE_DOCUMENT = 4 * 1024;
    uint8 public constant MAX_MUTATION_BATCH_ITEMS = 32;
    uint256 public constant MAX_MUTATION_BATCH_INLINE_DOCUMENTS = 64 * 1024;
    uint8 public constant MAX_OWNER_REF_DEPTH = 8;

    uint32 public constant KEY_PURPOSE_AUTHENTICATION = 1 << 0;
    uint32 public constant KEY_PURPOSE_RECOVERY = 1 << 1;
    uint32 public constant KEY_PURPOSE_SIGN_DOCUMENT = 1 << 2;

    uint32 public constant PERMISSION_PUBLISH_DOCUMENT = 1 << 0;
    uint32 public constant PERMISSION_REVOKE_DOCUMENT = 1 << 1;
    uint32 public constant PERMISSION_SET_PAYMENT = 1 << 2;
    uint32 public constant PERMISSION_SET_ALIAS = 1 << 3;
    uint32 public constant PERMISSION_SET_NAMESPACE = 1 << 4;

    bytes32 public constant STORAGE_INLINE =
        0x696e6c696e650000000000000000000000000000000000000000000000000000;
    bytes32 private constant OP_PUBLISH_DOCUMENT = keccak256("publish_document");
    bytes32 private constant OP_REVOKE_DOCUMENT = keccak256("revoke_document");
    bytes32 private constant OP_SET_PAYMENT = keccak256("set_payment");
    bytes32 private constant OP_SET_ALIAS = keccak256("set_alias");
    bytes32 private constant OP_SET_NAMESPACE = keccak256("set_namespace");

    bytes32 private constant EVENT_NAME_REGISTERED = keccak256("name_registered");
    bytes32 private constant EVENT_NAME_RENEWED = keccak256("name_renewed");
    bytes32 private constant EVENT_NAME_TRANSFERRED = keccak256("name_asset_transferred");
    bytes32 private constant EVENT_NAME_OWNER_UPDATED = keccak256("name_owner_updated");
    bytes32 private constant EVENT_AUTHORITY_UPDATED = keccak256("authority_keys_updated");
    bytes32 private constant EVENT_NAME_RELEASED = keccak256("name_released");
    bytes32 private constant EVENT_DOCUMENT_PUBLISHED = keccak256("document_published");
    bytes32 private constant EVENT_DOCUMENT_REVOKED = keccak256("document_revoked");
    bytes32 private constant EVENT_OWNER_IAT_FLOOR_UPDATED =
        keccak256("owner_iat_floor_updated");
    bytes32 private constant EVENT_CONTROLLER_POLICY = keccak256("controller_policy_updated");
    bytes32 private constant EVENT_NAMESPACE_POLICY = keccak256("namespace_policy_updated");
    bytes32 private constant EVENT_DID_ALIAS = keccak256("did_alias_set");
    bytes32 private constant EVENT_PAYMENT_TARGET = keccak256("payment_target_updated");
    bytes32 private constant EVENT_LOG_CHECKPOINT = keccak256("log_checkpoint_published");

    bytes32 private constant ERR_BAD_DURATION = keccak256("BAD_DURATION");
    bytes32 private constant ERR_NOT_RENEWABLE = keccak256("NOT_RENEWABLE");
    bytes32 private constant ERR_ROOT_AUTHORITY_NOT_USED = keccak256("ROOT_AUTHORITY_NOT_USED");
    bytes32 private constant ERR_EMPTY_STORAGE_TYPE = keccak256("EMPTY_STORAGE_TYPE");
    bytes32 private constant ERR_INLINE_URI_NOT_EMPTY = keccak256("INLINE_URI_NOT_EMPTY");
    bytes32 private constant ERR_BAD_CONTENT_HASH = keccak256("BAD_CONTENT_HASH");
    bytes32 private constant ERR_NON_INLINE_HAS_BYTES = keccak256("NON_INLINE_HAS_BYTES");
    bytes32 private constant ERR_INVALID_DID = keccak256("INVALID_DID");
    bytes32 private constant ERR_EMPTY_MUTATION_BATCH = keccak256("EMPTY_MUTATION_BATCH");
    bytes32 private constant ERR_MUTATION_BATCH_TOO_LARGE = keccak256("MUTATION_BATCH_TOO_LARGE");
    bytes32 private constant ERR_BATCH_INLINE_TOO_LARGE = keccak256("BATCH_INLINE_TOO_LARGE");
    bytes32 private constant ERR_DUPLICATE_DOC_TYPE = keccak256("DUPLICATE_DOC_TYPE");
    bytes32 private constant ERR_MIN_DOCUMENT_IAT_REGRESSION =
        keccak256("MIN_DOCUMENT_IAT_REGRESSION");

    mapping(bytes32 => NameState) private _names;
    mapping(bytes32 => bool) private _knownNameHash;
    bytes32[] private _nameHashes;

    mapping(bytes32 => AuthoritySetState) private _authoritySets;
    mapping(bytes32 => mapping(bytes32 => AuthorityKey)) private _authorityKeys;
    mapping(bytes32 => bytes32[]) private _authorityKeyIds;
    mapping(bytes32 => mapping(bytes32 => bool)) private _knownAuthorityKey;

    mapping(bytes32 => mapping(bytes32 => uint64)) private _currentDocumentVersions;
    mapping(bytes32 => mapping(bytes32 => mapping(uint64 => DocumentState))) private _documents;
    mapping(bytes32 => ControllerRule[]) private _controllerPolicies;
    mapping(bytes32 => AliasState) private _aliases;

    LogCheckpoint private _latestCheckpoint;

    uint64 public globalEventSeq;
    bytes32 public currentLogRoot;

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
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        uint64 expireAt,
        uint64 nameSeq
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
        bytes32 indexed nameHash,
        string name,
        address indexed actor,
        bytes32 policyHash,
        uint64 nameSeq
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

    function chainAccountPrincipal(address account) external pure returns (Principal memory) {
        return _chainAccountPrincipal(account);
    }

    function bnsNamePrincipal(string calldata name) external pure returns (Principal memory) {
        _validateName(name);
        return Principal({ kind: PrincipalKind.BnsName, value: bytes(name) });
    }

    function queryNameState(string calldata name) external view returns (NameState memory state) {
        bytes32 nameHash = _validateName(name);
        if (_names[nameHash].status == NameStatus.Available) {
            state.name = name;
            state.status = NameStatus.Available;
            return state;
        }
        return _materializeNameState(_names[nameHash]);
    }

    function resolveOwner(string calldata name) external view returns (OwnerResolution memory) {
        bytes32 nameHash = _validateName(name);
        _requireExistingName(nameHash, name);
        return _resolveOwner(nameHash, 0);
    }

    function isStandardTransferEnabled(string calldata name) external view returns (bool) {
        bytes32 nameHash = _validateName(name);
        _requireExistingName(nameHash, name);
        return _materializeNameState(_names[nameHash]).standardTransferEnabled;
    }

    function getAuthoritySet(string calldata name)
        external
        view
        returns (AuthoritySetState memory state)
    {
        bytes32 nameHash = _validateName(name);
        state = _authoritySets[nameHash];
        if (bytes(state.name).length == 0) {
            state.name = name;
        }
    }

    function getAuthorityKey(string calldata name, bytes32 kid)
        external
        view
        returns (AuthorityKey memory)
    {
        bytes32 nameHash = _validateName(name);
        return _authorityKeys[nameHash][kid];
    }

    function resolveDocument(string calldata name, string calldata docType)
        external
        view
        returns (ResolveResult memory result)
    {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        _requireExistingName(nameHash, name);

        result.nameState = _materializeNameState(_names[nameHash]);
        result.owner = _resolveOwner(nameHash, 0);
        uint64 version = _currentDocumentVersions[nameHash][docTypeHash];
        if (version == 0) {
            result.documentState.name = name;
            result.documentState.docType = docType;
            result.documentState.status = DocumentStatus.Missing;
            result.effectiveController = result.owner.effectiveOwner;
            result.status = DocumentStatus.Missing;
            result.proofRoot = currentLogRoot;
            return result;
        }

        result.documentState = _documents[nameHash][docTypeHash][version];
        result.effectiveController = result.documentState.controller.kind == PrincipalKind.Unset
            ? result.owner.effectiveOwner
            : result.documentState.controller;
        result.status = result.documentState.status;
        AliasState storage aliasState = _aliases[nameHash];
        result.aliasKind = aliasState.kind;
        result.aliasTargetDid = aliasState.targetDid;
        result.proofRoot = currentLogRoot;
    }

    function getDocumentVersion(string calldata name, string calldata docType, uint64 version)
        external
        view
        returns (DocumentState memory state)
    {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        state = _documents[nameHash][docTypeHash][version];
        if (state.version == 0) {
            state.name = name;
            state.docType = docType;
            state.version = version;
            state.status = DocumentStatus.Missing;
        }
    }

    function getAlias(string calldata name) external view returns (AliasState memory state) {
        bytes32 nameHash = _validateName(name);
        state = _aliases[nameHash];
        if (bytes(state.name).length == 0) {
            state.name = name;
        }
    }

    function getPurchaseContext(string calldata name, string calldata docType)
        external
        view
        returns (PurchaseContext memory context)
    {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        uint64 version = _currentDocumentVersions[nameHash][docTypeHash];
        if (version == 0) {
            revert DocumentNotFound(name, docType);
        }
        DocumentState storage document = _documents[nameHash][docTypeHash][version];
        context = PurchaseContext({
            name: name,
            docType: docType,
            documentVersion: document.version,
            beneficiary: document.beneficiary,
            paymentTarget: document.paymentTarget,
            paymentPolicyHash: document.paymentPolicyHash,
            splitPolicyHash: document.splitPolicyHash,
            pricePolicyHash: document.pricePolicyHash,
            rightsPolicyHash: document.rightsPolicyHash,
            status: document.status,
            proofRoot: currentLogRoot
        });
    }

    function resolvePaymentTarget(string calldata name, string calldata docType, uint64 version)
        external
        view
        returns (
            Principal memory beneficiary,
            address paymentTarget,
            bytes32 paymentPolicyHash,
            bytes32 splitPolicyHash,
            bytes32 pricePolicyHash,
            bytes32 rightsPolicyHash,
            bytes32 proofRoot
        )
    {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        DocumentState storage document = _documents[nameHash][docTypeHash][version];
        if (document.version == 0) {
            revert DocumentNotFound(name, docType);
        }
        return (
            document.beneficiary,
            document.paymentTarget,
            document.paymentPolicyHash,
            document.splitPolicyHash,
            document.pricePolicyHash,
            document.rightsPolicyHash,
            currentLogRoot
        );
    }

    function latestCheckpoint() external view returns (LogCheckpoint memory) {
        return _latestCheckpoint;
    }

    function registerName(
        string calldata name,
        address assetOwner,
        RegisterOptions calldata options,
        AuthorityKeyUpdate[] calldata authorityUpdates,
        Principal calldata semanticOwnerAfterAuthority,
        ControllerRule[] calldata controllerPolicy,
        bytes32 controllerPolicyHash,
        DocumentUpdate[] calldata initialDocuments,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    )
        external
        payable
        returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot)
    {
        _validateBatchBounds(authorityUpdates.length, initialDocuments);
        _validateUniqueDocumentTypes(initialDocuments);
        bytes32 nameHash =
            _registerNameHash(name, assetOwner, options, initialDocuments, authority, guard);

        if (authorityUpdates.length != 0) {
            AuthoritySetState memory set = _applyAuthorityUpdates(nameHash, name, authorityUpdates);
            authoritySeq = set.authoritySeq;
            authorityRoot = set.authorityRoot;
        }

        _validateSemanticOwnerCalldata(semanticOwnerAfterAuthority);
        if (semanticOwnerAfterAuthority.kind != PrincipalKind.Unset) {
            _requireActiveAuthoritySetForPrincipal(semanticOwnerAfterAuthority);
            NameState storage state = _names[nameHash];
            _copyPrincipal(state.semanticOwner, semanticOwnerAfterAuthority);
            state.updatedAt = _now();
            _validateAllOwnerGraphs();
            NameState memory materialized = _materializeNameState(state);
            _commitEvent(
                EVENT_NAME_OWNER_UPDATED,
                keccak256(
                    abi.encode(
                        nameHash,
                        materialized.semanticOwner.kind,
                        materialized.semanticOwner.value,
                        materialized.ownerSource,
                        materialized.standardTransferEnabled,
                        materialized.nameSeq
                    )
                )
            );
            emit NameOwnerUpdated(
                nameHash,
                name,
                msg.sender,
                materialized.semanticOwner.kind,
                materialized.semanticOwner.value,
                materialized.ownerSource,
                materialized.standardTransferEnabled,
                materialized.nameSeq
            );
        }

        if (controllerPolicy.length != 0 || controllerPolicyHash != bytes32(0)) {
            _setControllerPolicyInternal(nameHash, name, controllerPolicy, controllerPolicyHash, false);
        }

        NameState storage latest = _names[nameHash];
        AuthoritySetState memory finalSet = _authoritySets[nameHash];
        return (latest.nameSeq, finalSet.authoritySeq, finalSet.authorityRoot);
    }

    function renewName(string calldata name, uint64 duration)
        external
        payable
        returns (uint64 expireAt)
    {
        if (duration == 0) {
            revert InvalidMutation(ERR_BAD_DURATION);
        }
        bytes32 nameHash = _validateName(name);
        NameState storage state = _names[nameHash];
        _requireExistingName(nameHash, name);
        if (
            !state.renewable || state.status == NameStatus.Released
                || state.status == NameStatus.Tombstoned
        ) {
            revert InvalidMutation(ERR_NOT_RENEWABLE);
        }

        uint64 nowTs = _now();
        uint64 graceDelta = state.graceUntil > state.expireAt ? state.graceUntil - state.expireAt : 0;
        uint64 base = state.expireAt > nowTs ? state.expireAt : nowTs;
        state.expireAt = base + duration;
        state.graceUntil = state.expireAt + graceDelta;
        state.updatedAt = nowTs;
        state.nameSeq += 1;

        _commitEvent(EVENT_NAME_RENEWED, keccak256(abi.encode(nameHash, state.expireAt, state.nameSeq)));
        emit NameRenewed(nameHash, name, msg.sender, state.expireAt, state.nameSeq);
        return state.expireAt;
    }

    function transferName(
        string calldata name,
        address newAssetOwner,
        Principal calldata newSemanticOwner,
        DocumentUpdate[] calldata atomicDocumentUpdates,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        if (newAssetOwner == address(0)) {
            revert InvalidPrincipal();
        }
        bytes32 nameHash = _validateName(name);
        _validateSemanticOwnerCalldata(newSemanticOwner);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);
        _requireActiveAuthoritySetForPrincipal(newSemanticOwner);

        address oldAssetOwner = state.assetOwner;
        state.assetOwner = newAssetOwner;
        _copyPrincipal(state.semanticOwner, newSemanticOwner);
        state.nameSeq += 1;
        state.updatedAt = _now();
        _validateAllOwnerGraphs();

        NameState memory materialized = _materializeNameState(state);
        _commitEvent(
            EVENT_NAME_TRANSFERRED,
            keccak256(abi.encode(nameHash, oldAssetOwner, newAssetOwner, state.nameSeq))
        );
        emit NameAssetTransferred(nameHash, name, oldAssetOwner, newAssetOwner, false, state.nameSeq);

        _commitEvent(
            EVENT_NAME_OWNER_UPDATED,
            keccak256(
                abi.encode(
                    nameHash,
                    materialized.semanticOwner.kind,
                    materialized.semanticOwner.value,
                    materialized.ownerSource,
                    materialized.standardTransferEnabled,
                    materialized.nameSeq
                )
            )
        );
        emit NameOwnerUpdated(
            nameHash,
            name,
            msg.sender,
            materialized.semanticOwner.kind,
            materialized.semanticOwner.value,
            materialized.ownerSource,
            materialized.standardTransferEnabled,
            materialized.nameSeq
        );

        for (uint256 i = 0; i < atomicDocumentUpdates.length; i++) {
            _publishDocumentUpdateInternal(nameHash, name, atomicDocumentUpdates[i], false);
        }
        return state.nameSeq;
    }

    function setNameOwner(
        string calldata name,
        Principal calldata semanticOwner,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        _validateSemanticOwnerCalldata(semanticOwner);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);
        _requireActiveAuthoritySetForPrincipal(semanticOwner);

        _copyPrincipal(state.semanticOwner, semanticOwner);
        state.nameSeq += 1;
        state.updatedAt = _now();
        _validateAllOwnerGraphs();

        NameState memory materialized = _materializeNameState(state);
        _commitEvent(
            EVENT_NAME_OWNER_UPDATED,
            keccak256(
                abi.encode(
                    nameHash,
                    materialized.semanticOwner.kind,
                    materialized.semanticOwner.value,
                    materialized.ownerSource,
                    materialized.standardTransferEnabled,
                    materialized.nameSeq
                )
            )
        );
        emit NameOwnerUpdated(
            nameHash,
            name,
            msg.sender,
            materialized.semanticOwner.kind,
            materialized.semanticOwner.value,
            materialized.ownerSource,
            materialized.standardTransferEnabled,
            materialized.nameSeq
        );
        return state.nameSeq;
    }

    function releaseName(
        string calldata name,
        ReleaseMode mode,
        bytes32 reasonHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);

        state.status =
            mode == ReleaseMode.TombstoneForever ? NameStatus.Tombstoned : NameStatus.Released;
        state.nameSeq += 1;
        state.updatedAt = _now();
        _commitEvent(EVENT_NAME_RELEASED, keccak256(abi.encode(nameHash, mode, reasonHash, state.nameSeq)));
        emit NameReleased(nameHash, name, msg.sender, mode, reasonHash, state.nameSeq);
        return state.nameSeq;
    }

    function setNamespacePolicy(
        string calldata name,
        bool allowDelegatedSubnames,
        bytes32 namespacePolicyHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _authorizeUpdate(
            nameHash,
            name,
            state,
            "",
            PERMISSION_SET_NAMESPACE,
            OP_SET_NAMESPACE,
            authority,
            guard
        );

        state.allowDelegatedSubnames = allowDelegatedSubnames;
        state.namespacePolicyHash = namespacePolicyHash;
        state.nameSeq += 1;
        state.updatedAt = _now();
        _commitEvent(
            EVENT_NAMESPACE_POLICY,
            keccak256(abi.encode(nameHash, allowDelegatedSubnames, namespacePolicyHash, state.nameSeq))
        );
        emit NamespacePolicyUpdated(
            nameHash, name, msg.sender, allowDelegatedSubnames, namespacePolicyHash, state.nameSeq
        );
        return state.nameSeq;
    }

    function updateAuthorityKeys(
        string calldata name,
        AuthorityKeyUpdate[] calldata updates,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 authoritySeq, bytes32 authorityRoot) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);
        AuthoritySetState memory set = _applyAuthorityUpdates(nameHash, name, updates);
        return (set.authoritySeq, set.authorityRoot);
    }

    function setMinDocumentIat(
        string calldata name,
        uint64 minDocumentIat,
        bytes32 reasonHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq, uint64 ownerPolicySeq) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);
        return _setMinDocumentIatInternal(nameHash, name, minDocumentIat, reasonHash, true);
    }

    function applyMutations(
        string calldata name,
        AuthorityKeyUpdate[] calldata authorityUpdates,
        DocumentUpdate[] calldata documents,
        OwnerPolicyUpdate calldata ownerPolicy,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    )
        external
        returns (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot, uint64 ownerPolicySeq)
    {
        if (
            authorityUpdates.length == 0 && documents.length == 0
                && !ownerPolicy.updateMinDocumentIat
        ) {
            revert InvalidMutation(ERR_EMPTY_MUTATION_BATCH);
        }
        _validateBatchBounds(
            authorityUpdates.length + (ownerPolicy.updateMinDocumentIat ? 1 : 0), documents
        );
        _validateUniqueDocumentTypes(documents);

        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);

        bool ownerOnly = authorityUpdates.length != 0 || ownerPolicy.updateMinDocumentIat
            || _containsOwnerDocument(documents);
        if (ownerOnly) {
            _authorizeOwner(nameHash, name, state, authority);
        } else {
            for (uint256 i = 0; i < documents.length; i++) {
                _authorizeUpdateNoGuard(
                    nameHash,
                    name,
                    state,
                    documents[i].docType,
                    PERMISSION_PUBLISH_DOCUMENT,
                    OP_PUBLISH_DOCUMENT,
                    authority
                );
            }
        }

        if (authorityUpdates.length != 0) {
            _applyAuthorityUpdates(nameHash, name, authorityUpdates);
        }
        if (documents.length != 0 || ownerPolicy.updateMinDocumentIat) {
            state.nameSeq += 1;
            state.updatedAt = _now();
        }
        if (documents.length != 0) {
            for (uint256 i = 0; i < documents.length; i++) {
                _publishDocumentUpdateInternal(nameHash, name, documents[i], false);
            }
        }
        if (ownerPolicy.updateMinDocumentIat) {
            _setMinDocumentIatInternal(
                nameHash, name, ownerPolicy.minDocumentIat, ownerPolicy.reasonHash, false
            );
        }

        AuthoritySetState memory finalSet = _authoritySets[nameHash];
        return (state.nameSeq, finalSet.authoritySeq, finalSet.authorityRoot, state.ownerPolicySeq);
    }

    function publishDocument(
        string calldata name,
        string calldata docType,
        uint64 expectedVersion,
        DocumentRef calldata document,
        Principal calldata controller,
        Principal calldata beneficiary,
        address paymentTarget,
        uint64 expireAt,
        bytes32 controllerPolicyHash,
        bytes32 paymentPolicyHash,
        bytes32 splitPolicyHash,
        bytes32 pricePolicyHash,
        bytes32 rightsPolicyHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 version) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _authorizeUpdate(
            nameHash,
            name,
            state,
            docType,
            PERMISSION_PUBLISH_DOCUMENT,
            OP_PUBLISH_DOCUMENT,
            authority,
            guard
        );
        return _publishDocumentInternal(
            nameHash,
            name,
            docType,
            expectedVersion,
            document,
            controller,
            beneficiary,
            paymentTarget,
            expireAt,
            controllerPolicyHash,
            paymentPolicyHash,
            splitPolicyHash,
            pricePolicyHash,
            rightsPolicyHash,
            true
        );
    }

    function revokeDocument(
        string calldata name,
        string calldata docType,
        uint64 expectedVersion,
        bytes32 reasonHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 newVersion, uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _authorizeUpdate(
            nameHash,
            name,
            state,
            docType,
            PERMISSION_REVOKE_DOCUMENT,
            OP_REVOKE_DOCUMENT,
            authority,
            guard
        );

        uint64 current = _currentDocumentVersions[nameHash][docTypeHash];
        if (current != expectedVersion) {
            revert StaleDocumentVersion(name, docType, expectedVersion, current);
        }

        uint64 nowTs = _now();
        newVersion = current + 1;
        _currentDocumentVersions[nameHash][docTypeHash] = newVersion;

        DocumentState storage document = _documents[nameHash][docTypeHash][newVersion];
        document.name = name;
        document.docType = docType;
        document.version = newVersion;
        document.previousVersion = current;
        document.status = DocumentStatus.Revoked;
        document.validFrom = nowTs;
        document.expireAt = 0;
        document.revokedAt = nowTs;
        document.paymentTarget = address(0);
        document.controllerPolicyHash = bytes32(0);
        document.paymentPolicyHash = bytes32(0);
        document.splitPolicyHash = bytes32(0);
        document.pricePolicyHash = bytes32(0);
        document.rightsPolicyHash = bytes32(0);
        document.documentStateHash = _hashDocumentState(document);

        if (keccak256(bytes(docType)) == keccak256(bytes("owner"))) {
            state.ownerDocumentVersion = newVersion;
        }

        state.nameSeq += 1;
        state.updatedAt = nowTs;
        _commitEvent(
            EVENT_DOCUMENT_REVOKED,
            keccak256(abi.encode(nameHash, docTypeHash, current, newVersion, reasonHash))
        );
        emit DocumentRevoked(nameHash, name, docType, msg.sender, current, newVersion, reasonHash);
        return (newVersion, state.nameSeq);
    }

    function setControllerPolicy(
        string calldata name,
        ControllerRule[] calldata rules,
        bytes32 policyHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _checkGuard(state, guard, name);
        _authorizeOwner(nameHash, name, state, authority);
        return _setControllerPolicyInternal(nameHash, name, rules, policyHash, true);
    }

    function setDidAlias(
        string calldata name,
        string calldata targetDid,
        AliasKind kind,
        bytes32 proofHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 nameSeq) {
        bytes32 nameHash = _validateName(name);
        _requireActiveName(nameHash, name);
        if (kind != AliasKind.None) {
            _validateDid(targetDid);
        }
        NameState storage state = _names[nameHash];
        _authorizeUpdate(
            nameHash, name, state, "", PERMISSION_SET_ALIAS, OP_SET_ALIAS, authority, guard
        );

        state.nameSeq += 1;
        state.aliasStateHash = proofHash;
        state.updatedAt = _now();

        AliasState storage aliasState = _aliases[nameHash];
        aliasState.name = name;
        aliasState.kind = kind;
        aliasState.targetDid = targetDid;
        aliasState.proofHash = proofHash;
        aliasState.setAt = state.updatedAt;
        aliasState.nameSeq = state.nameSeq;

        _commitEvent(EVENT_DID_ALIAS, keccak256(abi.encode(nameHash, targetDid, kind, proofHash, state.nameSeq)));
        emit DidAliasSet(nameHash, name, msg.sender, targetDid, kind, proofHash, state.nameSeq);
        return state.nameSeq;
    }

    function setPaymentTarget(
        string calldata name,
        string calldata docType,
        uint64 expectedVersion,
        address paymentTarget,
        Principal calldata beneficiary,
        bytes32 paymentPolicyHash,
        bytes32 splitPolicyHash,
        bytes32 pricePolicyHash,
        bytes32 rightsPolicyHash,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) external returns (uint64 version) {
        bytes32 nameHash = _validateName(name);
        bytes32 docTypeHash = _validateDocType(docType);
        _validatePrincipalCalldata(beneficiary);
        _requireActiveName(nameHash, name);
        NameState storage state = _names[nameHash];
        _authorizeUpdate(
            nameHash,
            name,
            state,
            docType,
            PERMISSION_SET_PAYMENT,
            OP_SET_PAYMENT,
            authority,
            guard
        );

        uint64 current = _currentDocumentVersions[nameHash][docTypeHash];
        if (current != expectedVersion) {
            revert StaleDocumentVersion(name, docType, expectedVersion, current);
        }
        if (current == 0) {
            revert DocumentNotFound(name, docType);
        }

        DocumentState storage document = _documents[nameHash][docTypeHash][current];
        document.paymentTarget = paymentTarget;
        _copyPrincipal(document.beneficiary, beneficiary);
        document.paymentPolicyHash = paymentPolicyHash;
        document.splitPolicyHash = splitPolicyHash;
        document.pricePolicyHash = pricePolicyHash;
        document.rightsPolicyHash = rightsPolicyHash;
        document.documentStateHash = _hashDocumentState(document);

        state.paymentPolicyHash = paymentPolicyHash;
        state.nameSeq += 1;
        state.updatedAt = _now();

        _commitEvent(
            EVENT_PAYMENT_TARGET,
            keccak256(abi.encode(nameHash, docTypeHash, paymentTarget, paymentPolicyHash, current))
        );
        emit PaymentTargetUpdated(
            nameHash, name, docType, msg.sender, paymentTarget, paymentPolicyHash, current
        );
        return current;
    }

    function publishLogCheckpoint(Principal calldata issuer, bytes32 externalAnchor)
        external
        returns (LogCheckpoint memory checkpoint)
    {
        _validatePrincipalCalldata(issuer);
        checkpoint.logRoot = currentLogRoot;
        checkpoint.lastSeq = globalEventSeq;
        checkpoint.issuedAt = _now();
        _copyPrincipal(_latestCheckpoint.issuer, issuer);
        _latestCheckpoint.logRoot = checkpoint.logRoot;
        _latestCheckpoint.lastSeq = checkpoint.lastSeq;
        _latestCheckpoint.issuedAt = checkpoint.issuedAt;
        _latestCheckpoint.externalAnchor = externalAnchor;
        checkpoint.issuer = _latestCheckpoint.issuer;
        checkpoint.externalAnchor = externalAnchor;
        _commitEvent(
            EVENT_LOG_CHECKPOINT,
            keccak256(abi.encode(checkpoint.logRoot, checkpoint.lastSeq, checkpoint.issuedAt, externalAnchor))
        );
        emit LogCheckpointPublished(
            checkpoint.logRoot, msg.sender, checkpoint.lastSeq, checkpoint.issuedAt, externalAnchor
        );
    }

    function _registerNameHash(
        string calldata name,
        address assetOwner,
        RegisterOptions calldata options,
        DocumentUpdate[] calldata initialDocuments,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) internal returns (bytes32 nameHash) {
        if (assetOwner == address(0)) {
            revert InvalidPrincipal();
        }
        if (options.duration == 0) {
            revert InvalidMutation(ERR_BAD_DURATION);
        }
        nameHash = _validateName(name);
        _validateSemanticOwnerCalldata(options.initialSemanticOwner);
        _requireActiveAuthoritySetForPrincipal(options.initialSemanticOwner);

        NameState storage existing = _names[nameHash];
        if (
            existing.status == NameStatus.Active || existing.status == NameStatus.Expired
                || existing.status == NameStatus.Tombstoned
        ) {
            revert NameAlreadyExists(name);
        }

        string memory parent = _parentName(name);
        if (bytes(parent).length == 0) {
            if (authority.role != AuthorityRole.None) {
                revert InvalidMutation(ERR_ROOT_AUTHORITY_NOT_USED);
            }
        } else {
            bytes32 parentHash = _nameHash(parent);
            NameState storage parentState = _names[parentHash];
            _requireActiveName(parentHash, parent);
            if (parentState.nameSeq != guard.expectedParentNameSeq) {
                revert StaleParentNameSeq(parent, guard.expectedParentNameSeq, parentState.nameSeq);
            }
            _authorizeOwner(parentHash, parent, parentState, authority);
        }

        for (uint256 i = 0; i < initialDocuments.length; i++) {
            _validateDocType(initialDocuments[i].docType);
            if (initialDocuments[i].expectedVersion != 0) {
                revert StaleDocumentVersion(
                    name, initialDocuments[i].docType, initialDocuments[i].expectedVersion, 0
                );
            }
            _validateDocumentRef(initialDocuments[i].document);
            _validatePrincipalCalldata(initialDocuments[i].controller);
            _validatePrincipalCalldata(initialDocuments[i].beneficiary);
        }

        if (!_knownNameHash[nameHash]) {
            _knownNameHash[nameHash] = true;
            _nameHashes.push(nameHash);
        }

        uint64 nowTs = _now();
        uint64 nextSeq = 1;
        uint64 lineageEpoch = existing.nameSeq == 0 ? 0 : existing.lineageEpoch + 1;

        existing.name = name;
        existing.assetOwner = assetOwner;
        _copyPrincipal(existing.semanticOwner, options.initialSemanticOwner);
        delete existing.effectiveOwner;
        existing.ownerSource = OwnerSource.None;
        existing.standardTransferEnabled = false;
        existing.status = NameStatus.Active;
        existing.registeredAt = nowTs;
        existing.expireAt = nowTs + options.duration;
        existing.graceUntil = existing.expireAt + options.gracePeriod;
        existing.updatedAt = nowTs;
        existing.nameSeq = nextSeq;
        existing.ownerDocumentVersion = 0;
        existing.minDocumentIat = 0;
        existing.ownerPolicySeq = 0;
        existing.lineageEpoch = lineageEpoch;
        existing.renewable = options.renewable;
        existing.transferable = options.transferable;
        existing.allowDelegatedSubnames = options.allowDelegatedSubnames;
        existing.namespacePolicyHash = options.initialNamespacePolicyHash;
        existing.paymentPolicyHash = options.initialPaymentPolicyHash;
        existing.aliasStateHash = bytes32(0);

        _validateAllOwnerGraphs();

        _commitEvent(
            EVENT_NAME_REGISTERED,
            keccak256(abi.encode(nameHash, assetOwner, existing.expireAt, lineageEpoch, nextSeq))
        );
        emit NameRegistered(
            nameHash, name, assetOwner, msg.sender, existing.expireAt, lineageEpoch, nextSeq
        );

        for (uint256 i = 0; i < initialDocuments.length; i++) {
            _publishDocumentUpdateInternal(nameHash, name, initialDocuments[i], false);
        }
    }

    function _publishDocumentUpdateInternal(
        bytes32 nameHash,
        string memory name,
        DocumentUpdate calldata update,
        bool bumpNameSeq
    ) internal returns (uint64) {
        return _publishDocumentInternal(
            nameHash,
            name,
            update.docType,
            update.expectedVersion,
            update.document,
            update.controller,
            update.beneficiary,
            update.paymentTarget,
            update.expireAt,
            update.controllerPolicyHash,
            update.paymentPolicyHash,
            update.splitPolicyHash,
            update.pricePolicyHash,
            update.rightsPolicyHash,
            bumpNameSeq
        );
    }

    function _publishDocumentInternal(
        bytes32 nameHash,
        string memory name,
        string calldata docType,
        uint64 expectedVersion,
        DocumentRef calldata documentRef,
        Principal calldata controller,
        Principal calldata beneficiary,
        address paymentTarget,
        uint64 expireAt,
        bytes32 controllerPolicyHash,
        bytes32 paymentPolicyHash,
        bytes32 splitPolicyHash,
        bytes32 pricePolicyHash,
        bytes32 rightsPolicyHash,
        bool bumpNameSeq
    ) internal returns (uint64 version) {
        bytes32 docTypeHash = _validateDocType(docType);
        _validateDocumentRef(documentRef);
        _validatePrincipalCalldata(controller);
        _validatePrincipalCalldata(beneficiary);

        uint64 actualVersion = _currentDocumentVersions[nameHash][docTypeHash];
        if (actualVersion != expectedVersion) {
            revert StaleDocumentVersion(name, docType, expectedVersion, actualVersion);
        }
        version = actualVersion + 1;
        _currentDocumentVersions[nameHash][docTypeHash] = version;

        DocumentState storage document = _documents[nameHash][docTypeHash][version];
        document.name = name;
        document.docType = docType;
        document.version = version;
        document.previousVersion = actualVersion;
        document.status = DocumentStatus.Active;
        _copyDocumentRef(document.document, documentRef);
        _copyPrincipal(document.controller, controller);
        _copyPrincipal(document.beneficiary, beneficiary);
        document.paymentTarget = paymentTarget;
        document.validFrom = _now();
        document.expireAt = expireAt;
        document.revokedAt = 0;
        document.controllerPolicyHash = controllerPolicyHash;
        document.paymentPolicyHash = paymentPolicyHash;
        document.splitPolicyHash = splitPolicyHash;
        document.pricePolicyHash = pricePolicyHash;
        document.rightsPolicyHash = rightsPolicyHash;
        document.documentStateHash = _hashDocumentState(document);

        NameState storage nameState = _names[nameHash];
        if (keccak256(bytes(docType)) == keccak256(bytes("owner"))) {
            nameState.ownerDocumentVersion = version;
        }
        if (bumpNameSeq) {
            nameState.nameSeq += 1;
        }
        nameState.updatedAt = _now();

        _commitEvent(
            EVENT_DOCUMENT_PUBLISHED,
            keccak256(
                abi.encode(nameHash, docTypeHash, version, documentRef.contentHash, document.documentStateHash)
            )
        );
        emit DocumentPublished(
            nameHash,
            name,
            docType,
            version,
            msg.sender,
            documentRef.contentHash,
            document.documentStateHash
        );
    }

    function _setControllerPolicyInternal(
        bytes32 nameHash,
        string memory name,
        ControllerRule[] calldata rules,
        bytes32 policyHash,
        bool bumpNameSeq
    ) internal returns (uint64 nameSeq) {
        delete _controllerPolicies[nameHash];
        for (uint256 i = 0; i < rules.length; i++) {
            _validateControllerRule(rules[i]);
            if (rules[i].controller.kind == PrincipalKind.BnsName) {
                _requireActiveAuthoritySetForPrincipal(rules[i].controller);
            }
            _controllerPolicies[nameHash].push();
            ControllerRule storage stored = _controllerPolicies[nameHash][i];
            _copyPrincipal(stored.controller, rules[i].controller);
            stored.docType = rules[i].docType;
            stored.permissions = rules[i].permissions;
            stored.namespaceScopeHash = rules[i].namespaceScopeHash;
            stored.validFrom = rules[i].validFrom;
            stored.validUntil = rules[i].validUntil;
            stored.constraintHash = rules[i].constraintHash;
        }

        NameState storage state = _names[nameHash];
        if (bumpNameSeq) {
            state.nameSeq += 1;
        }
        state.updatedAt = _now();
        _commitEvent(EVENT_CONTROLLER_POLICY, keccak256(abi.encode(nameHash, policyHash, state.nameSeq)));
        emit ControllerPolicyUpdated(nameHash, name, msg.sender, policyHash, state.nameSeq);
        return state.nameSeq;
    }

    function _setMinDocumentIatInternal(
        bytes32 nameHash,
        string memory name,
        uint64 minDocumentIat,
        bytes32 reasonHash,
        bool bumpNameSeq
    ) internal returns (uint64 nameSeq, uint64 ownerPolicySeq) {
        NameState storage state = _names[nameHash];
        uint64 previous = state.minDocumentIat;
        if (minDocumentIat < previous) {
            revert InvalidMutation(ERR_MIN_DOCUMENT_IAT_REGRESSION);
        }

        if (bumpNameSeq) {
            state.nameSeq += 1;
        }
        state.minDocumentIat = minDocumentIat;
        state.ownerPolicySeq += 1;
        state.updatedAt = _now();

        _commitEvent(
            EVENT_OWNER_IAT_FLOOR_UPDATED,
            keccak256(
                abi.encode(
                    nameHash,
                    previous,
                    minDocumentIat,
                    state.ownerPolicySeq,
                    state.nameSeq,
                    reasonHash
                )
            )
        );
        emit OwnerDocumentIatFloorUpdated(
            nameHash,
            name,
            msg.sender,
            previous,
            minDocumentIat,
            state.ownerPolicySeq,
            state.nameSeq,
            reasonHash
        );
        return (state.nameSeq, state.ownerPolicySeq);
    }

    function _applyAuthorityUpdates(
        bytes32 nameHash,
        string memory name,
        AuthorityKeyUpdate[] calldata updates
    ) internal returns (AuthoritySetState memory set) {
        for (uint256 i = 0; i < updates.length; i++) {
            AuthorityKey calldata updateKey = updates[i].key;
            if (updateKey.kid == bytes32(0)) {
                revert InvalidKid(updateKey.kid);
            }
            if (updateKey.verificationMethod == bytes32(0)) {
                revert InvalidKid(updateKey.kid);
            }
            if (!_knownAuthorityKey[nameHash][updateKey.kid]) {
                _knownAuthorityKey[nameHash][updateKey.kid] = true;
                _authorityKeyIds[nameHash].push(updateKey.kid);
            }

            AuthorityKey storage stored = _authorityKeys[nameHash][updateKey.kid];
            stored.kid = updateKey.kid;
            stored.verificationMethod = updateKey.verificationMethod;
            stored.keyData = updateKey.keyData;
            stored.purposes = updateKey.purposes;
            stored.validFrom = updateKey.validFrom;
            stored.validUntil = updateKey.validUntil;
            stored.status = updates[i].active
                ? (
                    updateKey.status == AuthorityKeyStatus.Missing
                        ? AuthorityKeyStatus.Active
                        : updateKey.status
                )
                : AuthorityKeyStatus.Revoked;
            stored.metadataHash = updateKey.metadataHash;
        }

        set = _recomputeAuthoritySet(nameHash, name);
        if (set.activeKeyCount == 0 && _nameIsAuthorityOwner(nameHash)) {
            revert NoConcreteSigner();
        }
        _authoritySets[nameHash] = set;
        _commitEvent(EVENT_AUTHORITY_UPDATED, keccak256(abi.encode(nameHash, set.authoritySeq, set.authorityRoot)));
        emit AuthorityKeysUpdated(nameHash, name, msg.sender, set.authoritySeq, set.authorityRoot);
    }

    function _recomputeAuthoritySet(bytes32 nameHash, string memory name)
        internal
        view
        returns (AuthoritySetState memory set)
    {
        bytes32 root = bytes32(0);
        uint32 activeCount = 0;
        bytes32[] storage ids = _authorityKeyIds[nameHash];
        uint64 nowTs = _now();
        for (uint256 i = 0; i < ids.length; i++) {
            AuthorityKey storage key = _authorityKeys[nameHash][ids[i]];
            root = keccak256(
                abi.encodePacked(
                    root,
                    key.kid,
                    key.verificationMethod,
                    keccak256(key.keyData),
                    key.purposes,
                    key.validFrom,
                    key.validUntil,
                    key.status,
                    key.metadataHash
                )
            );
            if (_isActiveKey(key, KEY_PURPOSE_AUTHENTICATION, nowTs)) {
                activeCount += 1;
            }
        }
        AuthoritySetState storage previous = _authoritySets[nameHash];
        set = AuthoritySetState({
            name: name,
            authoritySeq: previous.authoritySeq + 1,
            authorityRoot: root,
            activeKeyCount: activeCount
        });
    }

    function _authorizeUpdate(
        bytes32 nameHash,
        string memory name,
        NameState storage state,
        string memory docType,
        uint32 permission,
        bytes32 operation,
        CallAuthority calldata authority,
        MutationGuard calldata guard
    ) internal view {
        _checkGuard(state, guard, name);
        _authorizeUpdateNoGuard(nameHash, name, state, docType, permission, operation, authority);
    }

    function _authorizeUpdateNoGuard(
        bytes32 nameHash,
        string memory name,
        NameState storage state,
        string memory docType,
        uint32 permission,
        bytes32 operation,
        CallAuthority calldata authority
    ) internal view {
        if (authority.role == AuthorityRole.Owner) {
            _authorizeOwner(nameHash, name, state, authority);
            return;
        }
        if (authority.role != AuthorityRole.Controller) {
            revert NotEffectiveOwner(name);
        }

        ControllerRule[] storage rules = _controllerPolicies[nameHash];
        for (uint256 i = 0; i < rules.length; i++) {
            ControllerRule storage rule = rules[i];
            if ((rule.permissions & permission) == 0) {
                continue;
            }
            if (!_docTypeMatches(rule.docType, docType)) {
                continue;
            }
            uint64 nowTs = _now();
            if (rule.validFrom > nowTs || (rule.validUntil != 0 && nowTs >= rule.validUntil)) {
                continue;
            }
            if (_authenticateExpectedPrincipal(rule.controller, authority, msg.sender)) {
                return;
            }
        }
        revert ControllerScopeDenied(name, docType, operation);
    }

    function _authorizeOwner(
        bytes32 nameHash,
        string memory name,
        NameState storage,
        CallAuthority calldata authority
    ) internal view {
        if (authority.role != AuthorityRole.Owner) {
            revert NotEffectiveOwner(name);
        }
        OwnerResolution memory owner = _resolveOwner(nameHash, 0);
        if (!_authenticateExpectedPrincipal(owner.effectiveOwner, authority, msg.sender)) {
            revert NotEffectiveOwner(name);
        }
    }

    function _authenticateExpectedPrincipal(
        Principal memory expected,
        CallAuthority calldata authority,
        address signer
    ) internal view returns (bool) {
        if (expected.kind == PrincipalKind.ChainAccount) {
            if (authority.actor.kind != PrincipalKind.ChainAccount) {
                return false;
            }
            (bool okExpected, address expectedAddress) = _tryAddressFromBytes(expected.value);
            (bool okActor, address actorAddress) = _tryAddressFromBytes(authority.actor.value);
            return okExpected && okActor && expectedAddress == signer && actorAddress == signer;
        }

        if (expected.kind == PrincipalKind.BnsName) {
            if (authority.actor.kind != PrincipalKind.BnsName) {
                return false;
            }
            if (keccak256(expected.value) != keccak256(authority.actor.value)) {
                return false;
            }
            bytes32 ownerHash = keccak256(expected.value);
            return _authorityKeyAuthenticates(ownerHash, authority.kid, signer);
        }

        return false;
    }

    function _authorityKeyAuthenticates(bytes32 authorityNameHash, bytes32 kid, address signer)
        internal
        view
        returns (bool)
    {
        AuthorityKey storage key = _authorityKeys[authorityNameHash][kid];
        if (!_isActiveKey(key, KEY_PURPOSE_AUTHENTICATION, _now())) {
            return false;
        }
        (bool ok, address keyAddress) = _tryAddressFromBytes(key.keyData);
        return ok && keyAddress == signer;
    }

    function _resolveOwner(bytes32 nameHash, uint256 depth)
        internal
        view
        returns (OwnerResolution memory)
    {
        if (depth > MAX_OWNER_REF_DEPTH) {
            revert OwnerGraphTooDeep(MAX_OWNER_REF_DEPTH);
        }
        NameState storage state = _names[nameHash];
        if (state.status == NameStatus.Available) {
            revert NameNotFound(state.name);
        }

        if (state.semanticOwner.kind == PrincipalKind.BnsName) {
            string memory ownerName = string(state.semanticOwner.value);
            bytes32 ownerHash = _nameHash(ownerName);
            AuthoritySetState memory set = _authoritySets[ownerHash];
            if (state.status == NameStatus.Active && set.activeKeyCount == 0) {
                revert NoConcreteSigner();
            }
            return OwnerResolution({
                effectiveOwner: state.semanticOwner,
                source: OwnerSource.ExplicitSemanticOwner,
                authorityRoot: set.authorityRoot,
                authoritySeq: set.authoritySeq
            });
        }

        string memory parent = _parentName(state.name);
        if (bytes(parent).length == 0) {
            AuthoritySetState memory set = _authoritySets[nameHash];
            return OwnerResolution({
                effectiveOwner: _chainAccountPrincipal(state.assetOwner),
                source: OwnerSource.AssetOwnerFallback,
                authorityRoot: set.authorityRoot,
                authoritySeq: set.authoritySeq
            });
        }

        OwnerResolution memory parentOwner = _resolveOwner(_nameHash(parent), depth + 1);
        parentOwner.source = OwnerSource.ParentInherited;
        return parentOwner;
    }

    function _materializeNameState(NameState storage stored)
        internal
        view
        returns (NameState memory state)
    {
        state = stored;
        OwnerResolution memory owner = _resolveOwner(_nameHash(stored.name), 0);
        state.effectiveOwner = owner.effectiveOwner;
        state.ownerSource = owner.source;
        state.standardTransferEnabled = stored.transferable && stored.status == NameStatus.Active
            && owner.source == OwnerSource.AssetOwnerFallback;
    }

    function _checkGuard(NameState storage state, MutationGuard calldata guard, string memory name)
        internal
        view
    {
        if (state.nameSeq != guard.expectedNameSeq) {
            revert StaleNameSeq(name, guard.expectedNameSeq, state.nameSeq);
        }
    }

    function _validateAllOwnerGraphs() internal view {
        for (uint256 i = 0; i < _nameHashes.length; i++) {
            NameState storage state = _names[_nameHashes[i]];
            if (state.status == NameStatus.Active) {
                _validateOwnerPath(_nameHashes[i]);
            }
        }
    }

    function _validateOwnerPath(bytes32 startHash) internal view {
        bytes32 current = startHash;
        bytes32[9] memory visited;
        for (uint256 depth = 0; depth <= MAX_OWNER_REF_DEPTH; depth++) {
            for (uint256 i = 0; i < depth; i++) {
                if (visited[i] == current) {
                    revert OwnerGraphCycle();
                }
            }
            visited[depth] = current;

            NameState storage state = _names[current];
            if (state.status != NameStatus.Active) {
                revert NoConcreteSigner();
            }

            if (state.semanticOwner.kind == PrincipalKind.BnsName) {
                bytes32 ownerHash = keccak256(state.semanticOwner.value);
                AuthoritySetState storage set = _authoritySets[ownerHash];
                if (ownerHash == current) {
                    if (set.activeKeyCount == 0) {
                        revert NoConcreteSigner();
                    }
                    return;
                }
                if (set.activeKeyCount > 0) {
                    return;
                }
                current = ownerHash;
            } else {
                string memory parent = _parentName(state.name);
                if (bytes(parent).length == 0) {
                    if (state.assetOwner == address(0)) {
                        revert NoConcreteSigner();
                    }
                    return;
                }
                current = _nameHash(parent);
            }

            if (depth == MAX_OWNER_REF_DEPTH) {
                revert OwnerGraphTooDeep(MAX_OWNER_REF_DEPTH);
            }
        }
    }

    function _nameIsAuthorityOwner(bytes32 authorityNameHash) internal view returns (bool) {
        for (uint256 i = 0; i < _nameHashes.length; i++) {
            NameState storage state = _names[_nameHashes[i]];
            if (
                state.status == NameStatus.Active && state.semanticOwner.kind == PrincipalKind.BnsName
                    && keccak256(state.semanticOwner.value) == authorityNameHash
            ) {
                return true;
            }
        }
        return false;
    }

    function _validateBatchBounds(uint256 authorityUpdateCount, DocumentUpdate[] calldata documents)
        internal
        pure
    {
        if (authorityUpdateCount + documents.length > MAX_MUTATION_BATCH_ITEMS) {
            revert InvalidMutation(ERR_MUTATION_BATCH_TOO_LARGE);
        }

        uint256 inlineBytes = 0;
        for (uint256 i = 0; i < documents.length; i++) {
            inlineBytes += documents[i].document.inlineDocument.length;
            if (inlineBytes > MAX_MUTATION_BATCH_INLINE_DOCUMENTS) {
                revert InvalidMutation(ERR_BATCH_INLINE_TOO_LARGE);
            }
        }
    }

    function _validateUniqueDocumentTypes(DocumentUpdate[] calldata documents) internal pure {
        bytes32[] memory seen = new bytes32[](documents.length);
        for (uint256 i = 0; i < documents.length; i++) {
            bytes32 docTypeHash = _validateDocType(documents[i].docType);
            for (uint256 j = 0; j < i; j++) {
                if (seen[j] == docTypeHash) {
                    revert InvalidMutation(ERR_DUPLICATE_DOC_TYPE);
                }
            }
            seen[i] = docTypeHash;
        }
    }

    function _containsOwnerDocument(DocumentUpdate[] calldata documents)
        internal
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < documents.length; i++) {
            if (keccak256(bytes(documents[i].docType)) == keccak256(bytes("owner"))) {
                return true;
            }
        }
        return false;
    }

    function _validateDocumentRef(DocumentRef calldata documentRef) internal pure {
        if (documentRef.storageType == bytes32(0)) {
            revert InvalidMutation(ERR_EMPTY_STORAGE_TYPE);
        }
        if (documentRef.storageType == STORAGE_INLINE) {
            if (bytes(documentRef.uri).length != 0) {
                revert InvalidMutation(ERR_INLINE_URI_NOT_EMPTY);
            }
            uint256 len = documentRef.inlineDocument.length;
            if (len == 0 || len > MAX_INLINE_DOCUMENT) {
                revert InlineDocumentTooLarge(len, MAX_INLINE_DOCUMENT);
            }
            if (sha256(documentRef.inlineDocument) != documentRef.contentHash) {
                revert InvalidMutation(ERR_BAD_CONTENT_HASH);
            }
        } else if (documentRef.inlineDocument.length != 0) {
            revert InvalidMutation(ERR_NON_INLINE_HAS_BYTES);
        }
    }

    function _validateControllerRule(ControllerRule calldata rule) internal pure {
        _validatePrincipalCalldata(rule.controller);
        if (rule.controller.kind == PrincipalKind.Unset) {
            revert InvalidPrincipal();
        }
        if (bytes(rule.docType).length != 0) {
            _validateDocType(rule.docType);
        }
    }

    function _validateSemanticOwnerCalldata(Principal calldata principal) internal pure {
        if (principal.kind == PrincipalKind.Unset) {
            if (principal.value.length != 0) {
                revert InvalidPrincipal();
            }
            return;
        }
        if (principal.kind != PrincipalKind.BnsName) {
            revert InvalidPrincipal();
        }
        _validateName(string(principal.value));
    }

    function _validatePrincipalCalldata(Principal calldata principal) internal pure {
        if (principal.kind == PrincipalKind.Unset) {
            if (principal.value.length != 0) {
                revert InvalidPrincipal();
            }
        } else if (principal.kind == PrincipalKind.ChainAccount) {
            (bool ok, address account) = _tryAddressFromBytes(principal.value);
            if (!ok || account == address(0)) {
                revert InvalidPrincipal();
            }
        } else if (principal.kind == PrincipalKind.BnsName) {
            _validateName(string(principal.value));
        } else {
            revert InvalidPrincipal();
        }
    }

    function _requireActiveAuthoritySetForPrincipal(Principal calldata principal) internal view {
        if (principal.kind == PrincipalKind.BnsName) {
            bytes32 authorityNameHash = keccak256(principal.value);
            if (
                _names[authorityNameHash].status != NameStatus.Active
                    || _authoritySets[authorityNameHash].activeKeyCount == 0
            ) {
                revert NoConcreteSigner();
            }
        }
    }

    function _requireExistingName(bytes32 nameHash, string memory name) internal view {
        if (_names[nameHash].status == NameStatus.Available) {
            revert NameNotFound(name);
        }
    }

    function _requireActiveName(bytes32 nameHash, string memory name) internal view {
        if (_names[nameHash].status != NameStatus.Active) {
            revert NameNotFound(name);
        }
    }

    function _isActiveKey(AuthorityKey storage key, uint32 purpose, uint64 nowTs)
        internal
        view
        returns (bool)
    {
        return key.status == AuthorityKeyStatus.Active && (key.purposes & purpose) != 0
            && key.validFrom <= nowTs && (key.validUntil == 0 || nowTs < key.validUntil);
    }

    function _docTypeMatches(string storage ruleDocType, string memory docType)
        internal
        view
        returns (bool)
    {
        return bytes(ruleDocType).length == 0
            || keccak256(bytes(ruleDocType)) == keccak256(bytes(docType));
    }

    function _validateName(string memory name) internal pure returns (bytes32) {
        bytes memory data = bytes(name);
        if (data.length == 0 || data.length > 253) {
            revert InvalidName(name);
        }

        uint256 dots = 0;
        uint256 labelStart = 0;
        for (uint256 i = 0; i < data.length; i++) {
            bytes1 c = data[i];
            if (c == ".") {
                if (i == labelStart || i - labelStart > 126 || data[i - 1] == "-") {
                    revert InvalidName(name);
                }
                dots += 1;
                if (dots > 1) {
                    revert InvalidName(name);
                }
                labelStart = i + 1;
                continue;
            }
            if (i == labelStart && c == "-") {
                revert InvalidName(name);
            }
            bool ok = (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-";
            if (!ok) {
                revert InvalidName(name);
            }
        }
        if (data.length == labelStart || data.length - labelStart > 126 || data[data.length - 1] == "-") {
            revert InvalidName(name);
        }
        return keccak256(data);
    }

    function _validateDocType(string memory docType) internal pure returns (bytes32) {
        bytes memory data = bytes(docType);
        if (data.length == 0 || data.length > 32) {
            revert InvalidDocType(docType);
        }
        for (uint256 i = 0; i < data.length; i++) {
            bytes1 c = data[i];
            bool ok = (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-"
                || c == "_";
            if (!ok) {
                revert InvalidDocType(docType);
            }
        }
        return keccak256(data);
    }

    function _validateDid(string memory did) internal pure {
        bytes memory data = bytes(did);
        if (data.length <= 4 || data[0] != "d" || data[1] != "i" || data[2] != "d" || data[3] != ":") {
            revert InvalidMutation(ERR_INVALID_DID);
        }
    }

    function _copyDocumentRef(DocumentRef storage target, DocumentRef calldata source) internal {
        target.storageType = source.storageType;
        target.uri = source.uri;
        target.inlineDocument = source.inlineDocument;
        target.contentHash = source.contentHash;
        target.schema = source.schema;
        target.codec = source.codec;
        target.extraHash = source.extraHash;
    }

    function _copyPrincipal(Principal storage target, Principal calldata source) internal {
        target.kind = source.kind;
        target.value = source.value;
    }

    function _hashDocumentState(DocumentState storage document) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                document.name,
                document.docType,
                document.version,
                document.previousVersion,
                document.status,
                document.document.storageType,
                document.document.uri,
                keccak256(document.document.inlineDocument),
                document.document.contentHash,
                document.document.schema,
                document.document.codec,
                document.document.extraHash,
                document.controller.kind,
                keccak256(document.controller.value),
                document.beneficiary.kind,
                keccak256(document.beneficiary.value),
                document.paymentTarget,
                document.validFrom,
                document.expireAt,
                document.revokedAt,
                document.controllerPolicyHash,
                document.paymentPolicyHash,
                document.splitPolicyHash,
                document.pricePolicyHash,
                document.rightsPolicyHash,
                block.chainid,
                address(this)
            )
        );
    }

    function _commitEvent(bytes32 eventType, bytes32 payloadHash) internal {
        bytes32 previous = currentLogRoot;
        globalEventSeq += 1;
        currentLogRoot = keccak256(
            abi.encodePacked(previous, block.chainid, address(this), globalEventSeq, eventType, payloadHash)
        );
        emit ProtocolEvent(globalEventSeq, eventType, msg.sender, previous, currentLogRoot);
    }

    function _parentName(string memory name) internal pure returns (string memory) {
        bytes memory data = bytes(name);
        for (uint256 i = 0; i < data.length; i++) {
            if (data[i] == ".") {
                bytes memory parent = new bytes(data.length - i - 1);
                for (uint256 j = i + 1; j < data.length; j++) {
                    parent[j - i - 1] = data[j];
                }
                return string(parent);
            }
        }
        return "";
    }

    function _nameHash(string memory name) internal pure returns (bytes32) {
        return keccak256(bytes(name));
    }

    function _chainAccountPrincipal(address account) internal pure returns (Principal memory) {
        return Principal({ kind: PrincipalKind.ChainAccount, value: abi.encodePacked(account) });
    }

    function _tryAddressFromBytes(bytes memory value) internal pure returns (bool, address account) {
        if (value.length == 20) {
            assembly ("memory-safe") {
                account := shr(96, mload(add(value, 32)))
            }
            return (true, account);
        }
        if (value.length == 32) {
            assembly ("memory-safe") {
                account := mload(add(value, 32))
            }
            return (true, account);
        }
        return (false, address(0));
    }

    function _now() internal view returns (uint64) {
        return uint64(block.timestamp);
    }
}
