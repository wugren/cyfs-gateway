// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/Bns.sol";

contract BnsActor {
    function forward(address target, bytes calldata data) external returns (bool, bytes memory) {
        return target.call(data);
    }
}

contract BnsTest {
    Bns private bns;
    BnsActor private actor;

    bytes32 private constant ZERO = bytes32(0);
    bytes32 private constant KID =
        0x6d61696e00000000000000000000000000000000000000000000000000000000;
    bytes32 private constant STORAGE_INLINE =
        0x696e6c696e650000000000000000000000000000000000000000000000000000;
    bytes32 private constant METHOD_EIP155_ACCOUNT =
        0x6569703135352d6163636f756e74000000000000000000000000000000000000;

    function setUp() public {
        bns = new Bns();
        actor = new BnsActor();
    }

    function testRegisterAndPublishInlineDocument() public {
        _registerRoot("alice", address(this));

        NameState memory nameState = bns.queryNameState("alice");
        require(nameState.status == NameStatus.Active, "name active");
        require(nameState.assetOwner == address(this), "asset owner");
        require(nameState.ownerSource == OwnerSource.AssetOwnerFallback, "fallback owner");
        require(nameState.standardTransferEnabled, "standard transfer");

        uint64 version = _publishOwnerDoc("alice", nameState.nameSeq, bytes("{\"id\":\"did:bns:alice\"}"));
        require(version == 1, "owner version");

        ResolveResult memory resolved = bns.resolveDocument("alice", "owner");
        require(resolved.status == DocumentStatus.Active, "doc active");
        require(resolved.documentState.version == 1, "doc version");
        require(
            resolved.documentState.document.contentHash == sha256(bytes("{\"id\":\"did:bns:alice\"}")),
            "content hash"
        );
    }

    function testStaleNameSeqRejectsPublish() public {
        _registerRoot("alice", address(this));

        bytes memory data = abi.encodeCall(
            Bns.publishDocument,
            (
                "alice",
                "owner",
                uint64(0),
                _inlineDoc(bytes("{\"id\":\"did:bns:alice\"}")),
                _unset(),
                _unset(),
                address(0),
                uint64(0),
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                _ownerAuth(address(this)),
                MutationGuard({ expectedNameSeq: 0, expectedParentNameSeq: 0 })
            )
        );
        (bool ok,) = address(bns).call(data);
        require(!ok, "stale guard rejected");
    }

    function testControllerCanOnlyPublishAllowedDocType() public {
        _registerRoot("alice", address(this));

        NameState memory nameState = bns.queryNameState("alice");
        ControllerRule[] memory rules = new ControllerRule[](1);
        rules[0] = ControllerRule({
            controller: _chain(address(actor)),
            docType: "dns_txt",
            permissions: uint32(1),
            namespaceScopeHash: ZERO,
            validFrom: 0,
            validUntil: 0,
            constraintHash: ZERO
        });
        bns.setControllerPolicy(
            "alice",
            rules,
            keccak256("dns_txt-controller"),
            _ownerAuth(address(this)),
            MutationGuard({ expectedNameSeq: nameState.nameSeq, expectedParentNameSeq: 0 })
        );

        nameState = bns.queryNameState("alice");
        bytes memory allowed = abi.encodeCall(
            Bns.publishDocument,
            (
                "alice",
                "dns_txt",
                uint64(0),
                _inlineDoc(bytes("[{\"ttl\":600,\"value\":\"bns-txt=ok\"}]")),
                _unset(),
                _unset(),
                address(0),
                uint64(0),
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                CallAuthority({ role: AuthorityRole.Controller, actor: _chain(address(actor)), kid: ZERO }),
                MutationGuard({ expectedNameSeq: nameState.nameSeq, expectedParentNameSeq: 0 })
            )
        );
        (bool ok,) = actor.forward(address(bns), allowed);
        require(ok, "controller publish dns_txt");

        nameState = bns.queryNameState("alice");
        bytes memory denied = abi.encodeCall(
            Bns.publishDocument,
            (
                "alice",
                "owner",
                uint64(0),
                _inlineDoc(bytes("{\"id\":\"did:bns:alice\"}")),
                _unset(),
                _unset(),
                address(0),
                uint64(0),
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                CallAuthority({ role: AuthorityRole.Controller, actor: _chain(address(actor)), kid: ZERO }),
                MutationGuard({ expectedNameSeq: nameState.nameSeq, expectedParentNameSeq: 0 })
            )
        );
        (ok,) = actor.forward(address(bns), denied);
        require(!ok, "controller denied owner doc");
    }

    function testBnsAuthorityKeyTakesOverFromAssetOwner() public {
        _registerRoot("org", address(this));
        NameState memory state = bns.queryNameState("org");

        AuthorityKeyUpdate[] memory updates = new AuthorityKeyUpdate[](1);
        updates[0] = AuthorityKeyUpdate({
            key: AuthorityKey({
                kid: KID,
                verificationMethod: METHOD_EIP155_ACCOUNT,
                keyData: abi.encodePacked(address(actor)),
                purposes: uint32(1),
                validFrom: 0,
                validUntil: 0,
                status: AuthorityKeyStatus.Active,
                metadataHash: ZERO
            }),
            active: true
        });
        bns.updateAuthorityKeys(
            "org",
            updates,
            _ownerAuth(address(this)),
            MutationGuard({ expectedNameSeq: state.nameSeq, expectedParentNameSeq: 0 })
        );

        bns.setNameOwner(
            "org",
            _bnsName("org"),
            _ownerAuth(address(this)),
            MutationGuard({ expectedNameSeq: state.nameSeq, expectedParentNameSeq: 0 })
        );

        state = bns.queryNameState("org");
        require(state.ownerSource == OwnerSource.ExplicitSemanticOwner, "explicit owner");
        require(!state.standardTransferEnabled, "standard transfer disabled");

        bytes memory byOldAssetOwner = abi.encodeCall(
            Bns.publishDocument,
            (
                "org",
                "owner",
                uint64(0),
                _inlineDoc(bytes("{\"id\":\"did:bns:org\"}")),
                _unset(),
                _unset(),
                address(0),
                uint64(0),
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                _ownerAuth(address(this)),
                MutationGuard({ expectedNameSeq: state.nameSeq, expectedParentNameSeq: 0 })
            )
        );
        (bool ok,) = address(bns).call(byOldAssetOwner);
        require(!ok, "old asset owner lost authority");

        bytes memory byBnsAuthority = abi.encodeCall(
            Bns.publishDocument,
            (
                "org",
                "owner",
                uint64(0),
                _inlineDoc(bytes("{\"id\":\"did:bns:org\"}")),
                _unset(),
                _unset(),
                address(0),
                uint64(0),
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                ZERO,
                CallAuthority({ role: AuthorityRole.Owner, actor: _bnsName("org"), kid: KID }),
                MutationGuard({ expectedNameSeq: state.nameSeq, expectedParentNameSeq: 0 })
            )
        );
        (ok,) = actor.forward(address(bns), byBnsAuthority);
        require(ok, "bns authority key can publish");
    }

    function testRevokeCurrentVersionKeepsCurrentPointerRevoked() public {
        _registerRoot("alice", address(this));
        NameState memory state = bns.queryNameState("alice");
        _publishOwnerDoc("alice", state.nameSeq, bytes("{\"id\":\"did:bns:alice\"}"));

        state = bns.queryNameState("alice");
        bns.revokeDocument(
            "alice",
            "owner",
            1,
            keccak256("bad-owner-doc"),
            _ownerAuth(address(this)),
            MutationGuard({ expectedNameSeq: state.nameSeq, expectedParentNameSeq: 0 })
        );

        ResolveResult memory resolved = bns.resolveDocument("alice", "owner");
        require(resolved.documentState.version == 2, "current pointer");
        require(resolved.status == DocumentStatus.Revoked, "current is revoked");
    }

    function _registerRoot(string memory name, address owner) internal {
        DocumentUpdate[] memory emptyDocs = new DocumentUpdate[](0);
        AuthorityKeyUpdate[] memory noKeys = new AuthorityKeyUpdate[](0);
        ControllerRule[] memory noRules = new ControllerRule[](0);
        bns.registerName(
            name,
            owner,
            _defaultOptions(_unset()),
            noKeys,
            _unset(),
            noRules,
            ZERO,
            emptyDocs,
            CallAuthority({ role: AuthorityRole.None, actor: _unset(), kid: ZERO }),
            MutationGuard({ expectedNameSeq: 0, expectedParentNameSeq: 0 })
        );
    }

    function _publishOwnerDoc(string memory name, uint64 expectedNameSeq, bytes memory body)
        internal
        returns (uint64)
    {
        return bns.publishDocument(
            name,
            "owner",
            0,
            _inlineDoc(body),
            _unset(),
            _unset(),
            address(0),
            0,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            _ownerAuth(address(this)),
            MutationGuard({ expectedNameSeq: expectedNameSeq, expectedParentNameSeq: 0 })
        );
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
            allowDelegatedSubnames: false,
            initialPaymentTarget: address(0),
            initialPaymentPolicyHash: ZERO,
            initialNamespacePolicyHash: ZERO
        });
    }

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

    function _ownerAuth(address owner) internal pure returns (CallAuthority memory) {
        return CallAuthority({ role: AuthorityRole.Owner, actor: _chain(owner), kid: ZERO });
    }

    function _unset() internal pure returns (Principal memory) {
        return Principal({ kind: PrincipalKind.Unset, value: "" });
    }

    function _chain(address account) internal pure returns (Principal memory) {
        return Principal({ kind: PrincipalKind.ChainAccount, value: abi.encodePacked(account) });
    }

    function _bnsName(string memory name) internal pure returns (Principal memory) {
        return Principal({ kind: PrincipalKind.BnsName, value: bytes(name) });
    }
}
