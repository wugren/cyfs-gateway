// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTestBase.sol";

contract BnsOwnerPolicyTest is BnsTestBase {
    function _docUpdate(string memory docType, uint64 expectedVersion, DocumentRef memory ref)
        internal
        pure
        returns (DocumentUpdate memory)
    {
        return DocumentUpdate({
            docType: docType,
            expectedVersion: expectedVersion,
            document: ref,
            controller: Principal({ kind: PrincipalKind.Unset, value: "" }),
            beneficiary: Principal({ kind: PrincipalKind.Unset, value: "" }),
            paymentTarget: address(0),
            expireAt: 0,
            controllerPolicyHash: ZERO,
            paymentPolicyHash: ZERO,
            splitPolicyHash: ZERO,
            pricePolicyHash: ZERO,
            rightsPolicyHash: ZERO
        });
    }

    function _authorityUpdate(bytes32 kid, address keyAddr, bool active)
        internal
        view
        returns (AuthorityKeyUpdate memory)
    {
        return AuthorityKeyUpdate({
            key: AuthorityKey({
                kid: kid,
                verificationMethod: METHOD_EIP155_ACCOUNT,
                keyData: abi.encodePacked(keyAddr),
                purposes: bns.KEY_PURPOSE_AUTHENTICATION(),
                validFrom: 0,
                validUntil: 0,
                status: AuthorityKeyStatus.Active,
                metadataHash: ZERO
            }),
            active: active
        });
    }

    function _registerSelfOwnedWithKey(string memory name, address assetOwner, address keyHolder)
        internal
    {
        AuthorityKeyUpdate[] memory keys = new AuthorityKeyUpdate[](1);
        keys[0] = _authorityUpdate(KID, keyHolder, true);
        ControllerRule[] memory noRules = new ControllerRule[](0);
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);

        bns.registerName(
            name,
            assetOwner,
            _defaultOptions(_unset()),
            keys,
            _bnsName(name),
            noRules,
            ZERO,
            noDocs,
            _noneAuth(),
            _guard(0)
        );
    }

    function _emptyAuthorityUpdates() internal pure returns (AuthorityKeyUpdate[] memory) {
        return new AuthorityKeyUpdate[](0);
    }

    function testRegisterInitializesOwnerPolicy() public {
        _registerRoot("alice", ALICE);

        NameState memory state = bns.queryNameState("alice");
        assertEqUint(state.minDocumentIat, 0, "initial min iat");
        assertEqUint(state.ownerPolicySeq, 0, "initial owner policy seq");
    }

    function testOwnerCanSetMinDocumentIat() public {
        _registerRoot("alice", ALICE);
        uint64 seqBefore = bns.queryNameState("alice").nameSeq;

        vm.prank(ALICE);
        (uint64 nameSeq, uint64 ownerPolicySeq) = bns.setMinDocumentIat(
            "alice", 1_770_000_000, keccak256("compromised"), _ownerAuth(ALICE), _guard(seqBefore)
        );

        NameState memory state = bns.queryNameState("alice");
        assertEqUint(nameSeq, seqBefore + 1, "name seq returned");
        assertEqUint(ownerPolicySeq, 1, "owner policy seq returned");
        assertEqUint(state.nameSeq, seqBefore + 1, "stored name seq");
        assertEqUint(state.minDocumentIat, 1_770_000_000, "stored min iat");
        assertEqUint(state.ownerPolicySeq, 1, "stored owner policy seq");
    }

    function testNonOwnerCannotSetMinDocumentIat() public {
        _registerRoot("alice", ALICE);
        uint64 seqBefore = bns.queryNameState("alice").nameSeq;

        vm.prank(BOB);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        bns.setMinDocumentIat(
            "alice", 1_770_000_000, keccak256("bad-actor"), _ownerAuth(BOB), _guard(seqBefore)
        );
    }

    function testControllerCannotSetMinDocumentIatEvenWithDocumentPermissions() public {
        _registerRoot("alice", ALICE);
        ControllerRule[] memory rules = _singleRule(
            _chain(CTRL),
            "",
            bns.PERMISSION_PUBLISH_DOCUMENT() | bns.PERMISSION_REVOKE_DOCUMENT(),
            0,
            0
        );
        vm.prank(ALICE);
        bns.setControllerPolicy("alice", rules, keccak256("policy"), _ownerAuth(ALICE), _guard(1));

        uint64 seqBefore = bns.queryNameState("alice").nameSeq;
        vm.prank(CTRL);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        bns.setMinDocumentIat(
            "alice", 1_770_000_000, keccak256("controller"), _controllerAuth(CTRL), _guard(seqBefore)
        );
    }

    function testMinDocumentIatCannotDecrease() public {
        _registerRoot("alice", ALICE);
        vm.prank(ALICE);
        bns.setMinDocumentIat(
            "alice", 1_770_000_000, keccak256("first"), _ownerAuth(ALICE), _guard(1)
        );

        uint64 seqBefore = bns.queryNameState("alice").nameSeq;
        vm.prank(ALICE);
        vm.expectPartialRevert(InvalidMutation.selector);
        bns.setMinDocumentIat(
            "alice", 1_760_000_000, keccak256("lower"), _ownerAuth(ALICE), _guard(seqBefore)
        );
    }

    function testApplyMutationsRotatesOwnerKeyPublishesOwnerDocAndRaisesFloor() public {
        _registerSelfOwnedWithKey("org", ALICE, CAROL);
        uint64 seqBefore = bns.queryNameState("org").nameSeq;

        AuthorityKeyUpdate[] memory keys = new AuthorityKeyUpdate[](2);
        keys[0] = _authorityUpdate(KID, CAROL, false);
        keys[1] = _authorityUpdate(KID2, BOB, true);

        DocumentUpdate[] memory docs = new DocumentUpdate[](1);
        docs[0] = _docUpdate("owner", 0, ownerRef);

        OwnerPolicyUpdate memory policy = OwnerPolicyUpdate({
            updateMinDocumentIat: true,
            minDocumentIat: 1_770_000_000,
            reasonHash: keccak256("recovery")
        });

        vm.prank(CAROL);
        (uint64 nameSeq, uint64 authoritySeq,, uint64 ownerPolicySeq) =
            bns.applyMutations("org", keys, docs, policy, _ownerAuthName("org", KID), _guard(seqBefore));

        NameState memory state = bns.queryNameState("org");
        assertEqUint(nameSeq, seqBefore + 1, "batch bumps nameSeq once");
        assertEqUint(authoritySeq, 2, "authority rotated");
        assertEqUint(ownerPolicySeq, 1, "owner policy seq");
        assertEqUint(state.ownerDocumentVersion, 1, "owner document version");
        assertEqUint(state.minDocumentIat, 1_770_000_000, "stored min iat");
        assertEqUint(state.ownerPolicySeq, 1, "stored owner policy seq");
        assertTrue(bns.getAuthorityKey("org", KID).status == AuthorityKeyStatus.Revoked, "old key revoked");
        assertTrue(bns.getAuthorityKey("org", KID2).status == AuthorityKeyStatus.Active, "new key active");
    }

    function testApplyMutationsWithOwnerPolicyRejectsController() public {
        _registerRoot("alice", ALICE);
        ControllerRule[] memory rules = _singleRule(
            _chain(CTRL),
            "",
            bns.PERMISSION_PUBLISH_DOCUMENT() | bns.PERMISSION_REVOKE_DOCUMENT(),
            0,
            0
        );
        vm.prank(ALICE);
        bns.setControllerPolicy("alice", rules, keccak256("policy"), _ownerAuth(ALICE), _guard(1));

        DocumentUpdate[] memory docs = new DocumentUpdate[](1);
        docs[0] = _docUpdate("dns_txt", 0, _inlineDoc(bytes("[{\"v\":1}]")));
        OwnerPolicyUpdate memory policy = OwnerPolicyUpdate({
            updateMinDocumentIat: true,
            minDocumentIat: 1_770_000_000,
            reasonHash: keccak256("controller")
        });

        uint64 seqBefore = bns.queryNameState("alice").nameSeq;
        vm.prank(CTRL);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        bns.applyMutations(
            "alice", _emptyAuthorityUpdates(), docs, policy, _controllerAuth(CTRL), _guard(seqBefore)
        );
    }

    function testReleasedNameReregisterResetsOwnerPolicy() public {
        _registerRoot("alice", ALICE);
        vm.prank(ALICE);
        bns.setMinDocumentIat(
            "alice", 1_770_000_000, keccak256("compromised"), _ownerAuth(ALICE), _guard(1)
        );

        uint64 seqBeforeRelease = bns.queryNameState("alice").nameSeq;
        vm.prank(ALICE);
        bns.releaseName(
            "alice",
            ReleaseMode.ReleaseAfterGrace,
            keccak256("release"),
            _ownerAuth(ALICE),
            _guard(seqBeforeRelease)
        );

        _registerRoot("alice", BOB);
        NameState memory state = bns.queryNameState("alice");
        assertEqUint(state.lineageEpoch, 1, "lineage epoch marks trust break");
        assertEqUint(state.minDocumentIat, 0, "min iat reset");
        assertEqUint(state.ownerPolicySeq, 0, "owner policy seq reset");
    }
}
