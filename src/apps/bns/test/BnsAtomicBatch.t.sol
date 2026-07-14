// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTestBase.sol";

contract BnsAtomicBatchTest is BnsTestBase {
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

    function _emptyAuthorityUpdates() internal pure returns (AuthorityKeyUpdate[] memory) {
        return new AuthorityKeyUpdate[](0);
    }

    function _registerSelfOwnedWithKey(string memory name, address assetOwner, address keyHolder)
        internal
    {
        AuthorityKeyUpdate[] memory keys = new AuthorityKeyUpdate[](1);
        keys[0] = _authorityUpdate(KID, keyHolder, true);
        ControllerRule[] memory noRules = new ControllerRule[](0);
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);

        (uint64 nameSeq, uint64 authoritySeq,) = bns.registerName(
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
        assertEqUint(nameSeq, 1, "create seq");
        assertEqUint(authoritySeq, 1, "initial authority seq");
    }

    function testApplyMutationsPublishesMultipleDocsWithOneNameSeqBump() public {
        _registerRoot("alice", ALICE);
        uint64 seqBefore = bns.queryNameState("alice").nameSeq;
        uint64 eventsBefore = bns.globalEventSeq();

        DocumentUpdate[] memory docs = new DocumentUpdate[](2);
        docs[0] = _docUpdate("zone", 0, _inlineDoc(bytes("{\"zone\":1}")));
        docs[1] = _docUpdate("boot", 0, _inlineDoc(bytes("{\"boot\":1}")));

        vm.prank(ALICE);
        (uint64 nameSeq, uint64 authoritySeq, bytes32 authorityRoot, uint64 ownerPolicySeq) =
            bns.applyMutations(
                "alice",
                _emptyAuthorityUpdates(),
                docs,
                _noOwnerPolicyUpdate(),
                _ownerAuth(ALICE),
                _guard(seqBefore)
            );

        assertEqUint(nameSeq, seqBefore + 1, "batch bumps nameSeq once");
        assertEqUint(bns.queryNameState("alice").nameSeq, seqBefore + 1, "stored nameSeq");
        assertEqUint(authoritySeq, 0, "authority unchanged");
        assertEqBytes32(authorityRoot, ZERO, "authority root unchanged");
        assertEqUint(ownerPolicySeq, 0, "owner policy unchanged");
        assertEqUint(bns.getDocumentVersion("alice", "zone", 1).version, 1, "zone v1");
        assertEqUint(bns.getDocumentVersion("alice", "boot", 1).version, 1, "boot v1");
        assertEqUint(bns.globalEventSeq(), eventsBefore + 2, "per-document ProtocolEvent");
    }

    function testApplyMutationsAuthorityOnlyDoesNotBumpNameSeq() public {
        _registerRoot("alice", ALICE);
        uint64 seqBefore = bns.queryNameState("alice").nameSeq;

        AuthorityKeyUpdate[] memory keys = new AuthorityKeyUpdate[](1);
        keys[0] = _authorityUpdate(KID, CAROL, true);
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);

        vm.prank(ALICE);
        (uint64 nameSeq, uint64 authoritySeq,, uint64 ownerPolicySeq) =
            bns.applyMutations(
                "alice", keys, noDocs, _noOwnerPolicyUpdate(), _ownerAuth(ALICE), _guard(seqBefore)
            );

        assertEqUint(nameSeq, seqBefore, "authority-only batch does not bump nameSeq");
        assertEqUint(authoritySeq, 1, "authority updated");
        assertEqUint(ownerPolicySeq, 0, "owner policy unchanged");
        assertEqUint(bns.queryNameState("alice").nameSeq, seqBefore, "stored nameSeq unchanged");
    }

    function testApplyMutationsAuthorizesAgainstPreStateBeforeRotatingKeys() public {
        _registerSelfOwnedWithKey("org", ALICE, CAROL);
        uint64 seqBefore = bns.queryNameState("org").nameSeq;

        AuthorityKeyUpdate[] memory keys = new AuthorityKeyUpdate[](2);
        keys[0] = _authorityUpdate(KID, CAROL, false);
        keys[1] = _authorityUpdate(KID2, BOB, true);

        DocumentUpdate[] memory docs = new DocumentUpdate[](1);
        docs[0] = _docUpdate("owner", 0, ownerRef);

        vm.prank(CAROL);
        (uint64 nameSeq, uint64 authoritySeq,, uint64 ownerPolicySeq) =
            bns.applyMutations(
                "org",
                keys,
                docs,
                _noOwnerPolicyUpdate(),
                _ownerAuthName("org", KID),
                _guard(seqBefore)
            );

        assertEqUint(nameSeq, seqBefore + 1, "owner document bumps nameSeq once");
        assertEqUint(authoritySeq, 2, "authority rotated");
        assertEqUint(ownerPolicySeq, 0, "owner policy unchanged");
        assertTrue(
            bns.getAuthorityKey("org", KID).status == AuthorityKeyStatus.Revoked,
            "old key revoked"
        );
        assertTrue(
            bns.getAuthorityKey("org", KID2).status == AuthorityKeyStatus.Active,
            "new key active"
        );
        assertEqUint(bns.getDocumentVersion("org", "owner", 1).version, 1, "owner doc published");
    }

    function testApplyMutationsRejectsEmptyBatch() public {
        _registerRoot("alice", ALICE);
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);

        vm.prank(ALICE);
        vm.expectPartialRevert(InvalidMutation.selector);
        bns.applyMutations(
            "alice",
            _emptyAuthorityUpdates(),
            noDocs,
            _noOwnerPolicyUpdate(),
            _ownerAuth(ALICE),
            _guard(1)
        );
    }

    function testApplyMutationsRejectsDuplicateDocTypes() public {
        _registerRoot("alice", ALICE);
        DocumentUpdate[] memory docs = new DocumentUpdate[](2);
        docs[0] = _docUpdate("zone", 0, _inlineDoc(bytes("{\"zone\":1}")));
        docs[1] = _docUpdate("zone", 1, _inlineDoc(bytes("{\"zone\":2}")));

        vm.prank(ALICE);
        vm.expectPartialRevert(InvalidMutation.selector);
        bns.applyMutations(
            "alice",
            _emptyAuthorityUpdates(),
            docs,
            _noOwnerPolicyUpdate(),
            _ownerAuth(ALICE),
            _guard(1)
        );
    }
}
