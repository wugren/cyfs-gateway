// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTestBase.sol";

/// §1.2 — Access control / signature boundary.
/// Core invariant under test: the contract only trusts `msg.sender`; the
/// `CallAuthority` struct is merely a role/kid hint. `_authenticateExpectedPrincipal`
/// must reconcile the resolved effective owner, the CallAuthority.actor, and msg.sender.
contract BnsAccessControlTest is BnsTestBase {
    // --- CallAuthority.actor address must equal msg.sender -----------------

    function testActorEqualsSenderPasses() public {
        _registerRoot("alice", ALICE);
        uint64 seq = bns.queryNameState("alice").nameSeq;

        vm.prank(ALICE);
        uint64 version = _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(seq));
        assertEqUint(version, 1, "owner doc published");
    }

    function testDifferentSenderSameAuthorityReverts() public {
        // CallAuthority unchanged (actor == ALICE) but msg.sender changed to BOB.
        _registerRoot("alice", ALICE);
        uint64 seq = bns.queryNameState("alice").nameSeq;

        vm.prank(BOB);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(seq));
    }

    function testActorNotMatchingSenderReverts() public {
        // msg.sender == ALICE (the real owner) but CallAuthority.actor claims BOB.
        _registerRoot("alice", ALICE);
        uint64 seq = bns.queryNameState("alice").nameSeq;

        vm.prank(ALICE);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(BOB), _guard(seq));
    }

    // --- role gating -------------------------------------------------------

    function testOwnerRoleByNonOwnerReverts() public {
        _registerRoot("alice", ALICE);
        uint64 seq = bns.queryNameState("alice").nameSeq;

        // role=Owner, actor=BOB, sender=BOB — BOB is not the owner.
        vm.prank(BOB);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(BOB), _guard(seq));
    }

    function testControllerRoleByUnregisteredControllerReverts() public {
        _registerRoot("alice", ALICE); // no controller policy installed
        uint64 seq = bns.queryNameState("alice").nameSeq;

        DocumentRef memory r = _inlineDoc(bytes("[]"));
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        _publishDoc("alice", "dns_txt", 0, r, _controllerAuth(CTRL), _guard(seq));
    }

    // --- authority key (BNS-name owned) -----------------------------------

    /// Make `org` self-owned (semanticOwner == bnsName "org") with an
    /// address-backed authority key. Returns the current name seq.
    function _selfOwnedWithKey(string memory name, bytes32 kid, address keyAddr, address assetOwner)
        internal
        returns (uint64 seq)
    {
        _registerRoot(name, assetOwner);
        seq = bns.queryNameState(name).nameSeq;
        seq = _installAuthorityKey(name, kid, keyAddr, assetOwner, 0, 0, seq);
        vm.prank(assetOwner);
        bns.setNameOwner(name, _bnsName(name), _ownerAuth(assetOwner), _guard(seq));
        seq = bns.queryNameState(name).nameSeq;

        NameState memory st = bns.queryNameState(name);
        assertTrue(st.ownerSource == OwnerSource.ExplicitSemanticOwner, "explicit owner");
        assertTrue(!st.standardTransferEnabled, "standard transfer disabled after takeover");
    }

    function testAuthorityKeyAddressMustEqualSender() public {
        uint64 seq = _selfOwnedWithKey("org", KID, CAROL, ALICE);

        // Key holder CAROL can publish the owner doc.
        vm.prank(CAROL);
        uint64 version = _publishDoc("org", "owner", 0, ownerRef, _ownerAuthName("org", KID), _guard(seq));
        assertEqUint(version, 1, "key holder publishes");

        // Same CallAuthority but a different sender (BOB) is rejected.
        seq = bns.queryNameState("org").nameSeq;
        vm.prank(BOB);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("org", "owner", 1, ownerRef, _ownerAuthName("org", KID), _guard(seq));
    }

    function testOldAssetOwnerLosesAuthorityAfterTakeover() public {
        uint64 seq = _selfOwnedWithKey("org", KID, CAROL, ALICE);

        // The former asset owner (ALICE) can no longer write — owner is now a BNS name.
        vm.prank(ALICE);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("org", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(seq));
    }

    function testExpiredAuthorityKeyReverts() public {
        _registerRoot("org", ALICE);
        uint64 seq = bns.queryNameState("org").nameSeq;
        // key valid only until t=2000
        seq = _installAuthorityKey("org", KID, CAROL, ALICE, 0, 2000, seq);
        vm.prank(ALICE);
        bns.setNameOwner("org", _bnsName("org"), _ownerAuth(ALICE), _guard(seq));
        seq = bns.queryNameState("org").nameSeq;

        // Before expiry: works.
        vm.warp(1000);
        vm.prank(CAROL);
        uint64 version = _publishDoc("org", "owner", 0, ownerRef, _ownerAuthName("org", KID), _guard(seq));
        assertEqUint(version, 1, "valid window publish");

        // After expiry: key no longer authenticates.
        seq = bns.queryNameState("org").nameSeq;
        vm.warp(3000);
        vm.prank(CAROL);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("org", "owner", 1, ownerRef, _ownerAuthName("org", KID), _guard(seq));
    }

    function testRevokedAuthorityKeyReverts() public {
        _registerRoot("org", ALICE);
        uint64 seq = bns.queryNameState("org").nameSeq;
        seq = _installAuthorityKey("org", KID, CAROL, ALICE, 0, 0, seq);
        seq = _installAuthorityKey("org", KID2, BOB, ALICE, 0, 0, seq);
        vm.prank(ALICE);
        bns.setNameOwner("org", _bnsName("org"), _ownerAuth(ALICE), _guard(seq));
        seq = bns.queryNameState("org").nameSeq;

        // Revoke KID (CAROL) using KID2 (BOB) as a still-active owner key.
        AuthorityKeyUpdate[] memory revoke = new AuthorityKeyUpdate[](1);
        revoke[0] = AuthorityKeyUpdate({
            key: AuthorityKey({
                kid: KID,
                verificationMethod: METHOD_EIP155_ACCOUNT,
                keyData: abi.encodePacked(CAROL),
                purposes: bns.KEY_PURPOSE_AUTHENTICATION(),
                validFrom: 0,
                validUntil: 0,
                status: AuthorityKeyStatus.Active,
                metadataHash: ZERO
            }),
            active: false // <-- revoke
        });
        vm.prank(BOB);
        bns.updateAuthorityKeys("org", revoke, _ownerAuthName("org", KID2), _guard(seq));
        seq = bns.queryNameState("org").nameSeq;

        // CAROL's revoked key no longer authenticates.
        vm.prank(CAROL);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("org", "owner", 0, ownerRef, _ownerAuthName("org", KID), _guard(seq));

        // The remaining active key (BOB) still works.
        vm.prank(BOB);
        uint64 version = _publishDoc("org", "owner", 0, ownerRef, _ownerAuthName("org", KID2), _guard(seq));
        assertEqUint(version, 1, "remaining key publishes");
    }

    // --- ownership transfer shifts write power ----------------------------

    function testTransferNameShiftsWritePower() public {
        _registerRoot("alice", ALICE);
        uint64 seq = bns.queryNameState("alice").nameSeq;

        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);
        vm.prank(ALICE);
        bns.transferName("alice", BOB, _unset(), noDocs, _ownerAuth(ALICE), _guard(seq));

        NameState memory st = bns.queryNameState("alice");
        assertTrue(st.assetOwner == BOB, "asset owner is BOB");
        seq = st.nameSeq;

        // Old owner ALICE can no longer write.
        vm.prank(ALICE);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(seq));

        // New owner BOB can write.
        vm.prank(BOB);
        uint64 version = _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(BOB), _guard(seq));
        assertEqUint(version, 1, "new owner publishes");
    }

    function testSetNameOwnerShiftsWritePowerToBnsAuthority() public {
        // keyholder name carries an authority key held by CAROL.
        _registerRoot("keyholder", ALICE);
        uint64 khSeq = bns.queryNameState("keyholder").nameSeq;
        _installAuthorityKey("keyholder", KID, CAROL, ALICE, 0, 0, khSeq);

        _registerRoot("org", BOB);
        uint64 seq = bns.queryNameState("org").nameSeq;

        vm.prank(BOB);
        bns.setNameOwner("org", _bnsName("keyholder"), _ownerAuth(BOB), _guard(seq));
        seq = bns.queryNameState("org").nameSeq;

        // Former asset owner BOB loses write power.
        vm.prank(BOB);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("org", "owner", 0, ownerRef, _ownerAuth(BOB), _guard(seq));

        // keyholder's key (CAROL) gains write power over org.
        vm.prank(CAROL);
        uint64 version = _publishDoc("org", "owner", 0, ownerRef, _ownerAuthName("keyholder", KID), _guard(seq));
        assertEqUint(version, 1, "delegated authority publishes");
    }

    // --- _authorizeOwner and _authorizeUpdate must agree on effectiveOwner -

    function testAuthorizeOwnerAndUpdatePathsAgreeUnderAuthorityKey() public {
        uint64 seq = _selfOwnedWithKey("org", KID, CAROL, ALICE);

        // _authorizeOwner path (setControllerPolicy) accepts the key holder.
        ControllerRule[] memory rules =
            _singleRule(_chain(CTRL), "dns_txt", bns.PERMISSION_PUBLISH_DOCUMENT(), 0, 0);
        vm.prank(CAROL);
        bns.setControllerPolicy("org", rules, keccak256("p"), _ownerAuthName("org", KID), _guard(seq));
        seq = bns.queryNameState("org").nameSeq;

        // _authorizeUpdate (Owner role) path also accepts the same key holder.
        vm.prank(CAROL);
        uint64 version = _publishDoc("org", "owner", 0, ownerRef, _ownerAuthName("org", KID), _guard(seq));
        assertEqUint(version, 1, "both authorize paths agree");

        // A non-key sender is rejected on both paths.
        seq = bns.queryNameState("org").nameSeq;
        vm.prank(BOB);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        bns.setControllerPolicy("org", rules, keccak256("p2"), _ownerAuthName("org", KID), _guard(seq));

        vm.prank(BOB);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _publishDoc("org", "owner", 1, ownerRef, _ownerAuthName("org", KID), _guard(seq));
    }
}
