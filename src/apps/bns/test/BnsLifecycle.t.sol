// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTestBase.sol";

/// §1.6 — Name lifecycle & namespace: register / bootstrap / renew / release,
/// namespace policy, DID alias & payment target read-write, log checkpoint.
contract BnsLifecycleTest is BnsTestBase {
    function _seq(string memory name) internal view returns (uint64) {
        return bns.queryNameState(name).nameSeq;
    }

    function _registerWith(string memory name, address owner, RegisterOptions memory opts)
        internal
        returns (uint64)
    {
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);
        return _registerName(name, owner, opts, noDocs, _noneAuth(), _guard(0));
    }

    // --- renew -------------------------------------------------------------

    function testRenewBeforeExpiryExtendsFromExpireAt() public {
        vm.warp(1000);
        _registerWith("alice", ALICE, _options(100 days, 30 days, true, true));
        uint64 expireAt = bns.queryNameState("alice").expireAt;
        assertEqUint(expireAt, 1000 + 100 days, "initial expireAt");

        vm.warp(1000 + 50 days); // before expiry
        uint64 newExpire = bns.renewName("alice", 100 days);
        assertEqUint(newExpire, expireAt + 100 days, "renew stacks on existing expireAt");
    }

    function testRenewAfterExpiryExtendsFromNow() public {
        vm.warp(1000);
        _registerWith("alice", ALICE, _options(100 days, 30 days, true, true));

        vm.warp(1000 + 200 days); // past expiry
        uint64 newExpire = bns.renewName("alice", 100 days);
        assertEqUint(newExpire, uint64(1000 + 200 days) + 100 days, "renew rebases on now after expiry");
    }

    function testRenewNonRenewableRejected() public {
        _registerWith("alice", ALICE, _options(100 days, 30 days, false, true));
        vm.expectPartialRevert(InvalidMutation.selector);
        bns.renewName("alice", 10 days);
    }

    // --- release / tombstone ----------------------------------------------

    function testReleasedNameRejectsWritesAndCanBeReRegistered() public {
        _registerRoot("alice", ALICE);
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        bns.releaseName("alice", ReleaseMode.ReleaseAfterGrace, keccak256("done"), _ownerAuth(ALICE), _guard(s));
        assertTrue(bns.queryNameState("alice").status == NameStatus.Released, "released");

        // State writes are rejected on a released name.
        s = _seq("alice");
        vm.prank(ALICE);
        vm.expectPartialRevert(NameNotFound.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(s));

        // A released name can be claimed again.
        _registerRoot("alice", BOB);
        assertTrue(bns.queryNameState("alice").status == NameStatus.Active, "re-registered active");
        assertTrue(bns.queryNameState("alice").assetOwner == BOB, "new owner after re-register");
    }

    function testTombstonedNameRejectsWritesAndReRegistration() public {
        _registerRoot("alice", ALICE);
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        bns.releaseName("alice", ReleaseMode.TombstoneForever, keccak256("evil"), _ownerAuth(ALICE), _guard(s));
        assertTrue(bns.queryNameState("alice").status == NameStatus.Tombstoned, "tombstoned");

        // Writes rejected.
        s = _seq("alice");
        vm.prank(ALICE);
        vm.expectPartialRevert(NameNotFound.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(s));

        // Re-registration is permanently blocked.
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);
        vm.expectPartialRevert(NameAlreadyExists.selector);
        _registerName("alice", BOB, _defaultOptions(_unset()), noDocs, _noneAuth(), _guard(0));
    }

    // --- bootstrap (atomic install) ---------------------------------------

    function testBootstrapInstallsAuthorityOwnerAndControllerPolicy() public {
        AuthorityKeyUpdate[] memory keys = new AuthorityKeyUpdate[](1);
        keys[0] = AuthorityKeyUpdate({
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
            active: true
        });
        ControllerRule[] memory rules =
            _singleRule(_chain(CTRL), "dns_txt", bns.PERMISSION_PUBLISH_DOCUMENT(), 0, 0);
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);

        (uint64 nameSeq, uint64 authoritySeq,) = bns.registerName(
            "zone",
            ALICE,
            _defaultOptions(_unset()),
            keys,
            _bnsName("zone"), // self-owned after authority install
            rules,
            keccak256("ctrl-policy"),
            noDocs,
            _noneAuth(),
            _guard(0)
        );
        assertEqUint(nameSeq, 1, "bootstrap register keeps create nameSeq");
        assertEqUint(authoritySeq, 1, "authority installed");

        NameState memory st = bns.queryNameState("zone");
        assertTrue(st.ownerSource == OwnerSource.ExplicitSemanticOwner, "self semantic owner");
        assertTrue(bns.getAuthoritySet("zone").activeKeyCount >= 1, "authority key installed");

        // The bootstrapped controller policy is effective: CTRL can publish dns_txt.
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"a\"}]"));
        uint64 s = _seq("zone");
        vm.prank(CTRL);
        uint64 v = _publishDoc("zone", "dns_txt", 0, r, _controllerAuth(CTRL), _guard(s));
        assertEqUint(v, 1, "bootstrapped controller can publish");
    }

    // --- namespace policy --------------------------------------------------

    function testSetNamespacePolicyReadWrite() public {
        _registerRoot("alice", ALICE);
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        bns.setNamespacePolicy("alice", false, keccak256("ns-policy"), _ownerAuth(ALICE), _guard(s));

        NameState memory st = bns.queryNameState("alice");
        assertTrue(!st.allowDelegatedSubnames, "allowDelegatedSubnames updated");
        assertEqBytes32(st.namespacePolicyHash, keccak256("ns-policy"), "namespace policy hash stored");
    }

    // --- DID alias / payment target ---------------------------------------

    function testSetDidAliasReadWrite() public {
        _registerRoot("alice", ALICE);
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        bns.setDidAlias(
            "alice", "did:web:alice.example", AliasKind.MigratedTo, keccak256("alias-proof"),
            _ownerAuth(ALICE), _guard(s)
        );

        AliasState memory a = bns.getAlias("alice");
        assertTrue(a.kind == AliasKind.MigratedTo, "alias kind");
        assertTrue(
            keccak256(bytes(a.targetDid)) == keccak256(bytes("did:web:alice.example")), "alias target"
        );
        assertEqBytes32(a.proofHash, keccak256("alias-proof"), "alias proof");
    }

    function testSetPaymentTargetReadWrite() public {
        _registerRoot("alice", ALICE);
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"a\"}]"));
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        _publishDoc("alice", "dns_txt", 0, r, _ownerAuth(ALICE), _guard(s)); // v1

        s = _seq("alice");
        vm.prank(ALICE);
        bns.setPaymentTarget(
            "alice", "dns_txt", 1, BOB, _chain(CAROL), keccak256("pp"), keccak256("sp"),
            keccak256("pr"), keccak256("ri"), _ownerAuth(ALICE), _guard(s)
        );

        (
            Principal memory beneficiary,
            address paymentTarget,
            bytes32 paymentPolicyHash,
            bytes32 splitPolicyHash,
            ,
            ,
        ) = bns.resolvePaymentTarget("alice", "dns_txt", 1);
        assertTrue(paymentTarget == BOB, "payment target");
        assertTrue(beneficiary.kind == PrincipalKind.ChainAccount, "beneficiary kind");
        assertEqBytes32(paymentPolicyHash, keccak256("pp"), "payment policy hash");
        assertEqBytes32(splitPolicyHash, keccak256("sp"), "split policy hash");
    }

    // --- log checkpoint ----------------------------------------------------

    function testPublishLogCheckpointOverwrites() public {
        _registerRoot("alice", ALICE); // advances globalEventSeq

        // The checkpoint snapshots the log as-of just before its own commit event.
        bytes32 rootBefore = bns.currentLogRoot();
        uint64 seqBefore = bns.globalEventSeq();
        bns.publishLogCheckpoint(_chain(ALICE), keccak256("anchor-1"));
        LogCheckpoint memory cp1 = bns.latestCheckpoint();
        assertEqBytes32(cp1.logRoot, rootBefore, "checkpoint logRoot == pre-commit root");
        assertEqUint(cp1.lastSeq, seqBefore, "checkpoint lastSeq == pre-commit seq");
        assertEqBytes32(cp1.externalAnchor, keccak256("anchor-1"), "anchor 1");

        // More activity, then a second checkpoint overwrites the first.
        _registerRoot("bob", BOB);
        bytes32 rootBefore2 = bns.currentLogRoot();
        bns.publishLogCheckpoint(_chain(BOB), keccak256("anchor-2"));
        LogCheckpoint memory cp2 = bns.latestCheckpoint();
        assertEqBytes32(cp2.logRoot, rootBefore2, "checkpoint2 logRoot == pre-commit root");
        assertTrue(cp2.lastSeq > cp1.lastSeq, "lastSeq advanced");
        assertEqBytes32(cp2.externalAnchor, keccak256("anchor-2"), "anchor 2 overwrote anchor 1");
    }
}
