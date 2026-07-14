// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTestBase.sol";

/// §1.7 — Event assertions. These pin the topics/data the indexer decodes.
/// Where an event carries a non-reconstructible field (documentStateHash,
/// authorityRoot, logRoot in data) we assert the indexed topics only
/// (checkData=false) and verify the derived field via a state read.
contract BnsEventsTest is BnsTestBase {
    function _nameHash(string memory name) internal pure returns (bytes32) {
        return keccak256(bytes(name));
    }

    function _seq(string memory name) internal view returns (uint64) {
        return bns.queryNameState(name).nameSeq;
    }

    // --- registration ------------------------------------------------------

    function testEmitNameRegistered() public {
        vm.warp(1000);
        bytes32 nh = _nameHash("reg");
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);

        vm.expectEmit(true, true, true, true, address(bns));
        emit NameRegistered(nh, "reg", ALICE, ALICE, uint64(1000 + 365 days), 0, 1);
        vm.prank(ALICE);
        _registerName("reg", ALICE, _defaultOptions(_unset()), noDocs, _noneAuth(), _guard(0));
    }

    function testEmitProtocolEventOnRegister() public {
        bytes32 nh = _nameHash("reg");
        nh; // not part of ProtocolEvent topics
        vm.expectEmit(true, true, true, false, address(bns));
        emit ProtocolEvent(1, keccak256("name_registered"), ALICE, bytes32(0), bytes32(0));
        vm.prank(ALICE);
        _registerRoot("reg", ALICE);
    }

    // --- document publish / revoke ----------------------------------------

    function testEmitDocumentPublished() public {
        _registerRoot("alice", ALICE);
        bytes32 nh = _nameHash("alice");
        uint64 s = _seq("alice");

        // documentStateHash is non-reconstructible here -> check indexed topics only.
        vm.expectEmit(true, true, true, false, address(bns));
        emit DocumentPublished(nh, "alice", "owner", 1, ALICE, sha256(DOC_OWNER_BODY), bytes32(0));
        vm.prank(ALICE);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(s));

        // The contentHash carried in the (unchecked) data is the real one.
        assertEqBytes32(
            bns.getDocumentVersion("alice", "owner", 1).document.contentHash,
            sha256(DOC_OWNER_BODY),
            "contentHash persisted"
        );
    }

    function testEmitDocumentRevoked() public {
        _registerRoot("alice", ALICE);
        bytes32 nh = _nameHash("alice");
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":1}]"));
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        _publishDoc("alice", "dns_txt", 0, r, _ownerAuth(ALICE), _guard(s)); // v1

        s = _seq("alice");
        vm.expectEmit(true, true, true, true, address(bns));
        emit DocumentRevoked(nh, "alice", "dns_txt", ALICE, 1, 2, keccak256("reason"));
        vm.prank(ALICE);
        bns.revokeDocument(
            "alice", "dns_txt", 1, keccak256("reason"), _ownerAuth(ALICE), _guard(s)
        );
    }

    function testEmitOwnerDocumentIatFloorUpdated() public {
        _registerRoot("alice", ALICE);
        bytes32 nh = _nameHash("alice");
        uint64 s = _seq("alice");

        vm.expectEmit(true, true, true, true, address(bns));
        emit OwnerDocumentIatFloorUpdated(
            nh, "alice", ALICE, 0, 1_770_000_000, 1, s + 1, keccak256("compromised")
        );
        vm.prank(ALICE);
        bns.setMinDocumentIat(
            "alice", 1_770_000_000, keccak256("compromised"), _ownerAuth(ALICE), _guard(s)
        );
    }

    // --- controller / namespace / alias / payment -------------------------

    function testEmitControllerPolicyUpdated() public {
        _registerRoot("alice", ALICE);
        bytes32 nh = _nameHash("alice");
        ControllerRule[] memory rules =
            _singleRule(_chain(CTRL), "dns_txt", bns.PERMISSION_PUBLISH_DOCUMENT(), 0, 0);
        uint64 s = _seq("alice");

        vm.expectEmit(true, true, true, true, address(bns));
        emit ControllerPolicyUpdated(nh, "alice", ALICE, keccak256("cp"), s + 1);
        vm.prank(ALICE);
        bns.setControllerPolicy("alice", rules, keccak256("cp"), _ownerAuth(ALICE), _guard(s));
    }

    function testEmitNamespacePolicyUpdated() public {
        _registerRoot("alice", ALICE);
        bytes32 nh = _nameHash("alice");
        uint64 s = _seq("alice");

        vm.expectEmit(true, true, true, true, address(bns));
        emit NamespacePolicyUpdated(nh, "alice", ALICE, false, keccak256("ns"), s + 1);
        vm.prank(ALICE);
        bns.setNamespacePolicy("alice", false, keccak256("ns"), _ownerAuth(ALICE), _guard(s));
    }

    function testEmitDidAliasSet() public {
        _registerRoot("alice", ALICE);
        bytes32 nh = _nameHash("alice");
        uint64 s = _seq("alice");

        vm.expectEmit(true, true, true, true, address(bns));
        emit DidAliasSet(nh, "alice", ALICE, "did:bns:alice", AliasKind.Alias, keccak256("pf"), s + 1);
        vm.prank(ALICE);
        bns.setDidAlias("alice", "did:bns:alice", AliasKind.Alias, keccak256("pf"), _ownerAuth(ALICE), _guard(s));
    }

    function testEmitPaymentTargetUpdated() public {
        _registerRoot("alice", ALICE);
        bytes32 nh = _nameHash("alice");
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":1}]"));
        uint64 s = _seq("alice");
        vm.prank(ALICE);
        _publishDoc("alice", "dns_txt", 0, r, _ownerAuth(ALICE), _guard(s)); // v1

        s = _seq("alice");
        vm.expectEmit(true, true, true, true, address(bns));
        emit PaymentTargetUpdated(nh, "alice", "dns_txt", ALICE, BOB, keccak256("pp"), 1);
        vm.prank(ALICE);
        bns.setPaymentTarget(
            "alice", "dns_txt", 1, BOB, _unset(), keccak256("pp"), ZERO, ZERO, ZERO,
            _ownerAuth(ALICE), _guard(s)
        );
    }

    // --- authority keys ----------------------------------------------------

    function testEmitAuthorityKeysUpdated() public {
        _registerRoot("alice", ALICE);
        bytes32 nh = _nameHash("alice");
        AuthorityKeyUpdate[] memory updates = new AuthorityKeyUpdate[](1);
        updates[0] = AuthorityKeyUpdate({
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
        uint64 s = _seq("alice");

        // authorityRoot is non-reconstructible -> indexed topics only.
        vm.expectEmit(true, true, false, false, address(bns));
        emit AuthorityKeysUpdated(nh, "alice", ALICE, 0, bytes32(0));
        vm.prank(ALICE);
        bns.updateAuthorityKeys("alice", updates, _ownerAuth(ALICE), _guard(s));
    }

    // --- renew / transfer / release ---------------------------------------

    function testEmitNameRenewed() public {
        vm.warp(1000);
        _registerWith("alice", ALICE, _options(100 days, 30 days, true, true));
        bytes32 nh = _nameHash("alice");
        uint64 s = _seq("alice");

        vm.expectEmit(true, true, false, true, address(bns));
        emit NameRenewed(nh, "alice", ALICE, uint64(1000 + 100 days) + 50 days, s + 1);
        vm.prank(ALICE);
        bns.renewName("alice", 50 days);
    }

    function testEmitNameAssetTransferred() public {
        _registerRoot("alice", ALICE);
        bytes32 nh = _nameHash("alice");
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);
        uint64 s = _seq("alice");

        vm.expectEmit(true, true, true, true, address(bns));
        emit NameAssetTransferred(nh, "alice", ALICE, BOB, false, s + 1);
        vm.prank(ALICE);
        bns.transferName("alice", BOB, _unset(), noDocs, _ownerAuth(ALICE), _guard(s));
    }

    function testEmitNameReleased() public {
        _registerRoot("alice", ALICE);
        bytes32 nh = _nameHash("alice");
        uint64 s = _seq("alice");

        vm.expectEmit(true, true, false, true, address(bns));
        emit NameReleased(nh, "alice", ALICE, ReleaseMode.ReleaseAfterGrace, keccak256("bye"), s + 1);
        vm.prank(ALICE);
        bns.releaseName("alice", ReleaseMode.ReleaseAfterGrace, keccak256("bye"), _ownerAuth(ALICE), _guard(s));
    }

    // --- checkpoint --------------------------------------------------------

    function testEmitLogCheckpointPublished() public {
        vm.warp(7777);
        _registerRoot("alice", ALICE);
        bytes32 rootBefore = bns.currentLogRoot();
        uint64 seqBefore = bns.globalEventSeq();

        vm.expectEmit(true, true, false, true, address(bns));
        emit LogCheckpointPublished(rootBefore, ALICE, seqBefore, 7777, keccak256("anchor"));
        vm.prank(ALICE);
        bns.publishLogCheckpoint(_chain(ALICE), keccak256("anchor"));
    }

    function _registerWith(string memory name, address owner, RegisterOptions memory opts) internal {
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);
        _registerName(name, owner, opts, noDocs, _noneAuth(), _guard(0));
    }
}
