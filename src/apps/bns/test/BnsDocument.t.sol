// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTestBase.sol";

/// §1.5 — Documents & large objects: inline content-hash binding, the 4KB
/// inline ceiling vs DocumentRef path, and current-state revoke semantics.
contract BnsDocumentTest is BnsTestBase {
    function setUp() public override {
        super.setUp();
        _registerRoot("alice", ALICE);
    }

    function _seq() internal view returns (uint64) {
        return bns.queryNameState("alice").nameSeq;
    }

    function _bytesOfLen(uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i = 0; i < n; i++) {
            b[i] = 0x61; // 'a'
        }
    }

    // --- inline content hash binding --------------------------------------

    function testInlineContentHashMustMatch() public {
        // Honest hash publishes.
        uint64 s = _seq();
        vm.prank(ALICE);
        uint64 v = _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(s));
        assertEqUint(v, 1, "honest content hash accepted");

        // Tampered hash (!= sha256(body)) is rejected.
        DocumentRef memory bad = _inlineDoc(bytes("{\"k\":\"v\"}"));
        bad.contentHash = keccak256("wrong"); // override with a non-matching hash
        s = _seq();
        vm.prank(ALICE);
        vm.expectPartialRevert(InvalidMutation.selector);
        _publishDoc("alice", "owner", 1, bad, _ownerAuth(ALICE), _guard(s));
    }

    // --- inline ceiling vs DocumentRef ------------------------------------

    function testInlineExactly4KbAccepted() public {
        DocumentRef memory ref = _inlineDoc(_bytesOfLen(4 * 1024)); // == MAX_INLINE_DOCUMENT
        uint64 s = _seq();
        vm.prank(ALICE);
        uint64 v = _publishDoc("alice", "blob", 0, ref, _ownerAuth(ALICE), _guard(s));
        assertEqUint(v, 1, "exactly 4KB inline accepted");
    }

    function testInlineOver4KbRejected() public {
        DocumentRef memory ref = _inlineDoc(_bytesOfLen(4 * 1024 + 1)); // 4KB + 1
        uint64 s = _seq();
        vm.prank(ALICE);
        vm.expectPartialRevert(InlineDocumentTooLarge.selector);
        _publishDoc("alice", "blob", 0, ref, _ownerAuth(ALICE), _guard(s));
    }

    function testLargeContentViaDocumentRef() public {
        bytes memory big = _bytesOfLen(64 * 1024); // far over the inline ceiling
        DocumentRef memory ref = _refDoc("ipfs://Qm-big-object", sha256(big));
        uint64 s = _seq();
        vm.prank(ALICE);
        uint64 v = _publishDoc("alice", "blob", 0, ref, _ownerAuth(ALICE), _guard(s));
        assertEqUint(v, 1, "large object via DocumentRef accepted");

        DocumentState memory st = bns.getDocumentVersion("alice", "blob", 1);
        assertEqBytes32(st.document.storageType, STORAGE_IPFS, "non-inline storage type");
        assertTrue(st.document.inlineDocument.length == 0, "no inline bytes stored");
        assertEqBytes32(st.document.contentHash, sha256(big), "content hash retained");
    }

    // --- current-state revoke semantics ------------------------------------

    function testMissingToRevokedCreatesV1() public {
        uint64 s = _seq();
        vm.prank(ALICE);
        (uint64 version, uint64 nameSeq) = bns.revokeDocument(
            "alice",
            "dns_txt",
            0,
            keccak256("lost-before-publish"),
            _ownerAuth(ALICE),
            _guard(s)
        );

        assertEqUint(version, 1, "missing revoke creates v1");
        assertEqUint(nameSeq, s + 1, "name seq bumped");

        ResolveResult memory resolved = bns.resolveDocument("alice", "dns_txt");
        assertEqUint(resolved.documentState.version, 1, "current pointer is revoked v1");
        assertEqUint(resolved.documentState.previousVersion, 0, "no previous version");
        assertTrue(resolved.status == DocumentStatus.Revoked, "current is revoked");
        assertTrue(
            bns.getDocumentVersion("alice", "dns_txt", 1).status == DocumentStatus.Revoked,
            "v1 stored as revoked"
        );
    }

    function testActiveToRevokedCreatesNewCurrentVersion() public {
        DocumentRef memory r1 = _inlineDoc(bytes("[{\"v\":1}]"));

        uint64 s = _seq();
        vm.prank(ALICE);
        _publishDoc("alice", "dns_txt", 0, r1, _ownerAuth(ALICE), _guard(s)); // v1

        s = _seq();
        vm.prank(ALICE);
        (uint64 version, uint64 nameSeq) = bns.revokeDocument(
            "alice", "dns_txt", 1, keccak256("bad"), _ownerAuth(ALICE), _guard(s)
        );

        assertEqUint(version, 2, "revoke creates v2");
        assertEqUint(nameSeq, s + 1, "name seq bumped");

        ResolveResult memory resolved = bns.resolveDocument("alice", "dns_txt");
        assertEqUint(resolved.documentState.version, 2, "current pointer is revoked v2");
        assertEqUint(resolved.documentState.previousVersion, 1, "points at active v1");
        assertTrue(resolved.status == DocumentStatus.Revoked, "current resolves revoked");

        assertTrue(
            bns.getDocumentVersion("alice", "dns_txt", 1).status == DocumentStatus.Active,
            "historical v1 remains active"
        );
        assertTrue(
            bns.getDocumentVersion("alice", "dns_txt", 2).status == DocumentStatus.Revoked,
            "current v2 stored as revoked"
        );
    }

    function testStaleExpectedVersionRejected() public {
        DocumentRef memory r1 = _inlineDoc(bytes("[{\"v\":1}]"));
        uint64 s = _seq();
        vm.prank(ALICE);
        _publishDoc("alice", "dns_txt", 0, r1, _ownerAuth(ALICE), _guard(s)); // v1

        s = _seq();
        vm.prank(ALICE);
        vm.expectPartialRevert(StaleDocumentVersion.selector);
        bns.revokeDocument(
            "alice", "dns_txt", 0, keccak256("stale"), _ownerAuth(ALICE), _guard(s)
        );
    }

    function testRevokedCanBeRepublishedActive() public {
        uint64 s = _seq();
        vm.prank(ALICE);
        bns.revokeDocument(
            "alice", "dns_txt", 0, keccak256("lost"), _ownerAuth(ALICE), _guard(s)
        ); // v1

        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":2}]"));
        s = _seq();
        vm.prank(ALICE);
        uint64 version = _publishDoc("alice", "dns_txt", 1, r, _ownerAuth(ALICE), _guard(s)); // v2

        ResolveResult memory resolved = bns.resolveDocument("alice", "dns_txt");
        assertEqUint(version, 2, "republish creates v2");
        assertEqUint(resolved.documentState.version, 2, "current pointer is active v2");
        assertEqUint(resolved.documentState.previousVersion, 1, "points at revoked v1");
        assertTrue(resolved.status == DocumentStatus.Active, "current resolves active");
        assertTrue(
            bns.getDocumentVersion("alice", "dns_txt", 1).status == DocumentStatus.Revoked,
            "historical v1 remains revoked"
        );
    }

    function testResolveRevokedDoesNotFallBackToPreviousActive() public {
        DocumentRef memory r1 = _inlineDoc(bytes("[{\"v\":1}]"));
        uint64 s = _seq();
        vm.prank(ALICE);
        _publishDoc("alice", "dns_txt", 0, r1, _ownerAuth(ALICE), _guard(s)); // v1

        s = _seq();
        vm.prank(ALICE);
        bns.revokeDocument(
            "alice", "dns_txt", 1, keccak256("bad"), _ownerAuth(ALICE), _guard(s)
        ); // v2

        ResolveResult memory resolved = bns.resolveDocument("alice", "dns_txt");
        assertEqUint(resolved.documentState.version, 2, "current pointer is revoked v2");
        assertTrue(resolved.status == DocumentStatus.Revoked, "current resolves revoked");
        assertTrue(
            bns.getDocumentVersion("alice", "dns_txt", 1).status == DocumentStatus.Active,
            "old active remains audit-only"
        );
    }

    function testExactChildRevokedDoesNotFallBackToParentDeviceDocument() public {
        DocumentRef memory parentDevice =
            _inlineDoc(bytes("{\"id\":\"did:bns:alice\",\"devices\":[\"laptop\"]}"));
        uint64 s = _seq();
        vm.prank(ALICE);
        _publishDoc("alice", "device", 0, parentDevice, _ownerAuth(ALICE), _guard(s)); // parent v1

        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);
        s = _seq();
        vm.prank(ALICE);
        _registerName(
            "laptop.alice",
            ALICE,
            _defaultOptions(_unset()),
            noDocs,
            _ownerAuth(ALICE),
            _guard(0, s)
        );

        s = bns.queryNameState("laptop.alice").nameSeq;
        vm.prank(ALICE);
        bns.revokeDocument(
            "laptop.alice",
            "device",
            0,
            keccak256("lost-laptop"),
            _ownerAuth(ALICE),
            _guard(s)
        );

        ResolveResult memory resolved = bns.resolveDocument("laptop.alice", "device");
        assertEqUint(resolved.documentState.version, 1, "child current is its own v1");
        assertTrue(resolved.status == DocumentStatus.Revoked, "exact child remains revoked");
        assertTrue(
            bns.resolveDocument("alice", "device").status == DocumentStatus.Active,
            "parent aggregate remains active"
        );
    }
}
