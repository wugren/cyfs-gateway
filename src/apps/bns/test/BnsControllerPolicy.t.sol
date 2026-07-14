// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTestBase.sol";

/// §1.3 — Controller policy permission bitmask, docType scope, validity window.
/// `alice` is owned by ALICE (asset-owner fallback). Controller rules are
/// installed by the owner; the controller acts as CTRL (msg.sender == CTRL).
///
/// NOTE: every `nameSeq` is read into a local BEFORE `vm.prank` /
/// `vm.expectRevert`, because a `queryNameState` call between the cheatcode and
/// the target call would consume the single-shot cheat.
contract BnsControllerPolicyTest is BnsTestBase {
    function setUp() public override {
        super.setUp();
        _registerRoot("alice", ALICE);
    }

    function _seq() internal view returns (uint64) {
        return bns.queryNameState("alice").nameSeq;
    }

    /// Install a controller policy (single rule) as the owner.
    function _installPolicy(string memory docType, uint32 perms, uint64 validFrom, uint64 validUntil)
        internal
    {
        ControllerRule[] memory rules = _singleRule(_chain(CTRL), docType, perms, validFrom, validUntil);
        uint64 s = _seq();
        vm.prank(ALICE);
        bns.setControllerPolicy("alice", rules, keccak256("policy"), _ownerAuth(ALICE), _guard(s));
    }

    /// Owner publishes an initial dns_txt doc (so revoke / setPayment have a target).
    function _ownerPublishDnsTxt() internal returns (uint64) {
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"a\"}]"));
        uint64 s = _seq();
        vm.prank(ALICE);
        return _publishDoc("alice", "dns_txt", 0, r, _ownerAuth(ALICE), _guard(s));
    }

    // --- per-permission bit ------------------------------------------------

    function testPublishPermissionBit() public {
        _installPolicy("", bns.PERMISSION_PUBLISH_DOCUMENT(), 0, 0);

        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"a\"}]"));
        uint64 s = _seq();
        vm.prank(CTRL);
        uint64 v = _publishDoc("alice", "dns_txt", 0, r, _controllerAuth(CTRL), _guard(s));
        assertEqUint(v, 1, "controller with PUBLISH bit can publish");

        // Lacks REVOKE bit -> revoke denied.
        s = _seq();
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        bns.revokeDocument(
            "alice", "dns_txt", 1, keccak256("r"), _controllerAuth(CTRL), _guard(s)
        );
    }

    function testRevokePermissionBit() public {
        _ownerPublishDnsTxt(); // v1 exists
        _installPolicy("", bns.PERMISSION_REVOKE_DOCUMENT(), 0, 0);

        uint64 s = _seq();
        vm.prank(CTRL);
        bns.revokeDocument(
            "alice", "dns_txt", 1, keccak256("r"), _controllerAuth(CTRL), _guard(s)
        );
        assertTrue(
            bns.resolveDocument("alice", "dns_txt").status == DocumentStatus.Revoked, "revoked"
        );

        // Lacks PUBLISH bit -> publish denied.
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"b\"}]"));
        s = _seq();
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        _publishDoc("alice", "dns_txt", 2, r, _controllerAuth(CTRL), _guard(s));
    }

    function testSetPaymentPermissionBit() public {
        _ownerPublishDnsTxt(); // v1 exists
        _installPolicy("", bns.PERMISSION_SET_PAYMENT(), 0, 0);

        uint64 s = _seq();
        vm.prank(CTRL);
        bns.setPaymentTarget(
            "alice", "dns_txt", 1, BOB, _unset(), keccak256("pp"), ZERO, ZERO, ZERO,
            _controllerAuth(CTRL), _guard(s)
        );
        ( , address paymentTarget, , , , , ) = bns.resolvePaymentTarget("alice", "dns_txt", 1);
        assertTrue(paymentTarget == BOB, "payment target set");

        // Lacks PUBLISH bit -> publish denied.
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"b\"}]"));
        s = _seq();
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        _publishDoc("alice", "dns_txt", 1, r, _controllerAuth(CTRL), _guard(s));
    }

    function testSetAliasPermissionBit() public {
        _installPolicy("", bns.PERMISSION_SET_ALIAS(), 0, 0);

        uint64 s = _seq();
        vm.prank(CTRL);
        bns.setDidAlias(
            "alice", "did:bns:alice", AliasKind.Alias, keccak256("proof"),
            _controllerAuth(CTRL), _guard(s)
        );
        AliasState memory a = bns.getAlias("alice");
        assertTrue(a.kind == AliasKind.Alias, "alias kind set");

        // Lacks PUBLISH bit -> publish denied.
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"b\"}]"));
        s = _seq();
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        _publishDoc("alice", "dns_txt", 0, r, _controllerAuth(CTRL), _guard(s));
    }

    function testSetNamespacePermissionBit() public {
        _installPolicy("", bns.PERMISSION_SET_NAMESPACE(), 0, 0);

        uint64 s = _seq();
        vm.prank(CTRL);
        bns.setNamespacePolicy("alice", true, keccak256("ns"), _controllerAuth(CTRL), _guard(s));
        assertEqBytes32(
            bns.queryNameState("alice").namespacePolicyHash, keccak256("ns"), "namespace policy set"
        );

        // Lacks SET_ALIAS bit -> alias denied.
        s = _seq();
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        bns.setDidAlias(
            "alice", "did:bns:alice", AliasKind.Alias, keccak256("p"), _controllerAuth(CTRL), _guard(s)
        );
    }

    // --- docType scope -----------------------------------------------------

    function testDocTypeScopeMatchAndMismatch() public {
        _installPolicy("dns_txt", bns.PERMISSION_PUBLISH_DOCUMENT(), 0, 0);

        // Matching docType: allowed.
        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"a\"}]"));
        uint64 s = _seq();
        vm.prank(CTRL);
        uint64 v = _publishDoc("alice", "dns_txt", 0, r, _controllerAuth(CTRL), _guard(s));
        assertEqUint(v, 1, "scoped docType allowed");

        // Different docType: denied.
        DocumentRef memory r2 = _inlineDoc(bytes("site-data"));
        s = _seq();
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        _publishDoc("alice", "site", 0, r2, _controllerAuth(CTRL), _guard(s));
    }

    function testControllerCannotPublishOwnerScopedDoc() public {
        // Controller scoped to dns_txt must never reach the owner document.
        _installPolicy("dns_txt", bns.PERMISSION_PUBLISH_DOCUMENT(), 0, 0);

        uint64 s = _seq();
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _controllerAuth(CTRL), _guard(s));
    }

    // --- validity window ---------------------------------------------------

    function testValidityWindow() public {
        vm.warp(1000);
        // valid only in [2000, 3000)
        _installPolicy("", bns.PERMISSION_PUBLISH_DOCUMENT(), 2000, 3000);

        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"a\"}]"));

        // Not yet valid.
        uint64 s = _seq();
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        _publishDoc("alice", "dns_txt", 0, r, _controllerAuth(CTRL), _guard(s));

        // Inside the window.
        vm.warp(2500);
        s = _seq();
        vm.prank(CTRL);
        uint64 v = _publishDoc("alice", "dns_txt", 0, r, _controllerAuth(CTRL), _guard(s));
        assertEqUint(v, 1, "in-window publish");

        // Expired.
        vm.warp(3500);
        s = _seq();
        vm.prank(CTRL);
        vm.expectPartialRevert(ControllerScopeDenied.selector);
        _publishDoc("alice", "dns_txt", 1, r, _controllerAuth(CTRL), _guard(s));
    }
}
