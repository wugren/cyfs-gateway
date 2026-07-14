// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTestBase.sol";

/// §1.4 — MutationGuard / replay protection.
/// Covers expectedNameSeq + expectedParentNameSeq, chain/address domain
/// separation baked into logRoot & documentStateHash, and the chained
/// seq/previousLogRoot/logRoot continuity of `ProtocolEvent`.
contract BnsGuardReplayTest is BnsTestBase {
    bytes32 constant PROTOCOL_EVENT_SIG =
        keccak256("ProtocolEvent(uint64,bytes32,address,bytes32,bytes32)");

    // --- expectedNameSeq ---------------------------------------------------

    function testExpectedNameSeqMismatchAndMatch() public {
        _registerRoot("alice", ALICE); // seq == 1

        // Wrong expected seq -> StaleNameSeq (thrown before authorization).
        vm.prank(ALICE);
        vm.expectPartialRevert(StaleNameSeq.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(999));

        // Correct expected seq -> succeeds.
        vm.prank(ALICE);
        uint64 v = _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(1));
        assertEqUint(v, 1, "matching guard publishes");
    }

    // --- expectedParentNameSeq (subname registration) ---------------------

    function testExpectedParentNameSeq() public {
        _registerRoot("alice", ALICE);
        uint64 parentSeq = bns.queryNameState("alice").nameSeq;
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);
        RegisterOptions memory opts = _defaultOptions(_unset());

        // Wrong parent seq -> StaleParentNameSeq.
        vm.prank(ALICE);
        vm.expectPartialRevert(StaleParentNameSeq.selector);
        _registerName("sub.alice", BOB, opts, noDocs, _ownerAuth(ALICE), _guard(0, 999));

        // Correct parent seq -> child registered.
        vm.prank(ALICE);
        _registerName("sub.alice", BOB, opts, noDocs, _ownerAuth(ALICE), _guard(0, parentSeq));
        NameState memory st = bns.queryNameState("sub.alice");
        assertTrue(st.status == NameStatus.Active, "subname active");
        assertTrue(st.assetOwner == BOB, "subname asset owner");
    }

    function testSubnameRegistrationRequiresParentOwner() public {
        _registerRoot("alice", ALICE);
        uint64 parentSeq = bns.queryNameState("alice").nameSeq;
        DocumentUpdate[] memory noDocs = new DocumentUpdate[](0);
        RegisterOptions memory opts = _defaultOptions(_unset());

        // BOB is not the parent owner -> not authorized.
        vm.prank(BOB);
        vm.expectPartialRevert(NotEffectiveOwner.selector);
        _registerName("sub.alice", BOB, opts, noDocs, _ownerAuth(BOB), _guard(0, parentSeq));
    }

    // --- domain separation: contract address ------------------------------

    function _registerPublishGetRoot() internal returns (bytes32 root, bytes32 docHash) {
        _registerRoot("alice", ALICE);
        uint64 s = bns.queryNameState("alice").nameSeq;
        vm.prank(ALICE);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(s));
        root = bns.currentLogRoot();
        docHash = bns.getDocumentVersion("alice", "owner", 1).documentStateHash;
    }

    function testLogRootDependsOnContractAddress() public {
        (bytes32 rootA, bytes32 hashA) = _registerPublishGetRoot();

        // Identical calldata on a different contract address (same chainid).
        bns = new Bns();
        (bytes32 rootB, bytes32 hashB) = _registerPublishGetRoot();

        assertTrue(rootA != rootB, "logRoot differs by address(this)");
        assertTrue(hashA != hashB, "documentStateHash differs by address(this)");
    }

    function testLogRootDependsOnChainId() public {
        uint256 snap = vm.snapshotState();
        (bytes32 root1, bytes32 hash1) = _registerPublishGetRoot();

        // Same contract address, identical calldata, only chainid differs.
        vm.revertToState(snap);
        vm.chainId(424242);
        (bytes32 root2, bytes32 hash2) = _registerPublishGetRoot();

        assertTrue(root1 != root2, "logRoot differs by block.chainid");
        assertTrue(hash1 != hash2, "documentStateHash differs by block.chainid");
    }

    // --- chained seq / previousLogRoot / logRoot continuity ----------------

    function testProtocolEventChainIsContinuous() public {
        vm.recordLogs();

        _registerRoot("alice", ALICE);
        uint64 s = bns.queryNameState("alice").nameSeq;
        vm.prank(ALICE);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(s));
        bns.renewName("alice", 10 days);

        Vm.Log[] memory logs = vm.getRecordedLogs();

        uint64 expectedSeq = 0;
        bytes32 prevRoot = bytes32(0);
        uint256 count = 0;
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics.length == 0 || logs[i].topics[0] != PROTOCOL_EVENT_SIG) {
                continue;
            }
            uint64 seq = uint64(uint256(logs[i].topics[1]));
            (bytes32 previousLogRoot, bytes32 logRoot) = abi.decode(logs[i].data, (bytes32, bytes32));

            expectedSeq += 1;
            assertEqUint(seq, expectedSeq, "seq strictly increments by 1");
            assertEqBytes32(previousLogRoot, prevRoot, "previousLogRoot == prior logRoot");
            assertTrue(logRoot != previousLogRoot, "logRoot advances");
            prevRoot = logRoot;
            count += 1;
        }

        assertTrue(count >= 3, "saw register + publish + renew protocol events");
        assertEqBytes32(prevRoot, bns.currentLogRoot(), "final logRoot == currentLogRoot");
        assertEqUint(bns.globalEventSeq(), expectedSeq, "globalEventSeq matches event count");
    }
}
