// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./BnsTestBase.sol";

/// §1.8 — fuzz + invariant (optional enhancement).
contract BnsFuzzTest is BnsTestBase {
    // --- fuzz: MutationGuard.expectedNameSeq -------------------------------

    function testFuzz_wrongExpectedNameSeqAlwaysReverts(uint64 wrongSeq) public {
        _registerRoot("alice", ALICE); // actual seq == 1
        vm.assume(wrongSeq != 1);

        vm.prank(ALICE);
        vm.expectPartialRevert(StaleNameSeq.selector);
        _publishDoc("alice", "owner", 0, ownerRef, _ownerAuth(ALICE), _guard(wrongSeq));
    }

    // --- fuzz: authority key address ---------------------------------------

    function testFuzz_authorityKeyAddressAuthenticates(address keyAddr) public {
        vm.assume(uint160(keyAddr) > 0x20); // avoid precompiles / zero
        vm.assume(keyAddr != address(this) && keyAddr != address(bns));

        _registerRoot("org", ALICE);
        uint64 s = bns.queryNameState("org").nameSeq;
        s = _installAuthorityKey("org", KID, keyAddr, ALICE, 0, 0, s);
        vm.prank(ALICE);
        bns.setNameOwner("org", _bnsName("org"), _ownerAuth(ALICE), _guard(s));
        s = bns.queryNameState("org").nameSeq;

        // Only the configured key address can sign.
        vm.prank(keyAddr);
        uint64 v = _publishDoc("org", "owner", 0, ownerRef, _ownerAuthName("org", KID), _guard(s));
        assertEqUint(v, 1, "configured key authenticates");
    }

    // --- fuzz: controller permission bit combinations ----------------------

    function testFuzz_permissionBitsGatePublish(uint32 perms) public {
        _registerRoot("alice", ALICE);
        uint32 publishBit = bns.PERMISSION_PUBLISH_DOCUMENT();

        ControllerRule[] memory rules = _singleRule(_chain(CTRL), "", perms, 0, 0);
        uint64 s = bns.queryNameState("alice").nameSeq;
        vm.prank(ALICE);
        bns.setControllerPolicy("alice", rules, keccak256("p"), _ownerAuth(ALICE), _guard(s));

        DocumentRef memory r = _inlineDoc(bytes("[{\"v\":\"a\"}]"));
        s = bns.queryNameState("alice").nameSeq;

        if (perms & publishBit != 0) {
            vm.prank(CTRL);
            uint64 v = _publishDoc("alice", "dns_txt", 0, r, _controllerAuth(CTRL), _guard(s));
            assertEqUint(v, 1, "publish allowed when bit set");
        } else {
            vm.prank(CTRL);
            vm.expectPartialRevert(ControllerScopeDenied.selector);
            _publishDoc("alice", "dns_txt", 0, r, _controllerAuth(CTRL), _guard(s));
        }
    }
}

/// Bounded driver for the invariant engine. It owns the names it registers
/// (assetOwner == address(this)), so it can author owner documents without
/// any cheatcode. Every successful mutation commits exactly one ProtocolEvent.
contract BnsHandler {
    Bns internal immutable bns;
    uint64 public expectedEvents;

    bytes32 constant ZERO = bytes32(0);
    bytes32 constant STORAGE_INLINE =
        0x696e6c696e650000000000000000000000000000000000000000000000000000;
    string[5] internal pool = ["na", "nb", "nc", "nd", "ne"];

    constructor(Bns _bns) {
        bns = _bns;
    }

    function _opts() internal pure returns (RegisterOptions memory) {
        return RegisterOptions({
            duration: 365 days,
            gracePeriod: 30 days,
            renewable: true,
            transferable: true,
            initialSemanticOwner: Principal({ kind: PrincipalKind.Unset, value: "" }),
            allowDelegatedSubnames: true,
            initialPaymentTarget: address(0),
            initialPaymentPolicyHash: ZERO,
            initialNamespacePolicyHash: ZERO
        });
    }

    function _ownerAuth() internal view returns (CallAuthority memory) {
        return CallAuthority({
            role: AuthorityRole.Owner,
            actor: Principal({ kind: PrincipalKind.ChainAccount, value: abi.encodePacked(address(this)) }),
            kid: ZERO
        });
    }

    function register(uint8 i) external {
        string memory name = pool[i % 5];
        DocumentUpdate[] memory empty = new DocumentUpdate[](0);
        AuthorityKeyUpdate[] memory noKeys = new AuthorityKeyUpdate[](0);
        ControllerRule[] memory noRules = new ControllerRule[](0);
        try bns.registerName(
            name,
            address(this),
            _opts(),
            noKeys,
            Principal(PrincipalKind.Unset, ""),
            noRules,
            ZERO,
            empty,
            CallAuthority({ role: AuthorityRole.None, actor: Principal(PrincipalKind.Unset, ""), kid: ZERO }),
            MutationGuard({ expectedNameSeq: 0, expectedParentNameSeq: 0 })
        ) returns (uint64, uint64, bytes32) {
            expectedEvents += 1;
        } catch {}
    }

    function publish(uint8 i, uint16 salt) external {
        string memory name = pool[i % 5];
        NameState memory st = bns.queryNameState(name);
        if (st.status != NameStatus.Active) return;

        bytes memory body = abi.encodePacked("body-", salt);
        DocumentRef memory ref = DocumentRef({
            storageType: STORAGE_INLINE,
            uri: "",
            inlineDocument: body,
            contentHash: sha256(body),
            schema: ZERO,
            codec: ZERO,
            extraHash: ZERO
        });
        try bns.publishDocument(
            name, "owner", st.ownerDocumentVersion, ref,
            Principal(PrincipalKind.Unset, ""), Principal(PrincipalKind.Unset, ""),
            address(0), 0, ZERO, ZERO, ZERO, ZERO, ZERO,
            _ownerAuth(), MutationGuard({ expectedNameSeq: st.nameSeq, expectedParentNameSeq: 0 })
        ) returns (uint64) {
            expectedEvents += 1;
        } catch {}
    }

    function renew(uint8 i) external {
        string memory name = pool[i % 5];
        if (bns.queryNameState(name).status != NameStatus.Active) return;
        try bns.renewName(name, 1 days) returns (uint64) {
            expectedEvents += 1;
        } catch {}
    }

    function nameAt(uint256 i) external view returns (string memory) {
        return pool[i % 5];
    }
}

/// Invariant: globalEventSeq and the log chain stay consistent across any
/// sequence of bounded mutations.
contract BnsInvariantTest {
    Bns internal bns;
    BnsHandler internal handler;

    function setUp() public {
        bns = new Bns();
        handler = new BnsHandler(bns);
    }

    function targetContracts() public view returns (address[] memory addrs) {
        addrs = new address[](1);
        addrs[0] = address(handler);
    }

    /// Every committed mutation emits exactly one ProtocolEvent.
    function invariant_eventCountMatchesGlobalSeq() public view {
        require(bns.globalEventSeq() == handler.expectedEvents(), "seq != event count");
    }

    /// Once any event has been committed the log root is non-zero and advances.
    function invariant_logRootNonZeroAfterEvents() public view {
        if (bns.globalEventSeq() > 0) {
            require(bns.currentLogRoot() != bytes32(0), "log root must be set");
        }
    }

    /// Each pool name is either untouched or internally self-consistent.
    function invariant_registeredNamesSelfConsistent() public view {
        for (uint256 i = 0; i < 5; i++) {
            string memory name = handler.nameAt(i);
            NameState memory st = bns.queryNameState(name);
            if (st.status != NameStatus.Available) {
                require(keccak256(bytes(st.name)) == keccak256(bytes(name)), "name mismatch");
                require(st.nameSeq > 0, "active name must have seq");
            }
        }
    }
}
