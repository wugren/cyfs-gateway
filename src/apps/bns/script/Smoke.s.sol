// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "../src/Bns.sol";

interface Vm {
    function envUint(string calldata key) external returns (uint256);
    function addr(uint256 privateKey) external returns (address);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract Smoke {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant ZERO = bytes32(0);
    bytes32 private constant STORAGE_INLINE =
        0x696e6c696e650000000000000000000000000000000000000000000000000000;

    function run() external {
        uint256 privateKey = vm.envUint("BNS_PRIVATE_KEY");
        address deployer = vm.addr(privateKey);

        vm.startBroadcast(privateKey);

        Bns bns = new Bns();
        DocumentUpdate[] memory emptyDocs = new DocumentUpdate[](0);
        AuthorityKeyUpdate[] memory noKeys = new AuthorityKeyUpdate[](0);
        ControllerRule[] memory noRules = new ControllerRule[](0);

        bns.registerName(
            "alice",
            deployer,
            _defaultOptions(_unset()),
            noKeys,
            _unset(),
            noRules,
            ZERO,
            emptyDocs,
            CallAuthority({ role: AuthorityRole.None, actor: _unset(), kid: ZERO }),
            MutationGuard({ expectedNameSeq: 0, expectedParentNameSeq: 0 })
        );

        NameState memory state = bns.queryNameState("alice");
        require(state.status == NameStatus.Active, "name not active");

        uint64 version = bns.publishDocument(
            "alice",
            "owner",
            0,
            _inlineDoc(bytes("{\"id\":\"did:bns:alice\"}")),
            _unset(),
            _unset(),
            address(0),
            0,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            ZERO,
            CallAuthority({ role: AuthorityRole.Owner, actor: _chain(deployer), kid: ZERO }),
            MutationGuard({ expectedNameSeq: state.nameSeq, expectedParentNameSeq: 0 })
        );
        require(version == 1, "document not published");

        ResolveResult memory resolved = bns.resolveDocument("alice", "owner");
        require(resolved.status == DocumentStatus.Active, "document not active");

        vm.stopBroadcast();
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

    function _unset() internal pure returns (Principal memory) {
        return Principal({ kind: PrincipalKind.Unset, value: "" });
    }

    function _chain(address account) internal pure returns (Principal memory) {
        return Principal({ kind: PrincipalKind.ChainAccount, value: abi.encodePacked(account) });
    }
}
