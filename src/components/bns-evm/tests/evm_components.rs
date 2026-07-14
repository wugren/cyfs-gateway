//! §2.1 BNS Rust 组件独立测试 —— `bns-evm`（ABI 绑定 + TX 构造/签名）。
//!
//! 覆盖测试计划 doc/SN/SN-测试计划.md §2.1 的补全项：
//! - calldata round-trip：每个写函数 `sol!` 绑定的 encode→decode 一致 + 结构 packing 一致。
//! - chainAccountPrincipal 编码：地址按 20 字节编码。
//! - TX 构造：`build_eip1559_contract_tx` 产出 EIP-1559 字段正确。
//! - 签名与 signer 恢复：sign → 解码 raw TX → 恢复 signer == key 地址。
//! - event 解码：用 sol! 绑定 encode 的事件字节验证 `decode_bns_event`。
//! - call 解码：`decode_bns_call` 从 calldata 还原入参。
//! - 边界/错误：截断 calldata、未知 selector、错误 chainId → 明确错误而非 panic。

use alloy_primitives::{address, Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolEvent, SolInterface, SolValue};
use bns_evm::{
    build_eip1559_contract_tx, decode_bns_call, decode_bns_event, decode_signed_eip1559,
    encode_call, sign_eip1559_tx, signer_from_private_key, AliasKind as EvmAliasKind,
    AuthorityRole as EvmAuthorityRole, Bns, CallAuthority as EvmCallAuthority,
    ControllerRule as EvmControllerRule, DocumentRef as EvmDocumentRef, Eip1559TxParams,
    MutationGuard as EvmMutationGuard, Principal as EvmPrincipal,
    PrincipalKind as EvmPrincipalKind, RegisterOptions as EvmRegisterOptions,
    ReleaseMode as EvmReleaseMode, TxKind,
};

// 测试中复用的 anvil 第 0 个确定性账户私钥/地址。
const ANVIL_KEY_0: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const ANVIL_ADDR_0: Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

fn unset_principal() -> EvmPrincipal {
    EvmPrincipal {
        kind: EvmPrincipalKind::Unset,
        value: Bytes::new(),
    }
}

fn chain_account_principal(account: Address) -> EvmPrincipal {
    EvmPrincipal {
        kind: EvmPrincipalKind::ChainAccount,
        value: Bytes::copy_from_slice(account.as_slice()),
    }
}

fn owner_authority(actor: Address) -> EvmCallAuthority {
    EvmCallAuthority {
        role: EvmAuthorityRole::Owner,
        actor: chain_account_principal(actor),
        kid: B256::ZERO,
    }
}

fn public_authority() -> EvmCallAuthority {
    EvmCallAuthority {
        role: EvmAuthorityRole::None,
        actor: unset_principal(),
        kid: B256::ZERO,
    }
}

fn empty_guard() -> EvmMutationGuard {
    EvmMutationGuard {
        expectedNameSeq: 3,
        expectedParentNameSeq: 7,
    }
}

fn default_register_options() -> EvmRegisterOptions {
    EvmRegisterOptions {
        duration: 365 * 24 * 60 * 60,
        gracePeriod: 30 * 24 * 60 * 60,
        renewable: true,
        transferable: true,
        initialSemanticOwner: unset_principal(),
        allowDelegatedSubnames: false,
        initialPaymentTarget: Address::ZERO,
        initialPaymentPolicyHash: B256::ZERO,
        initialNamespacePolicyHash: B256::ZERO,
    }
}

fn document_ref() -> EvmDocumentRef {
    EvmDocumentRef {
        storageType: B256::repeat_byte(0x11),
        uri: "ipfs://doc".to_string(),
        inlineDocument: Bytes::from_static(b"hello"),
        contentHash: B256::repeat_byte(0x22),
        schema: B256::repeat_byte(0x33),
        codec: B256::repeat_byte(0x44),
        extraHash: B256::repeat_byte(0x55),
    }
}

// ---- calldata round-trip：逐写函数 ----

#[test]
fn register_name_call_round_trips() {
    let call = Bns::registerNameCall {
        name: "alice".to_string(),
        assetOwner: ANVIL_ADDR_0,
        options: default_register_options(),
        authorityUpdates: Vec::new(),
        semanticOwnerAfterAuthority: unset_principal(),
        controllerPolicy: Vec::new(),
        controllerPolicyHash: B256::ZERO,
        initialDocuments: Vec::new(),
        authority: owner_authority(ANVIL_ADDR_0),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded = Bns::registerNameCall::abi_decode(&encoded).expect("decode registerName");
    assert_eq!(decoded.name, call.name);
    assert_eq!(decoded.assetOwner, call.assetOwner);
    assert_eq!(decoded.options.duration, call.options.duration);
    assert_eq!(decoded.guard.expectedNameSeq, 3);
    assert_eq!(decoded.guard.expectedParentNameSeq, 7);
    // CallAuthority / Principal packing 一致：role + chain-account actor。
    assert!(matches!(decoded.authority.role, EvmAuthorityRole::Owner));
    assert!(matches!(
        decoded.authority.actor.kind,
        EvmPrincipalKind::ChainAccount
    ));
    assert_eq!(
        decoded.authority.actor.value.as_ref(),
        ANVIL_ADDR_0.as_slice()
    );

    let iface = decode_bns_call(&encoded).expect("decode interface");
    assert_eq!(iface.selector(), Bns::registerNameCall::SELECTOR);
}

#[test]
fn publish_document_call_round_trips() {
    let call = Bns::publishDocumentCall {
        name: "alice".to_string(),
        docType: "device".to_string(),
        expectedVersion: 4,
        document: document_ref(),
        controller: chain_account_principal(ANVIL_ADDR_0),
        beneficiary: unset_principal(),
        paymentTarget: Address::ZERO,
        expireAt: 1_900_000_000,
        controllerPolicyHash: B256::ZERO,
        paymentPolicyHash: B256::ZERO,
        splitPolicyHash: B256::ZERO,
        pricePolicyHash: B256::ZERO,
        rightsPolicyHash: B256::ZERO,
        authority: public_authority(),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded = Bns::publishDocumentCall::abi_decode(&encoded).expect("decode publishDocument");
    assert_eq!(decoded.docType, "device");
    assert_eq!(decoded.expectedVersion, 4);
    assert_eq!(decoded.document.uri, "ipfs://doc");
    assert_eq!(decoded.document.inlineDocument.as_ref(), b"hello");
    assert_eq!(decoded.document.contentHash, B256::repeat_byte(0x22));
    assert_eq!(decoded.expireAt, 1_900_000_000);
    assert_eq!(
        decode_bns_call(&encoded).unwrap().selector(),
        Bns::publishDocumentCall::SELECTOR
    );
}

#[test]
fn revoke_document_call_round_trips() {
    let call = Bns::revokeDocumentCall {
        name: "alice".to_string(),
        docType: "device".to_string(),
        expectedVersion: 2,
        reasonHash: B256::repeat_byte(0xAB),
        authority: public_authority(),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded = Bns::revokeDocumentCall::abi_decode(&encoded).expect("decode revokeDocument");
    assert_eq!(decoded.expectedVersion, 2);
    assert_eq!(decoded.reasonHash, B256::repeat_byte(0xAB));
    assert_eq!(
        decode_bns_call(&encoded).unwrap().selector(),
        Bns::revokeDocumentCall::SELECTOR
    );
}

#[test]
fn set_min_document_iat_call_round_trips() {
    let call = Bns::setMinDocumentIatCall {
        name: "alice".to_string(),
        minDocumentIat: 1_770_000_000,
        reasonHash: B256::repeat_byte(0xA7),
        authority: owner_authority(ANVIL_ADDR_0),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded =
        Bns::setMinDocumentIatCall::abi_decode(&encoded).expect("decode setMinDocumentIat");
    assert_eq!(decoded.name, "alice");
    assert_eq!(decoded.minDocumentIat, 1_770_000_000);
    assert_eq!(decoded.reasonHash, B256::repeat_byte(0xA7));
    assert_eq!(
        decode_bns_call(&encoded).unwrap().selector(),
        Bns::setMinDocumentIatCall::SELECTOR
    );
}

#[test]
fn set_controller_policy_call_round_trips() {
    let rule = EvmControllerRule {
        controller: chain_account_principal(ANVIL_ADDR_0),
        docType: "device".to_string(),
        permissions: 0b0000_0011,
        namespaceScopeHash: B256::ZERO,
        validFrom: 100,
        validUntil: 200,
        constraintHash: B256::ZERO,
    };
    let call = Bns::setControllerPolicyCall {
        name: "alice".to_string(),
        rules: vec![rule.clone()],
        policyHash: B256::repeat_byte(0x7F),
        authority: owner_authority(ANVIL_ADDR_0),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded =
        Bns::setControllerPolicyCall::abi_decode(&encoded).expect("decode setControllerPolicy");
    assert_eq!(decoded.rules.len(), 1);
    assert_eq!(decoded.rules[0].docType, "device");
    assert_eq!(decoded.rules[0].permissions, 0b0000_0011);
    assert_eq!(decoded.rules[0].validUntil, 200);
    assert_eq!(decoded.policyHash, B256::repeat_byte(0x7F));
    assert_eq!(
        decode_bns_call(&encoded).unwrap().selector(),
        Bns::setControllerPolicyCall::SELECTOR
    );
}

#[test]
fn set_did_alias_call_round_trips() {
    let call = Bns::setDidAliasCall {
        name: "alice".to_string(),
        targetDid: "did:bns:bob".to_string(),
        kind: EvmAliasKind::Canonical,
        proofHash: B256::repeat_byte(0x9),
        authority: public_authority(),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded = Bns::setDidAliasCall::abi_decode(&encoded).expect("decode setDidAlias");
    assert_eq!(decoded.targetDid, "did:bns:bob");
    assert!(matches!(decoded.kind, EvmAliasKind::Canonical));
    assert_eq!(decoded.proofHash, B256::repeat_byte(0x9));
}

#[test]
fn set_payment_target_call_round_trips() {
    let call = Bns::setPaymentTargetCall {
        name: "alice".to_string(),
        docType: "payment".to_string(),
        expectedVersion: 1,
        paymentTarget: ANVIL_ADDR_0,
        beneficiary: chain_account_principal(ANVIL_ADDR_0),
        paymentPolicyHash: B256::repeat_byte(0x1),
        splitPolicyHash: B256::repeat_byte(0x2),
        pricePolicyHash: B256::repeat_byte(0x3),
        rightsPolicyHash: B256::repeat_byte(0x4),
        authority: public_authority(),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded = Bns::setPaymentTargetCall::abi_decode(&encoded).expect("decode setPaymentTarget");
    assert_eq!(decoded.paymentTarget, ANVIL_ADDR_0);
    assert_eq!(decoded.paymentPolicyHash, B256::repeat_byte(0x1));
    assert_eq!(decoded.rightsPolicyHash, B256::repeat_byte(0x4));
}

#[test]
fn set_namespace_policy_call_round_trips() {
    let call = Bns::setNamespacePolicyCall {
        name: "alice".to_string(),
        allowDelegatedSubnames: true,
        namespacePolicyHash: B256::repeat_byte(0xDD),
        authority: public_authority(),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded =
        Bns::setNamespacePolicyCall::abi_decode(&encoded).expect("decode setNamespacePolicy");
    assert!(decoded.allowDelegatedSubnames);
    assert_eq!(decoded.namespacePolicyHash, B256::repeat_byte(0xDD));
}

#[test]
fn release_name_call_round_trips() {
    let call = Bns::releaseNameCall {
        name: "alice".to_string(),
        mode: EvmReleaseMode::TombstoneForever,
        reasonHash: B256::repeat_byte(0xEE),
        authority: owner_authority(ANVIL_ADDR_0),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded = Bns::releaseNameCall::abi_decode(&encoded).expect("decode releaseName");
    assert!(matches!(decoded.mode, EvmReleaseMode::TombstoneForever));
    assert_eq!(decoded.reasonHash, B256::repeat_byte(0xEE));
}

#[test]
fn transfer_name_call_round_trips() {
    let call = Bns::transferNameCall {
        name: "alice".to_string(),
        newAssetOwner: ANVIL_ADDR_0,
        newSemanticOwner: chain_account_principal(ANVIL_ADDR_0),
        atomicDocumentUpdates: Vec::new(),
        authority: owner_authority(ANVIL_ADDR_0),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded = Bns::transferNameCall::abi_decode(&encoded).expect("decode transferName");
    assert_eq!(decoded.newAssetOwner, ANVIL_ADDR_0);
    assert!(matches!(
        decoded.newSemanticOwner.kind,
        EvmPrincipalKind::ChainAccount
    ));
}

#[test]
fn set_name_owner_call_round_trips() {
    let call = Bns::setNameOwnerCall {
        name: "alice".to_string(),
        semanticOwner: chain_account_principal(ANVIL_ADDR_0),
        authority: owner_authority(ANVIL_ADDR_0),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded = Bns::setNameOwnerCall::abi_decode(&encoded).expect("decode setNameOwner");
    assert_eq!(
        decoded.semanticOwner.value.as_ref(),
        ANVIL_ADDR_0.as_slice()
    );
}

#[test]
fn renew_name_call_round_trips() {
    let call = Bns::renewNameCall {
        name: "alice".to_string(),
        duration: 999,
    };
    let encoded = call.abi_encode();
    let decoded = Bns::renewNameCall::abi_decode(&encoded).expect("decode renewName");
    assert_eq!(decoded.duration, 999);
    assert_eq!(
        decode_bns_call(&encoded).unwrap().selector(),
        Bns::renewNameCall::SELECTOR
    );
}

// ---- chainAccountPrincipal 编码 ----

#[test]
fn chain_account_principal_encodes_address_as_20_bytes() {
    // 对应 client 侧 `evm_register_call_encodes_chain_account_principal_as_address_bytes`：
    // ChainAccount principal 的 value 必须是 20 字节裸地址，而非 32 字节左填充。
    let principal = chain_account_principal(ANVIL_ADDR_0);
    assert_eq!(principal.value.len(), 20);
    assert_eq!(principal.value.as_ref(), ANVIL_ADDR_0.as_slice());

    // 在 calldata 中往返后仍是 20 字节裸地址。
    let call = Bns::setNameOwnerCall {
        name: "alice".to_string(),
        semanticOwner: principal,
        authority: owner_authority(ANVIL_ADDR_0),
        guard: empty_guard(),
    };
    let encoded = call.abi_encode();
    let decoded = Bns::setNameOwnerCall::abi_decode(&encoded).unwrap();
    assert_eq!(decoded.semanticOwner.value.len(), 20);
    // 还原出的 20 字节可以重建出原地址。
    assert_eq!(
        Address::from_slice(decoded.semanticOwner.value.as_ref()),
        ANVIL_ADDR_0
    );
}

// ---- TX 构造：EIP-1559 字段正确 ----

#[test]
fn build_tx_sets_eip1559_fields() {
    let contract = address!("2000000000000000000000000000000000000002");
    let call = Bns::renewNameCall {
        name: "alice".to_string(),
        duration: 1,
    };
    let tx = build_eip1559_contract_tx(
        &call,
        Eip1559TxParams {
            chain_id: 31_337,
            nonce: 42,
            to: contract,
            gas_limit: 500_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            value: U256::ZERO,
        },
    );
    assert_eq!(tx.chain_id, 31_337);
    assert_eq!(tx.nonce, 42);
    assert_eq!(tx.gas_limit, 500_000);
    assert_eq!(tx.max_fee_per_gas, 2_000_000_000);
    assert_eq!(tx.max_priority_fee_per_gas, 1_000_000_000);
    assert_eq!(tx.to, TxKind::Call(contract));
    assert_eq!(tx.value, U256::ZERO);
    assert!(tx.access_list.is_empty());
    // input == ABI-encoded call。
    assert_eq!(tx.input, encode_call(&call));
}

// ---- 签名与 signer 恢复 ----

#[test]
fn signing_recovers_key_address_from_independent_decode() {
    let signer = signer_from_private_key(ANVIL_KEY_0).expect("anvil signer");
    assert_eq!(signer.address(), ANVIL_ADDR_0);
    let contract = address!("2000000000000000000000000000000000000002");
    let call = Bns::renewNameCall {
        name: "alice".to_string(),
        duration: 1,
    };
    let tx = build_eip1559_contract_tx(&call, Eip1559TxParams::anvil(31_337, 9, contract));
    let signed = sign_eip1559_tx(tx, &signer).expect("sign");
    assert_eq!(signed.signer, ANVIL_ADDR_0);
    assert_eq!(signed.nonce, 9);
    assert_eq!(signed.chain_id, 31_337);

    // 独立解码 raw TX，从签名恢复 signer，必须等于 key 地址（防"签了但 sender 不对"）。
    let decoded = decode_signed_eip1559(&signed.raw_tx).expect("decode raw tx");
    assert_eq!(decoded.recover_signer().expect("recover"), ANVIL_ADDR_0);
    assert_eq!(decoded.tx().chain_id, 31_337);
    assert_eq!(decoded.tx().nonce, 9);
    assert_eq!(decoded.tx().to, TxKind::Call(contract));
    assert_eq!(*decoded.hash(), signed.tx_hash);
}

#[test]
fn different_keys_recover_different_signers() {
    // 第二个 anvil 账户私钥/地址。
    let key1 = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    let addr1 = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
    let signer0 = signer_from_private_key(ANVIL_KEY_0).unwrap();
    let signer1 = signer_from_private_key(key1).unwrap();
    assert_eq!(signer1.address(), addr1);

    let contract = address!("2000000000000000000000000000000000000002");
    let call = Bns::renewNameCall {
        name: "alice".to_string(),
        duration: 1,
    };
    let tx = build_eip1559_contract_tx(&call, Eip1559TxParams::anvil(31_337, 0, contract));
    let signed0 = sign_eip1559_tx(tx.clone(), &signer0).unwrap();
    let signed1 = sign_eip1559_tx(tx, &signer1).unwrap();
    assert_ne!(signed0.signer, signed1.signer);
    assert_eq!(
        decode_signed_eip1559(&signed1.raw_tx)
            .unwrap()
            .recover_signer()
            .unwrap(),
        addr1
    );
}

// ---- event 解码 ----

#[test]
fn decode_protocol_event_round_trips() {
    // 用 §1.7 钉死的 ProtocolEvent 字段，验证 decode_bns_event 解出一致。
    let event = Bns::ProtocolEvent {
        seq: 12,
        eventType: B256::repeat_byte(0xA1),
        actor: ANVIL_ADDR_0,
        previousLogRoot: B256::repeat_byte(0xB2),
        logRoot: B256::repeat_byte(0xC3),
    };
    let log_data = event.encode_log_data();
    let log = bns_evm::Log {
        address: address!("2000000000000000000000000000000000000002"),
        data: log_data,
    };
    let decoded = decode_bns_event(&log).expect("decode event");
    match decoded.data {
        Bns::BnsEvents::ProtocolEvent(e) => {
            assert_eq!(e.seq, 12);
            assert_eq!(e.eventType, B256::repeat_byte(0xA1));
            assert_eq!(e.actor, ANVIL_ADDR_0);
            assert_eq!(e.previousLogRoot, B256::repeat_byte(0xB2));
            assert_eq!(e.logRoot, B256::repeat_byte(0xC3));
        }
        _ => panic!("expected ProtocolEvent"),
    }
}

#[test]
fn decode_document_published_event_round_trips() {
    let event = Bns::DocumentPublished {
        nameHash: B256::repeat_byte(0x01),
        name: "alice".to_string(),
        docType: "device".to_string(),
        version: 7,
        actor: ANVIL_ADDR_0,
        contentHash: B256::repeat_byte(0x22),
        documentStateHash: B256::repeat_byte(0x33),
    };
    let log = bns_evm::Log {
        address: address!("2000000000000000000000000000000000000002"),
        data: event.encode_log_data(),
    };
    let decoded = decode_bns_event(&log).expect("decode event");
    match decoded.data {
        Bns::BnsEvents::DocumentPublished(e) => {
            assert_eq!(e.name, "alice");
            assert_eq!(e.docType, "device");
            assert_eq!(e.version, 7);
            assert_eq!(e.contentHash, B256::repeat_byte(0x22));
        }
        _ => panic!("expected DocumentPublished"),
    }
}

#[test]
fn decode_name_registered_event_round_trips() {
    let event = Bns::NameRegistered {
        nameHash: B256::repeat_byte(0x01),
        name: "alice".to_string(),
        assetOwner: ANVIL_ADDR_0,
        actor: ANVIL_ADDR_0,
        expireAt: 1_900_000_000,
        lineageEpoch: 1,
        nameSeq: 1,
    };
    let log = bns_evm::Log {
        address: address!("2000000000000000000000000000000000000002"),
        data: event.encode_log_data(),
    };
    let decoded = decode_bns_event(&log).expect("decode event");
    match decoded.data {
        Bns::BnsEvents::NameRegistered(e) => {
            assert_eq!(e.name, "alice");
            assert_eq!(e.assetOwner, ANVIL_ADDR_0);
            assert_eq!(e.expireAt, 1_900_000_000);
        }
        _ => panic!("expected NameRegistered"),
    }
}

// ---- call 解码（indexer 补全入参时依赖）----

#[test]
fn decode_bns_call_recovers_authority_and_controller_inputs() {
    // indexer 用 decode_bns_call 从 tx calldata 补全事件未携带的 authority/controller 入参。
    let rule = EvmControllerRule {
        controller: chain_account_principal(ANVIL_ADDR_0),
        docType: "device".to_string(),
        permissions: 0b0000_0001,
        namespaceScopeHash: B256::ZERO,
        validFrom: 0,
        validUntil: u64::MAX,
        constraintHash: B256::ZERO,
    };
    let call = Bns::setControllerPolicyCall {
        name: "alice".to_string(),
        rules: vec![rule],
        policyHash: B256::repeat_byte(0x7F),
        authority: owner_authority(ANVIL_ADDR_0),
        guard: empty_guard(),
    };
    let calldata = call.abi_encode();
    match decode_bns_call(&calldata).expect("decode call") {
        Bns::BnsCalls::setControllerPolicy(decoded) => {
            assert_eq!(decoded.name, "alice");
            assert_eq!(decoded.rules.len(), 1);
            assert_eq!(decoded.rules[0].permissions, 0b0000_0001);
            assert_eq!(
                decoded.authority.actor.value.as_ref(),
                ANVIL_ADDR_0.as_slice()
            );
        }
        _ => panic!("expected setControllerPolicy"),
    }
}

// ---- 边界/错误：明确错误而非 panic ----

#[test]
fn truncated_calldata_returns_error_not_panic() {
    let call = Bns::renewNameCall {
        name: "alice".to_string(),
        duration: 1,
    };
    let mut encoded = call.abi_encode();
    encoded.truncate(8); // selector + 4 字节，参数被截断。
    let err = decode_bns_call(&encoded);
    assert!(err.is_err(), "truncated calldata must error");
}

#[test]
fn unknown_selector_returns_error_not_panic() {
    // 0xdeadbeef 不属于任何 BNS 写函数。
    let calldata = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00];
    let err = decode_bns_call(&calldata);
    assert!(err.is_err(), "unknown selector must error");
}

#[test]
fn empty_calldata_returns_error_not_panic() {
    assert!(decode_bns_call(&[]).is_err());
}

#[test]
fn malformed_raw_tx_returns_error_not_panic() {
    // 既非合法 EIP-2718 信封，也不会 panic。
    assert!(decode_signed_eip1559(&[0x02, 0x00, 0x01]).is_err());
    assert!(decode_signed_eip1559(&[]).is_err());
}

#[test]
fn wrong_chain_id_yields_different_signature_hash() {
    // 不同 chainId 的相同 calldata 必须产出不同的签名 hash（EIP-155 重放保护）。
    let contract = address!("2000000000000000000000000000000000000002");
    let call = Bns::renewNameCall {
        name: "alice".to_string(),
        duration: 1,
    };
    let signer = signer_from_private_key(ANVIL_KEY_0).unwrap();
    let tx_a = build_eip1559_contract_tx(&call, Eip1559TxParams::anvil(31_337, 0, contract));
    let tx_b = build_eip1559_contract_tx(&call, Eip1559TxParams::anvil(1, 0, contract));
    let signed_a = sign_eip1559_tx(tx_a, &signer).unwrap();
    let signed_b = sign_eip1559_tx(tx_b, &signer).unwrap();
    assert_ne!(signed_a.tx_hash, signed_b.tx_hash);
    // 解码后 chainId 各自正确。
    assert_eq!(
        decode_signed_eip1559(&signed_a.raw_tx)
            .unwrap()
            .tx()
            .chain_id,
        31_337
    );
    assert_eq!(
        decode_signed_eip1559(&signed_b.raw_tx)
            .unwrap()
            .tx()
            .chain_id,
        1
    );
}

#[test]
fn principal_value_packing_distinguishes_kinds() {
    // BnsName principal 的 value 是 utf-8 名字字节，ChainAccount 是 20 字节地址。
    let bns_name = EvmPrincipal {
        kind: EvmPrincipalKind::BnsName,
        value: Bytes::from_static(b"alice"),
    };
    let encoded = bns_name.abi_encode();
    let decoded = EvmPrincipal::abi_decode(&encoded).unwrap();
    assert!(matches!(decoded.kind, EvmPrincipalKind::BnsName));
    assert_eq!(decoded.value.as_ref(), b"alice");
}
