use alloy_primitives::{address, Address, Bytes, B256, U256};
use alloy_sol_types::{SolCall, SolInterface};
use bns_evm::{
    build_eip1559_contract_tx, decode_bns_call, decode_signed_eip1559, sign_eip1559_tx,
    signer_from_private_key, AuthorityRole as EvmAuthorityRole, Bns,
    CallAuthority as EvmCallAuthority, Eip1559TxParams, MutationGuard as EvmMutationGuard,
    Principal as EvmPrincipal, PrincipalKind as EvmPrincipalKind,
    RegisterOptions as EvmRegisterOptions,
};

fn unset_principal() -> EvmPrincipal {
    EvmPrincipal {
        kind: EvmPrincipalKind::Unset,
        value: Bytes::new(),
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
        expectedNameSeq: 0,
        expectedParentNameSeq: 0,
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

fn register_name_call() -> Bns::registerNameCall {
    Bns::registerNameCall {
        name: "alice".to_string(),
        assetOwner: address!("1000000000000000000000000000000000000001"),
        options: default_register_options(),
        authorityUpdates: Vec::new(),
        semanticOwnerAfterAuthority: unset_principal(),
        controllerPolicy: Vec::new(),
        controllerPolicyHash: B256::ZERO,
        initialDocuments: Vec::new(),
        authority: public_authority(),
        guard: empty_guard(),
    }
}

#[test]
fn calldata_round_trips_through_generated_binding() {
    let call = register_name_call();
    let encoded = call.abi_encode();

    let decoded = Bns::registerNameCall::abi_decode(&encoded).expect("decode registerName call");
    assert_eq!(decoded.name, call.name);
    assert_eq!(decoded.assetOwner, call.assetOwner);
    assert_eq!(decoded.options.duration, call.options.duration);
    assert!(matches!(decoded.authority.role, EvmAuthorityRole::None));

    let decoded_interface = decode_bns_call(&encoded).expect("decode BnsCalls interface");
    assert_eq!(
        decoded_interface.selector(),
        Bns::registerNameCall::SELECTOR
    );
}

#[test]
fn eip1559_tx_signing_recovers_expected_sender() {
    let signer = signer_from_private_key(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    )
    .expect("anvil signer");
    let contract = address!("2000000000000000000000000000000000000002");
    let call = register_name_call();
    let tx = build_eip1559_contract_tx(
        &call,
        Eip1559TxParams {
            chain_id: 31_337,
            nonce: 7,
            to: contract,
            gas_limit: 500_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            value: U256::ZERO,
        },
    );
    assert_eq!(tx.input, Bytes::from(call.abi_encode()));

    let signed = sign_eip1559_tx(tx, &signer).expect("sign tx");
    assert_eq!(signed.signer, signer.address());
    assert_eq!(signed.chain_id, 31_337);
    assert_eq!(signed.nonce, 7);

    let decoded = decode_signed_eip1559(&signed.raw_tx).expect("decode signed tx");
    assert_eq!(
        decoded.recover_signer().expect("recover signer"),
        signer.address()
    );
    assert_eq!(decoded.tx().chain_id, 31_337);
    assert_eq!(decoded.tx().nonce, 7);
    assert_eq!(decoded.tx().to, contract.into());
    assert_eq!(*decoded.hash(), signed.tx_hash);
}
