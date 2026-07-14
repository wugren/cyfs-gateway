use std::str::FromStr;

use alloy_consensus::{SignableTransaction, Signed, TxEip1559};
use alloy_primitives::{Address, Bytes, TxKind, B256, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolCall;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BnsEvmError {
    #[error("BNS ABI error: {0}")]
    Abi(String),

    #[error("BNS EVM signer error: {0}")]
    Signer(String),

    #[error("BNS EVM transaction error: {0}")]
    Transaction(String),

    #[error("BNS EVM RPC error: {0}")]
    Rpc(String),

    #[error("BNS EVM parse error: {0}")]
    Parse(String),
}

pub type BnsEvmResult<T> = Result<T, BnsEvmError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Eip1559TxParams {
    pub chain_id: u64,
    pub nonce: u64,
    pub to: Address,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub value: U256,
}

impl Eip1559TxParams {
    pub fn anvil(chain_id: u64, nonce: u64, to: Address) -> Self {
        Self {
            chain_id,
            nonce,
            to,
            gas_limit: 3_000_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            value: U256::ZERO,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEip1559Tx {
    pub raw_tx: Vec<u8>,
    pub tx_hash: B256,
    pub signer: Address,
    pub chain_id: u64,
    pub nonce: u64,
}

pub fn encode_call<C: SolCall>(call: &C) -> Bytes {
    call.abi_encode().into()
}

pub fn build_eip1559_contract_tx<C: SolCall>(call: &C, params: Eip1559TxParams) -> TxEip1559 {
    TxEip1559 {
        chain_id: params.chain_id,
        nonce: params.nonce,
        gas_limit: params.gas_limit,
        max_fee_per_gas: params.max_fee_per_gas,
        max_priority_fee_per_gas: params.max_priority_fee_per_gas,
        to: TxKind::Call(params.to),
        value: params.value,
        input: encode_call(call),
        access_list: Default::default(),
    }
}

pub fn signer_from_private_key(private_key: &str) -> BnsEvmResult<PrivateKeySigner> {
    PrivateKeySigner::from_str(private_key)
        .map_err(|err| BnsEvmError::Signer(format!("invalid private key: {err}")))
}

pub fn sign_eip1559_tx(tx: TxEip1559, signer: &PrivateKeySigner) -> BnsEvmResult<SignedEip1559Tx> {
    let chain_id = tx.chain_id;
    let nonce = tx.nonce;
    let signature = signer
        .sign_hash_sync(&tx.signature_hash())
        .map_err(|err| BnsEvmError::Signer(err.to_string()))?;
    let signed = tx.into_signed(signature);
    let recovered = signed
        .recover_signer()
        .map_err(|err| BnsEvmError::Signer(format!("failed to recover signed tx sender: {err}")))?;
    if recovered != signer.address() {
        return Err(BnsEvmError::Signer(format!(
            "signed tx recovers {recovered:?}, expected {:?}",
            signer.address()
        )));
    }

    let mut raw_tx = Vec::with_capacity(signed.eip2718_encoded_length());
    signed.eip2718_encode(&mut raw_tx);
    Ok(SignedEip1559Tx {
        raw_tx,
        tx_hash: *signed.hash(),
        signer: recovered,
        chain_id,
        nonce,
    })
}

pub fn decode_signed_eip1559(raw_tx: &[u8]) -> BnsEvmResult<Signed<TxEip1559>> {
    let mut bytes = raw_tx;
    Signed::<TxEip1559>::eip2718_decode(&mut bytes)
        .map_err(|err| BnsEvmError::Transaction(format!("decode EIP-1559 tx failed: {err}")))
}
