//! EVM ABI, transaction signing, JSON-RPC, and event helpers for the BNS contract.

mod rpc;
mod tx;

pub mod bindings {
    use alloy_sol_types::sol;

    sol!("../../apps/bns/src/Bns.sol");
}

pub use alloy_consensus::TxEip1559;
pub use alloy_primitives::{address, Address, Bytes, Log, LogData, TxKind, B256, U256};
pub use alloy_signer_local::PrivateKeySigner;
pub use alloy_sol_types::{SolCall, SolEventInterface, SolInterface};
pub use bindings::{
    AliasKind, AliasState, AuthorityKey, AuthorityKeyStatus, AuthorityKeyUpdate, AuthorityRole,
    AuthoritySetState, Bns, CallAuthority, ControllerRule, DocumentRef, DocumentState,
    DocumentStatus, DocumentUpdate, LogCheckpoint, MutationGuard, NameState, NameStatus,
    OwnerPolicyUpdate, OwnerResolution, OwnerSource, Principal, PrincipalKind, PurchaseContext,
    RegisterOptions, ReleaseMode, ResolveResult,
};
pub use rpc::{
    BlockRange, Eip1559FeeSuggestion, EthLog, EthRpcClient, EthTransaction, EthTransactionReceipt,
    RpcLogFilter,
};
pub use tx::{
    build_eip1559_contract_tx, decode_signed_eip1559, encode_call, sign_eip1559_tx,
    signer_from_private_key, BnsEvmError, BnsEvmResult, Eip1559TxParams, SignedEip1559Tx,
};

pub type BnsCall = Bns::BnsCalls;
pub type BnsEvent = Bns::BnsEvents;

pub fn decode_bns_call(calldata: &[u8]) -> BnsEvmResult<BnsCall> {
    BnsCall::abi_decode(calldata).map_err(|err| BnsEvmError::Abi(err.to_string()))
}

pub fn decode_bns_event(log: &Log) -> BnsEvmResult<Log<BnsEvent>> {
    BnsEvent::decode_log(log).map_err(|err| BnsEvmError::Abi(err.to_string()))
}
