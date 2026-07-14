use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use crate::{
    AuthorityKey, AuthorityKeyStatus, AuthorityKeyUpdate, AuthorityRole, CallAuthority,
    ControllerRule, DocumentRef, DocumentUpdate, MutationGuard, OwnerPolicyUpdate, Principal,
    PrincipalKind, RegisterOptions,
};
use async_trait::async_trait;
use bns_evm::{
    build_eip1559_contract_tx, sign_eip1559_tx, signer_from_private_key, Address,
    AuthorityKey as EvmAuthorityKey, AuthorityKeyStatus as EvmAuthorityKeyStatus,
    AuthorityKeyUpdate as EvmAuthorityKeyUpdate, AuthorityRole as EvmAuthorityRole, Bns,
    BnsEvmError, Bytes, CallAuthority as EvmCallAuthority, ControllerRule as EvmControllerRule,
    DocumentRef as EvmDocumentRef, DocumentUpdate as EvmDocumentUpdate, Eip1559TxParams,
    EthRpcClient, EthTransactionReceipt, MutationGuard as EvmMutationGuard,
    OwnerPolicyUpdate as EvmOwnerPolicyUpdate, Principal as EvmPrincipal,
    PrincipalKind as EvmPrincipalKind, RegisterOptions as EvmRegisterOptions, SignedEip1559Tx,
    SolCall, TxEip1559, B256, U256,
};
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration, Instant};

use crate::{
    BnsApplyMutationsReq, BnsBootstrapNameReq, BnsClientError, BnsClientResult, BnsIndexerApi,
    BnsPrepareTxReq, BnsPublishDocumentReq, BnsRegisterNameReq, BnsRevokeDocumentReq,
    BnsSetControllerPolicyReq, BnsSetMinDocumentIatReq, BnsSubmitRawTxReq, BnsSystemInfo,
    BnsTxExecutionState, BnsUpdateAuthorityKeysReq,
};

impl From<BnsEvmError> for BnsClientError {
    fn from(value: BnsEvmError) -> Self {
        match value {
            BnsEvmError::Rpc(message) => Self::Transport(message),
            BnsEvmError::Abi(message)
            | BnsEvmError::Signer(message)
            | BnsEvmError::Transaction(message)
            | BnsEvmError::Parse(message) => Self::Serialization(message),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsEvmClientConfig {
    pub rpc_endpoint: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

impl BnsEvmClientConfig {
    pub fn anvil(
        rpc_endpoint: impl Into<String>,
        contract_address: impl Into<String>,
        chain_id: u64,
    ) -> Self {
        Self {
            rpc_endpoint: rpc_endpoint.into(),
            chain_id,
            contract_address: contract_address.into(),
            gas_limit: 3_000_000,
            max_fee_per_gas: 2_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        }
    }

    pub fn from_system_info(info: &BnsSystemInfo) -> Self {
        Self {
            // Unified BNS RPC mode never dereferences this endpoint. Keeping it
            // empty makes accidental direct-chain use fail closed.
            rpc_endpoint: String::new(),
            chain_id: info.chain_id,
            contract_address: info.contract_address.clone(),
            gas_limit: u64::MAX,
            max_fee_per_gas: u128::MAX,
            max_priority_fee_per_gas: u128::MAX,
        }
    }

    fn contract(&self) -> BnsClientResult<Address> {
        parse_address(&self.contract_address, "contract_address")
    }

    fn tx_params(&self, nonce: u64) -> BnsClientResult<Eip1559TxParams> {
        Ok(Eip1559TxParams {
            chain_id: self.chain_id,
            nonce,
            to: self.contract()?,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            value: U256::ZERO,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsEvmTxSubmission {
    pub tx_hash: String,
    pub raw_tx: String,
    pub from: String,
    pub nonce: u64,
    pub chain_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_status: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_block_number: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_confirmations: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsEvmTxReceipt {
    pub tx_hash: String,
    pub status: Option<u64>,
    pub block_number: u64,
    pub confirmations: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsEvmTxSuggestion {
    pub estimated_gas: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsEvmReceiptWaitConfig {
    pub timeout_ms: u64,
    pub poll_interval_ms: u64,
    pub confirmations: u64,
    pub require_success: bool,
}

impl BnsEvmReceiptWaitConfig {
    pub fn included() -> Self {
        Self {
            timeout_ms: 30_000,
            poll_interval_ms: 500,
            confirmations: 1,
            require_success: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BnsEvmWriteOperation {
    Manual,
    RegisterName,
    BootstrapName,
    ApplyMutations,
    PublishDocument,
    RevokeDocument,
    SetMinDocumentIat,
    SetControllerPolicy,
    UpdateAuthorityKeys,
}

impl BnsEvmWriteOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::RegisterName => "register_name",
            Self::BootstrapName => "bootstrap_name",
            Self::ApplyMutations => "apply_mutations",
            Self::PublishDocument => "publish_document",
            Self::RevokeDocument => "revoke_document",
            Self::SetMinDocumentIat => "set_min_document_iat",
            Self::SetControllerPolicy => "set_controller_policy",
            Self::UpdateAuthorityKeys => "update_authority_keys",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsEvmSignRequest {
    pub operation: BnsEvmWriteOperation,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doc_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_owner: Option<String>,
    pub authority: CallAuthority,
}

impl BnsEvmSignRequest {
    pub fn new(
        operation: BnsEvmWriteOperation,
        name: impl Into<String>,
        authority: CallAuthority,
    ) -> Self {
        Self {
            operation,
            name: name.into(),
            doc_type: None,
            asset_owner: None,
            authority,
        }
    }

    fn for_register(operation: BnsEvmWriteOperation, req: &BnsRegisterNameReq) -> Self {
        Self {
            operation,
            name: req.name.clone(),
            doc_type: None,
            asset_owner: Some(req.asset_owner.clone()),
            authority: req.authority.clone(),
        }
    }

    fn for_bootstrap(req: &BnsBootstrapNameReq) -> Self {
        Self {
            operation: BnsEvmWriteOperation::BootstrapName,
            name: req.name.clone(),
            doc_type: None,
            asset_owner: Some(req.asset_owner.clone()),
            authority: req.authority.clone(),
        }
    }

    fn for_document(
        operation: BnsEvmWriteOperation,
        name: &str,
        doc_type: impl Into<String>,
        authority: CallAuthority,
    ) -> Self {
        Self {
            operation,
            name: name.to_string(),
            doc_type: Some(doc_type.into()),
            asset_owner: None,
            authority,
        }
    }
}

#[async_trait]
pub trait BnsEvmKeyManager: Send + Sync {
    async fn signer_address(&self, request: &BnsEvmSignRequest) -> BnsClientResult<Address>;

    async fn sign_transaction(
        &self,
        request: &BnsEvmSignRequest,
        tx: TxEip1559,
    ) -> BnsClientResult<SignedEip1559Tx>;
}

pub struct StaticBnsEvmKeyManager {
    private_key: String,
    signer_address: Address,
}

impl StaticBnsEvmKeyManager {
    pub fn new(private_key: impl Into<String>) -> BnsClientResult<Self> {
        let private_key = private_key.into();
        let signer = signer_from_private_key(private_key.as_str()).map_err(BnsClientError::from)?;
        Ok(Self {
            private_key,
            signer_address: signer.address(),
        })
    }

    pub fn signer_address(&self) -> Address {
        self.signer_address
    }
}

#[async_trait]
impl BnsEvmKeyManager for StaticBnsEvmKeyManager {
    async fn signer_address(&self, _request: &BnsEvmSignRequest) -> BnsClientResult<Address> {
        Ok(self.signer_address)
    }

    async fn sign_transaction(
        &self,
        _request: &BnsEvmSignRequest,
        tx: TxEip1559,
    ) -> BnsClientResult<SignedEip1559Tx> {
        let signer =
            signer_from_private_key(self.private_key.as_str()).map_err(BnsClientError::from)?;
        sign_eip1559_tx(tx, &signer).map_err(BnsClientError::from)
    }
}

#[derive(Clone)]
pub enum BnsEvmRawTxSubmitter {
    ChainRpc,
    BnsServer(Arc<dyn BnsIndexerApi>),
}

#[derive(Clone)]
pub struct BnsEvmStandardClient {
    rpc: Arc<EthRpcClient>,
    config: BnsEvmClientConfig,
}

impl BnsEvmStandardClient {
    pub fn new(config: BnsEvmClientConfig) -> Self {
        Self {
            rpc: Arc::new(EthRpcClient::new(config.rpc_endpoint.clone())),
            config,
        }
    }

    pub fn rpc(&self) -> &EthRpcClient {
        &self.rpc
    }

    pub fn config(&self) -> &BnsEvmClientConfig {
        &self.config
    }

    pub async fn submit_raw_tx(&self, raw_tx: &[u8]) -> BnsClientResult<String> {
        self.rpc
            .send_raw_transaction(raw_tx)
            .await
            .map(|hash| format!("{hash:#x}"))
            .map_err(Into::into)
    }

    pub fn build_calldata<C: SolCall>(&self, call: &C) -> Bytes {
        bns_evm::encode_call(call)
    }

    pub fn build_unsigned_tx<C: SolCall>(
        &self,
        call: &C,
        nonce: u64,
    ) -> BnsClientResult<TxEip1559> {
        Ok(build_eip1559_contract_tx(
            call,
            self.config.tx_params(nonce)?,
        ))
    }

    /// Build a transaction from live node estimates. A 20% buffer is added to
    /// `eth_estimateGas`; fee caps come from the node's EIP-1559 suggestion.
    pub async fn build_unsigned_tx_with_suggestion<C: SolCall>(
        &self,
        call: &C,
        from: Address,
        nonce: u64,
    ) -> BnsClientResult<(TxEip1559, BnsEvmTxSuggestion)> {
        let to = self.config.contract()?;
        let calldata = self.build_calldata(call);
        let estimated_gas = self
            .rpc
            .estimate_gas(from, to, &calldata)
            .await
            .map_err(BnsClientError::from)?;
        let gas_buffer = estimated_gas / 5 + u64::from(estimated_gas % 5 != 0);
        let gas_limit = estimated_gas.saturating_add(gas_buffer);
        let fees = self
            .rpc
            .suggest_eip1559_fees()
            .await
            .map_err(BnsClientError::from)?;
        let suggestion = BnsEvmTxSuggestion {
            estimated_gas,
            gas_limit,
            max_fee_per_gas: fees.max_fee_per_gas,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        };
        let tx = build_eip1559_contract_tx(
            call,
            Eip1559TxParams {
                chain_id: self.config.chain_id,
                nonce,
                to,
                gas_limit: suggestion.gas_limit,
                max_fee_per_gas: suggestion.max_fee_per_gas,
                max_priority_fee_per_gas: suggestion.max_priority_fee_per_gas,
                value: U256::ZERO,
            },
        );
        Ok((tx, suggestion))
    }
}

pub struct BnsEvmControllerClient {
    standard: BnsEvmStandardClient,
    key_manager: Arc<dyn BnsEvmKeyManager>,
    raw_tx_submitter: BnsEvmRawTxSubmitter,
    default_signer_address: Option<Address>,
    next_nonces: Mutex<HashMap<Address, u64>>,
    submission_lock: tokio::sync::Mutex<()>,
    receipt_wait: Option<BnsEvmReceiptWaitConfig>,
    dynamic_tx_params: bool,
}

impl BnsEvmControllerClient {
    pub fn new(config: BnsEvmClientConfig, private_key: &str) -> BnsClientResult<Self> {
        let key_manager = StaticBnsEvmKeyManager::new(private_key)?;
        let default_signer_address = Some(key_manager.signer_address());
        Ok(Self::new_with_key_manager_and_submitter(
            config,
            Arc::new(key_manager),
            BnsEvmRawTxSubmitter::ChainRpc,
            default_signer_address,
        ))
    }

    pub fn new_with_key_manager(
        config: BnsEvmClientConfig,
        key_manager: Arc<dyn BnsEvmKeyManager>,
    ) -> Self {
        Self::new_with_key_manager_and_submitter(
            config,
            key_manager,
            BnsEvmRawTxSubmitter::ChainRpc,
            None,
        )
    }

    pub fn new_with_bns_server_submitter(
        config: BnsEvmClientConfig,
        key_manager: Arc<dyn BnsEvmKeyManager>,
        bns_server: Arc<dyn BnsIndexerApi>,
    ) -> Self {
        Self::new_with_key_manager_and_submitter(
            config,
            key_manager,
            BnsEvmRawTxSubmitter::BnsServer(bns_server),
            None,
        )
    }

    fn new_with_key_manager_and_submitter(
        config: BnsEvmClientConfig,
        key_manager: Arc<dyn BnsEvmKeyManager>,
        raw_tx_submitter: BnsEvmRawTxSubmitter,
        default_signer_address: Option<Address>,
    ) -> Self {
        Self {
            standard: BnsEvmStandardClient::new(config),
            key_manager,
            raw_tx_submitter,
            default_signer_address,
            next_nonces: Mutex::new(HashMap::new()),
            submission_lock: tokio::sync::Mutex::new(()),
            receipt_wait: None,
            dynamic_tx_params: false,
        }
    }

    pub fn default_signer_address(&self) -> Option<Address> {
        self.default_signer_address
    }

    pub fn key_manager(&self) -> &Arc<dyn BnsEvmKeyManager> {
        &self.key_manager
    }

    pub async fn signer_address_for(
        &self,
        request: &BnsEvmSignRequest,
    ) -> BnsClientResult<Address> {
        self.key_manager.signer_address(request).await
    }

    pub fn with_raw_tx_submitter(mut self, raw_tx_submitter: BnsEvmRawTxSubmitter) -> Self {
        self.raw_tx_submitter = raw_tx_submitter;
        self
    }

    pub fn with_default_signer_address(mut self, address: Address) -> Self {
        self.default_signer_address = Some(address);
        self
    }

    pub fn with_receipt_wait(mut self, receipt_wait: Option<BnsEvmReceiptWaitConfig>) -> Self {
        self.receipt_wait = receipt_wait;
        self
    }

    /// Opt into live `eth_estimateGas` and fee suggestions for each signed
    /// transaction. Static config values remain useful for deterministic Anvil
    /// tests and callers that manage fee policy themselves.
    pub fn with_dynamic_tx_params(mut self, enabled: bool) -> Self {
        self.dynamic_tx_params = enabled;
        self
    }

    pub fn signer_address(&self) -> Option<Address> {
        self.default_signer_address
    }

    pub fn standard(&self) -> &BnsEvmStandardClient {
        &self.standard
    }

    pub async fn sign_and_submit<C: SolCall>(
        &self,
        call: &C,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let request =
            BnsEvmSignRequest::new(BnsEvmWriteOperation::Manual, "", CallAuthority::public());
        self.sign_and_submit_with_request(&request, call).await
    }

    pub async fn sign_and_submit_with_request<C: SolCall>(
        &self,
        request: &BnsEvmSignRequest,
        call: &C,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let signer_address = self.key_manager.signer_address(request).await?;
        let _submission_guard = self.submission_lock.lock().await;
        let tx = match &self.raw_tx_submitter {
            BnsEvmRawTxSubmitter::BnsServer(server) => {
                let calldata = self.standard.build_calldata(call);
                let prepared = server
                    .prepare_tx(BnsPrepareTxReq::new(
                        format!("{signer_address:#x}"),
                        calldata.as_ref(),
                    ))
                    .await?;
                let to = parse_address(&prepared.contract_address, "contract_address")?;
                Ok(build_eip1559_contract_tx(
                    call,
                    Eip1559TxParams {
                        chain_id: prepared.chain_id,
                        nonce: prepared.nonce,
                        to,
                        gas_limit: prepared.gas_limit,
                        max_fee_per_gas: prepared.max_fee_per_gas,
                        max_priority_fee_per_gas: prepared.max_priority_fee_per_gas,
                        value: U256::ZERO,
                    },
                ))
            }
            BnsEvmRawTxSubmitter::ChainRpc => {
                let nonce = self.next_nonce(signer_address).await?;
                if self.dynamic_tx_params {
                    self.standard
                        .build_unsigned_tx_with_suggestion(call, signer_address, nonce)
                        .await
                        .map(|(tx, _)| tx)
                } else {
                    self.standard.build_unsigned_tx(call, nonce)
                }
            }
        };
        let tx = match tx {
            Ok(tx) => tx,
            Err(error) => {
                self.reset_nonce(signer_address);
                return Err(error);
            }
        };
        let signed = match self.key_manager.sign_transaction(request, tx).await {
            Ok(signed) => signed,
            Err(error) => {
                self.reset_nonce(signer_address);
                return Err(error);
            }
        };
        if signed.signer != signer_address {
            self.reset_nonce(signer_address);
            return Err(BnsClientError::Serialization(format!(
                "BNS EVM key manager signed as {:#x}, expected {:#x}",
                signed.signer, signer_address
            )));
        }

        match self.submit_raw_tx(&signed.raw_tx).await {
            Ok(tx_hash) => {
                let receipt = match self.receipt_wait {
                    Some(config) => Some(self.wait_for_receipt(tx_hash.as_str(), config).await?),
                    None => None,
                };
                Ok(BnsEvmTxSubmission {
                    tx_hash,
                    raw_tx: format!("0x{}", hex::encode(&signed.raw_tx)),
                    from: format!("{:#x}", signed.signer),
                    nonce: signed.nonce,
                    chain_id: signed.chain_id,
                    receipt_status: receipt.as_ref().and_then(|receipt| receipt.status),
                    receipt_block_number: receipt.as_ref().map(|receipt| receipt.block_number),
                    receipt_confirmations: receipt.as_ref().map(|receipt| receipt.confirmations),
                })
            }
            Err(error) => {
                self.reset_nonce(signer_address);
                Err(error)
            }
        }
    }

    pub async fn wait_for_receipt(
        &self,
        tx_hash: &str,
        config: BnsEvmReceiptWaitConfig,
    ) -> BnsClientResult<BnsEvmTxReceipt> {
        let required_confirmations = config.confirmations.max(1);
        let poll_interval = Duration::from_millis(config.poll_interval_ms.max(1));
        let deadline = Instant::now() + Duration::from_millis(config.timeout_ms.max(1));

        if let BnsEvmRawTxSubmitter::BnsServer(server) = &self.raw_tx_submitter {
            loop {
                let state = server.query_tx_state(tx_hash).await?;
                match state.state {
                    BnsTxExecutionState::Succeeded
                        if state.confirmations >= required_confirmations =>
                    {
                        return Ok(BnsEvmTxReceipt {
                            tx_hash: state.tx_hash,
                            status: Some(1),
                            block_number: state.block_number.unwrap_or_default(),
                            confirmations: state.confirmations,
                        });
                    }
                    BnsTxExecutionState::Reverted => {
                        return Err(BnsClientError::registry(
                            "EVM_TX_REVERTED",
                            format!("BNS EVM tx {tx_hash} reverted"),
                        ));
                    }
                    _ => {}
                }
                if Instant::now() >= deadline {
                    return Err(BnsClientError::Transport(format!(
                        "timed out waiting for BNS EVM tx receipt {tx_hash}"
                    )));
                }
                sleep(poll_interval).await;
            }
        }

        let tx_hash_value = parse_b256(tx_hash, "tx_hash")?;

        loop {
            if let Some(receipt) = self
                .standard
                .rpc
                .transaction_receipt(tx_hash_value)
                .await
                .map_err(BnsClientError::from)?
            {
                if let Some(block_number) = receipt.block_number {
                    let confirmations = self.receipt_confirmations(block_number).await?;
                    if confirmations >= required_confirmations {
                        if config.require_success && receipt.status == Some(0) {
                            return Err(BnsClientError::registry(
                                "EVM_TX_REVERTED",
                                format!("BNS EVM tx {tx_hash} reverted"),
                            ));
                        }
                        return Ok(receipt_to_submission_receipt(
                            tx_hash,
                            receipt,
                            confirmations,
                        ));
                    }
                }
            }

            if Instant::now() >= deadline {
                return Err(BnsClientError::Transport(format!(
                    "timed out waiting for BNS EVM tx receipt {tx_hash}"
                )));
            }
            sleep(poll_interval).await;
        }
    }

    async fn receipt_confirmations(&self, block_number: u64) -> BnsClientResult<u64> {
        let latest = self
            .standard
            .rpc
            .block_number()
            .await
            .map_err(BnsClientError::from)?;
        Ok(latest.saturating_sub(block_number) + 1)
    }

    async fn submit_raw_tx(&self, raw_tx: &[u8]) -> BnsClientResult<String> {
        match &self.raw_tx_submitter {
            BnsEvmRawTxSubmitter::ChainRpc => self.standard.submit_raw_tx(raw_tx).await,
            BnsEvmRawTxSubmitter::BnsServer(server) => server
                .submit_raw_tx(BnsSubmitRawTxReq::from_bytes(raw_tx))
                .await
                .map(|resp| resp.tx_hash),
        }
    }

    pub async fn register_name(
        &self,
        req: &BnsRegisterNameReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let request = BnsEvmSignRequest::for_register(BnsEvmWriteOperation::RegisterName, req);
        self.sign_and_submit_with_request(&request, &register_name_call(req)?)
            .await
    }

    pub async fn bootstrap_name(
        &self,
        req: &BnsBootstrapNameReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let request = BnsEvmSignRequest::for_bootstrap(req);
        self.sign_and_submit_with_request(&request, &bootstrap_name_call(req)?)
            .await
    }

    pub async fn apply_mutations(
        &self,
        req: &BnsApplyMutationsReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let request = BnsEvmSignRequest::new(
            BnsEvmWriteOperation::ApplyMutations,
            req.name.clone(),
            req.authority.clone(),
        );
        self.sign_and_submit_with_request(&request, &apply_mutations_call(req)?)
            .await
    }

    pub async fn publish_document(
        &self,
        req: &BnsPublishDocumentReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let request = BnsEvmSignRequest::for_document(
            BnsEvmWriteOperation::PublishDocument,
            &req.name,
            req.update.doc_type.clone(),
            req.authority.clone(),
        );
        self.sign_and_submit_with_request(&request, &publish_document_call(req)?)
            .await
    }

    pub async fn revoke_document(
        &self,
        req: &BnsRevokeDocumentReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let request = BnsEvmSignRequest::for_document(
            BnsEvmWriteOperation::RevokeDocument,
            &req.name,
            req.doc_type.clone(),
            req.authority.clone(),
        );
        self.sign_and_submit_with_request(&request, &revoke_document_call(req)?)
            .await
    }

    pub async fn set_min_document_iat(
        &self,
        req: &BnsSetMinDocumentIatReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let request = BnsEvmSignRequest::new(
            BnsEvmWriteOperation::SetMinDocumentIat,
            req.name.clone(),
            req.authority.clone(),
        );
        self.sign_and_submit_with_request(&request, &set_min_document_iat_call(req)?)
            .await
    }

    pub async fn set_controller_policy(
        &self,
        req: &BnsSetControllerPolicyReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let request = BnsEvmSignRequest::new(
            BnsEvmWriteOperation::SetControllerPolicy,
            req.name.clone(),
            req.authority.clone(),
        );
        self.sign_and_submit_with_request(&request, &set_controller_policy_call(req)?)
            .await
    }

    pub async fn update_authority_keys(
        &self,
        req: &BnsUpdateAuthorityKeysReq,
    ) -> BnsClientResult<BnsEvmTxSubmission> {
        let request = BnsEvmSignRequest::new(
            BnsEvmWriteOperation::UpdateAuthorityKeys,
            req.name.clone(),
            req.authority.clone(),
        );
        self.sign_and_submit_with_request(&request, &update_authority_keys_call(req)?)
            .await
    }

    async fn next_nonce(&self, signer_address: Address) -> BnsClientResult<u64> {
        {
            let mut cached = self.next_nonces.lock().map_err(|_| {
                BnsClientError::Transport("BNS EVM nonce lock poisoned".to_string())
            })?;
            if let Some(nonce) = cached.get_mut(&signer_address) {
                let current = *nonce;
                *nonce += 1;
                return Ok(current);
            }
        }

        let chain_nonce = self
            .standard
            .rpc
            .transaction_count(signer_address)
            .await
            .map_err(BnsClientError::from)?;
        let mut cached = self
            .next_nonces
            .lock()
            .map_err(|_| BnsClientError::Transport("BNS EVM nonce lock poisoned".to_string()))?;
        let nonce = *cached.get(&signer_address).unwrap_or(&chain_nonce);
        cached.insert(signer_address, nonce + 1);
        Ok(nonce)
    }

    fn reset_nonce(&self, signer_address: Address) {
        if let Ok(mut cached) = self.next_nonces.lock() {
            cached.remove(&signer_address);
        }
    }
}

pub fn register_name_call(req: &BnsRegisterNameReq) -> BnsClientResult<Bns::registerNameCall> {
    Ok(Bns::registerNameCall {
        name: req.name.clone(),
        assetOwner: parse_address(&req.asset_owner, "asset_owner")?,
        options: register_options_to_evm(&req.options)?,
        authorityUpdates: authority_key_updates_to_evm(&req.authority_key_updates)?,
        semanticOwnerAfterAuthority: req
            .semantic_owner_after_authority
            .as_ref()
            .map(principal_to_evm)
            .transpose()?
            .unwrap_or_else(unset_principal),
        controllerPolicy: controller_rules_to_evm(&req.controller_policy)?,
        controllerPolicyHash: parse_b256_or_zero(
            &req.controller_policy_hash,
            "controller_policy_hash",
        )?,
        initialDocuments: document_updates_to_evm(&req.initial_documents)?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn bootstrap_name_call(req: &BnsBootstrapNameReq) -> BnsClientResult<Bns::registerNameCall> {
    Ok(Bns::registerNameCall {
        name: req.name.clone(),
        assetOwner: parse_address(&req.asset_owner, "asset_owner")?,
        options: register_options_to_evm(&req.options)?,
        authorityUpdates: authority_key_updates_to_evm(&req.authority_key_updates)?,
        semanticOwnerAfterAuthority: req
            .semantic_owner_after_authority
            .as_ref()
            .map(principal_to_evm)
            .transpose()?
            .unwrap_or_else(unset_principal),
        controllerPolicy: controller_rules_to_evm(&req.controller_policy)?,
        controllerPolicyHash: parse_b256_or_zero(
            &req.controller_policy_hash,
            "controller_policy_hash",
        )?,
        initialDocuments: document_updates_to_evm(&req.initial_documents)?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn apply_mutations_call(
    req: &BnsApplyMutationsReq,
) -> BnsClientResult<Bns::applyMutationsCall> {
    Ok(Bns::applyMutationsCall {
        name: req.name.clone(),
        authorityUpdates: authority_key_updates_to_evm(&req.authority_key_updates)?,
        documents: document_updates_to_evm(&req.documents)?,
        ownerPolicy: owner_policy_update_to_evm(&req.owner_policy)?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn publish_document_call(
    req: &BnsPublishDocumentReq,
) -> BnsClientResult<Bns::publishDocumentCall> {
    Ok(Bns::publishDocumentCall {
        name: req.name.clone(),
        docType: req.update.doc_type.clone(),
        expectedVersion: req.update.expected_version,
        document: document_ref_to_evm(&req.update.document)?,
        controller: principal_to_evm(&req.update.controller)?,
        beneficiary: principal_to_evm(&req.update.beneficiary)?,
        paymentTarget: parse_address_or_zero(&req.update.payment_target, "payment_target")?,
        expireAt: req.update.expire_at,
        controllerPolicyHash: parse_b256_or_zero(
            &req.update.controller_policy_hash,
            "controller_policy_hash",
        )?,
        paymentPolicyHash: parse_b256_or_zero(
            &req.update.payment_policy_hash,
            "payment_policy_hash",
        )?,
        splitPolicyHash: parse_b256_or_zero(&req.update.split_policy_hash, "split_policy_hash")?,
        pricePolicyHash: parse_b256_or_zero(&req.update.price_policy_hash, "price_policy_hash")?,
        rightsPolicyHash: parse_b256_or_zero(&req.update.rights_policy_hash, "rights_policy_hash")?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn revoke_document_call(
    req: &BnsRevokeDocumentReq,
) -> BnsClientResult<Bns::revokeDocumentCall> {
    Ok(Bns::revokeDocumentCall {
        name: req.name.clone(),
        docType: req.doc_type.clone(),
        expectedVersion: req.expected_version,
        reasonHash: parse_b256_or_zero(&req.reason_hash, "reason_hash")?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn set_min_document_iat_call(
    req: &BnsSetMinDocumentIatReq,
) -> BnsClientResult<Bns::setMinDocumentIatCall> {
    Ok(Bns::setMinDocumentIatCall {
        name: req.name.clone(),
        minDocumentIat: req.min_document_iat,
        reasonHash: parse_b256_or_zero(&req.reason_hash, "reason_hash")?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn set_controller_policy_call(
    req: &BnsSetControllerPolicyReq,
) -> BnsClientResult<Bns::setControllerPolicyCall> {
    Ok(Bns::setControllerPolicyCall {
        name: req.name.clone(),
        rules: controller_rules_to_evm(&req.rules)?,
        policyHash: parse_b256_or_zero(&req.policy_hash, "policy_hash")?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

pub fn update_authority_keys_call(
    req: &BnsUpdateAuthorityKeysReq,
) -> BnsClientResult<Bns::updateAuthorityKeysCall> {
    Ok(Bns::updateAuthorityKeysCall {
        name: req.name.clone(),
        updates: authority_key_updates_to_evm(&req.updates)?,
        authority: call_authority_to_evm(&req.authority)?,
        guard: mutation_guard_to_evm(req.guard),
    })
}

fn register_options_to_evm(options: &RegisterOptions) -> BnsClientResult<EvmRegisterOptions> {
    Ok(EvmRegisterOptions {
        duration: options.duration,
        gracePeriod: options.grace_period,
        renewable: options.renewable,
        transferable: options.transferable,
        initialSemanticOwner: principal_to_evm(&options.initial_semantic_owner)?,
        allowDelegatedSubnames: options.allow_delegated_subnames,
        initialPaymentTarget: parse_address_or_zero(
            &options.initial_payment_target,
            "initial_payment_target",
        )?,
        initialPaymentPolicyHash: parse_b256_or_zero(
            &options.initial_payment_policy_hash,
            "initial_payment_policy_hash",
        )?,
        initialNamespacePolicyHash: parse_b256_or_zero(
            &options.initial_namespace_policy_hash,
            "initial_namespace_policy_hash",
        )?,
    })
}

fn document_updates_to_evm(updates: &[DocumentUpdate]) -> BnsClientResult<Vec<EvmDocumentUpdate>> {
    updates.iter().map(document_update_to_evm).collect()
}

fn document_update_to_evm(update: &DocumentUpdate) -> BnsClientResult<EvmDocumentUpdate> {
    Ok(EvmDocumentUpdate {
        docType: update.doc_type.clone(),
        expectedVersion: update.expected_version,
        document: document_ref_to_evm(&update.document)?,
        controller: principal_to_evm(&update.controller)?,
        beneficiary: principal_to_evm(&update.beneficiary)?,
        paymentTarget: parse_address_or_zero(&update.payment_target, "payment_target")?,
        expireAt: update.expire_at,
        controllerPolicyHash: parse_b256_or_zero(
            &update.controller_policy_hash,
            "controller_policy_hash",
        )?,
        paymentPolicyHash: parse_b256_or_zero(&update.payment_policy_hash, "payment_policy_hash")?,
        splitPolicyHash: parse_b256_or_zero(&update.split_policy_hash, "split_policy_hash")?,
        pricePolicyHash: parse_b256_or_zero(&update.price_policy_hash, "price_policy_hash")?,
        rightsPolicyHash: parse_b256_or_zero(&update.rights_policy_hash, "rights_policy_hash")?,
    })
}

fn owner_policy_update_to_evm(update: &OwnerPolicyUpdate) -> BnsClientResult<EvmOwnerPolicyUpdate> {
    Ok(EvmOwnerPolicyUpdate {
        updateMinDocumentIat: update.update_min_document_iat,
        minDocumentIat: update.min_document_iat,
        reasonHash: parse_b256_or_zero(&update.reason_hash, "reason_hash")?,
    })
}

fn document_ref_to_evm(document: &DocumentRef) -> BnsClientResult<EvmDocumentRef> {
    Ok(EvmDocumentRef {
        storageType: bytes32_label_or_hash(&document.storage_type, "storage_type")?,
        uri: document.uri.clone(),
        inlineDocument: Bytes::from(document.inline_document.clone()),
        contentHash: parse_b256_or_zero(&document.content_hash, "content_hash")?,
        schema: parse_b256_or_zero(&document.schema, "schema")?,
        codec: parse_b256_or_zero(&document.codec, "codec")?,
        extraHash: parse_b256_or_zero(&document.extra_hash, "extra_hash")?,
    })
}

fn controller_rules_to_evm(rules: &[ControllerRule]) -> BnsClientResult<Vec<EvmControllerRule>> {
    rules.iter().map(controller_rule_to_evm).collect()
}

fn controller_rule_to_evm(rule: &ControllerRule) -> BnsClientResult<EvmControllerRule> {
    Ok(EvmControllerRule {
        controller: principal_to_evm(&rule.controller)?,
        docType: rule.doc_type.clone(),
        permissions: rule.permissions,
        namespaceScopeHash: parse_b256_or_zero(&rule.namespace_scope_hash, "namespace_scope_hash")?,
        validFrom: rule.valid_from,
        validUntil: rule.valid_until,
        constraintHash: parse_b256_or_zero(&rule.constraint_hash, "constraint_hash")?,
    })
}

fn authority_key_updates_to_evm(
    updates: &[AuthorityKeyUpdate],
) -> BnsClientResult<Vec<EvmAuthorityKeyUpdate>> {
    updates.iter().map(authority_key_update_to_evm).collect()
}

fn authority_key_update_to_evm(
    update: &AuthorityKeyUpdate,
) -> BnsClientResult<EvmAuthorityKeyUpdate> {
    Ok(EvmAuthorityKeyUpdate {
        key: authority_key_to_evm(&update.key)?,
        active: update.active,
    })
}

fn authority_key_to_evm(key: &AuthorityKey) -> BnsClientResult<EvmAuthorityKey> {
    Ok(EvmAuthorityKey {
        kid: parse_b256_or_zero(&key.kid, "kid")?,
        verificationMethod: bytes32_label_or_hash(&key.verification_method, "verification_method")?,
        keyData: Bytes::from(key.key_data.clone()),
        purposes: key.purposes,
        validFrom: key.valid_from,
        validUntil: key.valid_until,
        status: authority_key_status_to_evm(key.status),
        metadataHash: parse_b256_or_zero(&key.metadata_hash, "metadata_hash")?,
    })
}

fn call_authority_to_evm(authority: &CallAuthority) -> BnsClientResult<EvmCallAuthority> {
    Ok(EvmCallAuthority {
        role: authority_role_to_evm(authority.role),
        actor: principal_to_evm(&authority.actor)?,
        kid: parse_b256_or_zero(&authority.kid, "kid")?,
    })
}

fn principal_to_evm(principal: &Principal) -> BnsClientResult<EvmPrincipal> {
    let value = match principal.kind {
        PrincipalKind::Unset => {
            if !principal.value.is_empty() {
                return Err(BnsClientError::Serialization(
                    "unset principal must have empty value".to_string(),
                ));
            }
            Bytes::new()
        }
        PrincipalKind::ChainAccount => {
            let address = parse_address(&principal.value, "chain_account")?;
            Bytes::copy_from_slice(address.as_slice())
        }
        PrincipalKind::BnsName => Bytes::from(principal.value.as_bytes().to_vec()),
    };

    Ok(EvmPrincipal {
        kind: principal_kind_to_evm(principal.kind),
        value,
    })
}

fn unset_principal() -> EvmPrincipal {
    EvmPrincipal {
        kind: principal_kind_to_evm(PrincipalKind::Unset),
        value: Bytes::new(),
    }
}

fn mutation_guard_to_evm(guard: MutationGuard) -> EvmMutationGuard {
    EvmMutationGuard {
        expectedNameSeq: guard.expected_name_seq,
        expectedParentNameSeq: guard.expected_parent_name_seq,
    }
}

fn principal_kind_to_evm(kind: PrincipalKind) -> EvmPrincipalKind {
    match kind {
        PrincipalKind::Unset => EvmPrincipalKind::Unset,
        PrincipalKind::ChainAccount => EvmPrincipalKind::ChainAccount,
        PrincipalKind::BnsName => EvmPrincipalKind::BnsName,
    }
}

fn authority_role_to_evm(role: AuthorityRole) -> EvmAuthorityRole {
    match role {
        AuthorityRole::None => EvmAuthorityRole::None,
        AuthorityRole::Owner => EvmAuthorityRole::Owner,
        AuthorityRole::Controller => EvmAuthorityRole::Controller,
    }
}

fn authority_key_status_to_evm(status: AuthorityKeyStatus) -> EvmAuthorityKeyStatus {
    match status {
        AuthorityKeyStatus::Missing => EvmAuthorityKeyStatus::Missing,
        AuthorityKeyStatus::Active => EvmAuthorityKeyStatus::Active,
        AuthorityKeyStatus::Revoked => EvmAuthorityKeyStatus::Revoked,
        AuthorityKeyStatus::Expired => EvmAuthorityKeyStatus::Expired,
    }
}

fn parse_address(value: &str, field: &str) -> BnsClientResult<Address> {
    Address::from_str(value).map_err(|err| {
        BnsClientError::Serialization(format!("invalid {field} address `{value}`: {err}"))
    })
}

fn parse_address_or_zero(value: &str, field: &str) -> BnsClientResult<Address> {
    if value.is_empty() {
        Ok(Address::ZERO)
    } else {
        parse_address(value, field)
    }
}

fn parse_b256(value: &str, field: &str) -> BnsClientResult<B256> {
    B256::from_str(value).map_err(|err| {
        BnsClientError::Serialization(format!("invalid {field} bytes32 `{value}`: {err}"))
    })
}

fn parse_b256_or_zero(value: &str, field: &str) -> BnsClientResult<B256> {
    if value.is_empty() {
        return Ok(B256::ZERO);
    }
    parse_b256(value, field)
}

fn bytes32_label_or_hash(value: &str, field: &str) -> BnsClientResult<B256> {
    if value.is_empty() {
        return Ok(B256::ZERO);
    }
    if value.starts_with("0x") {
        return parse_b256_or_zero(value, field);
    }
    let bytes = value.as_bytes();
    if bytes.len() > 32 {
        return Err(BnsClientError::Serialization(format!(
            "{field} `{value}` is longer than 32 bytes"
        )));
    }
    let mut out = [0u8; 32];
    out[..bytes.len()].copy_from_slice(bytes);
    Ok(B256::from(out))
}

fn receipt_to_submission_receipt(
    tx_hash: &str,
    receipt: EthTransactionReceipt,
    confirmations: u64,
) -> BnsEvmTxReceipt {
    BnsEvmTxReceipt {
        tx_hash: tx_hash.to_string(),
        status: receipt.status,
        block_number: receipt.block_number.unwrap_or_default(),
        confirmations,
    }
}
