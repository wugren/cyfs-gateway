//! SN BNS proxy 的独立 EVM 签名组件。
//!
//! 设计边界（doc/SN/sn-bns-proxy-todo.md）：
//! - 私钥只存在于 [`SnBnsTxSigner`] 内部；业务模块拿不到明文私钥，也没有
//!   任意 calldata 签名入口。
//! - 只为白名单内的 TX 签名：合约地址、chain id、method selector、operation
//!   与 doc_type 组合、gas 上限全部在签名前校验，未知一律拒绝。
//! - 多把 controller key 由 `controller_id` 索引；[`BoundControllerKeyManager`]
//!   把某个 controller 绑定为 `bns_client::BnsEvmKeyManager`，供
//!   `BnsEvmControllerClient` 使用（nonce 由该 client 按 signer 地址管理）。

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use bns_client::{
    BnsClientError, BnsClientResult, BnsEvmClientConfig, BnsEvmKeyManager, BnsEvmSignRequest,
    BnsEvmWriteOperation,
};
use bns_evm::{
    sign_eip1559_tx, signer_from_private_key, Address, Bns, PrivateKeySigner, SignedEip1559Tx,
    SolCall, TxEip1559, TxKind,
};
use log::warn;

use crate::{sn_err, SnErrorCode, SnResult};

const DNS_TXT_DOC_TYPE: &str = "dns_txt";
const RELAY_ASSIGNMENT_DOC_TYPE: &str = "relay_assignment";

/// BNS proxy 对外暴露的白名单 operation。签名组件和 RPC 层共用同一枚举，
/// 保证「业务层放行的操作」和「签名组件愿意签的操作」不会漂移。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SnBnsProxyOperation {
    RegisterNameBootstrap,
    PublishDnsTxt,
    PublishRelayAssignment,
    PublishDocument,
}

impl SnBnsProxyOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegisterNameBootstrap => "register_name_bootstrap",
            Self::PublishDnsTxt => "publish_dns_txt",
            Self::PublishRelayAssignment => "publish_relay_assignment",
            Self::PublishDocument => "publish_document",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "register_name_bootstrap" => Some(Self::RegisterNameBootstrap),
            "publish_dns_txt" => Some(Self::PublishDnsTxt),
            "publish_relay_assignment" => Some(Self::PublishRelayAssignment),
            "publish_document" => Some(Self::PublishDocument),
            _ => None,
        }
    }

    pub fn all() -> [Self; 4] {
        [
            Self::RegisterNameBootstrap,
            Self::PublishDnsTxt,
            Self::PublishRelayAssignment,
            Self::PublishDocument,
        ]
    }
}

impl fmt::Display for SnBnsProxyOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 一把 controller key 的装载参数（私钥已由调用方从 env/file/inline 解析出明文）。
pub struct SnBnsControllerKeySpec {
    pub id: String,
    /// 配置声明的地址（可选）；与私钥推导地址不一致时装载失败。
    pub declared_address: Option<String>,
    pub private_key: String,
    /// 稳定分配权重；0 表示不再接收新用户（既有绑定仍可用，用于下线排水）。
    pub weight: u32,
}

impl fmt::Debug for SnBnsControllerKeySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnBnsControllerKeySpec")
            .field("id", &self.id)
            .field("declared_address", &self.declared_address)
            .field("private_key", &"<redacted>")
            .field("weight", &self.weight)
            .finish()
    }
}

struct ControllerKeyEntry {
    id: String,
    address: Address,
    address_hex: String,
    weight: u32,
    signer: PrivateKeySigner,
}

impl fmt::Debug for ControllerKeyEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ControllerKeyEntry")
            .field("id", &self.id)
            .field("address", &self.address_hex)
            .field("weight", &self.weight)
            .field("signer", &"<redacted>")
            .finish()
    }
}

/// controller key 的公开视图（无私钥）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnBnsControllerKeyInfo {
    pub id: String,
    pub address: Address,
    /// 小写 `0x` 前缀地址（SN 内部统一格式）。
    pub address_hex: String,
    pub weight: u32,
}

/// 多 controller EVM 签名保管库。
///
/// 只暴露 [`Self::sign_for_controller`]（且仅供同模块的
/// [`BoundControllerKeyManager`] 调用）与只读的 key 元信息；不存在返回
/// 私钥或对任意 calldata 签名的方法。
pub struct SnBnsTxSigner {
    chain_id: u64,
    contract: Address,
    max_gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
    allowed_operations: HashSet<SnBnsProxyOperation>,
    keys: Vec<ControllerKeyEntry>,
}

impl fmt::Debug for SnBnsTxSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SnBnsTxSigner")
            .field("chain_id", &self.chain_id)
            .field("contract", &format!("{:#x}", self.contract))
            .field("allowed_operations", &self.allowed_operations)
            .field("keys", &self.keys)
            .finish()
    }
}

impl SnBnsTxSigner {
    pub fn new(
        evm_config: &BnsEvmClientConfig,
        allowed_operations: HashSet<SnBnsProxyOperation>,
        key_specs: Vec<SnBnsControllerKeySpec>,
    ) -> SnResult<Self> {
        if key_specs.is_empty() {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "sn bns tx signer requires at least one controller key"
            ));
        }
        if allowed_operations.is_empty() {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "sn bns tx signer requires at least one allowed operation"
            ));
        }
        let contract = evm_config
            .contract_address
            .parse::<Address>()
            .map_err(|e| {
                sn_err!(
                    SnErrorCode::InvalidInput,
                    "invalid bns contract address {}: {}",
                    evm_config.contract_address,
                    e
                )
            })?;

        let mut keys: Vec<ControllerKeyEntry> = Vec::with_capacity(key_specs.len());
        for spec in key_specs {
            let id = spec.id.trim().to_string();
            if id.is_empty() {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "bns proxy controller id cannot be empty"
                ));
            }
            if keys.iter().any(|entry| entry.id == id) {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "duplicated bns proxy controller id `{}`",
                    id
                ));
            }
            let signer = signer_from_private_key(spec.private_key.trim()).map_err(|e| {
                sn_err!(
                    SnErrorCode::InvalidInput,
                    "load private key for bns proxy controller `{}` failed: {}",
                    id,
                    e
                )
            })?;
            let address = signer.address();
            if let Some(declared) = spec.declared_address.as_deref() {
                let declared_address = declared.trim().parse::<Address>().map_err(|e| {
                    sn_err!(
                        SnErrorCode::InvalidInput,
                        "invalid declared address for bns proxy controller `{}`: {}",
                        id,
                        e
                    )
                })?;
                if declared_address != address {
                    return Err(sn_err!(
                        SnErrorCode::InvalidInput,
                        "bns proxy controller `{}` declared address {:#x} does not match key address {:#x}",
                        id,
                        declared_address,
                        address
                    ));
                }
            }
            if keys.iter().any(|entry| entry.address == address) {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "duplicated bns proxy controller address {:#x}",
                    address
                ));
            }
            keys.push(ControllerKeyEntry {
                id,
                address,
                address_hex: format!("{address:#x}"),
                weight: spec.weight,
                signer,
            });
        }

        if keys.iter().all(|entry| entry.weight == 0) {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "at least one bns proxy controller must have weight > 0"
            ));
        }

        Ok(Self {
            chain_id: evm_config.chain_id,
            contract,
            max_gas_limit: evm_config.gas_limit,
            max_fee_per_gas: evm_config.max_fee_per_gas,
            max_priority_fee_per_gas: evm_config.max_priority_fee_per_gas,
            allowed_operations,
            keys,
        })
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    pub fn allowed_operations(&self) -> &HashSet<SnBnsProxyOperation> {
        &self.allowed_operations
    }

    pub fn allows(&self, operation: SnBnsProxyOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }

    pub fn controller_infos(&self) -> Vec<SnBnsControllerKeyInfo> {
        self.keys
            .iter()
            .map(|entry| SnBnsControllerKeyInfo {
                id: entry.id.clone(),
                address: entry.address,
                address_hex: entry.address_hex.clone(),
                weight: entry.weight,
            })
            .collect()
    }

    pub fn controller_info(&self, controller_id: &str) -> Option<SnBnsControllerKeyInfo> {
        self.keys
            .iter()
            .find(|entry| entry.id == controller_id)
            .map(|entry| SnBnsControllerKeyInfo {
                id: entry.id.clone(),
                address: entry.address,
                address_hex: entry.address_hex.clone(),
                weight: entry.weight,
            })
    }

    /// 为绑定的 controller 签名一笔白名单内的 BNS TX。
    ///
    /// `request` 描述业务意图（operation/doc_type），`tx` 是按共享
    /// `BnsEvmClientConfig` 构造的未签名 TX；两者与保管库配置交叉校验，
    /// 任何一项对不上都拒签。
    fn sign_for_controller(
        &self,
        controller_id: &str,
        request: &BnsEvmSignRequest,
        tx: TxEip1559,
    ) -> BnsClientResult<SignedEip1559Tx> {
        let entry = self
            .keys
            .iter()
            .find(|entry| entry.id == controller_id)
            .ok_or_else(|| {
                refuse(format!(
                    "unknown controller id `{controller_id}` for sn bns tx signer"
                ))
            })?;
        self.validate_request_tx(request, &tx)?;
        sign_eip1559_tx(tx, &entry.signer).map_err(BnsClientError::from)
    }

    fn validate_request_tx(
        &self,
        request: &BnsEvmSignRequest,
        tx: &TxEip1559,
    ) -> BnsClientResult<()> {
        if tx.chain_id != self.chain_id {
            return Err(refuse(format!(
                "refuse to sign for unknown chain id {} (expected {})",
                tx.chain_id, self.chain_id
            )));
        }
        match tx.to {
            TxKind::Call(address) if address == self.contract => {}
            TxKind::Call(address) => {
                return Err(refuse(format!(
                    "refuse to sign for unknown contract {address:#x} (expected {:#x})",
                    self.contract
                )));
            }
            TxKind::Create => {
                return Err(refuse(
                    "refuse to sign contract creation transaction".to_string(),
                ));
            }
        }
        if tx.gas_limit > self.max_gas_limit {
            return Err(refuse(format!(
                "refuse to sign: gas_limit {} exceeds limit {}",
                tx.gas_limit, self.max_gas_limit
            )));
        }
        if tx.max_fee_per_gas > self.max_fee_per_gas {
            return Err(refuse(format!(
                "refuse to sign: max_fee_per_gas {} exceeds limit {}",
                tx.max_fee_per_gas, self.max_fee_per_gas
            )));
        }
        if tx.max_priority_fee_per_gas > self.max_priority_fee_per_gas {
            return Err(refuse(format!(
                "refuse to sign: max_priority_fee_per_gas {} exceeds limit {}",
                tx.max_priority_fee_per_gas, self.max_priority_fee_per_gas
            )));
        }
        if !tx.value.is_zero() {
            return Err(refuse(
                "refuse to sign transaction carrying non-zero value".to_string(),
            ));
        }

        let selector: [u8; 4] = tx
            .input
            .get(0..4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .ok_or_else(|| refuse("refuse to sign transaction without method selector".into()))?;

        let proxy_operation = if selector == Bns::registerNameCall::SELECTOR {
            if !matches!(
                request.operation,
                BnsEvmWriteOperation::RegisterName | BnsEvmWriteOperation::BootstrapName
            ) {
                return Err(refuse(format!(
                    "registerName selector does not match declared operation `{}`",
                    request.operation.as_str()
                )));
            }
            SnBnsProxyOperation::RegisterNameBootstrap
        } else if selector == Bns::publishDocumentCall::SELECTOR {
            if request.operation != BnsEvmWriteOperation::PublishDocument {
                return Err(refuse(format!(
                    "publishDocument selector does not match declared operation `{}`",
                    request.operation.as_str()
                )));
            }
            match request.doc_type.as_deref() {
                Some(DNS_TXT_DOC_TYPE) => SnBnsProxyOperation::PublishDnsTxt,
                Some(RELAY_ASSIGNMENT_DOC_TYPE) => SnBnsProxyOperation::PublishRelayAssignment,
                Some("") => {
                    return Err(refuse(
                        "refuse to sign publishDocument without doc_type".to_string(),
                    ));
                }
                Some(_) => SnBnsProxyOperation::PublishDocument,
                None => {
                    return Err(refuse(
                        "refuse to sign publishDocument without doc_type".to_string(),
                    ));
                }
            }
        } else {
            return Err(refuse(format!(
                "refuse to sign unknown method selector 0x{}",
                hex::encode(selector)
            )));
        };

        if !self.allows(proxy_operation) {
            return Err(refuse(format!(
                "operation `{proxy_operation}` is not in the allowed operation list"
            )));
        }
        Ok(())
    }
}

fn refuse(message: String) -> BnsClientError {
    warn!("sn bns tx signer refused to sign: {}", message);
    BnsClientError::Serialization(format!("sn bns tx signer: {message}"))
}

/// 把保管库中的一把 controller key 绑定为 `BnsEvmKeyManager`。
///
/// 每个 controller 对应一个 `BnsEvmControllerClient` 实例；key 的选择在
/// 业务层（用户 → controller 绑定）完成，签名层只负责校验与签名。
pub struct BoundControllerKeyManager {
    vault: Arc<SnBnsTxSigner>,
    controller_id: String,
    address: Address,
}

impl BoundControllerKeyManager {
    pub fn new(vault: Arc<SnBnsTxSigner>, controller_id: &str) -> SnResult<Self> {
        let info = vault.controller_info(controller_id).ok_or_else(|| {
            sn_err!(
                SnErrorCode::InvalidInput,
                "unknown bns proxy controller id `{}`",
                controller_id
            )
        })?;
        Ok(Self {
            vault,
            controller_id: info.id,
            address: info.address,
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }
}

impl fmt::Debug for BoundControllerKeyManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoundControllerKeyManager")
            .field("controller_id", &self.controller_id)
            .field("address", &format!("{:#x}", self.address))
            .finish()
    }
}

#[async_trait]
impl BnsEvmKeyManager for BoundControllerKeyManager {
    async fn signer_address(&self, _request: &BnsEvmSignRequest) -> BnsClientResult<Address> {
        Ok(self.address)
    }

    async fn sign_transaction(
        &self,
        request: &BnsEvmSignRequest,
        tx: TxEip1559,
    ) -> BnsClientResult<SignedEip1559Tx> {
        self.vault
            .sign_for_controller(self.controller_id.as_str(), request, tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bns_client::{
        publish_document_call, register_name_call, set_controller_policy_call,
        BnsEvmStandardClient, BnsPublishDocumentReq, BnsRegisterNameReq,
        BnsSetControllerPolicyReq,
    };
    use bns_indexer::{
        default_document_update, CallAuthority, DocumentRef, MutationGuard, Principal,
        RegisterOptions,
    };

    const ANVIL_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const ANVIL_ADDRESS: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const SECOND_PRIVATE_KEY: &str =
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
    const CONTRACT: &str = "0x2222222222222222222222222222222222222222";
    const CHAIN_ID: u64 = 31_337;

    fn evm_config() -> BnsEvmClientConfig {
        BnsEvmClientConfig::anvil("http://127.0.0.1:8545", CONTRACT, CHAIN_ID)
    }

    fn all_ops() -> HashSet<SnBnsProxyOperation> {
        SnBnsProxyOperation::all().into_iter().collect()
    }

    fn vault() -> SnBnsTxSigner {
        SnBnsTxSigner::new(
            &evm_config(),
            all_ops(),
            vec![
                SnBnsControllerKeySpec {
                    id: "controller-a".to_string(),
                    declared_address: Some(ANVIL_ADDRESS.to_string()),
                    private_key: ANVIL_PRIVATE_KEY.to_string(),
                    weight: 1,
                },
                SnBnsControllerKeySpec {
                    id: "controller-b".to_string(),
                    declared_address: None,
                    private_key: SECOND_PRIVATE_KEY.to_string(),
                    weight: 1,
                },
            ],
        )
        .unwrap()
    }

    fn register_req() -> BnsRegisterNameReq {
        BnsRegisterNameReq {
            name: "alice".to_string(),
            asset_owner: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            options: RegisterOptions::default(),
            authority_key_updates: vec![],
            semantic_owner_after_authority: None,
            controller_policy: vec![],
            controller_policy_hash: String::new(),
            initial_documents: vec![],
            authority: CallAuthority::public(),
            guard: MutationGuard::default(),
        }
    }

    fn register_sign_request() -> BnsEvmSignRequest {
        BnsEvmSignRequest {
            operation: BnsEvmWriteOperation::RegisterName,
            name: "alice".to_string(),
            doc_type: None,
            asset_owner: Some("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            authority: CallAuthority::public(),
        }
    }

    fn publish_req(doc_type: &str) -> BnsPublishDocumentReq {
        BnsPublishDocumentReq {
            name: "alice".to_string(),
            update: default_document_update(doc_type, 0, DocumentRef::inline(b"[]".as_slice()))
                .unwrap(),
            authority: CallAuthority::controller(Principal::chain_account(ANVIL_ADDRESS), ""),
            guard: MutationGuard::default(),
        }
    }

    fn publish_sign_request(doc_type: &str) -> BnsEvmSignRequest {
        BnsEvmSignRequest {
            operation: BnsEvmWriteOperation::PublishDocument,
            name: "alice".to_string(),
            doc_type: Some(doc_type.to_string()),
            asset_owner: None,
            authority: CallAuthority::controller(Principal::chain_account(ANVIL_ADDRESS), ""),
        }
    }

    fn unsigned_tx_with<C: SolCall>(config: &BnsEvmClientConfig, call: &C) -> TxEip1559 {
        BnsEvmStandardClient::new(config.clone())
            .build_unsigned_tx(call, 0)
            .unwrap()
    }

    #[test]
    fn signs_whitelisted_register_name_with_bound_key() {
        let vault = vault();
        let call = register_name_call(&register_req()).unwrap();
        let tx = unsigned_tx_with(&evm_config(), &call);
        let signed = vault
            .sign_for_controller("controller-a", &register_sign_request(), tx)
            .unwrap();
        assert_eq!(format!("{:#x}", signed.signer), ANVIL_ADDRESS);
        assert_eq!(signed.chain_id, CHAIN_ID);
    }

    #[test]
    fn signs_whitelisted_dns_txt_publish() {
        let vault = vault();
        let call = publish_document_call(&publish_req("dns_txt")).unwrap();
        let tx = unsigned_tx_with(&evm_config(), &call);
        vault
            .sign_for_controller("controller-b", &publish_sign_request("dns_txt"), tx)
            .unwrap();
    }

    #[test]
    fn rejects_unknown_chain_id() {
        let vault = vault();
        let call = register_name_call(&register_req()).unwrap();
        let mut foreign = evm_config();
        foreign.chain_id = 1;
        let tx = unsigned_tx_with(&foreign, &call);
        let error = vault
            .sign_for_controller("controller-a", &register_sign_request(), tx)
            .unwrap_err();
        assert!(error.to_string().contains("unknown chain id"), "{error}");
    }

    #[test]
    fn rejects_unknown_contract() {
        let vault = vault();
        let call = register_name_call(&register_req()).unwrap();
        let mut foreign = evm_config();
        foreign.contract_address = "0x9999999999999999999999999999999999999999".to_string();
        let tx = unsigned_tx_with(&foreign, &call);
        let error = vault
            .sign_for_controller("controller-a", &register_sign_request(), tx)
            .unwrap_err();
        assert!(error.to_string().contains("unknown contract"), "{error}");
    }

    #[test]
    fn rejects_unknown_method_selector() {
        let vault = vault();
        let call = set_controller_policy_call(&BnsSetControllerPolicyReq {
            name: "alice".to_string(),
            rules: vec![],
            policy_hash: String::new(),
            authority: CallAuthority::owner(Principal::chain_account(ANVIL_ADDRESS), ""),
            guard: MutationGuard::default(),
        })
        .unwrap();
        let tx = unsigned_tx_with(&evm_config(), &call);
        let request = BnsEvmSignRequest {
            operation: BnsEvmWriteOperation::SetControllerPolicy,
            name: "alice".to_string(),
            doc_type: None,
            asset_owner: None,
            authority: CallAuthority::owner(Principal::chain_account(ANVIL_ADDRESS), ""),
        };
        let error = vault
            .sign_for_controller("controller-a", &request, tx)
            .unwrap_err();
        assert!(
            error.to_string().contains("unknown method selector"),
            "{error}"
        );
    }

    #[test]
    fn signs_generic_publish_document_when_operation_is_allowed() {
        let vault = vault();
        let call = publish_document_call(&publish_req("zone")).unwrap();
        let tx = unsigned_tx_with(&evm_config(), &call);
        vault
            .sign_for_controller("controller-a", &publish_sign_request("zone"), tx)
            .unwrap();
    }

    #[test]
    fn rejects_generic_publish_document_outside_allow_list() {
        let vault = SnBnsTxSigner::new(
            &evm_config(),
            [SnBnsProxyOperation::PublishDnsTxt].into_iter().collect(),
            vec![SnBnsControllerKeySpec {
                id: "controller-a".to_string(),
                declared_address: None,
                private_key: ANVIL_PRIVATE_KEY.to_string(),
                weight: 1,
            }],
        )
        .unwrap();
        let call = publish_document_call(&publish_req("zone")).unwrap();
        let tx = unsigned_tx_with(&evm_config(), &call);
        let error = vault
            .sign_for_controller("controller-a", &publish_sign_request("zone"), tx)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("operation `publish_document` is not in the allowed operation list"),
            "{error}"
        );
    }

    #[test]
    fn rejects_operation_outside_allow_list() {
        let vault = SnBnsTxSigner::new(
            &evm_config(),
            [SnBnsProxyOperation::PublishDnsTxt].into_iter().collect(),
            vec![SnBnsControllerKeySpec {
                id: "controller-a".to_string(),
                declared_address: None,
                private_key: ANVIL_PRIVATE_KEY.to_string(),
                weight: 1,
            }],
        )
        .unwrap();
        let call = register_name_call(&register_req()).unwrap();
        let tx = unsigned_tx_with(&evm_config(), &call);
        let error = vault
            .sign_for_controller("controller-a", &register_sign_request(), tx)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("not in the allowed operation list"),
            "{error}"
        );
    }

    #[test]
    fn rejects_gas_above_configured_limit() {
        let vault = vault();
        let call = register_name_call(&register_req()).unwrap();
        let mut expensive = evm_config();
        expensive.gas_limit *= 2;
        let tx = unsigned_tx_with(&expensive, &call);
        let error = vault
            .sign_for_controller("controller-a", &register_sign_request(), tx)
            .unwrap_err();
        assert!(error.to_string().contains("gas_limit"), "{error}");
    }

    #[test]
    fn rejects_unknown_controller_id() {
        let vault = vault();
        let call = register_name_call(&register_req()).unwrap();
        let tx = unsigned_tx_with(&evm_config(), &call);
        let error = vault
            .sign_for_controller("controller-x", &register_sign_request(), tx)
            .unwrap_err();
        assert!(error.to_string().contains("unknown controller id"), "{error}");
    }

    #[test]
    fn rejects_declared_address_mismatch_and_duplicates() {
        let mismatch = SnBnsTxSigner::new(
            &evm_config(),
            all_ops(),
            vec![SnBnsControllerKeySpec {
                id: "controller-a".to_string(),
                declared_address: Some("0x1111111111111111111111111111111111111111".to_string()),
                private_key: ANVIL_PRIVATE_KEY.to_string(),
                weight: 1,
            }],
        );
        assert!(mismatch.is_err());

        let duplicated_id = SnBnsTxSigner::new(
            &evm_config(),
            all_ops(),
            vec![
                SnBnsControllerKeySpec {
                    id: "controller-a".to_string(),
                    declared_address: None,
                    private_key: ANVIL_PRIVATE_KEY.to_string(),
                    weight: 1,
                },
                SnBnsControllerKeySpec {
                    id: "controller-a".to_string(),
                    declared_address: None,
                    private_key: SECOND_PRIVATE_KEY.to_string(),
                    weight: 1,
                },
            ],
        );
        assert!(duplicated_id.is_err());

        let duplicated_key = SnBnsTxSigner::new(
            &evm_config(),
            all_ops(),
            vec![
                SnBnsControllerKeySpec {
                    id: "controller-a".to_string(),
                    declared_address: None,
                    private_key: ANVIL_PRIVATE_KEY.to_string(),
                    weight: 1,
                },
                SnBnsControllerKeySpec {
                    id: "controller-b".to_string(),
                    declared_address: None,
                    private_key: ANVIL_PRIVATE_KEY.to_string(),
                    weight: 1,
                },
            ],
        );
        assert!(duplicated_key.is_err());
    }

    #[test]
    fn debug_output_never_leaks_private_key_material() {
        let spec = SnBnsControllerKeySpec {
            id: "controller-a".to_string(),
            declared_address: None,
            private_key: ANVIL_PRIVATE_KEY.to_string(),
            weight: 1,
        };
        let vault = vault();
        let bound =
            BoundControllerKeyManager::new(Arc::new(vault), "controller-a").unwrap();
        let key_body = ANVIL_PRIVATE_KEY.trim_start_matches("0x");

        for rendered in [
            format!("{spec:?}"),
            format!("{:?}", super::SnBnsTxSigner::new(
                &evm_config(),
                all_ops(),
                vec![SnBnsControllerKeySpec {
                    id: "controller-a".to_string(),
                    declared_address: None,
                    private_key: ANVIL_PRIVATE_KEY.to_string(),
                    weight: 1,
                }],
            )
            .unwrap()),
            format!("{bound:?}"),
        ] {
            assert!(!rendered.contains(key_body), "leaked key: {rendered}");
            assert!(!rendered.to_lowercase().contains(key_body), "leaked key");
        }
    }

    #[tokio::test]
    async fn bound_key_manager_signs_as_bound_controller_only() {
        let vault = Arc::new(vault());
        let bound_b = BoundControllerKeyManager::new(vault.clone(), "controller-b").unwrap();
        let request = register_sign_request();
        let address = bound_b.signer_address(&request).await.unwrap();
        assert_eq!(
            address,
            vault.controller_info("controller-b").unwrap().address
        );

        let call = register_name_call(&register_req()).unwrap();
        let tx = unsigned_tx_with(&evm_config(), &call);
        let signed = bound_b.sign_transaction(&request, tx).await.unwrap();
        assert_eq!(signed.signer, address);
    }
}
