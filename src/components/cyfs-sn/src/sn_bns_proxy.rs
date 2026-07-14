//! SN BNS proxy 写链编排（doc/SN/sn-bns-proxy-todo.md）。
//!
//! 职责切分：
//! - [`SnBnsTxSigner`](crate::sn_bns_signer::SnBnsTxSigner) 持有私钥并做白名单签名；
//! - 每把 controller key 对应一个 `bns_client::SnBnsController` 实例
//!   （controllerPolicy / controller authority 都锚定在实例的 principal 上）；
//! - 本模块负责「用户 → controller」持久化绑定、受限操作编排与审计日志。
//!
//! proxy 返回 `submitted` 只表示 SN 已投递 TX；BNS 权威状态仍以合约与
//! bns-rpc 投影为准，读侧不做任何伪造。

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bns_client::dns_document::{DnsTxtRecord, DNS_TXT_DOC_TYPE};
use bns_client::{
    canonical_doc_type, hash_json, BnsEvmReceiptWaitConfig, DnsTxtUpdate, PublishDocumentParams,
    RegisterNameParams, SnBnsController, SnBnsControllerError, UpsertDnsTxtParams, OWNER_DOC_TYPE,
    RELAY_ASSIGNMENT_DOC_TYPE,
};
use bns_client::{
    default_document_update, CallAuthority, DocumentRef, DocumentUpdate, MutationGuard, Principal,
    PublishRelayAssignmentParams, RegisterNameOutput, RegisterOptions,
};
pub use cyfs_gateway_api::{
    SnBnsDnsTxtRecord, SnBnsProxyInitialDocuments, SnBnsProxyStatus, SnBnsProxyTxOutcome,
};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};

use crate::sn_bns_signer::SnBnsProxyOperation;
use crate::{sn_err, SnErrorCode, SnResult};

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// `SNServerConfig.bns_proxy` 配置块。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNBnsProxyConfig {
    /// 显式关闭 proxy（保留 bns 读路径）。缺省 = true。
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 生产模式要求注册必须携带用户 `asset_owner`。缺省 = true；仅 devtest
    /// 场景可显式设为 false（此时回落为该用户绑定 controller 的地址）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_user_asset_owner: Option<bool>,
    #[serde(default)]
    pub controllers: Vec<SNBnsProxyControllerKeyConfig>,
    /// 白名单 operation 列表；缺省 = 全部
    /// （register_name_bootstrap / publish_dns_txt / publish_relay_assignment /
    /// publish_document）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_operations: Option<Vec<String>>,
}

fn default_enabled() -> bool {
    true
}

impl SNBnsProxyConfig {
    pub fn require_user_asset_owner(&self) -> bool {
        self.require_user_asset_owner.unwrap_or(true)
    }

    pub fn parse_allowed_operations(&self) -> SnResult<HashSet<SnBnsProxyOperation>> {
        let Some(values) = self.allowed_operations.as_ref() else {
            return Ok(SnBnsProxyOperation::all().into_iter().collect());
        };
        let mut operations = HashSet::new();
        for value in values {
            let operation = SnBnsProxyOperation::parse(value).ok_or_else(|| {
                sn_err!(
                    SnErrorCode::InvalidInput,
                    "unknown bns_proxy.allowed_operations entry `{}`",
                    value
                )
            })?;
            operations.insert(operation);
        }
        if operations.is_empty() {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "bns_proxy.allowed_operations cannot be empty"
            ));
        }
        Ok(operations)
    }
}

/// 一把 controller key 的配置。私钥来源三选一：env / file / inline。
#[derive(Clone, Serialize, Deserialize)]
pub struct SNBnsProxyControllerKeyConfig {
    pub id: String,
    /// 可选的地址声明；与私钥推导地址不一致时启动失败（防错配）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// 新用户分配权重；0 = 停止接新用户（排水）。缺省 = 1。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
}

impl fmt::Debug for SNBnsProxyControllerKeyConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SNBnsProxyControllerKeyConfig")
            .field("id", &self.id)
            .field("address", &self.address)
            .field("private_key_env", &self.private_key_env)
            .field("private_key_file", &self.private_key_file)
            .field(
                "private_key",
                &self.private_key.as_ref().map(|_| "<redacted>"),
            )
            .field("weight", &self.weight)
            .finish()
    }
}

impl SNBnsProxyControllerKeyConfig {
    /// 解析私钥明文（env > file > inline，与旧 `bns_evm.controller_private_key*` 同序）。
    pub fn load_private_key(&self) -> SnResult<String> {
        if let Some(env_name) = self.private_key_env.as_deref() {
            let value = std::env::var(env_name).map_err(|e| {
                sn_err!(
                    SnErrorCode::InvalidInput,
                    "read bns_proxy controller `{}` private_key_env {} failed: {}",
                    self.id,
                    env_name,
                    e
                )
            })?;
            let value = value.trim().to_string();
            if value.is_empty() {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "bns_proxy controller `{}` private_key_env {} is empty",
                    self.id,
                    env_name
                ));
            }
            return Ok(value);
        }
        if let Some(path) = self.private_key_file.as_deref() {
            let value = std::fs::read_to_string(path).map_err(|e| {
                sn_err!(
                    SnErrorCode::InvalidInput,
                    "read bns_proxy controller `{}` private_key_file {} failed: {}",
                    self.id,
                    path,
                    e
                )
            })?;
            let value = value.trim().to_string();
            if value.is_empty() {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "bns_proxy controller `{}` private_key_file {} is empty",
                    self.id,
                    path
                ));
            }
            return Ok(value);
        }
        self.private_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                sn_err!(
                    SnErrorCode::InvalidInput,
                    "bns_proxy controller `{}` requires private_key_env, private_key_file or private_key",
                    self.id
                )
            })
    }
}

// ---------------------------------------------------------------------------
// 用户 → controller 绑定持久化
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnBnsControllerBinding {
    pub username: String,
    pub controller_id: String,
    /// 绑定 controller 的 EVM 地址（小写 `0x` 格式）。
    pub controller_address: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[async_trait]
pub trait SnBnsControllerBindingStore: Send + Sync {
    async fn get_binding(&self, username: &str) -> SnResult<Option<SnBnsControllerBinding>>;

    /// 幂等插入：已存在则返回既有绑定（并发注册安全），绝不覆盖。
    async fn try_insert_binding(
        &self,
        binding: &SnBnsControllerBinding,
    ) -> SnResult<SnBnsControllerBinding>;
}

pub type SnBnsControllerBindingStoreRef = Arc<dyn SnBnsControllerBindingStore>;

pub struct SqliteSnBnsControllerBindingStore {
    pool: SqlitePool,
}

impl SqliteSnBnsControllerBindingStore {
    pub async fn new_by_path(path: &str) -> SnResult<Self> {
        let db_url = if path.starts_with("sqlite:") {
            path.to_string()
        } else {
            format!("sqlite://{}", path)
        };
        let options = SqliteConnectOptions::from_str(db_url.as_str())
            .map_err(|e| sn_err!(SnErrorCode::DBError, "parse sqlite url failed: {}", e))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(16)
            .connect_with(options)
            .await
            .map_err(|e| sn_err!(SnErrorCode::DBError, "open file {}: {}", path, e))?;
        Ok(Self { pool })
    }

    pub async fn initialize_database(&self) -> SnResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sn_bns_controller_bindings (
                username TEXT PRIMARY KEY,
                controller_id TEXT NOT NULL,
                controller_address TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| {
            sn_err!(
                SnErrorCode::DBError,
                "create sn_bns_controller_bindings table failed: {}",
                e
            )
        })?;
        Ok(())
    }

    fn binding_from_row(row: &sqlx::sqlite::SqliteRow) -> SnBnsControllerBinding {
        SnBnsControllerBinding {
            username: row.get::<String, _>("username"),
            controller_id: row.get::<String, _>("controller_id"),
            controller_address: row.get::<String, _>("controller_address"),
            created_at: row.get::<i64, _>("created_at") as u64,
            updated_at: row.get::<i64, _>("updated_at") as u64,
        }
    }
}

#[async_trait]
impl SnBnsControllerBindingStore for SqliteSnBnsControllerBindingStore {
    async fn get_binding(&self, username: &str) -> SnResult<Option<SnBnsControllerBinding>> {
        let row = sqlx::query(
            "SELECT username, controller_id, controller_address, created_at, updated_at
             FROM sn_bns_controller_bindings WHERE username = ?1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            sn_err!(
                SnErrorCode::DBError,
                "query controller binding for {} failed: {}",
                username,
                e
            )
        })?;
        Ok(row.as_ref().map(Self::binding_from_row))
    }

    async fn try_insert_binding(
        &self,
        binding: &SnBnsControllerBinding,
    ) -> SnResult<SnBnsControllerBinding> {
        sqlx::query(
            "INSERT INTO sn_bns_controller_bindings
                (username, controller_id, controller_address, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(username) DO NOTHING",
        )
        .bind(binding.username.as_str())
        .bind(binding.controller_id.as_str())
        .bind(binding.controller_address.as_str())
        .bind(binding.created_at as i64)
        .bind(binding.updated_at as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            sn_err!(
                SnErrorCode::DBError,
                "insert controller binding for {} failed: {}",
                binding.username,
                e
            )
        })?;
        self.get_binding(binding.username.as_str())
            .await?
            .ok_or_else(|| {
                sn_err!(
                    SnErrorCode::DBError,
                    "controller binding for {} disappeared after insert",
                    binding.username
                )
            })
    }
}

/// 测试用内存绑定存储。
#[derive(Default)]
pub struct MemorySnBnsControllerBindingStore {
    bindings: std::sync::Mutex<std::collections::HashMap<String, SnBnsControllerBinding>>,
}

impl MemorySnBnsControllerBindingStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SnBnsControllerBindingStore for MemorySnBnsControllerBindingStore {
    async fn get_binding(&self, username: &str) -> SnResult<Option<SnBnsControllerBinding>> {
        Ok(self.bindings.lock().unwrap().get(username).cloned())
    }

    async fn try_insert_binding(
        &self,
        binding: &SnBnsControllerBinding,
    ) -> SnResult<SnBnsControllerBinding> {
        let mut bindings = self.bindings.lock().unwrap();
        Ok(bindings
            .entry(binding.username.clone())
            .or_insert_with(|| binding.clone())
            .clone())
    }
}

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SnBnsProxyError {
    /// 白名单外操作。
    OperationNotAllowed(SnBnsProxyOperation),
    InvalidInput(String),
    /// 既有绑定指向的 controller 已不在当前配置（不能静默重分配，需人工迁移）。
    ControllerUnavailable {
        username: String,
        controller_id: String,
    },
    Store(String),
    /// BNS 写链路失败（构造/签名/投递）。
    Write(SnBnsControllerError),
}

impl fmt::Display for SnBnsProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnBnsProxyError::OperationNotAllowed(operation) => {
                write!(f, "bns proxy operation `{}` is not allowed", operation)
            }
            SnBnsProxyError::InvalidInput(message) => write!(f, "{}", message),
            SnBnsProxyError::ControllerUnavailable {
                username,
                controller_id,
            } => write!(
                f,
                "controller `{}` bound to user `{}` is not available; manual migration required",
                controller_id, username
            ),
            SnBnsProxyError::Store(message) => write!(f, "binding store error: {}", message),
            SnBnsProxyError::Write(error) => write!(f, "{}", error),
        }
    }
}

impl From<crate::SnError> for SnBnsProxyError {
    fn from(error: crate::SnError) -> Self {
        Self::Store(error.to_string())
    }
}

impl From<SnBnsControllerError> for SnBnsProxyError {
    fn from(error: SnBnsControllerError) -> Self {
        Self::Write(error)
    }
}

pub type SnBnsProxyResult<T> = Result<T, SnBnsProxyError>;

// ---------------------------------------------------------------------------
// proxy 本体
// ---------------------------------------------------------------------------

/// 一把 controller key 对应的运行态实例。
pub struct SnBnsProxyController {
    pub id: String,
    /// 小写 `0x` EVM 地址。
    pub address: String,
    pub principal: Principal,
    pub weight: u32,
    pub controller: Arc<SnBnsController>,
}

pub struct SnBnsProxyRegisterParams {
    pub request_id: String,
    pub name: String,
    /// 用户上传的 owner EVM 地址（生产必填；devtest 可回落绑定 controller 地址）。
    pub asset_owner: String,
    pub owner_config: Value,
    pub initial_documents: SnBnsProxyInitialDocuments,
}

pub struct SnBnsProxy {
    controllers: Vec<SnBnsProxyController>,
    bindings: SnBnsControllerBindingStoreRef,
    allowed_operations: HashSet<SnBnsProxyOperation>,
    require_user_asset_owner: bool,
}

impl SnBnsProxy {
    pub fn new(
        controllers: Vec<SnBnsProxyController>,
        bindings: SnBnsControllerBindingStoreRef,
        allowed_operations: HashSet<SnBnsProxyOperation>,
        require_user_asset_owner: bool,
    ) -> SnResult<Self> {
        if controllers.is_empty() {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "sn bns proxy requires at least one controller"
            ));
        }
        if allowed_operations.is_empty() {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "sn bns proxy requires at least one allowed operation"
            ));
        }
        for (index, entry) in controllers.iter().enumerate() {
            if controllers[..index]
                .iter()
                .any(|other| other.id == entry.id)
            {
                return Err(sn_err!(
                    SnErrorCode::InvalidInput,
                    "duplicated bns proxy controller id `{}`",
                    entry.id
                ));
            }
        }
        if controllers.iter().all(|entry| entry.weight == 0) {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "at least one bns proxy controller must have weight > 0"
            ));
        }
        Ok(Self {
            controllers,
            bindings,
            allowed_operations,
            require_user_asset_owner,
        })
    }

    pub fn require_user_asset_owner(&self) -> bool {
        self.require_user_asset_owner
    }

    pub fn allows(&self, operation: SnBnsProxyOperation) -> bool {
        self.allowed_operations.contains(&operation)
    }

    pub fn controller_count(&self) -> usize {
        self.controllers.len()
    }

    pub fn controller_addresses(&self) -> Vec<(String, String)> {
        self.controllers
            .iter()
            .map(|entry| (entry.id.clone(), entry.address.clone()))
            .collect()
    }

    fn ensure_operation(&self, operation: SnBnsProxyOperation) -> SnBnsProxyResult<()> {
        if self.allows(operation) {
            Ok(())
        } else {
            Err(SnBnsProxyError::OperationNotAllowed(operation))
        }
    }

    /// hash(username) 在权重环上的稳定选点；与 controller 列表顺序无关，
    /// 只与 (username, 各 controller id/weight) 相关。
    fn stable_pick(&self, username: &str) -> SnBnsProxyResult<&SnBnsProxyController> {
        let candidates: Vec<&SnBnsProxyController> = self
            .controllers
            .iter()
            .filter(|entry| entry.weight > 0)
            .collect();
        if candidates.is_empty() {
            return Err(SnBnsProxyError::InvalidInput(
                "no bns proxy controller accepts new users (all weights are 0)".to_string(),
            ));
        }
        // rendezvous hashing：对每个候选算 hash(username, controller_id)，取最大。
        // 相比取模，增删 controller 时只影响挪动到新 controller 的那部分用户。
        let winner = candidates
            .into_iter()
            .max_by_key(|entry| {
                let mut hasher = Sha256::new();
                hasher.update(username.as_bytes());
                hasher.update(b"\0");
                hasher.update(entry.id.as_bytes());
                let digest = hasher.finalize();
                let mut prefix = [0u8; 8];
                prefix.copy_from_slice(&digest[..8]);
                // 权重通过多虚拟节点近似：weight 参与 hash 排序键的次级放大。
                (u64::from_be_bytes(prefix) as u128) * entry.weight as u128
            })
            .expect("candidates is non-empty");
        Ok(winner)
    }

    fn controller_entry(
        &self,
        binding: &SnBnsControllerBinding,
    ) -> SnBnsProxyResult<&SnBnsProxyController> {
        let entry = self
            .controllers
            .iter()
            .find(|entry| entry.id == binding.controller_id)
            .ok_or_else(|| SnBnsProxyError::ControllerUnavailable {
                username: binding.username.clone(),
                controller_id: binding.controller_id.clone(),
            })?;
        if !entry
            .address
            .eq_ignore_ascii_case(binding.controller_address.as_str())
        {
            warn!(
                "sn bns proxy controller `{}` address changed: binding={} configured={}",
                binding.controller_id, binding.controller_address, entry.address
            );
            return Err(SnBnsProxyError::ControllerUnavailable {
                username: binding.username.clone(),
                controller_id: binding.controller_id.clone(),
            });
        }
        Ok(entry)
    }

    /// 取该用户绑定的 controller；无绑定时按稳定策略分配并持久化。
    /// 既有绑定永不静默覆盖；绑定指向的 controller 不在配置中 → 显式报错。
    pub async fn assign_controller_for_user(
        &self,
        username: &str,
    ) -> SnBnsProxyResult<SnBnsControllerBinding> {
        if let Some(existing) = self.bindings.get_binding(username).await? {
            self.controller_entry(&existing)?;
            return Ok(existing);
        }
        let picked = self.stable_pick(username)?;
        let now = now_secs();
        let binding = SnBnsControllerBinding {
            username: username.to_string(),
            controller_id: picked.id.clone(),
            controller_address: picked.address.clone(),
            created_at: now,
            updated_at: now,
        };
        // 并发注册时以先写入者为准（try_insert 返回既有行）。
        let stored = self.bindings.try_insert_binding(&binding).await?;
        self.controller_entry(&stored)?;
        Ok(stored)
    }

    /// 只读查询绑定（不触发分配）。
    pub async fn controller_for_user(
        &self,
        username: &str,
    ) -> SnBnsProxyResult<Option<SnBnsControllerBinding>> {
        Ok(self.bindings.get_binding(username).await?)
    }

    /// devtest 回落：asset_owner 缺省时使用该用户绑定 controller 的地址。
    pub async fn default_asset_owner_for_user(&self, username: &str) -> SnBnsProxyResult<String> {
        if self.require_user_asset_owner {
            return Err(SnBnsProxyError::InvalidInput(
                "asset_owner is required".to_string(),
            ));
        }
        let binding = self.assign_controller_for_user(username).await?;
        Ok(binding.controller_address)
    }

    /// 注册 bootstrap：`assetOwner = 用户地址`、`controllerPolicy.actor = 绑定
    /// controller`、`initialDocuments = owner + 请求携带的初始文档`，原子上链。
    pub async fn register_bootstrap(
        &self,
        params: SnBnsProxyRegisterParams,
    ) -> SnBnsProxyResult<SnBnsProxyTxOutcome> {
        self.ensure_operation(SnBnsProxyOperation::RegisterNameBootstrap)?;
        let asset_owner = normalize_evm_address(params.asset_owner.as_str()).ok_or_else(|| {
            SnBnsProxyError::InvalidInput(
                "asset_owner must be a 0x-prefixed EVM address".to_string(),
            )
        })?;
        if !params.owner_config.is_object() {
            return Err(SnBnsProxyError::InvalidInput(
                "owner_config must be a JSON object".to_string(),
            ));
        }

        let binding = self
            .assign_controller_for_user(params.name.as_str())
            .await?;
        let entry = self.controller_entry(&binding)?;
        let initial_documents = build_initial_documents(&params.initial_documents)?;

        let register_params = RegisterNameParams {
            request_id: params.request_id.clone(),
            name: params.name.clone(),
            asset_owner: asset_owner.clone(),
            register_options: RegisterOptions::default(),
            owner_config: params.owner_config.clone(),
            owner_authority_keys: Vec::new(),
            semantic_owner_after_authority: None,
            initial_documents,
            // root name 公共注册路径：合约按 msg.sender 准入，authority 用 None。
            authority: CallAuthority::public(),
            guard: MutationGuard::default(),
        };
        let payload_hash = hash_json(&register_params).unwrap_or_default();
        let output: RegisterNameOutput = entry
            .controller
            .register_name(register_params)
            .await
            .map_err(SnBnsProxyError::Write)?;

        let receipt = &output.receipt;
        let outcome = SnBnsProxyTxOutcome {
            request_id: params.request_id,
            operation: SnBnsProxyOperation::RegisterNameBootstrap
                .as_str()
                .to_string(),
            name: params.name,
            controller_id: entry.id.clone(),
            controller_address: entry.address.clone(),
            asset_owner: Some(asset_owner),
            doc_type: None,
            document_version: None,
            chain_id: receipt.evm_chain_id,
            nonce: receipt.evm_nonce,
            tx_hash: receipt.evm_tx_hash.clone(),
            raw_tx: receipt.evm_raw_tx.clone(),
            status: SnBnsProxyStatus::Submitted,
            reused: receipt.created_or_reused,
        };
        self.audit(&outcome, payload_hash.as_str());
        Ok(outcome)
    }

    /// 用户注册专用路径：提交 `registerName` 后等待成功的链上回执。
    ///
    /// 普通 BNS proxy 写接口仍只保证 `submitted`；只有本方法会阻塞到交易
    /// 上链，确保调用方可以安全地继续创建本地账号和签发会话。幂等重试
    /// 会复用原 tx_hash，并再次查询该交易的回执。
    pub async fn register_bootstrap_and_wait(
        &self,
        params: SnBnsProxyRegisterParams,
    ) -> SnBnsProxyResult<SnBnsProxyTxOutcome> {
        let mut outcome = self.register_bootstrap(params).await?;
        let tx_hash = outcome.tx_hash.clone().ok_or_else(|| {
            SnBnsProxyError::InvalidInput(
                "registerName submission did not return an EVM tx_hash".to_string(),
            )
        })?;
        let entry = self
            .controllers
            .iter()
            .find(|entry| entry.id == outcome.controller_id)
            .ok_or_else(|| SnBnsProxyError::ControllerUnavailable {
                username: outcome.name.clone(),
                controller_id: outcome.controller_id.clone(),
            })?;

        info!(
            "sn bns registerName waiting for chain receipt: name={} controller_id={} tx_hash={} request_id={} reused={}",
            outcome.name, outcome.controller_id, tx_hash, outcome.request_id, outcome.reused
        );
        let receipt = entry
            .controller
            .wait_for_evm_receipt(tx_hash.as_str(), BnsEvmReceiptWaitConfig::included())
            .await
            .map_err(SnBnsProxyError::Write)?;
        outcome.status = SnBnsProxyStatus::Confirmed;
        info!(
            "sn bns registerName confirmed on chain: name={} controller_id={} tx_hash={} block_number={} confirmations={} receipt_status={} request_id={}",
            outcome.name,
            outcome.controller_id,
            tx_hash,
            receipt.block_number,
            receipt.confirmations,
            receipt
                .status
                .map_or_else(|| "-".to_string(), |status| status.to_string()),
            outcome.request_id
        );
        Ok(outcome)
    }

    /// 通过用户绑定的 controller 发布 `dns_txt` document。
    pub async fn publish_dns_txt(
        &self,
        username: &str,
        request_id: String,
        update: DnsTxtUpdate,
    ) -> SnBnsProxyResult<SnBnsProxyTxOutcome> {
        self.ensure_operation(SnBnsProxyOperation::PublishDnsTxt)?;
        let binding = self.assign_controller_for_user(username).await?;
        let entry = self.controller_entry(&binding)?;
        let params = UpsertDnsTxtParams {
            request_id: request_id.clone(),
            name: username.to_string(),
            update,
            // authority 由服务端按绑定 controller 生成，客户端不可指定。
            authority: entry.controller.sn_controller_authority(),
        };
        let payload_hash = hash_json(&params).unwrap_or_default();
        let receipt = entry
            .controller
            .upsert_dns_txt(params)
            .await
            .map_err(SnBnsProxyError::Write)?;

        let outcome = SnBnsProxyTxOutcome {
            request_id,
            operation: SnBnsProxyOperation::PublishDnsTxt.as_str().to_string(),
            name: username.to_string(),
            controller_id: entry.id.clone(),
            controller_address: entry.address.clone(),
            asset_owner: None,
            doc_type: receipt.doc_type.clone(),
            document_version: receipt.document_version,
            chain_id: receipt.evm_chain_id,
            nonce: receipt.evm_nonce,
            tx_hash: receipt.evm_tx_hash.clone(),
            raw_tx: receipt.evm_raw_tx.clone(),
            status: SnBnsProxyStatus::Submitted,
            reused: receipt.created_or_reused,
        };
        self.audit(&outcome, payload_hash.as_str());
        Ok(outcome)
    }

    /// 通过用户绑定的 controller 发布任意非保留 document。
    ///
    /// `owner` 走 bns-client 的身份字段保护路径；`relay_assignment` 始终拒绝，
    /// 只能由 internal/admin 专用方法发布。
    pub async fn publish_document(
        &self,
        username: &str,
        request_id: String,
        doc_type: String,
        document: Value,
    ) -> SnBnsProxyResult<SnBnsProxyTxOutcome> {
        let doc_type = canonical_doc_type(&doc_type)
            .map_err(|error| SnBnsProxyError::InvalidInput(error.to_string()))?;
        if doc_type == RELAY_ASSIGNMENT_DOC_TYPE {
            return Err(SnBnsProxyError::InvalidInput(
                "relay_assignment is internal-only; use bns.publish_relay_assignment".to_string(),
            ));
        }
        if !document.is_object()
            && !document
                .as_str()
                .is_some_and(|value| !value.trim().is_empty())
        {
            return Err(SnBnsProxyError::InvalidInput(
                "document must be a JSON object or non-empty text string".to_string(),
            ));
        }
        if doc_type == OWNER_DOC_TYPE && !document.is_object() {
            return Err(SnBnsProxyError::InvalidInput(
                "owner document must be a JSON object".to_string(),
            ));
        }

        // dns_txt 保留既有专属 operation 白名单；其它 doc_type（含受保护的
        // owner）统一归入 publish_document。
        let required_operation = if doc_type == DNS_TXT_DOC_TYPE {
            SnBnsProxyOperation::PublishDnsTxt
        } else {
            SnBnsProxyOperation::PublishDocument
        };
        self.ensure_operation(required_operation)?;

        let binding = self.assign_controller_for_user(username).await?;
        let entry = self.controller_entry(&binding)?;
        let params = PublishDocumentParams {
            request_id: request_id.clone(),
            name: username.to_string(),
            doc_type: doc_type.clone(),
            document,
            authority: entry.controller.sn_controller_authority(),
        };
        let payload_hash = hash_json(&params).unwrap_or_default();
        let receipt = if doc_type == OWNER_DOC_TYPE {
            entry
                .controller
                .publish_guarded_owner_document(params)
                .await
        } else {
            entry.controller.publish_content_document(params).await
        }
        .map_err(SnBnsProxyError::Write)?;

        let outcome = SnBnsProxyTxOutcome {
            request_id,
            operation: SnBnsProxyOperation::PublishDocument.as_str().to_string(),
            name: username.to_string(),
            controller_id: entry.id.clone(),
            controller_address: entry.address.clone(),
            asset_owner: None,
            doc_type: receipt.doc_type.clone(),
            document_version: receipt.document_version,
            chain_id: receipt.evm_chain_id,
            nonce: receipt.evm_nonce,
            tx_hash: receipt.evm_tx_hash.clone(),
            raw_tx: receipt.evm_raw_tx.clone(),
            status: SnBnsProxyStatus::Submitted,
            reused: receipt.created_or_reused,
        };
        self.audit(&outcome, payload_hash.as_str());
        Ok(outcome)
    }

    /// SN 内部发布 relay assignment（internal/admin only，由路由层限制）。
    pub async fn publish_relay_assignment(
        &self,
        name: &str,
        request_id: String,
        relay_assignment: Value,
    ) -> SnBnsProxyResult<SnBnsProxyTxOutcome> {
        self.ensure_operation(SnBnsProxyOperation::PublishRelayAssignment)?;
        let binding = self.assign_controller_for_user(name).await?;
        let entry = self.controller_entry(&binding)?;
        let params = PublishRelayAssignmentParams {
            request_id: request_id.clone(),
            name: name.to_string(),
            relay_assignment,
            authority: entry.controller.sn_controller_authority(),
        };
        let payload_hash = hash_json(&params).unwrap_or_default();
        let receipt = entry
            .controller
            .publish_relay_assignment(params)
            .await
            .map_err(SnBnsProxyError::Write)?;

        let outcome = SnBnsProxyTxOutcome {
            request_id,
            operation: SnBnsProxyOperation::PublishRelayAssignment
                .as_str()
                .to_string(),
            name: name.to_string(),
            controller_id: entry.id.clone(),
            controller_address: entry.address.clone(),
            asset_owner: None,
            doc_type: receipt.doc_type.clone(),
            document_version: receipt.document_version,
            chain_id: receipt.evm_chain_id,
            nonce: receipt.evm_nonce,
            tx_hash: receipt.evm_tx_hash.clone(),
            raw_tx: receipt.evm_raw_tx.clone(),
            status: SnBnsProxyStatus::Submitted,
            reused: receipt.created_or_reused,
        };
        self.audit(&outcome, payload_hash.as_str());
        Ok(outcome)
    }

    /// 审计日志：不含私钥/raw payload，只落可回溯字段。
    fn audit(&self, outcome: &SnBnsProxyTxOutcome, payload_hash: &str) {
        info!(
            "sn bns proxy submitted: operation={} name={} doc_type={} controller_id={} \
             controller_address={} chain_id={} nonce={} tx_hash={} request_id={} \
             payload_hash={} reused={}",
            outcome.operation,
            outcome.name,
            outcome.doc_type.as_deref().unwrap_or("-"),
            outcome.controller_id,
            outcome.controller_address,
            outcome
                .chain_id
                .map_or_else(|| "-".to_string(), |v| v.to_string()),
            outcome
                .nonce
                .map_or_else(|| "-".to_string(), |v| v.to_string()),
            outcome.tx_hash.as_deref().unwrap_or("-"),
            outcome.request_id,
            payload_hash,
            outcome.reused,
        );
    }
}

fn build_initial_documents(
    initial: &SnBnsProxyInitialDocuments,
) -> SnBnsProxyResult<Vec<DocumentUpdate>> {
    let mut updates = Vec::new();
    if let Some(zone) = initial.zone.as_ref() {
        if !zone.is_object() {
            return Err(SnBnsProxyError::InvalidInput(
                "initial_documents.zone must be a JSON object".to_string(),
            ));
        }
        updates.push(inline_document_update("zone", zone)?);
    }
    if let Some(boot) = initial.boot.as_ref() {
        if !boot.is_object() {
            return Err(SnBnsProxyError::InvalidInput(
                "initial_documents.boot must be a JSON object".to_string(),
            ));
        }
        updates.push(inline_document_update("boot", boot)?);
    }
    if let Some(records) = initial.dns_txt.as_ref() {
        for record in records {
            DnsTxtRecord::new(record.ttl, record.value.clone())
                .map_err(|e| SnBnsProxyError::InvalidInput(e.to_string()))?;
        }
        let value = serde_json::to_value(records)
            .map_err(|e| SnBnsProxyError::InvalidInput(e.to_string()))?;
        updates.push(inline_document_update("dns_txt", &value)?);
    }
    Ok(updates)
}

fn inline_document_update(doc_type: &str, document: &Value) -> SnBnsProxyResult<DocumentUpdate> {
    let bytes =
        serde_json::to_vec(document).map_err(|e| SnBnsProxyError::InvalidInput(e.to_string()))?;
    if bytes.is_empty() || bytes.len() > bns_client::MAX_INLINE_DOCUMENT {
        return Err(SnBnsProxyError::InvalidInput(format!(
            "initial document `{}` is {} bytes, max {}",
            doc_type,
            bytes.len(),
            bns_client::MAX_INLINE_DOCUMENT
        )));
    }
    default_document_update(doc_type, 0, DocumentRef::inline(bytes))
        .map_err(|e| SnBnsProxyError::InvalidInput(e.to_string()))
}

fn normalize_evm_address(value: &str) -> Option<String> {
    let value = value.trim();
    let hex_part = value.strip_prefix("0x")?;
    if hex_part.len() == 40 && hex_part.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bns_client::{
        BnsApplyMutationsReq, BnsClientResult, BnsEvmTxSubmission, BnsIndexerApi, BnsIndexerClient,
        BnsPublishDocumentReq, BnsRegisterNameReq, MemorySnBnsWriteRequestStore,
        SnBnsControllerConfig, SnBnsEvmSubmitter,
    };
    use bns_indexer::{
        CentralizedBnsIndexerHandler, CentralizedBnsRegistry, PrincipalKind, SqliteBnsRegistryStore,
    };
    use serde_json::json;
    use std::sync::Mutex;

    const CONTROLLER_A: &str = "0xcccccccccccccccccccccccccccccccccccccc01";
    const CONTROLLER_B: &str = "0xcccccccccccccccccccccccccccccccccccccc02";
    const USER_OWNER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[derive(Default)]
    struct RecordingEvmSubmitter {
        registrations: Mutex<Vec<BnsRegisterNameReq>>,
        published: Mutex<Vec<BnsPublishDocumentReq>>,
        next_nonce: Mutex<u64>,
    }

    impl RecordingEvmSubmitter {
        fn registrations(&self) -> Vec<BnsRegisterNameReq> {
            self.registrations.lock().unwrap().clone()
        }

        fn submission(&self) -> BnsEvmTxSubmission {
            let mut next_nonce = self.next_nonce.lock().unwrap();
            let nonce = *next_nonce;
            *next_nonce += 1;
            BnsEvmTxSubmission {
                tx_hash: format!("0x{nonce:064x}"),
                raw_tx: format!("0x{nonce:02x}"),
                from: CONTROLLER_A.to_string(),
                nonce,
                chain_id: 31_337,
                receipt_status: None,
                receipt_block_number: None,
                receipt_confirmations: None,
            }
        }
    }

    #[async_trait]
    impl SnBnsEvmSubmitter for RecordingEvmSubmitter {
        async fn register_name(
            &self,
            req: &BnsRegisterNameReq,
        ) -> BnsClientResult<BnsEvmTxSubmission> {
            self.registrations.lock().unwrap().push(req.clone());
            Ok(self.submission())
        }

        async fn apply_mutations(
            &self,
            _req: &BnsApplyMutationsReq,
        ) -> BnsClientResult<BnsEvmTxSubmission> {
            Ok(self.submission())
        }

        async fn publish_document(
            &self,
            req: &BnsPublishDocumentReq,
        ) -> BnsClientResult<BnsEvmTxSubmission> {
            self.published.lock().unwrap().push(req.clone());
            Ok(self.submission())
        }
    }

    fn indexer_client() -> Arc<dyn BnsIndexerApi> {
        let registry = Arc::new(CentralizedBnsRegistry::new_legacy_state_machine(
            SqliteBnsRegistryStore::open_memory().unwrap(),
        ));
        let handler: Arc<dyn BnsIndexerApi> = Arc::new(CentralizedBnsIndexerHandler::new(registry));
        Arc::new(BnsIndexerClient::new_in_process(handler))
    }

    fn controller_entry(
        id: &str,
        address: &str,
        weight: u32,
        submitter: Arc<RecordingEvmSubmitter>,
    ) -> SnBnsProxyController {
        let controller = SnBnsController::new_with_evm_submitter(
            indexer_client(),
            Arc::new(MemorySnBnsWriteRequestStore::new()),
            SnBnsControllerConfig::new(Principal::chain_account(address), ""),
            submitter,
        )
        .unwrap();
        SnBnsProxyController {
            id: id.to_string(),
            address: address.to_string(),
            principal: Principal::chain_account(address),
            weight,
            controller: Arc::new(controller),
        }
    }

    fn proxy_with(
        controllers: Vec<SnBnsProxyController>,
        bindings: SnBnsControllerBindingStoreRef,
    ) -> SnBnsProxy {
        SnBnsProxy::new(
            controllers,
            bindings,
            SnBnsProxyOperation::all().into_iter().collect(),
            true,
        )
        .unwrap()
    }

    fn two_controller_proxy(
        bindings: SnBnsControllerBindingStoreRef,
    ) -> (SnBnsProxy, Arc<RecordingEvmSubmitter>) {
        let submitter = Arc::new(RecordingEvmSubmitter::default());
        let proxy = proxy_with(
            vec![
                controller_entry("controller-a", CONTROLLER_A, 1, submitter.clone()),
                controller_entry("controller-b", CONTROLLER_B, 1, submitter.clone()),
            ],
            bindings,
        );
        (proxy, submitter)
    }

    #[tokio::test]
    async fn controller_assignment_is_stable_per_user() {
        let bindings: SnBnsControllerBindingStoreRef =
            Arc::new(MemorySnBnsControllerBindingStore::new());
        let (proxy, _) = two_controller_proxy(bindings.clone());

        let first = proxy.assign_controller_for_user("alice").await.unwrap();
        for _ in 0..5 {
            let again = proxy.assign_controller_for_user("alice").await.unwrap();
            assert_eq!(again, first);
        }

        // 重新构建 proxy（模拟重启），绑定表持久化 → 结果不变。
        let (rebuilt, _) = two_controller_proxy(bindings.clone());
        let after_restart = rebuilt.assign_controller_for_user("alice").await.unwrap();
        assert_eq!(after_restart, first);

        // 无绑定表时纯 hash 也稳定（同配置下同结果）。
        let fresh_bindings: SnBnsControllerBindingStoreRef =
            Arc::new(MemorySnBnsControllerBindingStore::new());
        let (fresh, _) = two_controller_proxy(fresh_bindings);
        let recomputed = fresh.assign_controller_for_user("alice").await.unwrap();
        assert_eq!(recomputed.controller_id, first.controller_id);
    }

    #[tokio::test]
    async fn different_users_can_map_to_different_controllers() {
        let bindings: SnBnsControllerBindingStoreRef =
            Arc::new(MemorySnBnsControllerBindingStore::new());
        let (proxy, _) = two_controller_proxy(bindings);

        let mut seen = HashSet::new();
        for index in 0..32 {
            let username = format!("user{index:02}");
            let binding = proxy.assign_controller_for_user(&username).await.unwrap();
            seen.insert(binding.controller_id);
        }
        assert_eq!(
            seen.len(),
            2,
            "32 users should spread across both controllers"
        );
    }

    #[tokio::test]
    async fn binding_to_removed_controller_fails_instead_of_reassigning() {
        let bindings: SnBnsControllerBindingStoreRef =
            Arc::new(MemorySnBnsControllerBindingStore::new());
        let now = now_secs();
        bindings
            .try_insert_binding(&SnBnsControllerBinding {
                username: "alice".to_string(),
                controller_id: "controller-gone".to_string(),
                controller_address: CONTROLLER_A.to_string(),
                created_at: now,
                updated_at: now,
            })
            .await
            .unwrap();
        let (proxy, _) = two_controller_proxy(bindings);

        let error = proxy.assign_controller_for_user("alice").await.unwrap_err();
        assert!(matches!(
            error,
            SnBnsProxyError::ControllerUnavailable { .. }
        ));
        let error = proxy
            .publish_dns_txt(
                "alice",
                "req-1".to_string(),
                DnsTxtUpdate::Add {
                    ttl: 600,
                    value: "v".to_string(),
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            SnBnsProxyError::ControllerUnavailable { .. }
        ));
    }

    #[tokio::test]
    async fn zero_weight_controller_receives_no_new_users() {
        let bindings: SnBnsControllerBindingStoreRef =
            Arc::new(MemorySnBnsControllerBindingStore::new());
        let submitter = Arc::new(RecordingEvmSubmitter::default());
        let proxy = proxy_with(
            vec![
                controller_entry("controller-a", CONTROLLER_A, 0, submitter.clone()),
                controller_entry("controller-b", CONTROLLER_B, 1, submitter),
            ],
            bindings,
        );
        for index in 0..16 {
            let binding = proxy
                .assign_controller_for_user(&format!("user{index:02}"))
                .await
                .unwrap();
            assert_eq!(binding.controller_id, "controller-b");
        }
    }

    #[tokio::test]
    async fn register_bootstrap_uses_user_asset_owner_and_bound_controller_policy() {
        let bindings: SnBnsControllerBindingStoreRef =
            Arc::new(MemorySnBnsControllerBindingStore::new());
        let (proxy, submitter) = two_controller_proxy(bindings);

        let outcome = proxy
            .register_bootstrap(SnBnsProxyRegisterParams {
                request_id: "sn:register:alice".to_string(),
                name: "alice".to_string(),
                asset_owner: USER_OWNER.to_uppercase().replace("0X", "0x"),
                owner_config: json!({"name": "alice"}),
                initial_documents: SnBnsProxyInitialDocuments {
                    zone: Some(json!({"oods": ["ood1"]})),
                    boot: None,
                    dns_txt: Some(vec![SnBnsDnsTxtRecord {
                        ttl: 600,
                        value: "pkx=abc".to_string(),
                    }]),
                },
            })
            .await
            .unwrap();

        assert_eq!(outcome.status, SnBnsProxyStatus::Submitted);
        assert!(outcome.tx_hash.is_some());
        assert!(outcome.raw_tx.is_some());
        assert_eq!(outcome.asset_owner.as_deref(), Some(USER_OWNER));

        let binding = proxy.controller_for_user("alice").await.unwrap().unwrap();
        assert_eq!(binding.controller_id, outcome.controller_id);
        assert_eq!(binding.controller_address, outcome.controller_address);

        let registrations = submitter.registrations();
        assert_eq!(registrations.len(), 1);
        let req = &registrations[0];
        // assetOwner = 用户地址，而非 SN controller 地址。
        assert_eq!(req.asset_owner, USER_OWNER);
        // controllerPolicy actor = 分配给该用户的 controller。
        assert!(!req.controller_policy.is_empty());
        for rule in &req.controller_policy {
            assert_eq!(rule.controller.kind, PrincipalKind::ChainAccount);
            assert_eq!(rule.controller.value, binding.controller_address);
        }
        // initialDocuments 包含 owner + zone + dns_txt。
        let doc_types: Vec<&str> = req
            .initial_documents
            .iter()
            .map(|update| update.doc_type.as_str())
            .collect();
        assert_eq!(doc_types, vec!["owner", "zone", "dns_txt"]);
    }

    #[tokio::test]
    async fn register_bootstrap_rejects_invalid_asset_owner() {
        let bindings: SnBnsControllerBindingStoreRef =
            Arc::new(MemorySnBnsControllerBindingStore::new());
        let (proxy, submitter) = two_controller_proxy(bindings);
        let error = proxy
            .register_bootstrap(SnBnsProxyRegisterParams {
                request_id: "sn:register:alice".to_string(),
                name: "alice".to_string(),
                asset_owner: "not-an-address".to_string(),
                owner_config: json!({}),
                initial_documents: SnBnsProxyInitialDocuments::default(),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, SnBnsProxyError::InvalidInput(_)));
        assert!(submitter.registrations().is_empty());
    }

    #[tokio::test]
    async fn default_asset_owner_only_available_in_devtest_mode() {
        let bindings: SnBnsControllerBindingStoreRef =
            Arc::new(MemorySnBnsControllerBindingStore::new());
        let (strict, _) = two_controller_proxy(bindings.clone());
        assert!(strict.default_asset_owner_for_user("alice").await.is_err());

        let submitter = Arc::new(RecordingEvmSubmitter::default());
        let devtest = SnBnsProxy::new(
            vec![controller_entry("controller-a", CONTROLLER_A, 1, submitter)],
            Arc::new(MemorySnBnsControllerBindingStore::new()),
            SnBnsProxyOperation::all().into_iter().collect(),
            false,
        )
        .unwrap();
        assert_eq!(
            devtest.default_asset_owner_for_user("alice").await.unwrap(),
            CONTROLLER_A
        );
    }

    #[tokio::test]
    async fn operation_allow_list_is_enforced_at_proxy_level() {
        let bindings: SnBnsControllerBindingStoreRef =
            Arc::new(MemorySnBnsControllerBindingStore::new());
        let submitter = Arc::new(RecordingEvmSubmitter::default());
        let proxy = SnBnsProxy::new(
            vec![controller_entry("controller-a", CONTROLLER_A, 1, submitter)],
            bindings,
            [SnBnsProxyOperation::PublishDnsTxt].into_iter().collect(),
            true,
        )
        .unwrap();
        let error = proxy
            .register_bootstrap(SnBnsProxyRegisterParams {
                request_id: "req".to_string(),
                name: "alice".to_string(),
                asset_owner: USER_OWNER.to_string(),
                owner_config: json!({}),
                initial_documents: SnBnsProxyInitialDocuments::default(),
            })
            .await
            .unwrap_err();
        assert!(matches!(error, SnBnsProxyError::OperationNotAllowed(_)));
    }

    #[tokio::test]
    async fn generic_publish_rejects_relay_assignment_before_submission() {
        let bindings: SnBnsControllerBindingStoreRef =
            Arc::new(MemorySnBnsControllerBindingStore::new());
        let submitter = Arc::new(RecordingEvmSubmitter::default());
        let proxy = proxy_with(
            vec![controller_entry(
                "controller-a",
                CONTROLLER_A,
                1,
                submitter.clone(),
            )],
            bindings,
        );

        let error = proxy
            .publish_document(
                "alice",
                "publish-relay-via-generic".to_string(),
                RELAY_ASSIGNMENT_DOC_TYPE.to_string(),
                json!({"relay":"relay-a"}),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SnBnsProxyError::InvalidInput(_)));
        assert!(error.to_string().contains("internal-only"));
        assert!(submitter.published.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn sqlite_binding_store_round_trip_and_no_overwrite() {
        let file = tempfile::NamedTempFile::with_suffix(".db").unwrap();
        let store = SqliteSnBnsControllerBindingStore::new_by_path(file.path().to_str().unwrap())
            .await
            .unwrap();
        store.initialize_database().await.unwrap();

        assert!(store.get_binding("alice").await.unwrap().is_none());
        let now = now_secs();
        let first = SnBnsControllerBinding {
            username: "alice".to_string(),
            controller_id: "controller-a".to_string(),
            controller_address: CONTROLLER_A.to_string(),
            created_at: now,
            updated_at: now,
        };
        let stored = store.try_insert_binding(&first).await.unwrap();
        assert_eq!(stored, first);

        // 二次插入不同内容 → 返回既有绑定，不覆盖。
        let conflicting = SnBnsControllerBinding {
            controller_id: "controller-b".to_string(),
            controller_address: CONTROLLER_B.to_string(),
            ..first.clone()
        };
        let kept = store.try_insert_binding(&conflicting).await.unwrap();
        assert_eq!(kept, first);
        assert_eq!(store.get_binding("alice").await.unwrap().unwrap(), first);
    }
}
