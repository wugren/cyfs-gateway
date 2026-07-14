//! `bns-dv` —— DV（开发验证）集成环境的开发用守护/驱动二进制（对应 doc/SN/SN-测试计划.md §5）。
//!
//! 两个子命令：
//!
//! - `serve`：在一份共享 SQLite 投影库上同时跑
//!   * BNS-Indexer：轮询 `sync_once` 把链上事件投影进库；
//!   * BNS-Server：标准合约处理器 HTTP 服务（读查投影 / 写转发 `eth_sendRawTransaction`）。
//!   两者各开一条到同一 SQLite 文件的连接（WAL 并发读写）。
//!
//! - `smoke`：跨全分层冒烟驱动——Controller Client 经 BNS-Server 提交
//!   注册 → 发布(inline) → 轮询等待 indexer 投影 → 经 Server 读命中，打印每步耗时。
//!
//! 这是开发/调试用工具（被 scripts/dv-up.sh / dv-smoke.sh 调用），不是生产服务。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bns_client::{
    BnsApplyMutationsReq, BnsEvmClientConfig, BnsEvmControllerClient, BnsEvmReceiptWaitConfig,
    BnsEvmTxSubmission, BnsIndexerApi, BnsIndexerClient, BnsPublishDocumentReq, BnsRegisterNameReq,
    StaticBnsEvmKeyManager,
};
use bns_indexer::{
    default_document_update, BnsBlockSyncSourceConfig, BnsContractEventIndexer,
    BnsIndexerSyncConfig, CallAuthority, DocumentRef, DocumentStatus, MutationGuard, NameState,
    NameStatus, OwnerPolicyUpdate, Principal, RegisterOptions, SqliteBnsRegistryStore,
};
use bns_server::{bind_and_serve, BnsContractHttpServer, BnsContractServerHandler};
use cyfs_gateway_lib::HttpServer;
use serde::Deserialize;
use serde_json::Value;

type DynError = Box<dyn std::error::Error + Send + Sync>;

// Public Anvil account[0] private key for local DV chains using the standard
// "test test ... junk" mnemonic. Never use this for production state.
const DEFAULT_DEV_PRIVATE_KEY: &str =
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[derive(Debug, Clone, Deserialize, Default)]
struct BnsDvInitConfig {
    #[serde(default)]
    seed: InitSeedConfig,
    #[serde(default)]
    on_init_txs: Vec<InitTxConfig>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct InitSeedConfig {
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    private_key_env: Option<String>,
    #[serde(default)]
    asset_owner: Option<String>,
    #[serde(default)]
    if_exists: Option<InitIfExists>,
    #[serde(default)]
    wait_timeout_ms: Option<u64>,
    #[serde(default)]
    wait_poll_ms: Option<u64>,
    #[serde(default)]
    receipt_timeout_ms: Option<u64>,
    #[serde(default)]
    receipt_poll_ms: Option<u64>,
    #[serde(default)]
    receipt_confirmations: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InitIfExists {
    ApplyMutations,
    Fail,
}

impl Default for InitIfExists {
    fn default() -> Self {
        Self::ApplyMutations
    }
}

#[derive(Debug, Clone, Deserialize)]
struct InitTxConfig {
    #[serde(rename = "type")]
    tx_type: InitTxType,
    name: String,
    #[serde(default)]
    asset_owner: Option<String>,
    /// asset_owner 的私钥（仅限 devtest，如公开的 anvil 助记词账户）。
    /// 名字已注册且文档有变更时，合约只认 asset_owner 本人签名的
    /// apply_mutations——托管 seed key 发会被 revert，重放更新必须用它。
    #[serde(default)]
    asset_owner_key: Option<String>,
    #[serde(default)]
    if_exists: Option<InitIfExists>,
    #[serde(default)]
    initial_documents: Vec<InitDocumentConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InitTxType {
    RegisterName,
}

#[derive(Debug, Clone, Deserialize)]
struct InitDocumentConfig {
    doc_type: String,
    #[serde(default)]
    inline_json_file: Option<String>,
    #[serde(default)]
    inline_json: Option<Value>,
    /// 原样上链的文本文档（如 owner key 签名的 boot JWT——boot 的规范模型
    /// 是独立原子文档，内容就是 JWT 本身，不做 JSON 包装）。
    #[serde(default)]
    inline_text_file: Option<String>,
    #[serde(default)]
    inline_text: Option<String>,
}

#[derive(Debug, Clone)]
struct PreparedInitDocument {
    doc_type: String,
    inline_document: Vec<u8>,
}

#[derive(Debug, Clone)]
struct InitRuntimeConfig {
    private_key: String,
    signer: String,
    default_asset_owner: String,
    using_default_dev_key: bool,
    if_exists: InitIfExists,
    wait_timeout_ms: u64,
    wait_poll_ms: u64,
    receipt_wait: BnsEvmReceiptWaitConfig,
}

#[derive(Debug, Clone)]
struct ProjectedDocumentInfo {
    doc_type: String,
    version: u64,
}

#[derive(Debug, Clone)]
struct ProjectedInitState {
    name_seq: u64,
    documents: Vec<ProjectedDocumentInfo>,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("bns-dv error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), DynError> {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let flags = parse_flags(args.collect());
    match command.as_str() {
        "serve" => serve(flags).await,
        "smoke" => smoke(flags).await,
        other => Err(format!(
            "unknown subcommand `{other}`; expected `serve` or `smoke`\n\
             usage:\n  \
             bns-dv serve --rpc <url> --contract <addr> --chain-id <n> --db <path> --listen <addr> [--start-block n] [--confirmations n] [--interval-ms n] [--config seed.yaml] [--seed-key 0x..]\n  \
             bns-dv smoke --server <url> --rpc <url> --contract <addr> --chain-id <n> --key <0x..> [--name alice] [--timeout-ms n]"
        )
        .into()),
    }
}

// ===== serve: indexer 轮询 + server HTTP =====

async fn serve(flags: HashMap<String, String>) -> Result<(), DynError> {
    let rpc = require(&flags, "rpc")?;
    let contract = require(&flags, "contract")?;
    let chain_id: u64 = require(&flags, "chain-id")?.parse()?;
    let db = require(&flags, "db")?;
    let listen = require(&flags, "listen")?;
    let start_block: u64 = flags.get("start-block").map_or(Ok(0), |v| v.parse())?;
    let confirmations: u64 = flags.get("confirmations").map_or(Ok(0), |v| v.parse())?;
    let interval_ms: u64 = flags.get("interval-ms").map_or(Ok(1000), |v| v.parse())?;

    let mut source = BnsBlockSyncSourceConfig::anvil(rpc.clone(), contract.clone(), start_block);
    source.chain_id = chain_id;
    let mut sync_config = BnsIndexerSyncConfig::new(source.clone());
    sync_config.confirmations = confirmations;
    sync_config.validate()?;
    let source_id = source.source_id()?;

    // server 与 indexer 各开一条到同一 SQLite 文件的连接（WAL 并发）。
    let server_store = SqliteBnsRegistryStore::open(&db)?;
    let indexer_store = SqliteBnsRegistryStore::open(&db)?;

    // indexer 轮询循环。
    tokio::spawn(async move {
        let indexer = match BnsContractEventIndexer::new(&indexer_store, sync_config.clone()) {
            Ok(indexer) => indexer,
            Err(err) => {
                eprintln!("[indexer] config error: {err}");
                return;
            }
        };
        indexer
            .run_polling_loop(
                Duration::from_millis(interval_ms),
                |outcome| match outcome {
                    Ok(outcome) => {
                        if outcome.registry_events_stored > 0 || outcome.reorg_detected {
                            eprintln!(
                                "[indexer] synced to block {:?}: +{} events (cursor {:?}, reorg={})",
                                outcome.to_block,
                                outcome.registry_events_stored,
                                outcome.cursor.as_ref().map(|c| c.block_number),
                                outcome.reorg_detected,
                            );
                        }
                    }
                    Err(err) => eprintln!("[indexer] sync_once error: {err}"),
                },
            )
            .await;
    });

    run_on_init_txs(&flags, &rpc, &contract, chain_id, &db).await?;

    let server: Arc<dyn HttpServer> = Arc::new(
        BnsContractHttpServer::from_contract_store_with_chain_config(
            server_store,
            rpc.clone(),
            contract.clone(),
            chain_id,
        ),
    );

    eprintln!(
        "[serve] bns-dv ready\n  rpc={rpc}\n  contract={contract}\n  chain_id={chain_id}\n  \
         source={source_id}\n  db={db}\n  listen=http://{listen}  (rpc_path={})",
        server_rpc_path()
    );

    bind_and_serve(listen.as_str(), server).await?;
    Ok(())
}

fn server_rpc_path() -> &'static str {
    bns_client::BNS_SERVER_RPC_PATH
}

// ===== on_init_txs: startup seed transactions =====

async fn run_on_init_txs(
    flags: &HashMap<String, String>,
    rpc: &str,
    contract: &str,
    chain_id: u64,
    db: &str,
) -> Result<(), DynError> {
    let Some((config_path, config)) = load_init_config(flags)? else {
        return Ok(());
    };
    if config.on_init_txs.is_empty() {
        eprintln!(
            "[init] config={} has no on_init_txs; skipping",
            config_path.display()
        );
        return Ok(());
    }

    let config_dir = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let runtime = build_init_runtime(flags, &config.seed)?;
    if runtime.using_default_dev_key {
        eprintln!(
            "[init] seed key not configured; using public Anvil dev account[0] key ({})",
            runtime.signer
        );
    }
    let evm_config = BnsEvmClientConfig::anvil(rpc, contract, chain_id);
    let controller = BnsEvmControllerClient::new(evm_config.clone(), &runtime.private_key)?
        .with_receipt_wait(Some(runtime.receipt_wait));
    let api: Arc<dyn BnsIndexerApi> = Arc::new(BnsContractServerHandler::new(
        SqliteBnsRegistryStore::open(db)?,
        rpc.to_string(),
    ));

    eprintln!(
        "[init] running {} startup tx(s) from {} signer={}",
        config.on_init_txs.len(),
        config_path.display(),
        runtime.signer
    );

    for (index, tx) in config.on_init_txs.iter().enumerate() {
        match tx.tx_type {
            InitTxType::RegisterName => {
                run_register_name_init_tx(
                    index + 1,
                    tx,
                    &config_dir,
                    &runtime,
                    &controller,
                    &evm_config,
                    api.as_ref(),
                )
                .await?;
            }
        }
    }

    eprintln!("[init] startup txs complete");
    Ok(())
}

fn load_init_config(
    flags: &HashMap<String, String>,
) -> Result<Option<(PathBuf, BnsDvInitConfig)>, DynError> {
    let Some(config_path) = flags.get("config").or_else(|| flags.get("seed-config")) else {
        return Ok(None);
    };
    let path = PathBuf::from(config_path);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| format!("failed to read init config {}: {e}", path.display()))?;
    let config = serde_yaml_ng::from_str::<BnsDvInitConfig>(&text)
        .map_err(|e| format!("failed to parse init config {}: {e}", path.display()))?;
    Ok(Some((path, config)))
}

fn build_init_runtime(
    flags: &HashMap<String, String>,
    seed: &InitSeedConfig,
) -> Result<InitRuntimeConfig, DynError> {
    let configured_private_key = if let Some(private_key) = flags.get("seed-key") {
        Some(private_key.clone())
    } else if let Some(private_key) = &seed.private_key {
        Some(private_key.clone())
    } else if let Some(private_key) = &seed.key {
        Some(private_key.clone())
    } else if let Some(env_name) = &seed.private_key_env {
        Some(std::env::var(env_name).map_err(|_| {
            format!(
                "seed.private_key_env `{env_name}` is set, but the environment variable is missing"
            )
        })?)
    } else {
        None
    };
    let using_default_dev_key = configured_private_key.is_none();
    let private_key = configured_private_key.unwrap_or_else(|| DEFAULT_DEV_PRIVATE_KEY.to_string());
    let key_manager = StaticBnsEvmKeyManager::new(private_key.clone())?;
    let signer = format!("{:#x}", key_manager.signer_address());
    let default_asset_owner = resolve_asset_owner(seed.asset_owner.as_deref(), &signer);

    let wait_timeout_ms = seed.wait_timeout_ms.unwrap_or(30_000);
    let wait_poll_ms = seed.wait_poll_ms.unwrap_or(200);

    let mut receipt_wait = BnsEvmReceiptWaitConfig::included();
    receipt_wait.timeout_ms = seed
        .receipt_timeout_ms
        .or(seed.wait_timeout_ms)
        .unwrap_or(receipt_wait.timeout_ms);
    receipt_wait.poll_interval_ms = seed
        .receipt_poll_ms
        .or(seed.wait_poll_ms)
        .unwrap_or(receipt_wait.poll_interval_ms);
    receipt_wait.confirmations = seed
        .receipt_confirmations
        .unwrap_or(receipt_wait.confirmations);

    Ok(InitRuntimeConfig {
        private_key,
        signer,
        default_asset_owner,
        using_default_dev_key,
        if_exists: seed.if_exists.unwrap_or_default(),
        wait_timeout_ms,
        wait_poll_ms,
        receipt_wait,
    })
}

async fn run_register_name_init_tx(
    index: usize,
    tx: &InitTxConfig,
    config_dir: &Path,
    runtime: &InitRuntimeConfig,
    controller: &BnsEvmControllerClient,
    evm_config: &BnsEvmClientConfig,
    api: &dyn BnsIndexerApi,
) -> Result<(), DynError> {
    let name = tx.name.trim();
    if name.is_empty() {
        return Err(format!("on_init_txs[{index}] register_name requires non-empty name").into());
    }
    let documents = prepare_init_documents(&tx.initial_documents, config_dir)?;
    let if_exists = tx.if_exists.unwrap_or(runtime.if_exists);
    let asset_owner = resolve_asset_owner(tx.asset_owner.as_deref(), &runtime.default_asset_owner);

    let existing = api.query_name_state(name).await?;
    match existing {
        None => {
            let (authority, guard) =
                register_authority_and_guard(name, &runtime.signer, api).await?;
            let initial_documents = documents
                .iter()
                .map(|doc| doc.to_update(0))
                .collect::<Result<Vec<_>, _>>()?;
            let submitted = controller
                .register_name(&BnsRegisterNameReq {
                    name: name.to_string(),
                    asset_owner,
                    options: RegisterOptions::default(),
                    authority_key_updates: vec![],
                    semantic_owner_after_authority: None,
                    controller_policy: vec![],
                    controller_policy_hash: String::new(),
                    initial_documents,
                    authority,
                    guard,
                })
                .await?;
            let projected = wait_for_init_projection(
                api,
                name,
                &documents,
                1,
                &docs_with_min_versions(&documents, 1),
                runtime,
            )
            .await?;
            log_projected_init("register_name", index, name, &submitted, &projected);
        }
        Some(state) => {
            if if_exists == InitIfExists::Fail {
                return Err(format!(
                    "on_init_txs[{index}] name `{name}` already exists with status {:?}, name_seq {}; set if_exists: apply_mutations to update documents",
                    state.status, state.name_seq
                )
                .into());
            }
            if state.status != NameStatus::Active {
                return Err(format!(
                    "on_init_txs[{index}] name `{name}` exists but is {:?}; startup mutation only supports active names",
                    state.status
                )
                .into());
            }
            apply_init_document_mutations(
                index,
                name,
                documents,
                state,
                tx.asset_owner_key.as_deref(),
                runtime,
                controller,
                evm_config,
                api,
            )
            .await?;
        }
    }

    Ok(())
}

async fn register_authority_and_guard(
    name: &str,
    signer: &str,
    api: &dyn BnsIndexerApi,
) -> Result<(CallAuthority, MutationGuard), DynError> {
    let Some((_, parent)) = name.split_once('.') else {
        return Ok((CallAuthority::public(), MutationGuard::default()));
    };
    let parent_state = api
        .query_name_state(parent)
        .await?
        .ok_or_else(|| format!("cannot register `{name}`: parent `{parent}` is not projected"))?;
    if parent_state.status != NameStatus::Active {
        return Err(format!(
            "cannot register `{name}`: parent `{parent}` is {:?}",
            parent_state.status
        )
        .into());
    }
    Ok((
        CallAuthority::owner(Principal::chain_account(signer), ""),
        MutationGuard {
            expected_name_seq: 0,
            expected_parent_name_seq: parent_state.name_seq,
        },
    ))
}

async fn apply_init_document_mutations(
    index: usize,
    name: &str,
    documents: Vec<PreparedInitDocument>,
    state: NameState,
    asset_owner_key: Option<&str>,
    runtime: &InitRuntimeConfig,
    controller: &BnsEvmControllerClient,
    evm_config: &BnsEvmClientConfig,
    api: &dyn BnsIndexerApi,
) -> Result<(), DynError> {
    let mut updates = Vec::new();
    let mut min_versions = Vec::new();
    let mut current_documents = Vec::new();

    for doc in &documents {
        let current = current_document(api, name, &doc.doc_type).await?;
        let current_version = current.as_ref().map_or(0, |state| state.version);
        if current.as_ref().is_some_and(|state| {
            state.status == DocumentStatus::Active
                && state.document.inline_document == doc.inline_document
        }) {
            current_documents.push(ProjectedDocumentInfo {
                doc_type: doc.doc_type.clone(),
                version: current_version,
            });
            continue;
        }
        updates.push(doc.to_update(current_version)?);
        min_versions.push((doc.doc_type.clone(), current_version + 1));
    }

    if updates.is_empty() {
        let projected = ProjectedInitState {
            name_seq: state.name_seq,
            documents: current_documents,
        };
        eprintln!(
            "[init][{index}] register_name name={name} already up-to-date name_seq={}",
            projected.name_seq
        );
        for doc in projected.documents {
            eprintln!(
                "[init][{index}] document name={name} doc_type={} version={} already up-to-date",
                doc.doc_type, doc.version
            );
        }
        return Ok(());
    }

    // 合约 _authorizeOwner 要求 msg.sender 与 authority.actor 都是链上
    // asset_owner；种子经托管 key 代注册后 owner 已锚定用户地址，重放
    // 更新必须换 owner key 签名（asset_owner_key），托管 key 发会 revert。
    let (owner_controller, mutation_signer) =
        resolve_mutation_signer(index, name, &state, asset_owner_key, runtime, evm_config)?;
    let submitted = owner_controller
        .as_ref()
        .unwrap_or(controller)
        .apply_mutations(&BnsApplyMutationsReq {
            name: name.to_string(),
            authority_key_updates: vec![],
            documents: updates,
            owner_policy: OwnerPolicyUpdate::none(),
            authority: CallAuthority::owner(Principal::chain_account(mutation_signer), ""),
            guard: MutationGuard {
                expected_name_seq: state.name_seq,
                expected_parent_name_seq: 0,
            },
        })
        .await?;
    let projected = wait_for_init_projection(
        api,
        name,
        &documents,
        state.name_seq + 1,
        &min_versions,
        runtime,
    )
    .await?;
    log_projected_init("apply_mutations", index, name, &submitted, &projected);
    Ok(())
}

/// 选出能通过合约 owner 校验的 apply_mutations 签名者。返回
/// `(Some(owner_controller), owner)` 表示要用 asset_owner_key 的专属
/// controller；`(None, signer)` 表示种子托管 key 本身就是 owner，复用
/// 既有 controller。
fn resolve_mutation_signer(
    index: usize,
    name: &str,
    state: &NameState,
    asset_owner_key: Option<&str>,
    runtime: &InitRuntimeConfig,
    evm_config: &BnsEvmClientConfig,
) -> Result<(Option<BnsEvmControllerClient>, String), DynError> {
    if state.asset_owner.eq_ignore_ascii_case(&runtime.signer) {
        return Ok((None, runtime.signer.clone()));
    }
    let Some(owner_key) = asset_owner_key else {
        return Err(format!(
            "on_init_txs[{index}] name `{name}` documents changed, but on-chain asset_owner {} \
             differs from seed signer {} and the tx has no asset_owner_key; add the owner's \
             private key as asset_owner_key (devtest), or reset the dev chain (init_anvil.py --fresh)",
            state.asset_owner, runtime.signer
        )
        .into());
    };
    let key_manager = StaticBnsEvmKeyManager::new(owner_key.to_string())?;
    let owner_signer = format!("{:#x}", key_manager.signer_address());
    if !owner_signer.eq_ignore_ascii_case(&state.asset_owner) {
        return Err(format!(
            "on_init_txs[{index}] asset_owner_key of name `{name}` derives address {owner_signer}, \
             which is not the on-chain asset_owner {}; fix asset_owner_key or reset the dev chain \
             (init_anvil.py --fresh)",
            state.asset_owner
        )
        .into());
    }
    let owner_controller = BnsEvmControllerClient::new(evm_config.clone(), owner_key)?
        .with_receipt_wait(Some(runtime.receipt_wait));
    Ok((Some(owner_controller), owner_signer))
}

async fn current_document(
    api: &dyn BnsIndexerApi,
    name: &str,
    doc_type: &str,
) -> Result<Option<bns_indexer::DocumentState>, DynError> {
    match api.resolve_document(name, doc_type).await {
        Ok(result) => Ok(Some(result.document_state)),
        Err(error)
            if error.is_registry_code("DOCUMENT_NOT_FOUND")
                || error.is_registry_code("NAME_NOT_FOUND") =>
        {
            Ok(None)
        }
        Err(error) => Err(Box::new(error)),
    }
}

async fn wait_for_init_projection(
    api: &dyn BnsIndexerApi,
    name: &str,
    documents: &[PreparedInitDocument],
    min_name_seq: u64,
    min_versions: &[(String, u64)],
    runtime: &InitRuntimeConfig,
) -> Result<ProjectedInitState, DynError> {
    let deadline = Instant::now() + Duration::from_millis(runtime.wait_timeout_ms.max(1));
    let poll = Duration::from_millis(runtime.wait_poll_ms.max(1));
    loop {
        if let Ok(Some(name_state)) = api.query_name_state(name).await {
            if name_state.status == NameStatus::Active && name_state.name_seq >= min_name_seq {
                let mut projected_docs = Vec::with_capacity(documents.len());
                let mut all_ready = true;
                for doc in documents {
                    let min_version = min_versions
                        .iter()
                        .find(|(doc_type, _)| doc_type == &doc.doc_type)
                        .map_or(1, |(_, version)| *version);
                    match api.resolve_document(name, &doc.doc_type).await {
                        Ok(result)
                            if result.document_state.status == DocumentStatus::Active
                                && result.document_state.version >= min_version
                                && result.document_state.document.inline_document
                                    == doc.inline_document =>
                        {
                            projected_docs.push(ProjectedDocumentInfo {
                                doc_type: doc.doc_type.clone(),
                                version: result.document_state.version,
                            });
                        }
                        _ => {
                            all_ready = false;
                            break;
                        }
                    }
                }
                if all_ready {
                    return Ok(ProjectedInitState {
                        name_seq: name_state.name_seq,
                        documents: projected_docs,
                    });
                }
            }
        }

        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for indexer projection of startup tx for `{name}`"
            )
            .into());
        }
        tokio::time::sleep(poll).await;
    }
}

fn prepare_init_documents(
    docs: &[InitDocumentConfig],
    config_dir: &Path,
) -> Result<Vec<PreparedInitDocument>, DynError> {
    docs.iter()
        .enumerate()
        .map(|(index, doc)| prepare_init_document(index, doc, config_dir))
        .collect()
}

fn prepare_init_document(
    index: usize,
    doc: &InitDocumentConfig,
    config_dir: &Path,
) -> Result<PreparedInitDocument, DynError> {
    let sources = [
        doc.inline_json_file.is_some(),
        doc.inline_json.is_some(),
        doc.inline_text_file.is_some(),
        doc.inline_text.is_some(),
    ];
    if sources.iter().filter(|set| **set).count() != 1 {
        return Err(format!(
            "initial_documents[{index}] must set exactly one of inline_json_file, inline_json, inline_text_file or inline_text"
        )
        .into());
    }

    let inline_document = if let Some(file) = &doc.inline_json_file {
        let path = resolve_config_path(config_dir, file);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read inline_json_file {}: {e}", path.display()))?;
        let value = serde_json::from_str::<Value>(&text)
            .map_err(|e| format!("failed to parse JSON {}: {e}", path.display()))?;
        serde_json::to_vec(&value)?
    } else if let Some(value) = &doc.inline_json {
        serde_json::to_vec(value)?
    } else if let Some(file) = &doc.inline_text_file {
        let path = resolve_config_path(config_dir, file);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read inline_text_file {}: {e}", path.display()))?;
        text.trim().as_bytes().to_vec()
    } else {
        doc.inline_text
            .as_deref()
            .expect("checked inline_text")
            .trim()
            .as_bytes()
            .to_vec()
    };

    Ok(PreparedInitDocument {
        doc_type: doc.doc_type.clone(),
        inline_document,
    })
}

fn resolve_config_path(config_dir: &Path, file: &str) -> PathBuf {
    let path = PathBuf::from(file);
    if path.is_absolute() {
        path
    } else {
        config_dir.join(path)
    }
}

fn docs_with_min_versions(docs: &[PreparedInitDocument], version: u64) -> Vec<(String, u64)> {
    docs.iter()
        .map(|doc| (doc.doc_type.clone(), version))
        .collect()
}

impl PreparedInitDocument {
    fn to_update(
        &self,
        expected_version: u64,
    ) -> bns_indexer::BnsRegistryResult<bns_indexer::DocumentUpdate> {
        default_document_update(
            &self.doc_type,
            expected_version,
            DocumentRef::inline(self.inline_document.clone()),
        )
    }
}

fn resolve_asset_owner(value: Option<&str>, default: &str) -> String {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return default.to_string();
    };
    match value.to_ascii_lowercase().as_str() {
        "<dev signer>" | "<signer>" | "dev_signer" | "signer" | "$dev_signer" | "$signer" => {
            default.to_string()
        }
        _ => value.to_string(),
    }
}

fn log_projected_init(
    operation: &str,
    index: usize,
    name: &str,
    submitted: &BnsEvmTxSubmission,
    projected: &ProjectedInitState,
) {
    eprintln!(
        "[init][{index}] {operation} name={name} tx={} nonce={} name_seq={}",
        submitted.tx_hash, submitted.nonce, projected.name_seq
    );
    for doc in &projected.documents {
        eprintln!(
            "[init][{index}] document name={name} doc_type={} version={} tx={}",
            doc.doc_type, doc.version, submitted.tx_hash
        );
    }
}

// ===== smoke: 跨分层冒烟 =====

async fn smoke(flags: HashMap<String, String>) -> Result<(), DynError> {
    let server_url = require(&flags, "server")?;
    let rpc = require(&flags, "rpc")?;
    let contract = require(&flags, "contract")?;
    let chain_id: u64 = require(&flags, "chain-id")?.parse()?;
    let key = require(&flags, "key")?;
    let name = flags
        .get("name")
        .cloned()
        .unwrap_or_else(|| "alice".to_string());
    let timeout_ms: u64 = flags.get("timeout-ms").map_or(Ok(30_000), |v| v.parse())?;

    let key_manager = Arc::new(StaticBnsEvmKeyManager::new(key.clone())?);
    let signer = format!("{:#x}", key_manager.signer_address());

    let server_api: Arc<dyn BnsIndexerApi> =
        Arc::new(BnsIndexerClient::new_bns_server_url(&server_url, None));
    let controller = BnsEvmControllerClient::new_with_bns_server_submitter(
        BnsEvmClientConfig::anvil(rpc.clone(), contract.clone(), chain_id),
        key_manager,
        server_api.clone(),
    );

    let body = format!(r#"{{"id":"did:bns:{name}","smoke":true}}"#);

    // 1) 注册（经 server tx.submit_raw → eth_sendRawTransaction）。
    let t = Instant::now();
    let registered = controller
        .register_name(&BnsRegisterNameReq {
            name: name.clone(),
            asset_owner: signer.clone(),
            options: RegisterOptions::default(),
            authority_key_updates: vec![],
            semantic_owner_after_authority: None,
            controller_policy: vec![],
            controller_policy_hash: String::new(),
            initial_documents: vec![],
            authority: CallAuthority::public(),
            guard: MutationGuard::default(),
        })
        .await?;
    println!(
        "[1/4] register {name}: tx={} nonce={} ({} ms)",
        registered.tx_hash,
        registered.nonce,
        t.elapsed().as_millis()
    );

    // 2) 发布 owner 文档（inline）。注册后 nameSeq=1。
    let t = Instant::now();
    let published = controller
        .publish_document(&BnsPublishDocumentReq {
            name: name.clone(),
            update: default_document_update("owner", 0, DocumentRef::inline(body.as_bytes()))?,
            authority: CallAuthority::owner(Principal::chain_account(signer.clone()), ""),
            guard: MutationGuard {
                expected_name_seq: 1,
                expected_parent_name_seq: 0,
            },
        })
        .await?;
    println!(
        "[2/4] publish owner doc: tx={} nonce={} ({} ms)",
        published.tx_hash,
        published.nonce,
        t.elapsed().as_millis()
    );

    // 3) 等待 indexer 投影（轮询 server 读）。
    let t = Instant::now();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if let Ok(Some(state)) = server_api.query_name_state(&name).await {
            if state.status == NameStatus::Active {
                break;
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for indexer to project `{name}`").into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    println!(
        "[3/4] indexer projected {name} ({} ms)",
        t.elapsed().as_millis()
    );

    // 4) 经 server 读命中：resolveDocument 内容/版本一致。
    let t = Instant::now();
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let resolved = loop {
        if let Ok(result) = server_api.resolve_document(&name, "owner").await {
            if result.document_state.version >= 1 {
                break result;
            }
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for owner document projection".into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    let projected_body = String::from_utf8_lossy(&resolved.document_state.document.inline_document);
    if projected_body != body {
        return Err(format!(
            "projected document mismatch: expected `{body}`, got `{projected_body}`"
        )
        .into());
    }
    println!(
        "[4/4] read owner doc v{} via server: {} ({} ms)",
        resolved.document_state.version,
        projected_body,
        t.elapsed().as_millis()
    );

    println!("SMOKE OK: full BNS<->Indexer<->Server<->Client<->Controller path verified");
    Ok(())
}

// ===== 简易 --flag value 解析 =====

fn parse_flags(args: Vec<String>) -> HashMap<String, String> {
    let mut flags = HashMap::new();
    let mut iter = args.into_iter().peekable();
    while let Some(arg) = iter.next() {
        if let Some(name) = arg.strip_prefix("--") {
            if let Some((k, v)) = name.split_once('=') {
                flags.insert(k.to_string(), v.to_string());
            } else {
                let value = iter.next().unwrap_or_default();
                flags.insert(name.to_string(), value);
            }
        }
    }
    flags
}

fn require(flags: &HashMap<String, String>, key: &str) -> Result<String, DynError> {
    flags
        .get(key)
        .cloned()
        .ok_or_else(|| format!("missing required flag --{key}").into())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::process::Stdio;

    use bns_evm::{Address, EthRpcClient};
    use name_client::{BnsProvider, NsProvider};
    use name_lib::DID;
    use serde_json::json;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::process::{Child, Command};
    use tokio::time::sleep;

    const CHAIN_ID: u64 = 31_337;
    const DEPLOYER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

    fn foundry_available() -> bool {
        fn has(bin: &str) -> bool {
            std::process::Command::new(bin)
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .map(|status| status.success())
                .unwrap_or(false)
        }
        has("anvil") && has("forge")
    }

    async fn allocate_free_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn wait_for_tcp(addr: &str) {
        for _ in 0..120 {
            if TcpStream::connect(addr).await.is_ok() {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("server did not start on {addr}");
    }

    fn bns_app_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../apps/bns")
            .canonicalize()
            .expect("bns foundry project should exist")
    }

    struct AnvilNode {
        _child: Child,
        endpoint: String,
    }

    impl AnvilNode {
        async fn start() -> Self {
            let port = allocate_free_port().await;
            let child = Command::new("anvil")
                .args([
                    "--host",
                    "127.0.0.1",
                    "--port",
                    &port.to_string(),
                    "--chain-id",
                    &CHAIN_ID.to_string(),
                    "--mnemonic",
                    "test test test test test test test test test test test junk",
                    "--disable-code-size-limit",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .expect("failed to spawn anvil");

            let endpoint = format!("http://127.0.0.1:{port}");
            let rpc = EthRpcClient::new(endpoint.clone());
            for _ in 0..100 {
                if let Ok(chain_id) = rpc.chain_id().await {
                    assert_eq!(chain_id, CHAIN_ID);
                    return Self {
                        _child: child,
                        endpoint,
                    };
                }
                sleep(Duration::from_millis(100)).await;
            }
            panic!("anvil did not become ready at {endpoint}");
        }
    }

    async fn deploy_bns(endpoint: &str) -> Address {
        let output = Command::new("forge")
            .current_dir(bns_app_dir())
            .args([
                "create",
                "src/Bns.sol:Bns",
                "--rpc-url",
                endpoint,
                "--private-key",
                DEPLOYER_KEY,
                "--broadcast",
                "--json",
            ])
            .output()
            .await
            .expect("failed to run forge create");
        assert!(
            output.status.success(),
            "forge create failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let start = stdout
            .find('{')
            .unwrap_or_else(|| panic!("forge create produced no JSON: {stdout}"));
        let end = stdout
            .rfind('}')
            .unwrap_or_else(|| panic!("forge create produced no JSON object: {stdout}"));
        let parsed: Value = serde_json::from_str(&stdout[start..=end]).unwrap();
        parsed["deployedTo"]
            .as_str()
            .expect("forge create JSON missing deployedTo")
            .parse()
            .expect("invalid deployed contract address")
    }

    fn flags(entries: &[(&str, String)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect()
    }

    async fn resolve_json_doc(provider: &BnsProvider, did: &DID, doc_type: &str) -> Value {
        provider
            .query_did(did, Some(doc_type), None)
            .await
            .unwrap()
            .to_json_value()
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "requires Foundry (anvil/forge); run with --ignored"]
    async fn on_init_txs_seed_documents_are_readable_through_bns_http_resolver() {
        if !foundry_available() {
            eprintln!("skipping: anvil/forge not on PATH");
            return;
        }

        let node = AnvilNode::start().await;
        let contract = deploy_bns(&node.endpoint).await;
        let listen_port = allocate_free_port().await;
        let listen = format!("127.0.0.1:{listen_port}");
        let server_url = format!("http://{listen}");

        let temp = tempfile::tempdir().unwrap();
        let db = temp.path().join("indexer.sqlite");
        let zone_file = temp.path().join("alice.zone.bns.json");
        let boot_file = temp.path().join("alice.boot.bns.json");
        let device_file = temp.path().join("alice.device_mini_doc.bns.json");
        std::fs::write(
            &zone_file,
            serde_json::to_vec(&json!({
                "id": "did:bns:alice",
                "gateway_device_name": "ood1",
                "marker": "zone-from-on-init"
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            &boot_file,
            serde_json::to_vec(&json!({
                "id": "did:bns:alice",
                "oods": ["ood1"],
                "marker": "boot-from-on-init"
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::write(
            &device_file,
            serde_json::to_vec(&json!({
                "id": "did:bns:alice",
                "devices": {
                    "ood1": {
                        "id": "did:dev:ood1",
                        "device_name": "ood1",
                        "marker": "device-from-on-init"
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let config_file = temp.path().join("seed.yaml");
        std::fs::write(
            &config_file,
            format!(
                r#"
seed:
  if_exists: apply_mutations
  wait_timeout_ms: 30000
  wait_poll_ms: 100
on_init_txs:
  - type: register_name
    name: alice
    asset_owner: "<dev signer>"
    initial_documents:
      - doc_type: zone
        inline_json_file: {}
      - doc_type: boot
        inline_json_file: {}
      - doc_type: device_mini_doc
        inline_json_file: {}
"#,
                zone_file.display(),
                boot_file.display(),
                device_file.display()
            ),
        )
        .unwrap();

        let serve_flags = flags(&[
            ("rpc", node.endpoint.clone()),
            ("contract", format!("{contract:#x}")),
            ("chain-id", CHAIN_ID.to_string()),
            ("db", db.to_string_lossy().to_string()),
            ("listen", listen.clone()),
            ("start-block", "0".to_string()),
            ("confirmations", "0".to_string()),
            ("interval-ms", "100".to_string()),
            ("config", config_file.to_string_lossy().to_string()),
        ]);
        let server_task = tokio::spawn(async move { serve(serve_flags).await });
        wait_for_tcp(&listen).await;

        let provider = BnsProvider::new_with_config(json!({
            "web3_bridge": {
                "bns": server_url
            },
            "trust_did": [],
            "force_https": false
        }))
        .unwrap();
        let did = DID::new("bns", "alice");

        let zone = resolve_json_doc(&provider, &did, "zone").await;
        assert_eq!(
            zone,
            json!({
                "id": "did:bns:alice",
                "gateway_device_name": "ood1",
                "marker": "zone-from-on-init"
            })
        );

        let boot = resolve_json_doc(&provider, &did, "boot").await;
        assert_eq!(boot["marker"], "boot-from-on-init");

        let device = resolve_json_doc(&provider, &did, "device_mini_doc").await;
        assert_eq!(device["devices"]["ood1"]["marker"], "device-from-on-init");

        server_task.abort();
        let _ = server_task.await;
    }

    // anvil account[1]（公开助记词账户表）：种子里用户名字的 asset_owner。
    const OWNER_ADDRESS: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
    const OWNER_KEY: &str = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

    /// devtest 种子重放（web3-gateway 重启）语义：
    /// 1. 首次注册经托管 key 代发，asset_owner 锚定用户地址；
    /// 2. 文档未变的重放不发 tx，也不需要 owner key；
    /// 3. 文档变更的重放用 asset_owner_key 以 owner 身份 apply_mutations；
    /// 4. 变更但缺 asset_owner_key 时报带指引的错误（而不是裸 EVM revert）。
    #[tokio::test]
    #[ignore = "requires Foundry (anvil/forge); run with --ignored"]
    async fn on_init_txs_replay_updates_changed_documents_with_asset_owner_key() {
        if !foundry_available() {
            eprintln!("skipping: anvil/forge not on PATH");
            return;
        }

        let node = AnvilNode::start().await;
        let contract = deploy_bns(&node.endpoint).await;
        let contract_hex = format!("{contract:#x}");
        let listen_port = allocate_free_port().await;
        let listen = format!("127.0.0.1:{listen_port}");
        let server_url = format!("http://{listen}");

        let temp = tempfile::tempdir().unwrap();
        let db = temp
            .path()
            .join("indexer.sqlite")
            .to_string_lossy()
            .to_string();
        let zone_file = temp.path().join("alice.zone.bns.json");
        let write_zone = |marker: &str| {
            std::fs::write(
                &zone_file,
                serde_json::to_vec(&json!({ "id": "did:bns:alice", "marker": marker })).unwrap(),
            )
            .unwrap();
        };
        write_zone("seed-v1");

        let write_config = |file_name: &str, with_owner_key: bool| {
            let path = temp.path().join(file_name);
            let mut lines = vec![
                "seed:".to_string(),
                "  if_exists: apply_mutations".to_string(),
                "  wait_timeout_ms: 30000".to_string(),
                "  wait_poll_ms: 100".to_string(),
                "on_init_txs:".to_string(),
                "  - type: register_name".to_string(),
                "    name: alice".to_string(),
                format!("    asset_owner: \"{OWNER_ADDRESS}\""),
            ];
            if with_owner_key {
                lines.push(format!("    asset_owner_key: \"{OWNER_KEY}\""));
            }
            lines.push("    initial_documents:".to_string());
            lines.push("      - doc_type: zone".to_string());
            lines.push(format!("        inline_json_file: {}", zone_file.display()));
            std::fs::write(&path, lines.join("\n")).unwrap();
            path
        };
        let config_without_key = write_config("seed_no_key.yaml", false);
        let config_with_key = write_config("seed_with_key.yaml", true);

        // 阶段 1：serve 启动 + 托管代注册（不需要 owner key）。
        let serve_flags = flags(&[
            ("rpc", node.endpoint.clone()),
            ("contract", contract_hex.clone()),
            ("chain-id", CHAIN_ID.to_string()),
            ("db", db.clone()),
            ("listen", listen.clone()),
            ("start-block", "0".to_string()),
            ("confirmations", "0".to_string()),
            ("interval-ms", "100".to_string()),
            ("config", config_without_key.to_string_lossy().to_string()),
        ]);
        let server_task = tokio::spawn(async move { serve(serve_flags).await });
        wait_for_tcp(&listen).await;

        let server_api = BnsIndexerClient::new_bns_server_url(&server_url, None);
        let registered = server_api.query_name_state("alice").await.unwrap().unwrap();
        assert_eq!(
            registered.asset_owner.to_ascii_lowercase(),
            OWNER_ADDRESS.to_ascii_lowercase()
        );
        let doc = server_api.resolve_document("alice", "zone").await.unwrap();
        assert_eq!(doc.document_state.version, 1);

        let replay_flags =
            |config: &PathBuf| flags(&[("config", config.to_string_lossy().to_string())]);

        // 阶段 2：文档未变的重放不发 tx，无 owner key 也成功。
        run_on_init_txs(
            &replay_flags(&config_without_key),
            &node.endpoint,
            &contract_hex,
            CHAIN_ID,
            &db,
        )
        .await
        .unwrap();
        let doc = server_api.resolve_document("alice", "zone").await.unwrap();
        assert_eq!(doc.document_state.version, 1);

        // 阶段 3：文档变更 + asset_owner_key，以 owner 身份 apply_mutations。
        write_zone("seed-v2");
        run_on_init_txs(
            &replay_flags(&config_with_key),
            &node.endpoint,
            &contract_hex,
            CHAIN_ID,
            &db,
        )
        .await
        .unwrap();
        let doc = server_api.resolve_document("alice", "zone").await.unwrap();
        assert_eq!(doc.document_state.version, 2);
        let value: Value =
            serde_json::from_slice(&doc.document_state.document.inline_document).unwrap();
        assert_eq!(value["marker"], "seed-v2");

        // 阶段 4：文档变更但缺 asset_owner_key，必须报带指引的错误。
        write_zone("seed-v3");
        let err = run_on_init_txs(
            &replay_flags(&config_without_key),
            &node.endpoint,
            &contract_hex,
            CHAIN_ID,
            &db,
        )
        .await
        .expect_err("changed documents without asset_owner_key must fail with guidance");
        let message = err.to_string();
        assert!(
            message.contains("asset_owner_key"),
            "error should mention asset_owner_key: {message}"
        );
        let doc = server_api.resolve_document("alice", "zone").await.unwrap();
        assert_eq!(
            doc.document_state.version, 2,
            "failed replay must not mutate documents"
        );

        server_task.abort();
        let _ = server_task.await;
    }
}
