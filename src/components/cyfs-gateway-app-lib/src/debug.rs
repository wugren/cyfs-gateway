use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use anyhow::{Result, anyhow};
use buckyos_kit::{
    AsyncStream, apply_params_to_json, get_buckyos_service_data_dir, get_buckyos_system_etc_dir,
};
use cyfs_gateway_lib::{
    GlobalCollectionManager, GlobalCollectionManagerRef, GlobalProcessChains,
    GlobalProcessChainsRef, JsExternalsManager, JsExternalsManagerRef, ProcessChainConfig,
    ProcessChainConfigs, create_process_chain_executor, get_external_commands,
    normalize_all_path_value_config, normalize_config_file_path,
};
use cyfs_process_chain::{
    CollectionValue, CommandControl, CommandResult, MemoryMapCollection, MemorySetCollection,
};
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::{
    ConfigMerger, GATEWAY_CONTROL_SERVER_CONFIG, merge, parse_collections_from_raw_config,
};

async fn build_js_externals_from_raw_config(
    base_dir: &Path,
    raw_config: &Value,
) -> Result<JsExternalsManagerRef> {
    let manager = Arc::new(JsExternalsManager::new());
    let js_externals = raw_config
        .get("js_externals")
        .and_then(|value| value.as_object());

    let Some(js_externals) = js_externals else {
        return Ok(manager);
    };

    for (name, source_path) in js_externals {
        let source_path = source_path
            .as_str()
            .ok_or_else(|| anyhow!("js_externals.{} must be a string file path", name))?;
        let source_path = normalize_config_file_path(PathBuf::from(source_path), base_dir);
        let source = std::fs::read_to_string(source_path.as_path()).map_err(|e| {
            anyhow!(
                "read js external {} from {} failed: {}",
                name,
                source_path.to_string_lossy(),
                e
            )
        })?;

        manager
            .add_js_external(name, source)
            .await
            .map_err(|e| anyhow!("register js external {} failed: {}", name, e))?;
    }

    Ok(manager)
}

async fn build_global_process_chains_from_config(
    global_process_configs: &ProcessChainConfigs,
) -> Result<GlobalProcessChainsRef> {
    let mut global_process_chains = GlobalProcessChains::new();
    for process_chain_config in global_process_configs {
        let process_chain = process_chain_config.create_process_chain()?;
        global_process_chains.add_process_chain(Arc::new(process_chain))?;
    }
    Ok(Arc::new(global_process_chains))
}

fn parse_global_process_chains_from_raw_config(raw_config: &Value) -> Result<ProcessChainConfigs> {
    let Some(global) = raw_config
        .get("global_process_chains")
        .and_then(|value| value.as_object())
    else {
        return Ok(vec![]);
    };
    let mut chain_list = Vec::with_capacity(global.len());
    for (chain_id, chain_value) in global {
        chain_list.push(parse_chain_config(chain_id.as_str(), chain_value)?);
    }
    Ok(chain_list)
}

#[derive(Deserialize)]
struct DebugRequestFile {
    #[serde(default)]
    input: Map<String, Value>,
    id: Option<String>,
    #[serde(default)]
    output: Vec<String>,
}

enum DebugScopeKind {
    Stack,
    Server,
}

enum DebugTarget {
    GlobalChain {
        chain_id: String,
    },
    ScopeHookPoint {
        kind: DebugScopeKind,
        scope_id: String,
        mount_point: String,
    },
    ScopeChain {
        kind: DebugScopeKind,
        scope_id: String,
        mount_point: String,
        chain_id: String,
    },
    ScopeBlock {
        kind: DebugScopeKind,
        scope_id: String,
        mount_point: String,
        chain_id: String,
        block_id: String,
        line_spec: Option<String>,
    },
}

fn is_mount_point_segment(segment: &str) -> bool {
    segment == "hook_point" || segment.ends_with("_hook_point")
}

fn parse_debug_target(id: &str) -> Result<DebugTarget> {
    if let Some(chain_id) = id.strip_prefix("global_process_chain:") {
        if chain_id.is_empty() {
            return Err(anyhow!("invalid id: missing global process chain id"));
        }
        return Ok(DebugTarget::GlobalChain {
            chain_id: chain_id.to_string(),
        });
    }

    let parts: Vec<&str> = id.split(':').collect();
    if parts.len() < 2 {
        return Ok(DebugTarget::GlobalChain {
            chain_id: id.to_string(),
        });
    }

    let kind = match parts[0] {
        "stack" => DebugScopeKind::Stack,
        "server" => DebugScopeKind::Server,
        _ => {
            return Ok(DebugTarget::GlobalChain {
                chain_id: id.to_string(),
            });
        }
    };

    let scope_id = parts[1];
    if scope_id.is_empty() {
        return Err(anyhow!("invalid id: missing stack/server id"));
    }

    let mut index = 2;
    let mut mount_point = "hook_point";
    if parts.len() > index && is_mount_point_segment(parts[index]) {
        mount_point = parts[index];
        index += 1;
    }

    if parts.len() <= index {
        return Ok(DebugTarget::ScopeHookPoint {
            kind,
            scope_id: scope_id.to_string(),
            mount_point: mount_point.to_string(),
        });
    }

    let chain_id = parts[index];
    index += 1;
    if chain_id.is_empty() {
        return Err(anyhow!("invalid id: missing chain id"));
    }

    if parts.len() <= index {
        return Ok(DebugTarget::ScopeChain {
            kind,
            scope_id: scope_id.to_string(),
            mount_point: mount_point.to_string(),
            chain_id: chain_id.to_string(),
        });
    }

    if parts[index] == "blocks" {
        index += 1;
    }

    if parts.len() <= index {
        return Err(anyhow!("invalid id: missing block id"));
    }

    let block_id = parts[index];
    index += 1;
    if block_id.is_empty() {
        return Err(anyhow!("invalid id: missing block id"));
    }
    let line_spec = if parts.len() > index {
        Some(parts[index..].join(":"))
    } else {
        None
    };

    Ok(DebugTarget::ScopeBlock {
        kind,
        scope_id: scope_id.to_string(),
        mount_point: mount_point.to_string(),
        chain_id: chain_id.to_string(),
        block_id: block_id.to_string(),
        line_spec,
    })
}

fn blocks_value_to_vector(blocks: &Value) -> Result<Value> {
    match blocks {
        Value::Array(_) => Ok(blocks.clone()),
        Value::Object(map) => {
            let mut block_list = Vec::with_capacity(map.len());
            for (id, value) in map {
                let mut new_value = value.clone();
                new_value["id"] = Value::String(id.to_string());
                block_list.push(new_value);
            }
            Ok(Value::Array(block_list))
        }
        _ => Err(anyhow!("invalid blocks config, must be object or array")),
    }
}

fn parse_chain_config(chain_id: &str, chain_value: &Value) -> Result<ProcessChainConfig> {
    let mut value = chain_value.clone();
    value["id"] = Value::String(chain_id.to_string());
    if let Some(blocks) = value.get("blocks") {
        value["blocks"] = blocks_value_to_vector(blocks)?;
    }
    serde_json::from_value::<ProcessChainConfig>(value)
        .map_err(|e| anyhow!("invalid chain config {}: {}", chain_id, e))
}

fn select_block_lines(block: &str, line_spec: &str) -> Result<String> {
    let ends_with_newline = block.ends_with('\n');
    let lines: Vec<String> = block.lines().map(|s| s.to_string()).collect();
    if lines.is_empty() {
        return Ok(String::new());
    }

    let (start_str, end_str) = if let Some((start, end)) = line_spec.split_once(':') {
        (start, end)
    } else {
        (line_spec, line_spec)
    };
    let start: usize = start_str
        .parse()
        .map_err(|_| anyhow!("invalid line spec {}", line_spec))?;
    let end: usize = end_str
        .parse()
        .map_err(|_| anyhow!("invalid line spec {}", line_spec))?;

    if start == 0 || end == 0 || start > end || end > lines.len() {
        return Err(anyhow!("line range out of bounds"));
    }

    let mut selected = lines[start - 1..end].join("\n");
    if ends_with_newline && !selected.is_empty() {
        selected.push('\n');
    }
    Ok(selected)
}

fn filter_chain_for_block(
    mut chain: ProcessChainConfig,
    block_id: &str,
    line_spec: Option<&str>,
) -> Result<ProcessChainConfig> {
    let block = chain
        .blocks
        .into_iter()
        .find(|b| b.id == block_id)
        .ok_or_else(|| anyhow!("block not found: {}", block_id))?;

    let mut selected_block = block;
    if let Some(spec) = line_spec {
        selected_block.block = select_block_lines(selected_block.block.as_str(), spec)?;
    }
    chain.blocks = vec![selected_block];
    Ok(chain)
}

fn get_scope_root<'a>(config: &'a Value, kind: &DebugScopeKind) -> Result<&'a Map<String, Value>> {
    let key = match kind {
        DebugScopeKind::Stack => "stacks",
        DebugScopeKind::Server => "servers",
    };
    config
        .get(key)
        .and_then(|value| value.as_object())
        .ok_or_else(|| anyhow!("{} not found in config", key))
}

fn get_scope_hook_point<'a>(
    config: &'a Value,
    kind: &DebugScopeKind,
    scope_id: &str,
    mount_point: &str,
) -> Result<&'a Map<String, Value>> {
    let scope_root = get_scope_root(config, kind)?;
    let scope_value = scope_root
        .get(scope_id)
        .ok_or_else(|| anyhow!("scope not found: {}", scope_id))?;
    let scope_obj = scope_value
        .as_object()
        .ok_or_else(|| anyhow!("invalid scope config: {}", scope_id))?;
    scope_obj
        .get(mount_point)
        .and_then(|value| value.as_object())
        .ok_or_else(|| anyhow!("{} not found in scope {}", mount_point, scope_id))
}

fn build_debug_chain_configs(config: &Value, target: &DebugTarget) -> Result<ProcessChainConfigs> {
    match target {
        DebugTarget::GlobalChain { chain_id } => {
            let global = config
                .get("global_process_chains")
                .and_then(|value| value.as_object())
                .ok_or_else(|| anyhow!("global_process_chains not found in config"))?;
            let chain_value = global
                .get(chain_id)
                .ok_or_else(|| anyhow!("global chain not found: {}", chain_id))?;
            let chain = parse_chain_config(chain_id.as_str(), chain_value)?;
            Ok(vec![chain])
        }
        DebugTarget::ScopeHookPoint {
            kind,
            scope_id,
            mount_point,
        } => {
            let hook_point =
                get_scope_hook_point(config, kind, scope_id.as_str(), mount_point.as_str())?;
            let mut chain_list = Vec::with_capacity(hook_point.len());
            for (chain_id, chain_value) in hook_point {
                chain_list.push(parse_chain_config(chain_id.as_str(), chain_value)?);
            }
            Ok(chain_list)
        }
        DebugTarget::ScopeChain {
            kind,
            scope_id,
            mount_point,
            chain_id,
        } => {
            let hook_point =
                get_scope_hook_point(config, kind, scope_id.as_str(), mount_point.as_str())?;
            let chain_value = hook_point
                .get(chain_id)
                .ok_or_else(|| anyhow!("chain not found: {}", chain_id))?;
            let chain = parse_chain_config(chain_id.as_str(), chain_value)?;
            Ok(vec![chain])
        }
        DebugTarget::ScopeBlock {
            kind,
            scope_id,
            mount_point,
            chain_id,
            block_id,
            line_spec,
        } => {
            let hook_point =
                get_scope_hook_point(config, kind, scope_id.as_str(), mount_point.as_str())?;
            let chain_value = hook_point
                .get(chain_id)
                .ok_or_else(|| anyhow!("chain not found: {}", chain_id))?;
            let chain = parse_chain_config(chain_id.as_str(), chain_value)?;
            let chain = filter_chain_for_block(chain, block_id.as_str(), line_spec.as_deref())?;
            Ok(vec![chain])
        }
    }
}

fn merge_debug_chains(
    selected_chains: ProcessChainConfigs,
    global_process_chains: &ProcessChainConfigs,
) -> ProcessChainConfigs {
    let mut merged = selected_chains;
    for global_chain in global_process_chains {
        if merged.iter().any(|chain| chain.id == global_chain.id) {
            continue;
        }
        merged.push(global_chain.clone());
    }
    merged
}

fn resolve_debug_config_file_path(config_file: Option<&str>) -> PathBuf {
    let requested_path = config_file
        .map(PathBuf::from)
        .unwrap_or_else(get_default_config_path);
    let base_dir = std::env::current_dir().unwrap_or(PathBuf::new());
    let resolved_path = if requested_path.is_relative() {
        base_dir.join(requested_path)
    } else {
        requested_path
    };
    let real_config_file = resolved_path.canonicalize().unwrap_or(resolved_path);
    real_config_file
}

fn get_default_config_path() -> PathBuf {
    let mut default_config = get_buckyos_system_etc_dir().join("cyfs_gateway.yaml");
    if !default_config.exists() {
        default_config = get_buckyos_system_etc_dir().join("cyfs_gateway.json");
    }
    default_config.canonicalize().unwrap_or(default_config)
}

async fn get_gateway_remote_config_cache_path() -> PathBuf {
    let cache_dir = get_buckyos_service_data_dir("cyfs_gateway").join("config_cache");
    if !cache_dir.exists() {
        let _ = tokio::fs::create_dir_all(cache_dir.clone()).await;
    }
    cache_dir
}

async fn load_debug_config_from_file(config_file: &Path) -> Result<Value> {
    let config_dir = config_file
        .parent()
        .ok_or_else(|| anyhow!("cannot get config dir: {:?}", config_file))?;
    let cache_dir = get_gateway_remote_config_cache_path().await;
    let config_json = ConfigMerger::load_dir_with_root(config_dir, config_file, None, &cache_dir)
        .await
        .map_err(|e| {
            anyhow!(
                "local config {} failed {:?}",
                config_file.to_string_lossy(),
                e
            )
        })?;
    let mut cmd_config: Value = serde_yaml_ng::from_str(GATEWAY_CONTROL_SERVER_CONFIG)?;
    merge(&mut cmd_config, &config_json);
    let mut config_json = apply_params_to_json(&cmd_config, None)
        .map_err(|e| anyhow!("apply params to config json failed: {}", e))?;
    normalize_all_path_value_config(&mut config_json, config_dir);
    Ok(config_json)
}

fn resolve_req_file_base_dir(req_file: &str) -> PathBuf {
    let requested_path = PathBuf::from(req_file);
    let base_dir = std::env::current_dir().unwrap_or(PathBuf::new());
    let resolved_path = if requested_path.is_relative() {
        base_dir.join(requested_path)
    } else {
        requested_path
    };
    let real_req_file = resolved_path.canonicalize().unwrap_or(resolved_path);
    real_req_file
        .parent()
        .unwrap_or(base_dir.as_path())
        .to_path_buf()
}

#[async_recursion::async_recursion]
async fn json_to_collection_value(
    value: &Value,
    config_base_dir: &Path,
) -> Result<CollectionValue> {
    match value {
        Value::Object(map) => {
            let target = MemoryMapCollection::new_ref();
            for (key, item) in map {
                let item = json_to_collection_value(item, config_base_dir).await?;
                target
                    .insert(key, item)
                    .await
                    .map_err(|e| anyhow!("insert map key {} failed: {}", key, e))?;
            }
            Ok(CollectionValue::Map(target))
        }
        Value::Array(array) => {
            let target = MemorySetCollection::new_ref();
            for item in array {
                let item_str = item.to_string();
                target
                    .insert(item_str.as_str())
                    .await
                    .map_err(|e| anyhow!("insert set item failed: {}", e))?;
            }
            Ok(CollectionValue::Set(target))
        }
        Value::String(s) => {
            let path = PathBuf::from(s);
            let path = if path.is_relative() {
                config_base_dir.join(path)
            } else {
                path
            };
            if path.is_file() {
                let bytes = tokio::fs::read(path.as_path())
                    .await
                    .map_err(|e| anyhow!("read file {} failed: {}", path.to_string_lossy(), e))?;
                let slot = bytes_to_async_stream_slot(bytes).await?;
                return Ok(CollectionValue::Any(Arc::new(slot)));
            }
            Ok(CollectionValue::String(s.clone()))
        }
        Value::Number(n) => Ok(CollectionValue::String(n.to_string())),
        Value::Bool(b) => Ok(CollectionValue::String(b.to_string())),
        Value::Null => Ok(CollectionValue::String(String::new())),
    }
}

async fn bytes_to_async_stream_slot(
    bytes: Vec<u8>,
) -> Result<Arc<Mutex<Option<Box<dyn AsyncStream>>>>> {
    let cap = bytes.len().max(1);
    let (mut writer, reader) = tokio::io::duplex(cap);
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _ = writer.write_all(&bytes).await;
        let _ = writer.shutdown().await;
    });
    let stream: Box<dyn AsyncStream> = Box::new(reader);
    Ok(Arc::new(Mutex::new(Some(stream))))
}

#[async_recursion::async_recursion]
async fn collection_value_to_json(value: CollectionValue) -> Result<Value> {
    match value {
        CollectionValue::Null => Ok(Value::Null),
        CollectionValue::Bool(v) => Ok(Value::Bool(v)),
        CollectionValue::Number(v) => {
            if let Ok(n) = v.to_string().parse::<i64>() {
                Ok(Value::Number(n.into()))
            } else if let Ok(f) = v.to_string().parse::<f64>() {
                if let Some(n) = serde_json::Number::from_f64(f) {
                    Ok(Value::Number(n))
                } else {
                    Ok(Value::String(v.to_string()))
                }
            } else {
                Ok(Value::String(v.to_string()))
            }
        }
        CollectionValue::String(s) => Ok(Value::String(s)),
        CollectionValue::List(list) => {
            let values = list
                .dump()
                .await
                .map_err(|e| anyhow!("dump list failed: {}", e))?;
            let mut output = Vec::with_capacity(values.len());
            for item in values {
                output.push(collection_value_to_json(item).await?);
            }
            Ok(Value::Array(output))
        }
        CollectionValue::Set(set) => {
            let values = set
                .dump()
                .await
                .map_err(|e| anyhow!("dump set failed: {}", e))?;
            Ok(Value::Array(
                values.into_iter().map(Value::String).collect(),
            ))
        }
        CollectionValue::Map(map) => {
            let mut output = Map::new();
            let values = map
                .dump()
                .await
                .map_err(|e| anyhow!("dump map failed: {}", e))?;
            for (key, item) in values {
                output.insert(key, collection_value_to_json(item).await?);
            }
            Ok(Value::Object(output))
        }
        CollectionValue::MultiMap(mmap) => {
            let values = mmap
                .dump()
                .await
                .map_err(|e| anyhow!("dump multi map failed: {}", e))?;
            let mut output = Map::new();
            for (key, value_set) in values {
                output.insert(
                    key,
                    Value::Array(value_set.into_iter().map(Value::String).collect()),
                );
            }
            Ok(Value::Object(output))
        }
        CollectionValue::Visitor(_) => Ok(Value::String("[Visitor]".to_string())),
        CollectionValue::Any(_) => Ok(Value::String("[Any]".to_string())),
    }
}

fn command_result_to_json(result: &CommandResult) -> Value {
    match result {
        CommandResult::Success(value) => json!({
            "type": "success",
            "value": value,
        }),
        CommandResult::Error(value) => json!({
            "type": "error",
            "value": value,
        }),
        CommandResult::Control(control) => match control {
            CommandControl::Return(value) => json!({
                "type": "control",
                "action": "return",
                "level": value.level.as_str(),
                "value": value.value,
            }),
            CommandControl::Error(value) => json!({
                "type": "control",
                "action": "error",
                "level": value.level.as_str(),
                "value": value.value,
            }),
            CommandControl::Exit(value) => json!({
                "type": "control",
                "action": "exit",
                "value": value,
            }),
            CommandControl::Break(value) => json!({
                "type": "control",
                "action": "break",
                "value": value,
            }),
        },
    }
}

async fn execute_debug_once(
    executor: &cyfs_process_chain::ProcessChainLibExecutor,
    hook_point_env: &cyfs_process_chain::HookPointEnv,
    request: &DebugRequestFile,
    req_base_dir: &Path,
) -> Result<Value> {
    let exec = executor.fork();
    let global_env = exec.global_env().clone();

    for (key, value) in &request.input {
        let coll_value = json_to_collection_value(value, req_base_dir).await?;
        global_env
            .create(key.as_str(), coll_value)
            .await
            .map_err(|e| anyhow!("inject input {} failed: {}", key, e))?;
    }

    hook_point_env.pipe().stdout.reset_buffer();
    hook_point_env.pipe().stderr.reset_buffer();

    let run_result = exec
        .execute_lib()
        .await
        .map_err(|e| anyhow!("execute process chain failed: {}", e))?;

    let stdout = hook_point_env.pipe().stdout.clone_string();
    let stderr = hook_point_env.pipe().stderr.clone_string();

    let mut output = Map::new();
    for key in &request.output {
        let value = global_env
            .get(key.as_str())
            .await
            .map_err(|e| anyhow!("read output {} failed: {}", key, e))?;
        match value {
            Some(value) => {
                output.insert(key.clone(), collection_value_to_json(value).await?);
            }
            None => {
                output.insert(key.clone(), Value::Null);
            }
        }
    }

    Ok(json!({
        "control_result": command_result_to_json(&run_result),
        "stdout": stdout,
        "stderr": stderr,
        "output": output,
    }))
}

async fn build_debug_result(
    req_file: &str,
    config_file: Option<&str>,
    id: Option<&str>,
    repeat: usize,
) -> Result<Value> {
    if repeat == 0 {
        return Err(anyhow!("repeat must be greater than 0"));
    }

    let req_content = tokio::fs::read_to_string(req_file).await?;
    let request = serde_json::from_str::<DebugRequestFile>(&req_content)
        .map_err(|e| anyhow!("invalid req_file {}: {}", req_file, e))?;

    let id = id
        .map(|s| s.to_string())
        .or_else(|| request.id.clone())
        .ok_or_else(|| anyhow!("id is required, provide --id or req_file.id"))?;

    let req_base_dir = resolve_req_file_base_dir(req_file);
    let config_file = resolve_debug_config_file_path(config_file);
    let config_json = load_debug_config_from_file(config_file.as_path()).await?;

    let collections = parse_collections_from_raw_config(&config_json)?;
    let global_process_chain_configs = parse_global_process_chains_from_raw_config(&config_json)?;
    let global_collections: GlobalCollectionManagerRef =
        GlobalCollectionManager::create(collections).await?;
    let config_base_dir = config_file
        .parent()
        .ok_or_else(|| anyhow!("cannot get config dir: {}", config_file.to_string_lossy()))?;
    let js_externals: JsExternalsManagerRef =
        build_js_externals_from_raw_config(config_base_dir, &config_json).await?;
    let global_process_chains: GlobalProcessChainsRef =
        build_global_process_chains_from_config(&global_process_chain_configs).await?;

    let target = parse_debug_target(id.as_str())?;
    let chains = build_debug_chain_configs(&config_json, &target)?;
    let chains = merge_debug_chains(chains, &global_process_chain_configs);
    if chains.is_empty() {
        return Err(anyhow!("no process chain selected for id {}", id));
    }

    let (executor, hook_point_env) = create_process_chain_executor(
        &chains,
        Some(global_process_chains),
        Some(global_collections),
        Some(get_external_commands(Weak::new())),
        Some(js_externals),
    )
    .await
    .map_err(|e| anyhow!("create process chain executor failed: {}", e.msg()))?;

    if repeat == 1 {
        return execute_debug_once(&executor, &hook_point_env, &request, req_base_dir.as_path())
            .await;
    }

    let mut results = Vec::with_capacity(repeat);
    for iteration in 0..repeat {
        let mut result =
            execute_debug_once(&executor, &hook_point_env, &request, req_base_dir.as_path())
                .await?;
        if let Some(object) = result.as_object_mut() {
            object.insert("iteration".to_string(), json!(iteration + 1));
        }
        results.push(result);
    }

    Ok(json!({
        "repeat": repeat,
        "results": results,
    }))
}

pub async fn run_debug_command(
    req_file: &str,
    config_file: Option<&str>,
    id: Option<&str>,
    repeat: usize,
) -> Result<()> {
    let result = build_debug_result(req_file, config_file, id, repeat).await?;
    if repeat == 1 {
        if let Some(stdout) = result.get("stdout").and_then(|value| value.as_str()) {
            if !stdout.is_empty() {
                print!("{}", stdout);
            }
        }
        if let Some(stderr) = result.get("stderr").and_then(|value| value.as_str()) {
            if !stderr.is_empty() {
                eprint!("{}", stderr);
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use buckyos_kit::AsyncStream;
    use cyfs_process_chain::CollectionValue;
    use serde_json::json;
    use tokio::io::AsyncReadExt;

    use super::{
        build_debug_result, json_to_collection_value, resolve_req_file_base_dir, run_debug_command,
    };

    fn write_json_temp(value: &serde_json::Value) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let content = serde_json::to_string_pretty(value).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    fn build_test_config(js_path: &str) -> serde_json::Value {
        json!({
            "collections": [],
            "js_externals": {
                "test_ext": js_path
            },
            "global_process_chains": {
                "global_chain": {
                    "priority": 1,
                    "blocks": {
                        "b1": {
                            "priority": 1,
                            "block": "echo \"global\";\necho ${REQ.target_host};"
                        }
                    }
                }
            },
            "stacks": {
                "s1": {
                    "hook_point": {
                        "main": {
                            "priority": 1,
                            "blocks": {
                                "b1": {
                                    "priority": 1,
                                    "block": "echo \"s-line-1\";\necho \"s-line-2\";"
                                }
                            }
                        }
                    }
                }
            },
            "servers": {
                "http1": {
                    "hook_point": {
                        "main": {
                            "priority": 1,
                            "blocks": {
                                "b1": {
                                    "priority": 1,
                                    "block": "echo \"h-line-1\";\necho \"h-line-2\";"
                                }
                            }
                        }
                    },
                    "post_hook_point": {
                        "main": {
                            "priority": 1,
                            "blocks": {
                                "b1": {
                                    "priority": 1,
                                    "block": "echo \"p-line-1\";\necho \"p-line-2\";"
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    fn build_req(id: Option<&str>, output: Vec<&str>) -> serde_json::Value {
        let mut value = json!({
            "input": {
                "REQ": {
                    "target_host": "www.buckyos.com",
                    "path": "/index.html"
                }
            },
            "output": output
        });
        if let Some(id) = id {
            value["id"] = serde_json::Value::String(id.to_string());
        }
        value
    }

    #[tokio::test]
    async fn test_run_debug_command_all_id_targets() {
        let js_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(js_file.path(), "function test_ext() { return true; }").unwrap();
        let config = build_test_config(js_file.path().to_str().unwrap());
        let config_file = write_json_temp(&config);
        let config_path = config_file.path().to_str().unwrap();

        let success_ids = vec![
            "global_chain",
            "global_process_chain:global_chain",
            "stack:s1",
            "stack:s1:hook_point:main",
            "stack:s1:main",
            "stack:s1:main:blocks:b1",
            "stack:s1:main:blocks:b1:2",
            "stack:s1:main:blocks:b1:1:2",
            "server:http1",
            "server:http1:hook_point:main",
            "server:http1:main",
            "server:http1:main:blocks:b1",
            "server:http1:main:blocks:b1:2",
            "server:http1:post_hook_point:main",
            "server:http1:post_hook_point:main:blocks:b1",
        ];

        for id in success_ids {
            let req = build_req(None, vec!["RESP", "NOT_EXIST"]);
            let req_file = write_json_temp(&req);
            let ret = run_debug_command(
                req_file.path().to_str().unwrap(),
                Some(config_path),
                Some(id),
                1,
            )
            .await;
            assert!(ret.is_ok(), "id={} should succeed, got {:?}", id, ret.err());
        }

        let req_with_id = build_req(Some("global_chain"), vec!["RESP"]);
        let req_with_id_file = write_json_temp(&req_with_id);
        let ret = run_debug_command(
            req_with_id_file.path().to_str().unwrap(),
            Some(config_path),
            None,
            1,
        )
        .await;
        assert!(
            ret.is_ok(),
            "req_file.id fallback should succeed: {:?}",
            ret.err()
        );

        let req_missing_id = build_req(None, vec!["RESP"]);
        let req_missing_id_file = write_json_temp(&req_missing_id);
        let err = run_debug_command(
            req_missing_id_file.path().to_str().unwrap(),
            Some(config_path),
            None,
            1,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(err.contains("id is required"), "unexpected error: {}", err);

        let req_empty_output = build_req(Some("global_chain"), vec![]);
        let req_empty_output_file = write_json_temp(&req_empty_output);
        let ret = run_debug_command(
            req_empty_output_file.path().to_str().unwrap(),
            Some(config_path),
            None,
            1,
        )
        .await;
        assert!(
            ret.is_ok(),
            "empty output should be allowed: {:?}",
            ret.err()
        );

        let req_no_output = json!({
            "input": {
                "REQ": {
                    "target_host": "www.buckyos.com",
                    "path": "/index.html"
                }
            },
            "id": "global_chain"
        });
        let req_no_output_file = write_json_temp(&req_no_output);
        let ret = run_debug_command(
            req_no_output_file.path().to_str().unwrap(),
            Some(config_path),
            None,
            1,
        )
        .await;
        assert!(
            ret.is_ok(),
            "missing output should be allowed: {:?}",
            ret.err()
        );

        let req_line_oob = build_req(None, vec!["RESP"]);
        let req_line_oob_file = write_json_temp(&req_line_oob);
        let err = run_debug_command(
            req_line_oob_file.path().to_str().unwrap(),
            Some(config_path),
            Some("stack:s1:main:blocks:b1:1:999"),
            1,
        )
        .await
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("line range out of bounds"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_run_debug_command_loads_all_global_chains_for_cross_chain_exec() {
        let js_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(js_file.path(), "function test_ext() { return true; }").unwrap();

        let config = json!({
            "collections": [],
            "js_externals": {
                "test_ext": js_file.path().to_str().unwrap()
            },
            "global_process_chains": {
                "global_chain": {
                    "priority": 1,
                    "blocks": {
                        "b1": {
                            "priority": 1,
                            "block": "exec --block helper_chain:helper;\necho \"done\";"
                        }
                    }
                },
                "helper_chain": {
                    "priority": 2,
                    "blocks": {
                        "helper": {
                            "priority": 1,
                            "block": "echo \"helper\";"
                        }
                    }
                }
            }
        });
        let config_file = write_json_temp(&config);
        let req = json!({
            "id": "global_chain",
            "input": {},
            "output": []
        });
        let req_file = write_json_temp(&req);

        let ret = run_debug_command(
            req_file.path().to_str().unwrap(),
            Some(config_file.path().to_str().unwrap()),
            None,
            1,
        )
        .await;

        assert!(
            ret.is_ok(),
            "cross-global exec should succeed in debug mode: {:?}",
            ret.err()
        );
    }

    #[tokio::test]
    async fn test_build_debug_result_repeat_rotates_round_robin_within_same_process() {
        let config = json!({
            "collections": [],
            "global_process_chains": {
                "global_chain": {
                    "priority": 1,
                    "blocks": {
                        "b1": {
                            "priority": 1,
                            "block": "forward round_robin http://127.0.0.1:10162 http://127.0.0.1:10163;"
                        }
                    }
                }
            }
        });
        let config_file = write_json_temp(&config);
        let req = json!({
            "id": "global_chain",
            "input": {},
            "output": []
        });
        let req_file = write_json_temp(&req);

        let result = build_debug_result(
            req_file.path().to_str().unwrap(),
            Some(config_file.path().to_str().unwrap()),
            None,
            3,
        )
        .await
        .unwrap();

        let results = result
            .get("results")
            .and_then(|value| value.as_array())
            .expect("repeat result must contain results array");
        assert_eq!(results.len(), 3);

        let selected: Vec<&str> = results
            .iter()
            .map(|item| {
                item.get("control_result")
                    .and_then(|value| value.get("value"))
                    .and_then(|value| value.as_str())
                    .expect("control result should contain selected forward target")
            })
            .collect();

        assert_eq!(selected[0], "forward \"http://127.0.0.1:10162\"");
        assert_eq!(selected[1], "forward \"http://127.0.0.1:10163\"");
        assert_eq!(selected[2], "forward \"http://127.0.0.1:10162\"");
    }

    #[tokio::test]
    async fn test_json_file_value_to_binary_stream_any() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("payload.bin");
        std::fs::write(&file_path, b"abc123").unwrap();

        let value = serde_json::Value::String("payload.bin".to_string());
        let coll = json_to_collection_value(&value, dir.path()).await.unwrap();

        match coll {
            CollectionValue::Any(any) => {
                let slot = any
                    .downcast::<Arc<Mutex<Option<Box<dyn AsyncStream>>>>>()
                    .ok()
                    .unwrap();
                let mut input = slot.lock().unwrap().take().unwrap();
                let mut out = Vec::new();
                input.read_to_end(&mut out).await.unwrap();
                assert_eq!(out, b"abc123");
            }
            _ => panic!("expected Any for file value"),
        }
    }

    #[test]
    fn test_resolve_req_file_base_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        let req_file = dir.path().join("req.json");
        std::fs::write(&req_file, "{}").unwrap();

        let old_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let resolved = resolve_req_file_base_dir("req.json");
        std::env::set_current_dir(old_dir).unwrap();

        let resolved = resolved.canonicalize().unwrap_or(resolved);
        let expected = dir.path().canonicalize().unwrap();
        assert_eq!(resolved, expected);
    }
}
