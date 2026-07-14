#![allow(dead_code)]
#![allow(unused_imports)]

mod acme_sn_provider;
mod config_loader;
mod gateway;

use acme_sn_provider::*;
pub use config_loader::*;
pub use cyfs_gateway_app_lib::{
    merge, run_debug_command, AcmeConfig, AcmeHostConfig, AcmeHttpChallengeServerConfigParser,
    ConfigMerger, CyfsDirServerConfigParser, DirServerConfigParser, DnsServerConfigParser,
    GatewayControlServer, GatewayControlServerConfig, GatewayControlServerConfigParser,
    GatewayControlServerContext, GatewayControlServerFactory, GatewayProcessChainDoc,
    HttpServerConfigParser, LocalDnsConfigParser, QuicStackConfigParser, RtcpStackConfigParser,
    SocksServerConfigParser, TcpStackConfigParser, TlsCA, TlsStackConfigParser,
    TunStackConfigParser, UdpStackConfigParser, GATEWAY_CONTROL_SERVER_CONFIG,
    GATEWAY_CONTROL_SERVER_KEY,
};
pub use cyfs_gateway_lib::{
    cmd_err, into_cmd_err, ControlError, ControlErrorCode, ControlResult, CyfsTokenFactory,
    CyfsTokenVerifier, ExternalCmd, GatewayControlClient, GatewayControlCmdHandler, LoginReq,
    CONTROL_SERVER,
};
pub use gateway::*;

use clap::{Arg, ArgAction, ArgMatches, Command};
use console_subscriber::{self, Server};
use cyfs_dns::{InnerDnsRecordManager, LocalDnsFactory, ProcessChainDnsServerFactory};
use cyfs_gateway_lib::*;
use std::collections::HashSet;

use anyhow::anyhow;
use anyhow::Result;
use buckyos_kit::init_logging;
use buckyos_kit::{get_buckyos_service_data_dir, get_buckyos_system_etc_dir};
use cyfs_sn::SnServerFactory;
use cyfs_socks::SocksServerFactory;
use cyfs_tun::TunStackFactory;
use kRPC::RPCSessionToken;
use log::*;
use name_client::*;
use name_lib::*;
use serde::Deserialize;
use serde_json::Value;
use sfo_js::object::builtins::JsArray;
use sfo_js::{JsEngine, JsPkgManager, JsString, JsValue};
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::create_dir_all;
use tokio::task;
use url::Url;

pub async fn gateway_service_main(config_file: &Path, params: GatewayParams) -> Result<()> {
    let loaded_config = load_config_from_file(config_file).await?;
    debug!(
        "Gateway config: {}",
        serde_json::to_string_pretty(&loaded_config.effective_config).unwrap()
    );

    run_gateway_with_config(
        loaded_config.effective_config,
        Some(loaded_config.user_config),
        Some(config_file),
        params,
    )
    .await
}

async fn run_gateway_with_config(
    config_json: Value,
    user_config_json: Option<Value>,
    config_file: Option<&Path>,
    params: GatewayParams,
) -> Result<()> {
    let config_json = merge_keep_tunnel_into_rtcp_stack_config(config_json, &params.keep_tunnel);
    let parser = Arc::new(GatewayConfigParser::new());
    parser.register_stack_config_parser("tcp", Arc::new(TcpStackConfigParser::new()));
    parser.register_stack_config_parser("udp", Arc::new(UdpStackConfigParser::new()));
    parser.register_stack_config_parser("rtcp", Arc::new(RtcpStackConfigParser::new()));
    parser.register_stack_config_parser("tls", Arc::new(TlsStackConfigParser::new()));
    parser.register_stack_config_parser("quic", Arc::new(QuicStackConfigParser::new()));
    parser.register_stack_config_parser("tun", Arc::new(TunStackConfigParser::new()));

    parser.register_server_config_parser("http", Arc::new(HttpServerConfigParser::new()));
    parser.register_server_config_parser("socks", Arc::new(SocksServerConfigParser::new()));
    parser.register_server_config_parser("dns", Arc::new(DnsServerConfigParser::new()));
    parser.register_server_config_parser("dir", Arc::new(DirServerConfigParser::new()));
    parser.register_server_config_parser("cyfs-dir", Arc::new(CyfsDirServerConfigParser::new()));
    parser.register_server_config_parser(
        "control_server",
        Arc::new(GatewayControlServerConfigParser::new()),
    );
    parser.register_server_config_parser("local_dns", Arc::new(LocalDnsConfigParser::new()));
    parser.register_server_config_parser("sn", Arc::new(SNServerConfigParser::new()));
    parser.register_server_config_parser(
        "acme_response",
        Arc::new(AcmeHttpChallengeServerConfigParser::new()),
    );

    debug!("Parse cyfs-gatway config...");
    let gateway_config = parser.parse(config_json.clone()).map_err(|e| {
        let msg = format!("Error loading config: {}", e.msg());
        error!("{}", msg);
        anyhow::anyhow!(msg)
    })?;
    let init_gateway_config = if let Some(user_config_json) = user_config_json {
        parser.parse(user_config_json).map_err(|e| {
            let msg = format!("Error loading user config: {}", e.msg());
            error!("{}", msg);
            anyhow::anyhow!(msg)
        })?
    } else {
        gateway_config.clone()
    };
    debug!("Parse cyfs-gatway config success");

    let connect_manager = ConnectionManager::new();
    if gateway_config.device_manager.enabled {
        let offline_timeout =
            Duration::from_secs(gateway_config.device_manager.offline_timeout_seconds.max(1));
        let cleanup_interval = Duration::from_secs(
            gateway_config
                .device_manager
                .cleanup_interval_seconds
                .max(1),
        );
        let device_online_db_path =
            get_buckyos_service_data_dir("cyfs_gateway").join("device_online.db");
        let store = SqliteDeviceOnlineStore::new(device_online_db_path)
            .await
            .map_err(|e| anyhow::anyhow!("create sqlite device online store failed: {}", e))?;
        connect_manager.set_device_manager(
            DeviceManager::new(Arc::new(store), offline_timeout, cleanup_interval).await,
        );
        info!(
            "device_manager enabled: offline_timeout={}s cleanup_interval={}s",
            offline_timeout.as_secs(),
            cleanup_interval.as_secs(),
        );
    } else {
        info!("device_manager disabled");
    }

    let tcp_server_runtime = ReuseportServerRuntime::start(ReuseportServerRuntimeConfig::new())
        .map_err(|e| anyhow!("start tcp server runtime failed: {}", e))?;
    let factory = GatewayFactory::new(connect_manager.clone(), parser.clone());
    factory.register_stack_factory(
        StackProtocol::Tcp,
        Arc::new(TcpStackFactory::new(
            connect_manager.clone(),
            tcp_server_runtime.clone(),
        )),
    );
    debug!("Register tcp stack factory");
    factory.register_stack_factory(
        StackProtocol::Udp,
        Arc::new(UdpStackFactory::new(
            connect_manager.clone(),
            tcp_server_runtime.clone(),
        )),
    );
    debug!("Register udp stack factory");
    factory.register_stack_factory(
        StackProtocol::Tls,
        Arc::new(TlsStackFactory::new(
            connect_manager.clone(),
            tcp_server_runtime.clone(),
        )),
    );
    debug!("Register tls stack factory");
    factory.register_stack_factory(
        StackProtocol::Quic,
        Arc::new(QuicStackFactory::new(
            connect_manager.clone(),
            tcp_server_runtime.clone(),
        )),
    );
    factory.register_stack_factory(
        StackProtocol::Rtcp,
        Arc::new(RtcpStackFactory::new(
            connect_manager.clone(),
            tcp_server_runtime.clone(),
        )),
    );
    debug!("Register rtcp stack factory");
    factory.register_stack_factory(
        StackProtocol::Extension("tun".to_string()),
        Arc::new(TunStackFactory::new(
            connect_manager.clone(),
            tcp_server_runtime.clone(),
        )),
    );
    debug!("Register tun stack context factory");
    factory.register_server_factory("http", Arc::new(ProcessChainHttpServerFactory::new()));
    debug!("Register http server factory");
    factory.register_server_factory("dir", Arc::new(DirServerFactory::new()));
    factory.register_server_factory("cyfs-dir", Arc::new(CyfsDirServerFactory::new()));
    debug!("Register cyfs-dir server factory");
    factory.register_server_factory("socks", Arc::new(SocksServerFactory::new()));
    debug!("Register dir server factory");
    factory.register_server_factory("dns", Arc::new(ProcessChainDnsServerFactory::new()));
    debug!("Register dns server factory");
    factory.register_server_factory(
        "acme_response",
        Arc::new(AcmeHttpChallengeServerFactory::new()),
    );
    debug!("Register acme response server factory");
    factory.register_server_factory(
        "control_server",
        Arc::new(GatewayControlServerFactory::new()),
    );
    debug!("Register control server factory");
    factory.register_server_factory("local_dns", Arc::new(LocalDnsFactory::new()));
    debug!("Register local dns server factory");
    factory.register_server_factory("sn", Arc::new(SnServerFactory::new()));
    debug!("Register sn server factory");
    let gateway = factory
        .create_gateway(config_file, gateway_config, init_gateway_config)
        .await
        .map_err(|e| {
            let msg = format!("create gateway failed: {}", e);
            error!("{}", msg);
            anyhow::anyhow!(msg)
        })?;
    gateway.start(params).await?;

    let _ = tokio::signal::ctrl_c().await;

    Ok(())
}

fn merge_keep_tunnel_into_rtcp_stack_config(
    mut config_json: Value,
    keep_tunnels: &[String],
) -> Value {
    if keep_tunnels.is_empty() {
        return config_json;
    }

    let Some(stacks) = config_json.get_mut("stacks").and_then(Value::as_object_mut) else {
        return config_json;
    };

    let mut found_rtcp_stack = false;
    for (stack_id, stack_value) in stacks.iter_mut() {
        let Some(stack_obj) = stack_value.as_object_mut() else {
            continue;
        };
        let Some(protocol) = stack_obj.get("protocol").and_then(Value::as_str) else {
            continue;
        };
        if !protocol.eq_ignore_ascii_case("rtcp") {
            continue;
        }

        found_rtcp_stack = true;
        let keep_tunnel_key = if stack_obj.contains_key("keep-tunnel") {
            "keep-tunnel"
        } else {
            "keep_tunnel"
        };
        let keep_tunnel_value = stack_obj
            .entry(keep_tunnel_key.to_string())
            .or_insert_with(|| Value::Array(vec![]));
        let Some(keep_tunnel_array) = keep_tunnel_value.as_array_mut() else {
            warn!(
                "skip merging keep_tunnel into rtcp stack {}: {} must be an array",
                stack_id, keep_tunnel_key
            );
            continue;
        };
        for keep_tunnel in keep_tunnels {
            let keep_tunnel = keep_tunnel.trim();
            if keep_tunnel.is_empty() {
                continue;
            }
            let keep_tunnel_value = Value::String(keep_tunnel.to_string());
            if !keep_tunnel_array
                .iter()
                .any(|existing| existing == &keep_tunnel_value)
            {
                keep_tunnel_array.push(keep_tunnel_value);
            }
        }
    }

    if !found_rtcp_stack {
        warn!("keep_tunnel specified but no rtcp stack found in config");
    }

    config_json
}

fn get_config_file_path(matches: &clap::ArgMatches) -> PathBuf {
    let default_config = get_default_config_path();
    let config_file = matches.get_one::<String>("config_file");
    let requested_path = if config_file.is_none() {
        default_config
    } else {
        PathBuf::from(config_file.unwrap())
    };
    let base_dir = std::env::current_dir().unwrap_or(PathBuf::new());
    let resolved_path = if requested_path.is_relative() {
        base_dir.join(requested_path)
    } else {
        requested_path
    };
    let real_config_file = resolved_path.canonicalize().unwrap_or(resolved_path);
    let config_dir = if real_config_file.is_dir() {
        real_config_file.clone()
    } else {
        real_config_file
            .parent()
            .unwrap_or(base_dir.as_path())
            .to_path_buf()
    };
    set_gateway_main_config_dir(&config_dir);
    real_config_file
}

fn generate_ed25519_key_pair_to_local() {
    // Get temp path
    let temp_dir = std::env::temp_dir();
    let key_dir = temp_dir.join("buckyos").join("keys");
    if !key_dir.is_dir() {
        std::fs::create_dir_all(&key_dir).unwrap();
    }
    println!("key_dir: {:?}", key_dir);

    let (private_key, public_key) = generate_ed25519_key_pair();

    let sk_file = key_dir.join("private_key.pem");
    std::fs::write(&sk_file, private_key).unwrap();
    println!("Private key saved to: {:?}", sk_file);

    let pk_file = key_dir.join("public_key.json");
    std::fs::write(&pk_file, serde_json::to_string(&public_key).unwrap()).unwrap();
    println!("Public key saved to: {:?}", pk_file);
}

pub fn read_login_token(server: &str) -> Option<String> {
    let data_dir = get_buckyos_service_data_dir("cyfs_gateway").join("token_key");
    let token_dir = get_buckyos_service_data_dir("cyfs_gateway").join("cli_token");
    if !token_dir.exists() {
        let _ = create_dir_all(token_dir.as_path());
    }

    if server.to_lowercase() == CONTROL_SERVER {
        let private_key = data_dir.join("private_key.pem");
        let encode_key = match load_private_key(private_key.as_path()) {
            Ok(key) => key,
            Err(e) => {
                error!("load private key failed: {}", e);
                return None;
            }
        };

        let (token, _) =
            match RPCSessionToken::generate_jwt_token("root", "cyfs-gateway", None, &encode_key) {
                Ok(token) => token,
                Err(e) => {
                    error!("generate jwt token failed: {}", e);
                    return None;
                }
            };
        Some(token)
    } else {
        let token_file = token_dir.join(hex::encode(server.to_lowercase()));
        match std::fs::read_to_string(token_file) {
            Ok(token) => Some(token),
            Err(e) => {
                error!("read token file failed: {}", e);
                None
            }
        }
    }
}

fn save_login_token(server: &str, token: &str) {
    if server.to_lowercase() == CONTROL_SERVER {
        return;
    }
    let token_dir = get_buckyos_service_data_dir("cyfs_gateway").join("cli_token");
    let token_file = token_dir.join(hex::encode(server.to_lowercase()));
    let _ = std::fs::write(token_file, token);
}

struct StartTemplateArgs {
    template_id: Option<String>,
    args: Vec<String>,
    help: bool,
}

#[derive(Debug, Deserialize)]
struct ToolConfig {
    description: Option<String>,
    script: String,
    #[serde(default, alias = "platfroms")]
    platforms: Option<Vec<String>>,
}

#[derive(Debug)]
struct LocalToolCommand {
    name: String,
    description: String,
    platforms: Option<Vec<String>>,
    tool_dir: PathBuf,
    script_path: PathBuf,
}

fn parse_os_release_value(line: &str, key: &str) -> Option<String> {
    let (k, v) = line.split_once('=')?;
    if k != key {
        return None;
    }
    Some(v.trim_matches('"').to_ascii_lowercase())
}

fn detect_platform_tags() -> HashSet<String> {
    let mut tags = HashSet::new();
    let os = std::env::consts::OS.to_ascii_lowercase();
    tags.insert(os.clone());

    match os.as_str() {
        "windows" => {
            tags.insert("win32".to_string());
            tags.insert("win".to_string());
        }
        "macos" => {
            tags.insert("darwin".to_string());
            tags.insert("osx".to_string());
        }
        "linux" => {
            if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
                for line in content.lines() {
                    if let Some(id) = parse_os_release_value(line, "ID") {
                        if !id.is_empty() {
                            tags.insert(id);
                        }
                        continue;
                    }
                    if let Some(id_like) = parse_os_release_value(line, "ID_LIKE") {
                        for item in id_like.split_whitespace() {
                            let item = item.trim();
                            if !item.is_empty() {
                                tags.insert(item.to_string());
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }

    tags
}

fn is_tool_supported(platforms: &Option<Vec<String>>, tags: &HashSet<String>) -> bool {
    match platforms {
        None => true,
        Some(list) if list.is_empty() => true,
        Some(list) => list
            .iter()
            .any(|platform| tags.contains(&platform.to_ascii_lowercase())),
    }
}

fn script_extension(script_path: &Path) -> String {
    script_path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .unwrap_or_default()
}

fn is_script_supported_on_current_os(script_path: &Path) -> bool {
    let ext = script_extension(script_path);
    let is_windows = std::env::consts::OS == "windows";

    if is_windows {
        return ext == "bat" || ext == "cmd";
    }

    ext != "bat" && ext != "cmd"
}

fn load_local_tools() -> Vec<LocalToolCommand> {
    let tools_dir = get_buckyos_system_etc_dir()
        .join("cyfs_gateway")
        .join("tools");
    let platform_tags = detect_platform_tags();
    let mut tools = Vec::new();

    let entries = match std::fs::read_dir(&tools_dir) {
        Ok(entries) => entries,
        Err(_) => {
            return tools;
        }
    };

    for entry in entries.flatten() {
        let tool_dir = entry.path();
        if !tool_dir.is_dir() {
            continue;
        }

        let tool_name = match tool_dir.file_name().and_then(|name| name.to_str()) {
            Some(name) if !name.is_empty() => name.to_string(),
            _ => continue,
        };

        let config_path = tool_dir.join("config.yaml");
        if !config_path.is_file() {
            continue;
        }

        let config_text = match std::fs::read_to_string(&config_path) {
            Ok(text) => text,
            Err(e) => {
                warn!("read tool config failed {}: {}", config_path.display(), e);
                continue;
            }
        };

        let config: ToolConfig = match serde_yaml_ng::from_str(&config_text) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!("parse tool config failed {}: {}", config_path.display(), e);
                continue;
            }
        };

        if !is_tool_supported(&config.platforms, &platform_tags) {
            continue;
        }

        let script = config.script.trim();
        if script.is_empty() {
            warn!("tool script is empty: {}", config_path.display());
            continue;
        }

        let script_path = tool_dir.join(script);
        if !script_path.exists() {
            warn!("tool script not found: {}", script_path.display());
            continue;
        }

        if !is_script_supported_on_current_os(&script_path) {
            continue;
        }

        tools.push(LocalToolCommand {
            name: tool_name,
            description: config.description.unwrap_or_default(),
            platforms: config.platforms,
            tool_dir,
            script_path,
        });
    }

    tools.sort_by(|a, b| a.name.cmp(&b.name));
    tools
}

fn build_command_with_local_tools_for_help(
    command: &Command,
    tools: &[LocalToolCommand],
) -> Command {
    let mut merged = command.clone();
    for tool in tools {
        if is_builtin_subcommand(&merged, tool.name.as_str()) {
            continue;
        }

        let mut sub = Command::new(tool.name.clone());
        if !tool.description.is_empty() {
            sub = sub.about(tool.description.clone());
        }
        merged = merged.subcommand(sub);
    }
    merged
}

fn infer_top_level_command_from_args(args: &[String]) -> Option<(String, usize)> {
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];

        if arg == "--" {
            if index + 1 < args.len() {
                return Some((args[index + 1].clone(), index + 1));
            }
            return None;
        }

        if arg == "--config" || arg == "--config_file" {
            index += 2;
            continue;
        }

        if arg == "--keep_tunnel" {
            index += 1;
            while index < args.len() && !args[index].starts_with('-') {
                index += 1;
            }
            continue;
        }

        if arg == "--help"
            || arg == "-h"
            || arg == "--debug"
            || arg.starts_with("--config=")
            || arg.starts_with("--config_file=")
            || arg.starts_with("--keep_tunnel=")
        {
            index += 1;
            continue;
        }

        if arg.starts_with('-') {
            index += 1;
            continue;
        }

        return Some((arg.clone(), index));
    }

    None
}

fn run_local_tool(tool: &LocalToolCommand, args: &[String]) -> Result<i32> {
    let platform_tags = detect_platform_tags();
    if !is_tool_supported(&tool.platforms, &platform_tags) {
        return Err(anyhow!(
            "tool '{}' is not supported on current platform",
            tool.name
        ));
    }

    if !is_script_supported_on_current_os(&tool.script_path) {
        let ext = script_extension(&tool.script_path);
        if std::env::consts::OS == "windows" {
            return Err(anyhow!(
                "tool script type '.{}' is not supported on windows (only .bat/.cmd are supported)",
                if ext.is_empty() { "" } else { ext.as_str() }
            ));
        }
        return Err(anyhow!(
            "tool script type '.{}' is only supported on windows",
            if ext.is_empty() { "" } else { ext.as_str() }
        ));
    }

    let ext = script_extension(&tool.script_path);
    if std::env::consts::OS == "windows" {
        let status = ProcessCommand::new("cmd")
            .arg("/C")
            .arg(&tool.script_path)
            .args(args)
            .current_dir(&tool.tool_dir)
            .status()
            .map_err(|e| anyhow!("run tool failed {}: {}", tool.script_path.display(), e))?;
        return Ok(status.code().unwrap_or(1));
    }

    if ext == "bat" || ext == "cmd" {
        return Err(anyhow!(
            "tool script type '.{}' is only supported on windows",
            ext
        ));
    }

    if ext == "sh" {
        let direct_status = ProcessCommand::new(&tool.script_path)
            .args(args)
            .current_dir(&tool.tool_dir)
            .status();

        match direct_status {
            Ok(status) => return Ok(status.code().unwrap_or(1)),
            Err(_) => {
                let status = ProcessCommand::new("bash")
                    .arg(&tool.script_path)
                    .args(args)
                    .current_dir(&tool.tool_dir)
                    .status()
                    .map_err(|e| {
                        anyhow!("run tool failed {}: {}", tool.script_path.display(), e)
                    })?;
                return Ok(status.code().unwrap_or(1));
            }
        }
    }

    let direct_status = ProcessCommand::new(&tool.script_path)
        .args(args)
        .current_dir(&tool.tool_dir)
        .status();

    match direct_status {
        Ok(status) => Ok(status.code().unwrap_or(1)),
        Err(e) => Err(anyhow!(
            "run tool failed {}: {}",
            tool.script_path.display(),
            e
        )),
    }
}

fn is_builtin_subcommand(command: &Command, cmd: &str) -> bool {
    command
        .get_subcommands()
        .any(|subcommand| subcommand.get_name() == cmd)
}

fn infer_subcommand_path_from_args(command: &Command, args: &[String]) -> Vec<String> {
    let mut path = Vec::new();
    let mut current = command;

    for arg in args {
        if arg == "--help" || arg == "-h" {
            break;
        }
        if arg.starts_with('-') {
            continue;
        }
        if let Some(sub_cmd) = current
            .get_subcommands()
            .find(|sub| sub.get_name() == arg.as_str())
        {
            path.push(arg.clone());
            current = sub_cmd;
        }
    }

    path
}

fn parse_server_arg_after_command(command: &str) -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut seen = false;
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        if !seen {
            if arg == command {
                seen = true;
            }
            continue;
        }

        if arg == "--server" || arg == "-s" {
            if let Some(server) = iter.next() {
                return server;
            }
            break;
        }
        if let Some(server) = arg.strip_prefix("--server=") {
            return server.to_owned();
        }
        if let Some(server) = arg.strip_prefix("-s=") {
            return server.to_owned();
        }
    }

    CONTROL_SERVER.to_owned()
}

fn print_help_for_subcommand_path(command: &mut Command, path: &[String]) -> bool {
    let mut current = command;
    for name in path {
        if let Some(sub_cmd) = current.find_subcommand_mut(name) {
            current = sub_cmd;
        } else {
            return false;
        }
    }
    current.print_help().unwrap();
    println!();
    true
}

fn parse_template_args(command: &str, ignore_server: bool) -> StartTemplateArgs {
    let mut args = Vec::new();
    let mut seen_start = false;
    for arg in std::env::args() {
        if seen_start {
            args.push(arg);
        } else if arg == command {
            seen_start = true;
        }
    }

    let mut filtered = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if !ignore_server {
            filtered.push(arg);
            continue;
        }
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg == "--server" || arg == "-s" {
            skip_next = true;
            continue;
        }
        if arg.starts_with("--server=") || arg.starts_with("-s=") {
            continue;
        }
        filtered.push(arg);
    }

    let mut help = false;
    let mut template_id = None;
    let mut template_args = Vec::new();
    for arg in filtered {
        if arg == "--help" || arg == "-h" {
            help = true;
            continue;
        }
        if template_id.is_none() && !arg.starts_with('-') {
            template_id = Some(arg);
        } else if template_id.is_some() {
            template_args.push(arg);
        }
    }

    StartTemplateArgs {
        template_id,
        args: template_args,
        help,
    }
}

async fn run_template_local(template_id: &str, args: Vec<String>) -> Result<()> {
    let template_dir = get_buckyos_system_etc_dir()
        .join("cyfs_gateway")
        .join("server_templates");
    let external_cmds = JsPkgManager::new(template_dir);
    let pkg = external_cmds
        .get_pkg(template_id)
        .await
        .map_err(|e| anyhow!("get pkg failed: {:?}", e))?;
    let output = run_server_tempalte_pkg(pkg, args).await.map_err(|e| {
        let msg = format!("run template failed: {}", e);
        error!("{}", msg);
        anyhow!(msg)
    })?;
    let output = output.trim();
    if output.is_empty() {
        return Err(anyhow!("template returned empty config"));
    }
    let template_config: Value =
        serde_json::from_str(output).map_err(|e| anyhow!("invalid template config: {}", e))?;
    let mut config_json = buckyos_kit::apply_params_to_json(&template_config, None)
        .map_err(|e| anyhow!("apply params failed: {}", e))?;
    let config_dir =
        std::env::current_dir().map_err(|e| anyhow!("read current dir failed: {}", e))?;
    normalize_all_path_value_config(&mut config_json, config_dir.as_path());
    run_gateway_with_config(
        config_json,
        None,
        None,
        GatewayParams {
            keep_tunnel: vec![],
        },
    )
    .await
}

pub async fn web3_gateway_main() {
    let mut command = Command::new("Web3 Gateway Service")
        .version(buckyos_kit::get_version())
        .disable_help_flag(true)
        .disable_help_subcommand(true)
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .help("Show help information")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("config")
                .long("config")
                .help("config in json format")
                .required(false),
        )
        .arg(
            Arg::new("config_file")
                .long("config_file")
                .help("config file path file with json format content")
                .required(false),
        )
        .arg(
            Arg::new("keep_tunnel")
                .long("keep_tunnel")
                .help("keep tunnel when start")
                .num_args(1..),
        )
        .arg(
            Arg::new("debug")
                .long("debug")
                .help("enable debug mode")
                .action(ArgAction::SetTrue),
        )
        .subcommand(Command::new("gen_rtcp_key")
            .about("Generate a new rtcp key pair")
            .arg(Arg::new("name")
                .long("name")
                .short('n')
                .help("rtcp name")
                .required(true))
            .arg(Arg::new("path")
                .long("path")
                .short('p')
                .help("The save path of the generated key")
                .required(false)))
        .subcommand(Command::new("login")
            .about("Login to server")
            .arg(Arg::new("user")
                .long("user")
                .short('u')
                .help("user name")
                .required(true))
            .arg(Arg::new("password")
                .long("password")
                .short('p')
                .help("password")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("show")
            .about("Show config")
            .arg(Arg::new("id")
                .help("config id")
                .required(false))
            .arg(Arg::new("format")
                .long("format")
                .short('f')
                .help("Show format, optional json | yaml")
                .required(false)
                .default_value("yaml"))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER))
            .subcommand(Command::new("config")
                .about("Show init config")
                .arg(Arg::new("format")
                    .long("format")
                    .short('f')
                    .help("Show format, optional json | yaml")
                    .required(false)
                    .default_value("yaml"))
                .arg(Arg::new("server")
                    .long("server")
                    .short('s')
                    .help("server url")
                    .required(false)
                    .default_value(CONTROL_SERVER))))
        .subcommand(Command::new("save")
            .about("Save current config to device")
            .arg(Arg::new("config")
                .long("config")
                .short('c')
                .help("save path")
                .required(false))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("show_connections")
            .about("Show current connections")
            .arg(Arg::new("format")
                .long("format")
                .short('f')
                .help("Show format, optional json | yaml")
                .required(false)
                .default_value("yaml"))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("show_connection_devices")
            .about("Show current connection devices")
            .arg(Arg::new("format")
                .long("format")
                .short('f')
                .help("Show format, optional json | yaml")
                .required(false)
                .default_value("yaml"))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("add_rule")
            .about("Add a rule")
            .after_help("Examples:\n  cyfs_gateway add_rule stack:s1:main \"http-probe && call-server www;\"")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("rule")
                .help("rule content")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("append_rule")
            .about("Append a rule with lowest priority")
            .after_help("Examples:\n  cyfs_gateway append_rule stack:s1:main \"eq ${REQ.host} \\\"a.com\\\" && call-server a;\"")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("rule")
                .help("rule content")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("insert_rule")
            .about("Insert a rule at specific position/priority")
            .after_help("Examples:\n  cyfs_gateway insert_rule stack:s1:main 2 \"rewrite /old /new;\"")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("pos")
                .help("priority or line position")
                .required(true))
            .arg(Arg::new("rule")
                .help("rule content")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("move_rule")
            .about("Move a chain/block/rule to a new position or priority")
            .after_help("Examples:\n  cyfs_gateway move_rule stack:s1:main 1\n  cyfs_gateway move_rule stack:s1:main:b1:2 3")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("new_pos")
                .help("new priority or line position")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("set_rule")
            .about("Replace a chain/block/line rule content")
            .after_help("Examples:\n  cyfs_gateway set_rule stack:s1:main:b1 \"forward \\\"tcp:///1.1.1.1:80\\\";\"\n  cyfs_gateway set_rule stack:s1:main:b1:2 \"rewrite /old /new;\"")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("rule")
                .help("new rule content")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("add-name-provider")
            .about("Add a name-client HTTP/HTTPS resolver provider")
            .after_help("Examples:\n  cyfs_gateway add-name-provider http://127.0.0.1:8080\n  cyfs_gateway add-name-provider https://resolver.example.com --trust-level 100")
            .arg(Arg::new("url")
                .help("provider base url, scheme://host[:port]")
                .required(true))
            .arg(Arg::new("trust_level")
                .long("trust-level")
                .help("provider trust level, lower number has higher priority")
                .required(false))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("add_dispatch")
            .about("Add a local port dispatch to target")
            .after_help("Examples:\n  cyfs_gateway add_dispatch 18080 192.168.0.1:1900\n  cyfs_gateway add_dispatch 0.0.0.0:8080 10.0.0.1:9000 --protocol udp")
            .arg(Arg::new("local")
                .help("local endpoint, such as 18080 or 0.0.0.0:18080")
                .required(true))
            .arg(Arg::new("target")
                .help("target endpoint, ip:port format")
                .required(true))
            .arg(Arg::new("protocol")
                .long("protocol")
                .short('p')
                .help("tcp or udp, default tcp")
                .required(false))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("remove_dispatch")
            .about("Remove a local port dispatch")
            .after_help("Examples:\n  cyfs_gateway remove_dispatch 18080\n  cyfs_gateway remove_dispatch 0.0.0.0:8080 --protocol udp")
            .arg(Arg::new("local")
                .help("local endpoint, such as 18080 or 0.0.0.0:18080")
                .required(true))
            .arg(Arg::new("protocol")
                .long("protocol")
                .short('p')
                .help("tcp or udp, default tcp")
                .required(false))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("add_router")
            .about("Add a router rule to http server")
            .after_help("Examples:\n  cyfs_gateway add_router --uri /sn --target /www\n  cyfs_gateway add_router --uri /api --target http://127.0.0.1:9000/ --id server:api:main")
            .arg(Arg::new("id")
                .long("id")
                .help("rule id (same format as add_rule, e.g. server:<id>:<chain>[:blocks:<block>]), optional; if missing will create router_<rand>")
                .required(false))
            .arg(Arg::new("uri")
                .long("uri")
                .help("uri match rule, supports =/path, /path (prefix), /path/*, ~regex")
                .required(true))
            .arg(Arg::new("target")
                .long("target")
                .help("target mapping, supports dir path or http(s) url")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("remove_router")
            .about("Remove a router rule from http server")
            .after_help("Examples:\n  cyfs_gateway remove_router --id api_router --uri /api --target http://127.0.0.1:9000/")
            .arg(Arg::new("id")
                .long("id")
                .help("rule id (same format as add_rule, optional if unique match can be found)")
                .required(false))
            .arg(Arg::new("uri")
                .long("uri")
                .help("uri match rule used when adding router")
                .required(true))
            .arg(Arg::new("target")
                .long("target")
                .help("target mapping used when adding router")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("remove_rule")
            .about("Delete a rule")
            .after_help("Examples:\n  cyfs_gateway remove_rule stack:s1:main:b1\n  cyfs_gateway remove_rule stack:s1:main:b1:2")
            .arg(Arg::new("id")
                .help("rule id")
                .required(true))
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER))
        )
        .subcommand(Command::new("start")
            .allow_external_subcommands(true)
            .allow_missing_positional(true)
            .ignore_errors(true)
            .about("start a new server")
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("run")
            .allow_external_subcommands(true)
            .allow_missing_positional(true)
            .ignore_errors(true)
            .about("run a server template locally"))
        .subcommand(Command::new("process_chain")
            .about("Show process chain command help")
            .arg(Arg::new("command")
                .help("process chain command name")
                .required(false))
            .arg(Arg::new("all")
                .long("all")
                .short('a')
                .help("show full documentation for all commands")
                .action(ArgAction::SetTrue))
            .arg(Arg::new("file")
                .long("file")
                .short('f')
                .help("write output to file")
                .value_name("PATH")
                .required(false)))
        .subcommand(Command::new("collection")
            .about("Operate global collections")
            .subcommand(Command::new("list")
                .about("List global collections")
                .arg(Arg::new("server")
                    .long("server")
                    .short('s')
                    .help("server url")
                    .required(false)
                    .default_value(CONTROL_SERVER)))
            .subcommand(Command::new("get")
                .about("Get collection items")
                .arg(Arg::new("name")
                    .help("collection name")
                    .required(true))
                .arg(Arg::new("key")
                    .help("map key, optional")
                    .required(false))
                .arg(Arg::new("server")
                    .long("server")
                    .short('s')
                    .help("server url")
                    .required(false)
                    .default_value(CONTROL_SERVER)))
            .subcommand(Command::new("set-add")
                .about("Add an item to a set collection")
                .arg(Arg::new("name")
                    .help("set collection name")
                    .required(true))
                .arg(Arg::new("value")
                    .help("value to add")
                    .required(true))
                .arg(Arg::new("server")
                    .long("server")
                    .short('s')
                    .help("server url")
                    .required(false)
                    .default_value(CONTROL_SERVER)))
            .subcommand(Command::new("set-del")
                .about("Delete an item from a set collection")
                .arg(Arg::new("name")
                    .help("set collection name")
                    .required(true))
                .arg(Arg::new("value")
                    .help("value to delete")
                    .required(true))
                .arg(Arg::new("server")
                    .long("server")
                    .short('s')
                    .help("server url")
                    .required(false)
                    .default_value(CONTROL_SERVER)))
            .subcommand(Command::new("map-put")
                .about("Put a key-value in a map collection")
                .arg(Arg::new("name")
                    .help("map collection name")
                    .required(true))
                .arg(Arg::new("key")
                    .help("map key")
                    .required(true))
                .arg(Arg::new("value")
                    .help("value to put")
                    .required(true))
                .arg(Arg::new("json")
                    .long("json")
                    .help("parse value as JSON before storing")
                    .action(ArgAction::SetTrue))
                .arg(Arg::new("server")
                    .long("server")
                    .short('s')
                    .help("server url")
                    .required(false)
                    .default_value(CONTROL_SERVER)))
            .subcommand(Command::new("map-del")
                .about("Delete a key from a map collection")
                .arg(Arg::new("name")
                    .help("map collection name")
                    .required(true))
                .arg(Arg::new("key")
                    .help("map key")
                    .required(true))
                .arg(Arg::new("server")
                    .long("server")
                    .short('s')
                    .help("server url")
                    .required(false)
                    .default_value(CONTROL_SERVER))))
        .subcommand(Command::new("debug")
            .about("Debug process chain rule with request file")
            .arg(Arg::new("config_file")
                .long("config_file")
                .help("config file path, optional; uses default config if omitted")
                .required(false))
            .arg(Arg::new("req_file")
                .long("req_file")
                .help("request file path in JSON format")
                .required(true))
            .arg(Arg::new("id")
                .long("id")
                .help("rule id to debug; if omitted, use id field from req_file")
                .required(false))
            .arg(Arg::new("repeat")
                .long("repeat")
                .help("execute the same debug request multiple times in one process")
                .required(false)
                .value_parser(clap::value_parser!(usize))
                .default_value("1")))
        .subcommand(Command::new("reload")
            .about("reload config")
            .arg(Arg::new("server")
                .long("server")
                .short('s')
                .help("server url")
                .required(false)
                .default_value(CONTROL_SERVER)))
        .subcommand(Command::new("help")
            .about("Show help for a command or subcommand")
            .arg(
                Arg::new("subcommand")
                    .help("Subcommand to display help for")
                    .required(false),
            ));

    let local_tools = load_local_tools();
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let help_requested = raw_args.iter().any(|arg| arg == "--help" || arg == "-h");
    if help_requested {
        let subcommand_path = infer_subcommand_path_from_args(&command, &raw_args);

        if subcommand_path.is_empty() {
            if let Some((candidate_cmd, cmd_index)) = infer_top_level_command_from_args(&raw_args) {
                if !is_builtin_subcommand(&command, candidate_cmd.as_str()) {
                    if let Some(tool) = local_tools.iter().find(|tool| tool.name == candidate_cmd) {
                        let tool_args = raw_args.get(cmd_index + 1..).unwrap_or(&[]).to_vec();
                        match run_local_tool(tool, &tool_args) {
                            Ok(code) => std::process::exit(code),
                            Err(e) => {
                                println!("{}", e);
                                std::process::exit(1);
                            }
                        }
                    }
                }
            }
        }

        if subcommand_path.is_empty() {
            let mut help_command = build_command_with_local_tools_for_help(&command, &local_tools);
            help_command.print_help().unwrap();
            std::process::exit(0);
        }

        if subcommand_path.first().map(|s| s.as_str()) == Some("start") {
            let start_args = parse_template_args("start", true);
            let server = parse_server_arg_after_command("start");
            if start_args.template_id.is_none() {
                let _ = print_help_for_subcommand_path(&mut command, &subcommand_path);
                let cyfs_cmd_client =
                    GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                match cyfs_cmd_client.get_external_cmds().await {
                    Ok(cmds) => {
                        println!("Available templates ({}):", cmds.len());
                        for cmd in cmds {
                            if cmd.description.is_empty() {
                                println!("  {}", cmd.name);
                            } else {
                                println!("  {} - {}", cmd.name, cmd.description);
                            }
                        }
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("start template list error: {}", e);
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }

            if let Some(template_id) = start_args.template_id {
                let cyfs_cmd_client =
                    GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                match cyfs_cmd_client
                    .get_external_cmd_help(template_id.as_str())
                    .await
                {
                    Ok(help) => {
                        println!("{}", help);
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("start template help error: {}", e);
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }
        }

        if !print_help_for_subcommand_path(&mut command, &subcommand_path) {
            let mut help_command = build_command_with_local_tools_for_help(&command, &local_tools);
            help_command.print_help().unwrap();
            println!();
        }
        std::process::exit(0);
    }

    if let Some((candidate_cmd, cmd_index)) = infer_top_level_command_from_args(&raw_args) {
        if !is_builtin_subcommand(&command, candidate_cmd.as_str()) {
            if let Some(tool) = local_tools.iter().find(|tool| tool.name == candidate_cmd) {
                let tool_args = raw_args.get(cmd_index + 1..).unwrap_or(&[]).to_vec();
                match run_local_tool(tool, &tool_args) {
                    Ok(code) => std::process::exit(code),
                    Err(e) => {
                        println!("{}", e);
                        std::process::exit(1);
                    }
                }
            }
        }
    }

    let matches = command.clone().get_matches();
    let is_service = matches.subcommand().is_none();

    init_logging("", is_service);

    match matches.subcommand() {
        Some(("help", sub_matches)) => {
            if let Some(sub_name) = sub_matches.get_one::<String>("subcommand") {
                if let Some(sub_cmd) = command.find_subcommand_mut(sub_name) {
                    sub_cmd.print_help().unwrap();
                    println!();
                } else {
                    let cyfs_cmd_client =
                        GatewayControlClient::new(CONTROL_SERVER, read_login_token(CONTROL_SERVER));
                    if let Ok(help) = cyfs_cmd_client.get_external_cmd_help(sub_name).await {
                        println!("{}", help);
                    } else {
                        println!("Unknown command: {}", sub_name);
                    }
                }
            } else {
                let mut help_command =
                    build_command_with_local_tools_for_help(&command, &local_tools);
                help_command.print_help().unwrap();
                println!();
            }
            std::process::exit(0);
        }
        Some(("gen_rtcp_key", sub_matches)) => {
            let name = sub_matches
                .get_one::<String>("name")
                .expect("Missing key 'name'");
            // Get temp path
            let temp_dir = std::env::temp_dir();
            let key_dir = temp_dir.join("buckyos").join("keys");
            let default_path = key_dir.to_string_lossy().to_string();
            let save_path = sub_matches
                .get_one::<String>("path")
                .unwrap_or(&default_path);
            let key_dir = Path::new(save_path);
            if !key_dir.is_dir() {
                std::fs::create_dir_all(&key_dir).unwrap();
            }
            println!("key_dir: {:?}", key_dir);

            let (private_key, public_key) = generate_ed25519_key_pair();
            let device_config =
                DeviceConfig::new_by_jwk(name, serde_json::from_value(public_key).unwrap());
            let sk_file = key_dir.join("device.key.pem");
            std::fs::write(&sk_file, private_key).unwrap();
            println!("Private key saved to: {:?}", sk_file);

            let pk_file = key_dir.join("device.doc.json");
            std::fs::write(&pk_file, serde_json::to_string(&device_config).unwrap()).unwrap();
            println!("Device doc saved to: {:?}", pk_file);
            std::process::exit(0);
        }
        Some(("login", sub_matches)) => {
            let user = sub_matches.get_one::<String>("user").unwrap();
            let password = sub_matches.get_one::<String>("password").unwrap();
            let server = sub_matches.get_one::<String>("server").unwrap();
            if server.to_lowercase() == CONTROL_SERVER {
                std::process::exit(0);
            }
            let cyfs_cmd_client = GatewayControlClient::new(server.as_str(), None);
            let login_result = match cyfs_cmd_client.login(user, password).await {
                Ok(result) => result,
                Err(e) => {
                    println!("{}", e.msg());
                    std::process::exit(1);
                }
            };
            save_login_token(server.as_str(), login_result.as_str());
        }
        Some(("show", sub_matches)) => match sub_matches.subcommand() {
            Some(("config", config_matches)) => {
                let format = config_matches.get_one::<String>("format").unwrap();
                let server = config_matches.get_one::<String>("server").unwrap();
                let cyfs_cmd_client =
                    GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                match cyfs_cmd_client.get_init_config().await {
                    Ok(result) => {
                        if format == "json" {
                            println!("{}", serde_json::to_string_pretty(&result).unwrap());
                        } else {
                            println!("{}", serde_yaml_ng::to_string(&result).unwrap());
                        }
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e.msg());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }
            None => {
                let id = sub_matches.get_one::<String>("id");
                let format = sub_matches.get_one::<String>("format").unwrap();
                let server = sub_matches.get_one::<String>("server").unwrap();
                let cyfs_cmd_client =
                    GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                let result = cyfs_cmd_client
                    .get_config_by_id(id.map(|value| value.as_str()))
                    .await;
                match result {
                    Ok(result) => {
                        if format == "json" {
                            println!("{}", serde_json::to_string_pretty(&result).unwrap());
                        } else {
                            println!("{}", serde_yaml_ng::to_string(&result).unwrap());
                        }
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e.msg());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }
            _ => {}
        },
        Some(("save", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            let path = sub_matches.get_one::<String>("config");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.save_config(path.map(|s| s.as_str())).await {
                Ok(result) => {
                    if let Some(path) = result.as_str() {
                        println!("config saved: {}", path);
                    } else {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    }
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("show_connections", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            let format = sub_matches.get_one::<String>("format").unwrap();
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.get_connections().await {
                Ok(result) => {
                    if format == "json" {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    } else {
                        println!("{}", serde_yaml_ng::to_string(&result).unwrap());
                    }
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("show_connection_devices", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            let format = sub_matches.get_one::<String>("format").unwrap();
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.get_connection_devices().await {
                Ok(result) => {
                    if format == "json" {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    } else {
                        println!("{}", serde_yaml_ng::to_string(&result).unwrap());
                    }
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("remove_rule", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").expect("id is required");
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.remove_rule(id).await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("add_rule", sub_matches)) => {
            let config_type = sub_matches.get_one::<String>("id").expect("id is required");
            let config_id = sub_matches
                .get_one::<String>("rule")
                .expect("rule is required");
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.add_rule(config_type, config_id).await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("append_rule", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").expect("id is required");
            let rule = sub_matches
                .get_one::<String>("rule")
                .expect("rule is required");
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.append_rule(id, rule).await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("insert_rule", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").expect("id is required");
            let pos = sub_matches
                .get_one::<String>("pos")
                .expect("pos is required");
            let rule = sub_matches
                .get_one::<String>("rule")
                .expect("rule is required");
            let pos: i32 = pos.parse().expect("pos must be integer");
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.insert_rule(id, pos, rule).await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("move_rule", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").expect("id is required");
            let pos = sub_matches
                .get_one::<String>("new_pos")
                .expect("new_pos is required");
            let pos: i32 = pos.parse().expect("new_pos must be integer");
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.move_rule(id, pos).await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("set_rule", sub_matches)) => {
            let id = sub_matches.get_one::<String>("id").expect("id is required");
            let rule = sub_matches
                .get_one::<String>("rule")
                .expect("rule is required");
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.set_rule(id, rule).await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("add-name-provider", sub_matches)) => {
            let url = sub_matches
                .get_one::<String>("url")
                .expect("url is required");
            let trust_level = match sub_matches.get_one::<String>("trust_level") {
                Some(value) => Some(value.parse::<i32>().expect("trust-level must be integer")),
                None => None,
            };
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client
                .add_name_provider(url.as_str(), trust_level)
                .await
            {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("add_dispatch", sub_matches)) => {
            let local = sub_matches
                .get_one::<String>("local")
                .expect("local is required");
            let target = sub_matches
                .get_one::<String>("target")
                .expect("target is required");
            let protocol = sub_matches
                .get_one::<String>("protocol")
                .map(|s| s.as_str());
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.add_dispatch(local, target, protocol).await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("add_router", sub_matches)) => {
            let server_id = sub_matches.get_one::<String>("id").map(|s| s.as_str());
            let uri = sub_matches
                .get_one::<String>("uri")
                .expect("uri is required");
            let target = sub_matches
                .get_one::<String>("target")
                .expect("target is required");
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.add_router(server_id, uri, target).await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("remove_router", sub_matches)) => {
            let server_id = sub_matches.get_one::<String>("id").map(|s| s.as_str());
            let uri = sub_matches
                .get_one::<String>("uri")
                .expect("uri is required");
            let target = sub_matches
                .get_one::<String>("target")
                .expect("target is required");
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.remove_router(server_id, uri, target).await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("remove_dispatch", sub_matches)) => {
            let local = sub_matches
                .get_one::<String>("local")
                .expect("local is required");
            let protocol = sub_matches
                .get_one::<String>("protocol")
                .map(|s| s.as_str());
            let server = sub_matches
                .get_one::<String>("server")
                .expect("server is required");
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.remove_dispatch(local, protocol).await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("collection", sub_matches)) => match sub_matches.subcommand() {
            Some(("list", list_matches)) => {
                let server = list_matches
                    .get_one::<String>("server")
                    .expect("server is required");
                let cyfs_cmd_client =
                    GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                match cyfs_cmd_client.collection_list().await {
                    Ok(result) => {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e.msg());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }
            Some(("get", get_matches)) => {
                let name = get_matches
                    .get_one::<String>("name")
                    .expect("name is required");
                let key = get_matches.get_one::<String>("key").map(|s| s.as_str());
                let server = get_matches
                    .get_one::<String>("server")
                    .expect("server is required");
                let cyfs_cmd_client =
                    GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                match cyfs_cmd_client.collection_get(name, key).await {
                    Ok(result) => {
                        println!("{}", serde_json::to_string_pretty(&result).unwrap());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e.msg());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }
            Some(("set-add", set_add_matches)) => {
                let name = set_add_matches
                    .get_one::<String>("name")
                    .expect("name is required");
                let value = set_add_matches
                    .get_one::<String>("value")
                    .expect("value is required");
                let server = set_add_matches
                    .get_one::<String>("server")
                    .expect("server is required");
                let cyfs_cmd_client =
                    GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                match cyfs_cmd_client.collection_set_add(name, value).await {
                    Ok(_result) => {
                        println!("success");
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e.msg());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }
            Some(("set-del", set_del_matches)) => {
                let name = set_del_matches
                    .get_one::<String>("name")
                    .expect("name is required");
                let value = set_del_matches
                    .get_one::<String>("value")
                    .expect("value is required");
                let server = set_del_matches
                    .get_one::<String>("server")
                    .expect("server is required");
                let cyfs_cmd_client =
                    GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                match cyfs_cmd_client.collection_set_del(name, value).await {
                    Ok(_result) => {
                        println!("success");
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e.msg());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }
            Some(("map-put", map_put_matches)) => {
                let name = map_put_matches
                    .get_one::<String>("name")
                    .expect("name is required");
                let key = map_put_matches
                    .get_one::<String>("key")
                    .expect("key is required");
                let raw_value = map_put_matches
                    .get_one::<String>("value")
                    .expect("value is required");
                let value = if map_put_matches.get_flag("json") {
                    match serde_json::from_str::<Value>(raw_value.as_str()) {
                        Ok(v) => v.to_string(),
                        Err(e) => {
                            println!("invalid --json value: {}", e);
                            std::process::exit(1);
                        }
                    }
                } else {
                    raw_value.clone()
                };
                let server = map_put_matches
                    .get_one::<String>("server")
                    .expect("server is required");
                let cyfs_cmd_client =
                    GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                match cyfs_cmd_client
                    .collection_map_put(name, key, value.as_str())
                    .await
                {
                    Ok(_result) => {
                        println!("success");
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e.msg());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }
            Some(("map-del", map_del_matches)) => {
                let name = map_del_matches
                    .get_one::<String>("name")
                    .expect("name is required");
                let key = map_del_matches
                    .get_one::<String>("key")
                    .expect("key is required");
                let server = map_del_matches
                    .get_one::<String>("server")
                    .expect("server is required");
                let cyfs_cmd_client =
                    GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
                match cyfs_cmd_client.collection_map_del(name, key).await {
                    Ok(_result) => {
                        println!("success");
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e.msg());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }
            _ => {
                println!("collection subcommand is required");
                std::process::exit(1);
            }
        },
        Some(("process_chain", sub_matches)) => {
            let doc = match GatewayProcessChainDoc::new() {
                Ok(doc) => doc,
                Err(e) => {
                    println!("process_chain init error: {}", e);
                    std::process::exit(1);
                }
            };

            let cmd = sub_matches.get_one::<String>("command");
            let output = if sub_matches.get_flag("all") {
                doc.render_all_docs()
            } else if let Some(cmd) = cmd {
                doc.render_command_help(cmd)
            } else {
                doc.render_command_list()
            };

            if let Some(path) = sub_matches.get_one::<String>("file") {
                if let Err(e) = std::fs::write(path, output) {
                    println!("{}", e);
                    std::process::exit(1);
                }
                println!("Documentation saved to {}", path);
            } else {
                println!("{}", output);
            }
            std::process::exit(0);
        }
        Some(("debug", sub_matches)) => {
            let req_file = sub_matches
                .get_one::<String>("req_file")
                .expect("req_file is required");
            let config_file = sub_matches
                .get_one::<String>("config_file")
                .map(|s| s.as_str());
            let id = sub_matches.get_one::<String>("id").map(|s| s.as_str());
            let repeat = *sub_matches.get_one::<usize>("repeat").unwrap_or(&1usize);
            match run_debug_command(req_file.as_str(), config_file, id, repeat).await {
                Ok(_) => {
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("debug error: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(("reload", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            match cyfs_cmd_client.reload().await {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("start", sub_matches)) => {
            let server = sub_matches.get_one::<String>("server").unwrap();
            let start_args = parse_template_args("start", true);
            let cyfs_cmd_client =
                GatewayControlClient::new(server.as_str(), read_login_token(server.as_str()));
            if start_args.template_id.is_none() {
                match cyfs_cmd_client.get_external_cmds().await {
                    Ok(cmds) => {
                        println!("Available templates ({}):", cmds.len());
                        for cmd in cmds {
                            if cmd.description.is_empty() {
                                println!("  {}", cmd.name);
                            } else {
                                println!("  {} - {}", cmd.name, cmd.description);
                            }
                        }
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e.msg());
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }

            let template_id = start_args.template_id.unwrap();
            if start_args.help {
                match cyfs_cmd_client
                    .get_external_cmd_help(template_id.as_str())
                    .await
                {
                    Ok(help) => {
                        println!("{}", help);
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e);
                        if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                            save_login_token(server.as_str(), token.as_str());
                        }
                        std::process::exit(1);
                    }
                }
            }

            match cyfs_cmd_client
                .start_template(template_id.as_str(), start_args.args)
                .await
            {
                Ok(_result) => {
                    println!("success");
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e.msg());
                    if let Some(token) = cyfs_cmd_client.get_latest_token().await {
                        save_login_token(server.as_str(), token.as_str());
                    }
                    std::process::exit(1);
                }
            }
        }
        Some(("run", _sub_matches)) => {
            let run_args = parse_template_args("run", false);
            let template_dir = get_buckyos_system_etc_dir()
                .join("cyfs_gateway")
                .join("server_templates");
            let external_cmds = JsPkgManager::new(template_dir);
            if run_args.template_id.is_none() {
                match external_cmds.list_pkgs().await {
                    Ok(cmds) => {
                        println!("Available templates ({}):", cmds.len());
                        for cmd in cmds {
                            if cmd.description().is_empty() {
                                println!("  {}", cmd.name());
                            } else {
                                println!("  {} - {}", cmd.name(), cmd.description());
                            }
                        }
                        std::process::exit(0);
                    }
                    Err(e) => {
                        println!("{}", e.msg());
                        std::process::exit(1);
                    }
                }
            }

            let template_id = run_args.template_id.unwrap();
            if run_args.help {
                match external_cmds.get_pkg(template_id.as_str()).await {
                    Ok(pkg) => match pkg.help().await {
                        Ok(help) => {
                            println!("{}", help);
                            std::process::exit(0);
                        }
                        Err(e) => {
                            println!("{}", e.msg());
                            std::process::exit(1);
                        }
                    },
                    Err(e) => {
                        println!("{}", e.msg());
                        std::process::exit(1);
                    }
                }
            }
            info!("web3_gateway start...");

            if matches.get_flag("debug") {
                debug!("Debug mode enabled");
                unsafe {
                    std::env::set_var("RUST_BACKTRACE", "1");
                }
                console_subscriber::init();
            }
            match run_template_local(template_id.as_str(), run_args.args).await {
                Ok(_) => {
                    std::process::exit(0);
                }
                Err(e) => {
                    println!("{}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {}
    }
    info!("web3 gateway service start...");

    if matches.get_flag("debug") {
        debug!("Debug mode enabled");
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "1");
        }
        console_subscriber::init();
    }

    let config_file = get_config_file_path(&matches);

    // Extract necessary params from command line
    let params = GatewayParams {
        keep_tunnel: matches
            .get_many::<String>("keep_tunnel")
            .unwrap_or_default()
            .map(|s| s.to_string())
            .collect(),
    };

    if let Err(e) = gateway_service_main(config_file.as_path(), params).await {
        error!("Gateway run error: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::merge_keep_tunnel_into_rtcp_stack_config;
    use serde_json::json;

    /// web3_gateway.yaml 与三个独立部署拆分（web3_dns / web3_relay /
    /// web3_sn_api）必须都能通过真实加载链路：includes 合并、{{param}}
    /// 替换（params.json 缺 key 会在这里失败）、按 type 的类型化解析。
    #[tokio::test]
    async fn test_web3_gateway_configs_parse() {
        use super::*;

        let parser = GatewayConfigParser::new();
        parser.register_stack_config_parser("tcp", Arc::new(TcpStackConfigParser::new()));
        parser.register_stack_config_parser("udp", Arc::new(UdpStackConfigParser::new()));
        parser.register_stack_config_parser("rtcp", Arc::new(RtcpStackConfigParser::new()));
        parser.register_stack_config_parser("tls", Arc::new(TlsStackConfigParser::new()));
        parser.register_stack_config_parser("quic", Arc::new(QuicStackConfigParser::new()));
        parser.register_stack_config_parser("tun", Arc::new(TunStackConfigParser::new()));
        parser.register_server_config_parser("http", Arc::new(HttpServerConfigParser::new()));
        parser.register_server_config_parser("socks", Arc::new(SocksServerConfigParser::new()));
        parser.register_server_config_parser("dns", Arc::new(DnsServerConfigParser::new()));
        parser.register_server_config_parser("dir", Arc::new(DirServerConfigParser::new()));
        parser
            .register_server_config_parser("cyfs-dir", Arc::new(CyfsDirServerConfigParser::new()));
        parser.register_server_config_parser("local_dns", Arc::new(LocalDnsConfigParser::new()));
        parser.register_server_config_parser("sn", Arc::new(SNServerConfigParser::new()));
        parser.register_server_config_parser(
            "control_server",
            Arc::new(GatewayControlServerConfigParser::new()),
        );
        parser.register_server_config_parser(
            "acme_response",
            Arc::new(AcmeHttpChallengeServerConfigParser::new()),
        );

        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web3-gateway");
        for name in [
            "web3_gateway.yaml",
            "web3_dns.yaml",
            "web3_relay.yaml",
            "web3_sn_api.yaml",
        ] {
            let loaded = load_config_from_file(&base.join(name))
                .await
                .unwrap_or_else(|e| panic!("load {} failed: {}", name, e));
            parser
                .parse(loaded.effective_config)
                .unwrap_or_else(|e| panic!("parse {} failed: {}", name, e.msg()));
        }
    }

    #[test]
    fn test_merge_keep_tunnel_into_rtcp_stack_config() {
        let config = json!({
            "stacks": {
                "rtcp1": {
                    "protocol": "rtcp",
                    "keep_tunnel": ["did:old", "did:dup"]
                },
                "tcp1": {
                    "protocol": "tcp"
                }
            }
        });

        let merged = merge_keep_tunnel_into_rtcp_stack_config(
            config,
            &[
                "did:dup".to_string(),
                "did:new".to_string(),
                " ".to_string(),
            ],
        );

        assert_eq!(
            merged["stacks"]["rtcp1"]["keep_tunnel"],
            json!(["did:old", "did:dup", "did:new"])
        );
        assert!(merged["stacks"]["tcp1"].get("keep_tunnel").is_none());
    }

    #[test]
    fn test_merge_keep_tunnel_preserves_hyphenated_key() {
        let config = json!({
            "stacks": {
                "rtcp1": {
                    "protocol": "rtcp",
                    "keep-tunnel": ["did:old"]
                }
            }
        });

        let merged = merge_keep_tunnel_into_rtcp_stack_config(config, &["did:new".to_string()]);

        assert_eq!(
            merged["stacks"]["rtcp1"]["keep-tunnel"],
            json!(["did:old", "did:new"])
        );
        assert!(merged["stacks"]["rtcp1"].get("keep_tunnel").is_none());
    }
}
