use buckyos_kit::get_buckyos_service_data_dir;
use cyfs_acme::{AcmeIdentityConfig, ChallengeType};
use cyfs_dns::{DnsServerConfig, LocalDnsConfig};
use cyfs_gateway_lib::{
    AcmeHttpChallengeServerConfig, BlockConfig, CollectionConfig, ConfigErrorCode, ConfigResult,
    CyfsDirServerConfig, DirServerConfig, ProcessChainConfig, ProcessChainConfigs,
    ProcessChainHttpServerConfig, QuicStackConfig, RtcpStackConfig, ServerConfig, StackConfig,
    TcpStackConfig, TlsStackConfig, UdpStackConfig, config_err,
};
use cyfs_socks::SocksServerConfig;
use cyfs_tun::TunStackConfig;
use log::*;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub trait StackConfigParser<D: for<'de> Deserializer<'de>>: Send + Sync {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>>;
}

pub struct CyfsStackConfigParser<D: for<'de> Deserializer<'de>> {
    parsers: Mutex<HashMap<String, Arc<dyn StackConfigParser<D>>>>,
}

impl<D: for<'de> Deserializer<'de>> Default for CyfsStackConfigParser<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: for<'de> Deserializer<'de>> CyfsStackConfigParser<D> {
    pub fn new() -> Self {
        Self {
            parsers: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, protocol: &str, factory: Arc<dyn StackConfigParser<D>>) {
        self.parsers
            .lock()
            .unwrap()
            .insert(protocol.to_string(), factory);
    }
}

#[derive(Serialize, Deserialize)]
struct StackProtocolConfig {
    protocol: String,
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for CyfsStackConfigParser<D> {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let config = StackProtocolConfig::deserialize(de.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid stack config. error: {} input:\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                    .unwrap()
            )
        })?;
        let factory = self
            .parsers
            .lock()
            .unwrap()
            .get(config.protocol.as_str())
            .cloned();
        if factory.is_none() {
            warn!(
                "invalid stack config. unknown protocol: {}",
                config.protocol
            );
            return Err(config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid stack config. error: {} input:\n{}",
                format!("unknown protocol: {}", config.protocol),
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                    .unwrap()
            ));
        }
        let factory = factory.unwrap();
        factory.parse(de)
    }
}

pub fn blocks_map_to_vector(blocks: &serde_json::Value) -> ConfigResult<serde_json::Value> {
    if let Some(blocks) = blocks.as_object() {
        let mut block_list = vec![];
        for (id, value) in blocks {
            let mut new_value = value.clone();
            new_value["id"] = serde_json::Value::String(id.to_string());
            block_list.push(new_value);
        }
        Ok(serde_json::Value::Array(block_list))
    } else {
        Err(config_err!(
            ConfigErrorCode::InvalidConfig,
            "invalid block config.It must be map\n{}",
            serde_json::to_string_pretty(blocks).unwrap()
        ))
    }
}

fn hook_point_map_to_vector(hook_point: &serde_json::Value) -> ConfigResult<serde_json::Value> {
    if let Some(chains) = hook_point.as_object() {
        let mut chain_list = vec![];
        for (id, value) in chains {
            let mut new_value = value.clone();
            new_value["id"] = serde_json::Value::String(id.to_string());
            if let Some(blocks) = value.get("blocks") {
                new_value["blocks"] = blocks_map_to_vector(blocks)?;
            }
            chain_list.push(new_value);
        }
        let new_hook_point = serde_json::Value::Array(chain_list);
        ProcessChainConfigs::deserialize(new_hook_point.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid hook point config.{}\n{}",
                e,
                serde_json::to_string_pretty(hook_point).unwrap()
            )
        })?;
        Ok(new_hook_point)
    } else {
        Err(config_err!(
            ConfigErrorCode::InvalidConfig,
            "invalid hook point config.It must be map\n{}",
            serde_json::to_string_pretty(hook_point).unwrap()
        ))
    }
}

fn hook_point_value_map_to_vector_in_value(
    mut stack_config: serde_json::Value,
    key_name: &str,
) -> ConfigResult<serde_json::Value> {
    if let Some(hook_point) = stack_config.get(key_name) {
        let hook_point = hook_point_map_to_vector(hook_point)?;
        stack_config[key_name] = hook_point;
    };

    Ok(stack_config)
}

fn hook_point_value_map_to_vector<D: for<'de> Deserializer<'de> + Clone>(
    de: D,
    key_name: &str,
) -> ConfigResult<serde_json::Value> {
    let stack_config = serde_json::Value::deserialize(de.clone()).map_err(|e| {
        config_err!(
            ConfigErrorCode::InvalidConfig,
            "invalid stack config. error: {} input:\n{}",
            e,
            serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                .unwrap()
        )
    })?;

    hook_point_value_map_to_vector_in_value(stack_config, key_name)
}

pub fn parse_collections_from_raw_config(
    raw_config: &serde_json::Value,
) -> ConfigResult<Vec<CollectionConfig>> {
    let mut collections = Vec::new();
    let Some(collections_value) = raw_config.get("collections") else {
        return Ok(collections);
    };

    let Some(collections_value) = collections_value.as_object() else {
        return Ok(collections);
    };

    let geo_ip_cache_path = get_buckyos_service_data_dir("cyfs_gateway")
        .join("geo_ip")
        .to_string_lossy()
        .to_string();

    for (name, process_chain) in collections_value.iter() {
        let mut chain_value = process_chain.clone();
        chain_value["name"] = serde_json::Value::String(name.clone());

        if chain_value
            .get("type")
            .and_then(|v| v.as_str())
            .is_some_and(|v| v == "ip_region_map")
        {
            if let Some(obj) = chain_value.as_object_mut() {
                obj.insert(
                    "cache_path".to_string(),
                    serde_json::Value::String(geo_ip_cache_path.clone()),
                );
            }
        }

        let chain = serde_json::from_value::<CollectionConfig>(chain_value).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid collections: {:?}\n{}",
                e,
                serde_json::to_string_pretty(collections_value).unwrap()
            )
        })?;
        collections.push(chain);
    }

    Ok(collections)
}

pub fn parse_timers_from_raw_config(
    raw_config: &serde_json::Value,
) -> ConfigResult<Vec<TimerConfig>> {
    let mut timers = Vec::new();
    if let Some(timers_value) = raw_config.get("timers") {
        if let Some(timers_value) = timers_value.as_object() {
            for (id, timer_value) in timers_value.iter() {
                let mut timer_with_id = timer_value.clone();
                timer_with_id["id"] = serde_json::Value::String(id.clone());
                let timer = serde_json::from_value::<TimerConfig>(timer_with_id).map_err(|e| {
                    config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid timer config: {:?}\n{}",
                        e,
                        serde_json::to_string_pretty(timer_value).unwrap()
                    )
                })?;
                if timer.timeout == 0 {
                    return Err(config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid timer config {}: timeout must be greater than 0",
                        timer.id
                    ));
                }
                timers.push(timer);
            }
        }
    }

    Ok(timers)
}

pub struct TcpStackConfigParser {}

impl TcpStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for TcpStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let tcp_config =
            TcpStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
                .map_err(|e| {
                    config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid tcp stack config.{}\n{}",
                        e,
                        serde_json::to_string_pretty(
                            &serde_json::Value::deserialize(de.clone()).unwrap()
                        )
                        .unwrap()
                    )
                })?;
        Ok(Arc::new(tcp_config))
    }
}

pub struct UdpStackConfigParser {}

impl UdpStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for UdpStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let udp_config =
            UdpStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
                .map_err(|e| {
                    config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid udp stack config.{}\n{}",
                        e,
                        serde_json::to_string_pretty(
                            &serde_json::Value::deserialize(de.clone()).unwrap()
                        )
                        .unwrap()
                    )
                })?;
        Ok(Arc::new(udp_config))
    }
}
pub struct TlsStackConfigParser {}

impl TlsStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for TlsStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let tls_config =
            TlsStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
                .map_err(|e| {
                    config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid tls stack config: {}\n{}",
                        e,
                        serde_json::to_string_pretty(
                            &serde_json::Value::deserialize(de.clone()).unwrap()
                        )
                        .unwrap()
                    )
                })?;
        Ok(Arc::new(tls_config))
    }
}

pub struct QuicStackConfigParser {}

impl QuicStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for QuicStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let quic_config =
            QuicStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
                .map_err(|e| {
                    config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid quic stack config: {}\n{}",
                        e,
                        serde_json::to_string_pretty(
                            &serde_json::Value::deserialize(de.clone()).unwrap()
                        )
                        .unwrap()
                    )
                })?;
        Ok(Arc::new(quic_config))
    }
}
pub struct RtcpStackConfigParser {}

impl RtcpStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for RtcpStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let mut value = hook_point_value_map_to_vector(de.clone(), "hook_point")?;
        value = hook_point_value_map_to_vector_in_value(value, "on_new_tunnel_hook_point")?;
        let rtcp_config = RtcpStackConfig::deserialize(value).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid rtcp stack config: {}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                    .unwrap()
            )
        })?;
        Ok(Arc::new(rtcp_config))
    }
}

pub struct TunStackConfigParser {}

impl TunStackConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> StackConfigParser<D> for TunStackConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn StackConfig>> {
        let tun_config =
            TunStackConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
                .map_err(|e| {
                    config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid tun stack config: {}\n{}",
                        e,
                        serde_json::to_string_pretty(
                            &serde_json::Value::deserialize(de.clone()).unwrap()
                        )
                        .unwrap()
                    )
                })?;
        Ok(Arc::new(tun_config))
    }
}

pub trait ServerConfigParser<D: for<'de> Deserializer<'de>>: Send + Sync {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>>;
}

pub struct CyfsServerConfigParser<D: for<'de> Deserializer<'de>> {
    parsers: Mutex<HashMap<String, Arc<dyn ServerConfigParser<D>>>>,
}

impl<D: for<'de> Deserializer<'de>> CyfsServerConfigParser<D> {
    pub fn new() -> Self {
        Self {
            parsers: Mutex::new(HashMap::new()),
        }
    }

    pub fn register(&self, name: &str, parser: Arc<dyn ServerConfigParser<D>>) {
        self.parsers
            .lock()
            .unwrap()
            .insert(name.to_string(), parser);
    }
}

#[derive(Serialize, Deserialize)]
pub struct ServerConfigType {
    #[serde(rename = "type")]
    ty: String,
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for CyfsServerConfigParser<D> {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let server_type = ServerConfigType::deserialize(de.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid stack config. error: {} input:\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                    .unwrap()
            )
        })?;
        let parser = { self.parsers.lock().unwrap().get(&server_type.ty).cloned() };
        if let Some(parser) = parser {
            parser.parse(de)
        } else {
            Err(config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid stack config.unknown server type:{}",
                server_type.ty
            ))
        }
    }
}

pub struct HttpServerConfigParser {}

impl HttpServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for HttpServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let mut value = hook_point_value_map_to_vector(de.clone(), "hook_point")?;
        value = hook_point_value_map_to_vector_in_value(value, "post_hook_point")?;
        let config = ProcessChainHttpServerConfig::deserialize(value).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid http server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                    .unwrap()
            )
        })?;
        Ok(Arc::new(config))
    }
}

pub struct DnsServerConfigParser {}

impl DnsServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for DnsServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config =
            DnsServerConfig::deserialize(hook_point_value_map_to_vector(de.clone(), "hook_point")?)
                .map_err(|e| {
                    config_err!(
                        ConfigErrorCode::InvalidConfig,
                        "invalid dns server config.{:?}\n{}",
                        e,
                        serde_json::to_string_pretty(
                            &serde_json::Value::deserialize(de.clone()).unwrap()
                        )
                        .unwrap()
                    )
                })?;
        Ok(Arc::new(config))
    }
}

pub struct SocksServerConfigParser {}

impl SocksServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for SocksServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = SocksServerConfig::deserialize(hook_point_value_map_to_vector(
            de.clone(),
            "hook_point",
        )?)
        .map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid socks server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                    .unwrap()
            )
        })?;

        Ok(Arc::new(config))
    }
}

pub struct CyfsDirServerConfigParser {}

impl CyfsDirServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for CyfsDirServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        // Allow either an array `hook_point: [...]` or the map shorthand
        // `hook_point: { id: { ... } }` (consistent with the http server).
        let value = hook_point_value_map_to_vector(de.clone(), "hook_point")?;
        let config = CyfsDirServerConfig::deserialize(value).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid cyfs-dir server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                    .unwrap()
            )
        })?;
        Ok(Arc::new(config))
    }
}

pub struct DirServerConfigParser {}

impl DirServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for DirServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = DirServerConfig::deserialize(de.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid dir server config.{}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                    .unwrap()
            )
        })?;
        Ok(Arc::new(config))
    }
}

pub struct LocalDnsConfigParser {}

impl LocalDnsConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D> for LocalDnsConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = LocalDnsConfig::deserialize(de.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid local dns config.{:?}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                    .unwrap()
            )
        })?;
        Ok(Arc::new(config))
    }
}

pub struct AcmeHttpChallengeServerConfigParser {}

impl AcmeHttpChallengeServerConfigParser {
    pub fn new() -> Self {
        Self {}
    }
}

impl<D: for<'de> Deserializer<'de> + Clone> ServerConfigParser<D>
    for AcmeHttpChallengeServerConfigParser
{
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = AcmeHttpChallengeServerConfig::deserialize(de.clone()).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid acme http challenge server config.{:?}\n{}",
                e,
                serde_json::to_string_pretty(&serde_json::Value::deserialize(de.clone()).unwrap())
                    .unwrap()
            )
        })?;
        Ok(Arc::new(config))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct GatewayIdentityManagerConfig {
    #[serde(
        default,
        alias = "public_root",
        alias = "public_identity_root",
        alias = "public_identity_root_path",
        skip_serializing_if = "Option::is_none"
    )]
    pub public_root_path: Option<String>,
    #[serde(
        default,
        alias = "security_root",
        skip_serializing_if = "Option::is_none"
    )]
    pub security_root_path: Option<String>,
}

impl GatewayIdentityManagerConfig {
    pub fn to_acme_identity_config(&self) -> AcmeIdentityConfig {
        AcmeIdentityConfig {
            public_root_path: self.public_root_path.clone(),
            security_root_path: self.security_root_path.clone(),
        }
    }
}

fn identity_manager_value(identity_manager: &GatewayIdentityManagerConfig) -> serde_json::Value {
    let mut value = serde_json::Map::new();
    if let Some(public_root_path) = identity_manager.public_root_path.as_ref() {
        value.insert(
            "public_root_path".to_string(),
            serde_json::Value::String(public_root_path.clone()),
        );
    }
    if let Some(security_root_path) = identity_manager.security_root_path.as_ref() {
        value.insert(
            "security_root_path".to_string(),
            serde_json::Value::String(security_root_path.clone()),
        );
    }
    serde_json::Value::Object(value)
}

fn stack_uses_identity_hosts(stack_config: &serde_json::Value) -> bool {
    stack_config
        .get("hosts")
        .and_then(|value| value.as_array())
        .map(|hosts| {
            hosts
                .iter()
                .any(|host| host.as_str().is_some_and(|host| !host.trim().is_empty()))
        })
        .unwrap_or(false)
}

fn stack_declares_rtcp_identity(stack_config: &serde_json::Value) -> bool {
    ["identity", "did", "device_did"].iter().any(|key| {
        stack_config
            .get(key)
            .and_then(|value| value.as_str())
            .is_some_and(|identity| !identity.trim().is_empty())
    })
}

pub fn apply_gateway_identity_manager_to_stack(
    mut stack_config: serde_json::Value,
    identity_manager: Option<&GatewayIdentityManagerConfig>,
) -> serde_json::Value {
    let Some(identity_manager) = identity_manager else {
        return stack_config;
    };
    if stack_config.get("identity_manager").is_some() {
        return stack_config;
    }

    let protocol = stack_config
        .get("protocol")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let should_apply =
        if protocol.eq_ignore_ascii_case("tls") || protocol.eq_ignore_ascii_case("quic") {
            stack_uses_identity_hosts(&stack_config)
        } else if protocol.eq_ignore_ascii_case("rtcp") {
            stack_declares_rtcp_identity(&stack_config)
        } else {
            false
        };

    if should_apply {
        if let Some(stack_config) = stack_config.as_object_mut() {
            stack_config.insert(
                "identity_manager".to_string(),
                identity_manager_value(identity_manager),
            );
        }
    }

    stack_config
}

#[derive(Deserialize, Clone)]
pub struct TimerConfig {
    pub id: String,
    pub timeout: u64,
    #[serde(rename = "process-chain", alias = "process_chain")]
    pub process_chain: String,
}

impl TimerConfig {
    pub fn to_process_chains(&self) -> ProcessChainConfigs {
        vec![ProcessChainConfig {
            id: "main".to_string(),
            priority: 1,
            blocks: vec![BlockConfig {
                id: "default".to_string(),
                priority: 1,
                block: self.process_chain.clone(),
            }],
        }]
    }
}

fn default_offline_timeout_seconds() -> u64 {
    600
}

fn default_cleanup_interval_seconds() -> u64 {
    60
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
pub struct DeviceManagerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_offline_timeout_seconds")]
    pub offline_timeout_seconds: u64,
    #[serde(default = "default_cleanup_interval_seconds")]
    pub cleanup_interval_seconds: u64,
}

impl Default for DeviceManagerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            offline_timeout_seconds: default_offline_timeout_seconds(),
            cleanup_interval_seconds: default_cleanup_interval_seconds(),
        }
    }
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
pub struct AcmeHostConfig {
    #[serde(alias = "hostname", alias = "domain")]
    pub host: String,
    #[serde(alias = "acme_type", alias = "method")]
    pub challenge_type: Option<ChallengeType>,
    pub dns_provider: Option<String>,
    pub identity: Option<String>,
    pub identity_manager: Option<AcmeIdentityConfig>,
    #[serde(flatten)]
    pub data: Option<serde_json::Value>,
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
pub struct AcmeConfig {
    pub account: Option<String>,
    pub issuer: Option<String>,
    pub dns_providers: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    pub hosts: Vec<AcmeHostConfig>,
    pub identity_manager: Option<AcmeIdentityConfig>,
    pub check_interval: Option<u64>,
    pub renew_before_expiry: Option<u64>,
}

pub fn parse_acme_config_from_raw_config(
    raw_config: &serde_json::Value,
    identity_manager: Option<&GatewayIdentityManagerConfig>,
) -> Option<AcmeConfig> {
    let mut acme_config: Option<AcmeConfig> = match raw_config.get("acme") {
        Some(config) => match serde_json::from_value::<AcmeConfig>(config.clone()) {
            Ok(config) => Some(config),
            Err(err) => {
                let msg = format!("invalid acme config: {}", err);
                error!("{}", msg);
                None
            }
        },
        None => None,
    };
    if let Some(acme_config) = acme_config.as_mut() {
        if acme_config.identity_manager.is_none() {
            acme_config.identity_manager = identity_manager
                .as_ref()
                .map(|config| config.to_acme_identity_config());
        }
    }
    acme_config
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
pub struct LimiterConfig {
    pub id: String,
    pub upper_limiter: Option<String>,
    #[serde(with = "speed_parser")]
    #[serde(default)]
    pub download_speed: Option<u64>,
    #[serde(with = "speed_parser")]
    #[serde(default)]
    pub upload_speed: Option<u64>,
    pub concurrent: Option<u64>,
}

#[derive(Deserialize, Clone, Eq, PartialEq)]
pub struct TlsCA {
    pub cert_path: String,
    pub key_path: String,
}

mod speed_parser {
    use cyfs_gateway_lib::parse_speed;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = Option::<String>::deserialize(deserializer)?;
        if s.is_none() {
            return Ok(None);
        }
        match parse_speed(s.unwrap().as_str()) {
            Ok(speed) => Ok(Some(speed)),
            Err(e) => Err(D::Error::custom(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_limiter_config_parser() {
        let json = r#"
        {
            "id": "limiter_id",
            "upper_limiter": "upper_limiter",
            "download_speed": "100KB/s",
            "upload_speed": "100KB/s",
            "concurrent": 100
        }
        "#;
        let config = serde_json::from_str::<LimiterConfig>(json).unwrap();
        assert_eq!(config.upper_limiter, Some("upper_limiter".to_string()));
        assert_eq!(config.download_speed, Some(100 * 1024));
        assert_eq!(config.upload_speed, Some(100 * 1024));
        assert_eq!(config.concurrent, Some(100));

        let json = r#"
        {
            "id": "limiter_id",
            "download_speed": "100KB/s",
            "upload_speed": "100KB/s",
            "concurrent": 100
        }
        "#;
        let config = serde_json::from_str::<LimiterConfig>(json).unwrap();
        assert_eq!(config.upper_limiter, None);
        assert_eq!(config.download_speed, Some(100 * 1024));
        assert_eq!(config.upload_speed, Some(100 * 1024));
        assert_eq!(config.concurrent, Some(100));

        let json = r#"
        {
            "id": "limiter_id",
            "upper_limiter": "upper_limiter",
            "download_speed": "101KB/s",
            "concurrent": 100
        }
        "#;
        let config = serde_json::from_str::<LimiterConfig>(json).unwrap();
        assert_eq!(config.upper_limiter, Some("upper_limiter".to_string()));
        assert_eq!(config.upload_speed, None);
        assert_eq!(config.download_speed, Some(101 * 1024));
        assert_eq!(config.concurrent, Some(100));

        let json = r#"
        {
            "id": "limiter_id",
            "upper_limiter": "upper_limiter",
            "download_speed": "100KB/s",
            "upload_speed": "100KB/s"
        }
        "#;
        let config = serde_json::from_str::<LimiterConfig>(json).unwrap();
        assert_eq!(config.upper_limiter, Some("upper_limiter".to_string()));
        assert_eq!(config.download_speed, Some(100 * 1024));
        assert_eq!(config.upload_speed, Some(100 * 1024));
        assert_eq!(config.concurrent, None);
    }

    #[test]
    fn test_timer_config_parser() {
        let timers = parse_timers_from_raw_config(&json!({
            "timers": {
                "t1": {
                    "timeout": 120,
                    "process-chain": "echo \"test\";"
                },
                "t2": {
                    "timeout": 60,
                    "process_chain": "echo \"test2\";"
                }
            }
        }))
        .unwrap();

        assert_eq!(timers.len(), 2);
        let t1 = timers.iter().find(|timer| timer.id == "t1").unwrap();
        let t2 = timers.iter().find(|timer| timer.id == "t2").unwrap();
        assert_eq!(t1.timeout, 120);
        assert_eq!(t2.timeout, 60);
    }

    #[test]
    fn test_timer_config_timeout_zero() {
        assert!(
            parse_timers_from_raw_config(&json!({
                "timers": {
                    "t1": {
                        "timeout": 0,
                        "process-chain": "echo \"test\";"
                    }
                }
            }))
            .is_err()
        );
    }

    #[test]
    fn test_acme_config_hosts_parser() {
        let acme = parse_acme_config_from_raw_config(
            &json!({
                "acme": {
                    "account": "admin@example.com",
                    "dns_providers": {
                        "sn-dns": {
                            "sn": "https://sn.devtests.org/kapi/sn",
                            "key_path": "./node_private_key.pem"
                        }
                    },
                    "hosts": [
                        {
                            "host": "gateway.example.com",
                            "challenge_type": "dns-01",
                            "dns_provider": "sn-dns"
                        },
                        {
                            "domain": "*.example.com",
                            "method": "tls-alpn-01",
                            "identity": "did:web:example.com"
                        }
                    ]
                }
            }),
            None,
        )
        .unwrap();

        assert_eq!(acme.hosts.len(), 2);
        assert_eq!(acme.hosts[0].host, "gateway.example.com");
        assert_eq!(acme.hosts[0].challenge_type, Some(ChallengeType::Dns01));
        assert_eq!(acme.hosts[0].dns_provider.as_deref(), Some("sn-dns"));
        assert_eq!(acme.hosts[1].host, "*.example.com");
        assert_eq!(acme.hosts[1].challenge_type, Some(ChallengeType::TlsAlpn01));
        assert_eq!(
            acme.hosts[1].identity.as_deref(),
            Some("did:web:example.com")
        );
    }

    #[test]
    fn test_rtcp_keep_tunnel_config_parser() {
        let config = RtcpStackConfigParser::new()
            .parse(json!({
                "id": "rtcp1",
                "protocol": "rtcp",
                "bind": "127.0.0.1:0",
                "key_path": "/tmp/test.pem",
                "name": "test",
                "keep_tunnel": ["did:1"],
                "hook_point": {}
            }))
            .unwrap();

        let rtcp_config = config.as_any().downcast_ref::<RtcpStackConfig>().unwrap();
        assert_eq!(rtcp_config.keep_tunnel, vec!["did:1".to_string()]);
    }

    #[test]
    fn test_rtcp_keep_tunnel_hyphenated_alias_parser() {
        let config = RtcpStackConfigParser::new()
            .parse(json!({
                "id": "rtcp1",
                "protocol": "rtcp",
                "bind": "127.0.0.1:0",
                "key_path": "/tmp/test.pem",
                "name": "test",
                "keep-tunnel": ["did:1", "did:2"],
                "hook_point": {}
            }))
            .unwrap();

        let rtcp_config = config.as_any().downcast_ref::<RtcpStackConfig>().unwrap();
        assert_eq!(
            rtcp_config.keep_tunnel,
            vec!["did:1".to_string(), "did:2".to_string()]
        );
    }

    #[test]
    fn test_rtcp_identity_config_parser_without_key_path() {
        let config = RtcpStackConfigParser::new()
            .parse(json!({
                "id": "rtcp1",
                "protocol": "rtcp",
                "bind": "127.0.0.1:0",
                "identity": "did:web:example.com",
                "identity_manager": {
                    "public_root_path": "/tmp/identity",
                    "security_root_path": "/tmp/security"
                },
                "hook_point": {}
            }))
            .unwrap();

        let rtcp_config = config.as_any().downcast_ref::<RtcpStackConfig>().unwrap();
        assert_eq!(rtcp_config.identity.as_deref(), Some("did:web:example.com"));
        assert!(rtcp_config.key_path.is_none());
    }

    #[test]
    fn test_gateway_identity_manager_applies_to_identity_aware_configs() {
        let identity_manager = GatewayIdentityManagerConfig {
            public_root_path: Some("/gateway/identity".to_string()),
            security_root_path: Some("/gateway/security".to_string()),
        };
        let raw_config = json!({
            "acme": {
                "hosts": [
                    {
                        "host": "gateway.example.com"
                    }
                ]
            }
        });
        let acme = parse_acme_config_from_raw_config(&raw_config, Some(&identity_manager)).unwrap();
        assert_eq!(
            acme.identity_manager
                .as_ref()
                .unwrap()
                .public_root_path
                .as_deref(),
            Some("/gateway/identity")
        );

        let tls_config = apply_gateway_identity_manager_to_stack(
            json!({
                "id": "tls1",
                "protocol": "tls",
                "bind": "127.0.0.1:0",
                "hosts": ["gateway.example.com"],
                "hook_point": {}
            }),
            Some(&identity_manager),
        );
        let tls_config = TlsStackConfigParser::new().parse(tls_config).unwrap();
        let tls_config = tls_config
            .as_any()
            .downcast_ref::<TlsStackConfig>()
            .unwrap();
        assert_eq!(
            tls_config
                .identity_manager
                .as_ref()
                .unwrap()
                .public_root_path
                .as_deref(),
            Some("/gateway/identity")
        );

        let quic_config = apply_gateway_identity_manager_to_stack(
            json!({
                "id": "quic1",
                "protocol": "quic",
                "bind": "127.0.0.1:0",
                "hosts": ["gateway.example.com"],
                "hook_point": {}
            }),
            Some(&identity_manager),
        );
        let quic_config = QuicStackConfigParser::new().parse(quic_config).unwrap();
        let quic_config = quic_config
            .as_any()
            .downcast_ref::<QuicStackConfig>()
            .unwrap();
        assert_eq!(
            quic_config
                .identity_manager
                .as_ref()
                .unwrap()
                .security_root_path
                .as_deref(),
            Some("/gateway/security")
        );

        let rtcp_config = apply_gateway_identity_manager_to_stack(
            json!({
                "id": "rtcp1",
                "protocol": "rtcp",
                "bind": "127.0.0.1:0",
                "identity": "did:web:device.example.com",
                "hook_point": {}
            }),
            Some(&identity_manager),
        );
        let rtcp_config = RtcpStackConfigParser::new().parse(rtcp_config).unwrap();
        let rtcp_config = rtcp_config
            .as_any()
            .downcast_ref::<RtcpStackConfig>()
            .unwrap();
        assert_eq!(
            rtcp_config
                .identity_manager
                .as_ref()
                .unwrap()
                .public_root_path
                .as_deref(),
            Some("/gateway/identity")
        );

        let rtcp_legacy_config = apply_gateway_identity_manager_to_stack(
            json!({
                "id": "rtcp_legacy",
                "protocol": "rtcp",
                "bind": "127.0.0.1:0",
                "key_path": "/tmp/test.pem",
                "name": "legacy",
                "hook_point": {}
            }),
            Some(&identity_manager),
        );
        let rtcp_legacy_config = RtcpStackConfigParser::new()
            .parse(rtcp_legacy_config)
            .unwrap();
        let rtcp_legacy_config = rtcp_legacy_config
            .as_any()
            .downcast_ref::<RtcpStackConfig>()
            .unwrap();
        assert!(rtcp_legacy_config.identity_manager.is_none());
    }

    #[test]
    fn test_gateway_identity_manager_keeps_specific_overrides() {
        let identity_manager = GatewayIdentityManagerConfig {
            public_root_path: Some("/gateway/identity".to_string()),
            security_root_path: Some("/gateway/security".to_string()),
        };

        let acme = parse_acme_config_from_raw_config(
            &json!({
                "acme": {
                    "identity_manager": {
                        "public_root_path": "/acme/identity",
                        "security_root_path": "/acme/security"
                    },
                    "hosts": [
                        {
                            "host": "gateway.example.com"
                        }
                    ]
                }
            }),
            Some(&identity_manager),
        )
        .unwrap();

        assert_eq!(
            acme.identity_manager
                .as_ref()
                .unwrap()
                .public_root_path
                .as_deref(),
            Some("/acme/identity")
        );

        let tls_config = apply_gateway_identity_manager_to_stack(
            json!({
                "id": "tls1",
                "protocol": "tls",
                "bind": "127.0.0.1:0",
                "hosts": ["gateway.example.com"],
                "identity_manager": {
                    "public_root_path": "/stack/identity",
                    "security_root_path": "/stack/security"
                },
                "hook_point": {}
            }),
            Some(&identity_manager),
        );
        let tls_config = TlsStackConfigParser::new().parse(tls_config).unwrap();
        let tls_config = tls_config
            .as_any()
            .downcast_ref::<TlsStackConfig>()
            .unwrap();
        assert_eq!(
            tls_config
                .identity_manager
                .as_ref()
                .unwrap()
                .security_root_path
                .as_deref(),
            Some("/stack/security")
        );
    }
}
