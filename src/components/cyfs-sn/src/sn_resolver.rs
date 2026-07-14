use crate::sn_did_resolver::{SnDidDocumentSource, SnDidResolveResponse, SnDidResolverProfile};
use crate::{
    RelayAssignment, RelayAssignmentState, SNUserInfo, SnAuthDBRef, SnDeviceInfoDBRef,
    SnDeviceStateView, SnRelayManagerRef, ZoneInfo,
};
use async_trait::async_trait;
use bns_client::canonical_bns_name;
use cyfs_gateway_lib::{server_err, ServerError, ServerErrorCode};
use jsonwebtoken::DecodingKey;
use log::{debug, warn};
use name_client::{NameInfo, RecordType};
use name_lib::{
    decode_json_from_jwt_with_pk, DeviceConfig, DeviceMiniConfig as NameDeviceMiniConfig,
    EncodedDocument, DID,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

pub const DEFAULT_SN_RESOLVER_TTL_SECS: u32 = 60;
pub const DEFAULT_LEGACY_GATEWAY_DEVICE: &str = "ood1";
pub const BNS_DOC_ZONE: &str = "zone";
pub const BNS_DOC_BOOT: &str = "boot";
pub const BNS_DOC_DEVICE_MINI: &str = "device_mini_doc";
pub const BNS_DOC_DNS_TXT: &str = "dns_txt";
pub const UNASSIGNED_RELAY_SN: &str = "unassigned";

pub type SnResolverRef = Arc<SnResolver>;
pub type SnResolverResult<T> = std::result::Result<T, SnResolverError>;
pub type SnAuthReaderRef = Arc<dyn SnAuthReader>;
pub type BnsDocumentReaderRef = Arc<dyn BnsDocumentReader>;
pub type DeviceOnlineReaderRef = Arc<dyn DeviceOnlineReader>;
pub type RelayAssignmentReaderRef = Arc<dyn RelayAssignmentReader>;
pub type ResolverCompatibilityReaderRef = Arc<dyn ResolverCompatibilityReader>;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SnResolverErrorKind {
    NotManaged,
    NameNotFound,
    DocumentNotFound,
    DeviceNotFound,
    UnsupportedRecordType,
    UnsupportedDidMethod,
    InvalidHostname,
    InvalidDid,
    BackendUnavailable,
}

#[derive(Debug, Clone)]
pub struct SnResolverError {
    kind: SnResolverErrorKind,
    message: String,
}

impl SnResolverError {
    pub fn new(kind: SnResolverErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> SnResolverErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(SnResolverErrorKind::NameNotFound, message)
    }

    pub fn backend(message: impl Into<String>) -> Self {
        Self::new(SnResolverErrorKind::BackendUnavailable, message)
    }

    pub fn to_server_error(&self) -> ServerError {
        let code = match self.kind {
            SnResolverErrorKind::InvalidHostname
            | SnResolverErrorKind::InvalidDid
            | SnResolverErrorKind::UnsupportedRecordType
            | SnResolverErrorKind::UnsupportedDidMethod => ServerErrorCode::InvalidParam,
            SnResolverErrorKind::NotManaged
            | SnResolverErrorKind::NameNotFound
            | SnResolverErrorKind::DocumentNotFound
            | SnResolverErrorKind::DeviceNotFound => ServerErrorCode::NotFound,
            SnResolverErrorKind::BackendUnavailable => ServerErrorCode::ProcessChainError,
        };

        server_err!(code, "{}", self.message)
    }
}

impl fmt::Display for SnResolverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for SnResolverError {}

#[derive(Debug, Clone)]
pub struct SnResolverConfig {
    pub server_host: String,
    pub server_ip: IpAddr,
    pub aliases: Vec<String>,
    pub boot_jwt: String,
    pub owner_pkx: String,
    pub device_jwts: Vec<String>,
    pub default_ttl: u32,
    pub legacy_gateway_device_name: String,
}

impl SnResolverConfig {
    pub fn new(
        server_host: impl Into<String>,
        server_ip: IpAddr,
        boot_jwt: impl Into<String>,
        owner_pkx: impl Into<String>,
        device_jwts: Vec<String>,
    ) -> Self {
        Self {
            server_host: normalize_host_lossy(server_host.into().as_str()),
            server_ip,
            aliases: Vec::new(),
            boot_jwt: boot_jwt.into(),
            owner_pkx: owner_pkx.into(),
            device_jwts,
            default_ttl: DEFAULT_SN_RESOLVER_TTL_SECS,
            legacy_gateway_device_name: DEFAULT_LEGACY_GATEWAY_DEVICE.to_string(),
        }
    }

    pub fn with_aliases(mut self, aliases: Vec<String>) -> Self {
        self.aliases = aliases
            .into_iter()
            .map(|alias| normalize_host_lossy(alias.as_str()))
            .filter(|alias| !alias.is_empty())
            .collect();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum ZoneResolutionSource {
    BnsName,
    UserDomain,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum DnsResolutionSource {
    ExplicitRecord,
    BnsDocument,
    DeviceOnlineInfo,
    SnSelf,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum RelayState {
    Healthy,
    Draining,
    Offline,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RelayMigrationHint {
    pub migrated_from: Option<String>,
    pub migration_deadline: Option<u64>,
    pub generation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct BnsOwner {
    pub name: String,
    pub effective_owner: Option<String>,
    pub owner_config: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Default)]
pub struct BnsDocumentMeta {
    pub version: Option<u64>,
    pub name_seq: Option<u64>,
    pub updated_at: Option<u64>,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BnsDocumentContent {
    Json(Value),
    Jwt(String),
    Text(String),
}

impl BnsDocumentContent {
    fn to_encoded_document(&self) -> EncodedDocument {
        match self {
            Self::Json(value) => EncodedDocument::JsonLd(value.clone()),
            Self::Jwt(jwt) => EncodedDocument::Jwt(jwt.clone()),
            Self::Text(text) => EncodedDocument::Jwt(text.clone()),
        }
    }

    fn to_json_value(&self) -> Option<Value> {
        match self {
            Self::Json(value) => Some(value.clone()),
            Self::Jwt(jwt) | Self::Text(jwt) => {
                EncodedDocument::Jwt(jwt.clone()).to_json_value().ok()
            }
        }
    }

    fn as_jwt(&self) -> Option<String> {
        match self {
            Self::Jwt(jwt) => Some(jwt.clone()),
            Self::Text(text) if !text.trim_start().starts_with('{') => Some(text.clone()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BnsDocument {
    pub name: String,
    pub doc_type: String,
    pub content: BnsDocumentContent,
    pub meta: BnsDocumentMeta,
}

impl BnsDocument {
    pub fn json(name: impl Into<String>, doc_type: impl Into<String>, value: Value) -> Self {
        Self {
            name: name.into(),
            doc_type: doc_type.into(),
            content: BnsDocumentContent::Json(value),
            meta: BnsDocumentMeta::default(),
        }
    }

    pub fn jwt(
        name: impl Into<String>,
        doc_type: impl Into<String>,
        jwt: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            doc_type: doc_type.into(),
            content: BnsDocumentContent::Jwt(jwt.into()),
            meta: BnsDocumentMeta::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZoneDocument {
    pub raw: Option<Value>,
    pub jwt: Option<String>,
    pub boot_jwt: Option<String>,
    pub devices: HashMap<String, Value>,
    pub gateway_device_name: Option<String>,
    pub gateway_ips: Vec<IpAddr>,
    pub ttl: Option<u32>,
    pub version: Option<u64>,
}

impl ZoneDocument {
    fn empty() -> Self {
        Self {
            raw: None,
            jwt: None,
            boot_jwt: None,
            devices: HashMap::new(),
            gateway_device_name: None,
            gateway_ips: Vec::new(),
            ttl: None,
            version: None,
        }
    }

    fn from_bns_document(document: &BnsDocument) -> Self {
        let raw = document.content.to_json_value();
        let jwt = document.content.as_jwt();
        let boot_jwt = raw.as_ref().and_then(find_boot_jwt);
        let devices = raw.as_ref().map(find_device_mini_map).unwrap_or_default();
        let gateway_device_name = raw.as_ref().and_then(find_gateway_device_name);
        let gateway_ips = raw.as_ref().map(find_gateway_ips).unwrap_or_default();
        let ttl = raw.as_ref().and_then(find_ttl).or(document.meta.ttl);
        Self {
            raw,
            jwt,
            boot_jwt,
            devices,
            gateway_device_name,
            gateway_ips,
            ttl,
            version: document.meta.version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BootDocument {
    pub raw: Option<Value>,
    pub jwt: Option<String>,
    pub gateway_device_name: Option<String>,
    pub ttl: Option<u32>,
    pub version: Option<u64>,
}

impl BootDocument {
    fn empty() -> Self {
        Self {
            raw: None,
            jwt: None,
            gateway_device_name: None,
            ttl: None,
            version: None,
        }
    }

    fn from_bns_document(document: &BnsDocument) -> Self {
        let raw = document.content.to_json_value();
        let jwt = document.content.as_jwt();
        let gateway_device_name = raw.as_ref().and_then(find_gateway_device_name);
        let ttl = raw.as_ref().and_then(find_ttl).or(document.meta.ttl);
        Self {
            raw,
            jwt,
            gateway_device_name,
            ttl,
            version: document.meta.version,
        }
    }

    fn from_legacy_boot_jwt(jwt: &str) -> Self {
        let raw = EncodedDocument::Jwt(jwt.to_string()).to_json_value().ok();
        Self {
            gateway_device_name: raw.as_ref().and_then(find_gateway_device_name),
            ttl: raw.as_ref().and_then(find_ttl),
            raw,
            jwt: Some(jwt.to_string()),
            version: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceMiniDocument {
    pub zone_name: String,
    pub device_name: String,
    pub did: String,
    pub mini_config_jwt: Option<String>,
    pub document: Option<Value>,
    pub ttl: Option<u32>,
    pub version: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZoneResolution {
    pub input: String,
    pub canonical_name: String,
    pub zone_name: String,
    pub owner: BnsOwner,
    pub zone_doc: ZoneDocument,
    pub boot_doc: BootDocument,
    pub user_domain: Option<String>,
    pub self_cert: bool,
    pub relay_sn: Option<String>,
    pub source: ZoneResolutionSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GatewayResolution {
    pub zone_name: String,
    pub hostname: String,
    pub gateway_device_name: String,
    pub gateway_did: String,
    pub device_doc: DeviceMiniDocument,
    pub online: Option<SnDeviceStateView>,
    pub addresses: Vec<IpAddr>,
    pub relay_sn: Option<String>,
    pub self_cert: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DnsResolution {
    pub hostname: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub addresses: Vec<IpAddr>,
    pub txt: Vec<String>,
    pub source: DnsResolutionSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct RelayResolution {
    pub zone_name: String,
    pub relay_sn: String,
    pub relay_state: RelayState,
    pub migration_hint: Option<RelayMigrationHint>,
}

#[async_trait]
pub trait BnsDocumentReader: Send + Sync + 'static {
    async fn resolve_owner(&self, _name: &str) -> SnResolverResult<Option<BnsOwner>> {
        Ok(None)
    }

    async fn get_document(
        &self,
        _name: &str,
        _doc_type: &str,
    ) -> SnResolverResult<Option<BnsDocument>> {
        Ok(None)
    }
}

pub struct EmptyBnsDocumentReader;

#[async_trait]
impl BnsDocumentReader for EmptyBnsDocumentReader {}

#[async_trait]
pub trait SnAuthReader: Send + Sync + 'static {
    async fn get_user_info(&self, username: &str) -> SnResolverResult<Option<SNUserInfo>>;
    async fn get_user_by_domain(&self, domain: &str) -> SnResolverResult<Option<SNUserInfo>>;
    async fn get_zone_info(&self, username: &str) -> SnResolverResult<Option<ZoneInfo>>;

    async fn get_user_sn_ips(&self, username: &str) -> SnResolverResult<Vec<IpAddr>> {
        let Some(zone_info) = self.get_zone_info(username).await? else {
            return Ok(Vec::new());
        };
        Ok(parse_sn_ips(zone_info.sn_ips.as_deref(), username))
    }
}

pub struct EmptySnAuthReader;

#[async_trait]
impl SnAuthReader for EmptySnAuthReader {
    async fn get_user_info(&self, username: &str) -> SnResolverResult<Option<SNUserInfo>> {
        let _ = username;
        Ok(None)
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResolverResult<Option<SNUserInfo>> {
        let _ = domain;
        Ok(None)
    }

    async fn get_zone_info(&self, username: &str) -> SnResolverResult<Option<ZoneInfo>> {
        Ok(Some(ZoneInfo::default_for(username)))
    }
}

pub struct SnAuthResolverReader {
    db: SnAuthDBRef,
}

impl SnAuthResolverReader {
    pub fn new(db: SnAuthDBRef) -> Self {
        Self { db }
    }
}

#[async_trait]
impl SnAuthReader for SnAuthResolverReader {
    async fn get_user_info(&self, username: &str) -> SnResolverResult<Option<SNUserInfo>> {
        self.db
            .get_user_info(username)
            .await
            .map_err(|e| SnResolverError::backend(format!("query user {} failed: {}", username, e)))
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResolverResult<Option<SNUserInfo>> {
        self.db.get_user_by_domain(domain).await.map_err(|e| {
            SnResolverError::backend(format!("query user by domain {} failed: {}", domain, e))
        })
    }

    async fn get_zone_info(&self, username: &str) -> SnResolverResult<Option<ZoneInfo>> {
        self.db.get_zone_info(username).await.map_err(|e| {
            SnResolverError::backend(format!("query zone_info {} failed: {}", username, e))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResolverDeviceDocument {
    pub zone_name: String,
    pub device_name: String,
    pub did: String,
    pub mini_config_jwt: Option<String>,
    pub document: Option<Value>,
    pub info_document: Option<Value>,
    pub addresses: Vec<IpAddr>,
    pub ttl: Option<u32>,
    pub version: Option<u64>,
}

impl ResolverDeviceDocument {
    fn to_device_mini_document(&self) -> DeviceMiniDocument {
        DeviceMiniDocument {
            zone_name: self.zone_name.clone(),
            device_name: self.device_name.clone(),
            did: self.did.clone(),
            mini_config_jwt: self.mini_config_jwt.clone(),
            document: self.document.clone(),
            ttl: self.ttl,
            version: self.version,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResolverDidDocument {
    pub obj_id: String,
    pub document_json: String,
    pub doc_type: Option<String>,
}

#[async_trait]
pub trait ResolverCompatibilityReader: Send + Sync + 'static {
    async fn query_domain_record(
        &self,
        _domain: &str,
        _record_type: RecordType,
    ) -> SnResolverResult<Option<(String, u32)>> {
        Ok(None)
    }

    async fn get_device_by_name(
        &self,
        _zone_name: &str,
        _device_name: &str,
    ) -> SnResolverResult<Option<ResolverDeviceDocument>> {
        Ok(None)
    }

    async fn get_device_by_did(
        &self,
        _did: &str,
    ) -> SnResolverResult<Option<ResolverDeviceDocument>> {
        Ok(None)
    }

    async fn query_user_did_document(
        &self,
        _owner_user: &str,
        _obj_name: &str,
        _doc_type: Option<&str>,
    ) -> SnResolverResult<Option<ResolverDidDocument>> {
        Ok(None)
    }
}

pub struct EmptyResolverCompatibilityReader;

#[async_trait]
impl ResolverCompatibilityReader for EmptyResolverCompatibilityReader {}

#[async_trait]
pub trait DeviceOnlineReader: Send + Sync + 'static {
    async fn get_device_state(&self, _did: &str) -> SnResolverResult<Option<SnDeviceStateView>> {
        Ok(None)
    }

    async fn get_device_state_by_name(
        &self,
        _zone: &str,
        _device_name: &str,
    ) -> SnResolverResult<Option<SnDeviceStateView>> {
        Ok(None)
    }
}

pub struct EmptyDeviceOnlineReader;

#[async_trait]
impl DeviceOnlineReader for EmptyDeviceOnlineReader {}

pub struct SnDeviceInfoResolverReader {
    db: SnDeviceInfoDBRef,
}

impl SnDeviceInfoResolverReader {
    pub fn new(db: SnDeviceInfoDBRef) -> Self {
        Self { db }
    }
}

#[async_trait]
impl DeviceOnlineReader for SnDeviceInfoResolverReader {
    async fn get_device_state(&self, did: &str) -> SnResolverResult<Option<SnDeviceStateView>> {
        self.db.get_device_state(did).await.map_err(|e| {
            SnResolverError::backend(format!("query device online state {} failed: {}", did, e))
        })
    }

    async fn get_device_state_by_name(
        &self,
        zone: &str,
        device_name: &str,
    ) -> SnResolverResult<Option<SnDeviceStateView>> {
        self.db
            .get_device_state_by_name(zone, device_name)
            .await
            .map_err(|e| {
                SnResolverError::backend(format!(
                    "query device online state {}.{} failed: {}",
                    device_name, zone, e
                ))
            })
    }
}

#[async_trait]
pub trait RelayAssignmentReader: Send + Sync + 'static {
    async fn get_zone_relay(&self, _zone: &str) -> SnResolverResult<Option<RelayAssignment>> {
        Ok(None)
    }
}

pub struct EmptyRelayAssignmentReader;

#[async_trait]
impl RelayAssignmentReader for EmptyRelayAssignmentReader {}

pub struct SnRelayManagerResolverReader {
    manager: SnRelayManagerRef,
}

impl SnRelayManagerResolverReader {
    pub fn new(manager: SnRelayManagerRef) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl RelayAssignmentReader for SnRelayManagerResolverReader {
    async fn get_zone_relay(&self, zone: &str) -> SnResolverResult<Option<RelayAssignment>> {
        self.manager.get_zone_relay(zone).await.map_err(|e| {
            SnResolverError::backend(format!("query relay assignment {} failed: {}", zone, e))
        })
    }
}

#[derive(Debug)]
pub struct SnResolverCache {
    dns: RwLock<HashMap<DnsCacheKey, DnsCacheEntry>>,
    min_ttl: Duration,
}

impl Default for SnResolverCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SnResolverCache {
    pub fn new() -> Self {
        Self {
            dns: RwLock::new(HashMap::new()),
            min_ttl: Duration::from_secs(DEFAULT_SN_RESOLVER_TTL_SECS as u64),
        }
    }

    pub fn query_dns(&self, hostname: &str, record_type: RecordType) -> Option<DnsCacheValue> {
        let key = DnsCacheKey::new(hostname, record_type);
        let now = Instant::now();
        {
            let items = self.dns.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = items.get(&key) {
                if entry.expires_at > now {
                    return Some(entry.value.clone());
                }
            }
        }

        let mut items = self.dns.write().unwrap_or_else(|e| e.into_inner());
        if items
            .get(&key)
            .map(|entry| entry.expires_at <= now)
            .unwrap_or(false)
        {
            items.remove(&key);
        }
        None
    }

    pub fn insert_dns(
        &self,
        hostname: &str,
        record_type: RecordType,
        value: DnsCacheValue,
        ttl: Option<u32>,
    ) {
        let requested = Duration::from_secs(ttl.unwrap_or(DEFAULT_SN_RESOLVER_TTL_SECS) as u64);
        let entry = DnsCacheEntry {
            value,
            expires_at: Instant::now() + requested.max(self.min_ttl),
        };
        self.dns
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(DnsCacheKey::new(hostname, record_type), entry);
    }

    pub fn remove_dns(&self, hostname: &str, record_type: RecordType) -> bool {
        self.dns
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&DnsCacheKey::new(hostname, record_type))
            .is_some()
    }

    pub fn clear(&self) {
        self.dns.write().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

#[derive(Clone, Debug)]
pub enum DnsCacheValue {
    Hit(DnsResolution),
    Tombstone(SnResolverErrorKind),
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DnsCacheKey {
    hostname: String,
    record_type: String,
}

impl DnsCacheKey {
    fn new(hostname: &str, record_type: RecordType) -> Self {
        Self {
            hostname: normalize_host_lossy(hostname),
            record_type: record_type.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct DnsCacheEntry {
    value: DnsCacheValue,
    expires_at: Instant,
}

pub struct SnResolver {
    config: SnResolverConfig,
    auth: SnAuthReaderRef,
    bns: BnsDocumentReaderRef,
    device_online: DeviceOnlineReaderRef,
    relay_reader: RelayAssignmentReaderRef,
    compatibility: ResolverCompatibilityReaderRef,
    cache: Arc<SnResolverCache>,
}

impl SnResolver {
    pub fn new(config: SnResolverConfig, auth: SnAuthReaderRef) -> Self {
        Self::new_with_bns(config, auth, Arc::new(EmptyBnsDocumentReader))
    }

    pub fn new_with_bns(
        config: SnResolverConfig,
        auth: SnAuthReaderRef,
        bns: BnsDocumentReaderRef,
    ) -> Self {
        Self {
            config,
            auth,
            bns,
            device_online: Arc::new(EmptyDeviceOnlineReader),
            relay_reader: Arc::new(EmptyRelayAssignmentReader),
            compatibility: Arc::new(EmptyResolverCompatibilityReader),
            cache: Arc::new(SnResolverCache::new()),
        }
    }

    pub fn new_ref(config: SnResolverConfig, auth: SnAuthReaderRef) -> SnResolverRef {
        Arc::new(Self::new(config, auth))
    }

    pub fn with_bns_reader(mut self, reader: BnsDocumentReaderRef) -> Self {
        self.bns = reader;
        self
    }

    pub fn with_device_online_reader(mut self, reader: DeviceOnlineReaderRef) -> Self {
        self.device_online = reader;
        self
    }

    pub fn with_relay_reader(mut self, reader: RelayAssignmentReaderRef) -> Self {
        self.relay_reader = reader;
        self
    }

    pub fn with_compatibility_reader(mut self, reader: ResolverCompatibilityReaderRef) -> Self {
        self.compatibility = reader;
        self
    }

    pub fn cache(&self) -> Arc<SnResolverCache> {
        self.cache.clone()
    }

    pub fn config(&self) -> &SnResolverConfig {
        &self.config
    }

    pub fn parse_record_type(record_type: &str) -> Option<RecordType> {
        match record_type.trim().to_ascii_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "TXT" => Some(RecordType::TXT),
            _ => None,
        }
    }

    pub fn normalize_hostname(hostname: &str) -> SnResolverResult<String> {
        let name = normalize_host_lossy(hostname);
        if name.is_empty() {
            return Err(SnResolverError::new(
                SnResolverErrorKind::InvalidHostname,
                "hostname is empty",
            ));
        }
        if name.len() > 253 || name.contains(char::is_whitespace) {
            return Err(SnResolverError::new(
                SnResolverErrorKind::InvalidHostname,
                format!("invalid hostname {}", hostname),
            ));
        }
        if name
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
        {
            return Err(SnResolverError::new(
                SnResolverErrorKind::InvalidHostname,
                format!("invalid hostname label in {}", hostname),
            ));
        }
        Ok(name)
    }

    pub fn is_self_hostname(&self, hostname: &str) -> bool {
        let hostname = normalize_host_lossy(hostname);
        let sn_full_host = format!("sn.{}", self.config.server_host);
        hostname == sn_full_host
            || hostname == self.config.server_host
            || self.config.aliases.iter().any(|alias| alias == &hostname)
    }

    pub async fn resolve_dns_cached(
        &self,
        hostname: &str,
        record_type: RecordType,
    ) -> SnResolverResult<DnsResolution> {
        let normalized = Self::normalize_hostname(hostname)?;
        if !is_supported_record_type(record_type) {
            return Err(SnResolverError::new(
                SnResolverErrorKind::UnsupportedRecordType,
                format!("unsupported record type {}", record_type.to_string()),
            ));
        }

        match self.cache.query_dns(normalized.as_str(), record_type) {
            Some(DnsCacheValue::Hit(result)) => {
                debug!(
                    "sn_resolver dns cache hit: {} {}",
                    normalized,
                    record_type.to_string()
                );
                return Ok(result);
            }
            Some(DnsCacheValue::Tombstone(kind)) => {
                debug!(
                    "sn_resolver dns tombstone hit: {} {}",
                    normalized,
                    record_type.to_string()
                );
                return Err(SnResolverError::new(
                    kind,
                    format!("no dns result for {}", normalized),
                ));
            }
            None => {}
        }

        match self.resolve_dns(normalized.as_str(), record_type).await {
            Ok(result) => {
                self.cache.insert_dns(
                    normalized.as_str(),
                    record_type,
                    DnsCacheValue::Hit(result.clone()),
                    Some(result.ttl),
                );
                Ok(result)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    SnResolverErrorKind::NotManaged
                        | SnResolverErrorKind::NameNotFound
                        | SnResolverErrorKind::DocumentNotFound
                        | SnResolverErrorKind::DeviceNotFound
                ) =>
            {
                self.cache.insert_dns(
                    normalized.as_str(),
                    record_type,
                    DnsCacheValue::Tombstone(e.kind()),
                    Some(DEFAULT_SN_RESOLVER_TTL_SECS),
                );
                Err(e)
            }
            Err(e) => Err(e),
        }
    }

    pub async fn resolve_name_info(
        &self,
        query_name: &str,
        record_type: RecordType,
    ) -> SnResolverResult<NameInfo> {
        self.resolve_dns_cached(query_name, record_type)
            .await
            .map(|resolution| resolution.into_name_info(query_name))
    }

    pub async fn resolve_dns(
        &self,
        hostname: &str,
        record_type: RecordType,
    ) -> SnResolverResult<DnsResolution> {
        let hostname = Self::normalize_hostname(hostname)?;
        if !is_supported_record_type(record_type) {
            return Err(SnResolverError::new(
                SnResolverErrorKind::UnsupportedRecordType,
                format!("unsupported record type {}", record_type.to_string()),
            ));
        }

        if self.is_self_hostname(hostname.as_str()) {
            return Ok(self.resolve_self_dns(hostname.as_str(), record_type));
        }

        if let Some((record, ttl)) = self
            .compatibility
            .query_domain_record(hostname.as_str(), record_type)
            .await?
        {
            return explicit_dns_record(hostname.as_str(), record_type, record.as_str(), ttl);
        }

        let zone = self.resolve_zone_by_hostname(hostname.as_str()).await?;

        if record_type == RecordType::TXT {
            let mut txt = self.resolve_zone_txt(&zone).await?;
            if txt.is_empty() {
                return Err(SnResolverError::new(
                    SnResolverErrorKind::DocumentNotFound,
                    format!("TXT document not found for {}", hostname),
                ));
            }
            dedup_strings(&mut txt);
            return Ok(DnsResolution {
                hostname,
                record_type,
                ttl: effective_ttl(
                    &[zone.zone_doc.ttl, zone.boot_doc.ttl],
                    self.config.default_ttl,
                ),
                addresses: Vec::new(),
                txt,
                source: DnsResolutionSource::BnsDocument,
            });
        }

        if !zone.zone_doc.gateway_ips.is_empty() {
            let mut addresses = Vec::new();
            for ip in zone.zone_doc.gateway_ips.iter().copied() {
                push_dns_address(&mut addresses, ip, record_type);
            }
            return Ok(DnsResolution {
                hostname,
                record_type,
                ttl: zone.zone_doc.ttl.unwrap_or(self.config.default_ttl),
                addresses,
                txt: Vec::new(),
                source: DnsResolutionSource::BnsDocument,
            });
        }

        let gateway = self
            .resolve_gateway_for_zone(hostname.as_str(), &zone)
            .await?;
        let mut addresses = Vec::new();
        for ip in gateway.addresses.iter().copied() {
            // 设备来源的 IP 已在 resolve_gateway_addresses 内做过 zonegate
            // 过滤；SN 中继回退地址不再过滤（dev-local 下是 127.0.0.1）。
            push_dns_address_unfiltered(&mut addresses, ip, record_type);
        }

        Ok(DnsResolution {
            hostname,
            record_type,
            ttl: self.config.default_ttl,
            addresses,
            txt: Vec::new(),
            source: DnsResolutionSource::DeviceOnlineInfo,
        })
    }

    pub async fn resolve_gateway_by_hostname(
        &self,
        hostname: &str,
    ) -> SnResolverResult<GatewayResolution> {
        let hostname = Self::normalize_hostname(hostname)?;
        let zone = self.resolve_zone_by_hostname(hostname.as_str()).await?;
        self.resolve_gateway_for_zone(hostname.as_str(), &zone)
            .await
    }

    pub async fn resolve_zone_by_hostname(
        &self,
        hostname: &str,
    ) -> SnResolverResult<ZoneResolution> {
        let hostname = Self::normalize_hostname(hostname)?;

        if let Some(owner) = self.bns.resolve_owner(hostname.as_str()).await? {
            return self
                .resolve_zone_by_bns_owner(
                    hostname.as_str(),
                    hostname.as_str(),
                    owner,
                    ZoneResolutionSource::BnsName,
                    None,
                    None,
                )
                .await;
        }

        if let Some(user) = self.auth.get_user_by_domain(hostname.as_str()).await? {
            let username = user.username.clone().ok_or_else(|| {
                SnResolverError::not_found(format!("user_domain {} has no username", hostname))
            })?;
            return self
                .resolve_zone_by_user(
                    hostname.as_str(),
                    username.as_str(),
                    user,
                    ZoneResolutionSource::UserDomain,
                )
                .await;
        }

        if !hostname.contains('.') {
            return self
                .resolve_zone_by_bns_name(
                    hostname.as_str(),
                    hostname.as_str(),
                    ZoneResolutionSource::BnsName,
                    None,
                )
                .await;
        }

        // BNS 兼容域名（SN-Resolver.md "BNS 兼容域名"）：
        //   alice.web3.<server_host>       -> BNS name alice
        //   home.alice.web3.<server_host>  -> BNS name alice（sub_host 只作
        //   relay 上下文，不决定 owner，这里取 web3 前缀的末级 label）。
        // 旧 URL 的 `www-alice` 连字符规则不在此实现（用户名可含 '-'，
        // 会误切；需要时由显式 dns record 覆盖）。
        if let Some(bns_name) = self.bns_compat_name_of(hostname.as_str()) {
            return self
                .resolve_zone_by_bns_name(
                    bns_name.as_str(),
                    hostname.as_str(),
                    ZoneResolutionSource::BnsName,
                    None,
                )
                .await;
        }

        Err(SnResolverError::new(
            SnResolverErrorKind::NotManaged,
            format!("hostname {} is not managed by this SN", hostname),
        ))
    }

    /// `<...>.<name>.web3.<server_host>` -> `<name>`；不匹配返回 None。
    fn bns_compat_name_of(&self, hostname: &str) -> Option<String> {
        bns_compat_name_for(self.config.server_host.as_str(), hostname)
    }

    pub async fn resolve_zone_by_bns_name(
        &self,
        bns_name: &str,
        input: &str,
        source: ZoneResolutionSource,
        user_domain: Option<String>,
    ) -> SnResolverResult<ZoneResolution> {
        let canonical_name = normalize_bns_name(bns_name)?;
        let bns_owner = self.bns.resolve_owner(canonical_name.as_str()).await?;
        let user = self.auth.get_user_info(canonical_name.as_str()).await?;

        if bns_owner.is_none() && user.is_none() {
            return Err(SnResolverError::new(
                SnResolverErrorKind::NameNotFound,
                format!("BNS name {} not found", canonical_name),
            ));
        }

        let owner =
            bns_owner.unwrap_or_else(|| legacy_owner(canonical_name.as_str(), user.as_ref()));
        self.resolve_zone_by_bns_owner(
            input,
            canonical_name.as_str(),
            owner,
            source,
            user,
            user_domain,
        )
        .await
    }

    pub async fn resolve_relay_for_zone(
        &self,
        zone_name: &str,
    ) -> SnResolverResult<RelayResolution> {
        let zone_name = normalize_bns_name(zone_name)?;
        if let Some(assignment) = self.relay_reader.get_zone_relay(zone_name.as_str()).await? {
            return Ok(relay_resolution_from_assignment(
                zone_name.as_str(),
                assignment,
            ));
        }

        if let Some(zone_info) = self.auth.get_zone_info(zone_name.as_str()).await? {
            if let Some(relay_sn) = zone_info.relay_sn {
                if !relay_sn.trim().is_empty() {
                    return Ok(RelayResolution {
                        zone_name,
                        relay_sn,
                        relay_state: RelayState::Unknown,
                        migration_hint: None,
                    });
                }
            }
        }

        Ok(RelayResolution {
            zone_name,
            relay_sn: UNASSIGNED_RELAY_SN.to_string(),
            relay_state: RelayState::Unknown,
            migration_hint: None,
        })
    }

    pub async fn resolve_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
        _from_ip: Option<IpAddr>,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let doc_type = normalize_doc_type(doc_type);
        match did.method.as_str() {
            "web" => self.resolve_web_did(did, doc_type.as_deref()).await,
            "bns" => self.resolve_bns_did(did, doc_type.as_deref()).await,
            "dev" => self.resolve_dev_did(did, doc_type.as_deref()).await,
            other => Err(SnResolverError::new(
                SnResolverErrorKind::UnsupportedDidMethod,
                format!("unsupported did method {}", other),
            )),
        }
    }

    async fn resolve_zone_by_user(
        &self,
        input: &str,
        username: &str,
        user: SNUserInfo,
        source: ZoneResolutionSource,
    ) -> SnResolverResult<ZoneResolution> {
        let owner = self
            .bns
            .resolve_owner(username)
            .await?
            .unwrap_or_else(|| legacy_owner(username, Some(&user)));
        let user_domain = user.user_domain.clone();

        self.resolve_zone_by_bns_owner(input, username, owner, source, Some(user), user_domain)
            .await
    }

    async fn resolve_zone_by_bns_owner(
        &self,
        input: &str,
        zone_name: &str,
        owner: BnsOwner,
        source: ZoneResolutionSource,
        user: Option<SNUserInfo>,
        user_domain: Option<String>,
    ) -> SnResolverResult<ZoneResolution> {
        let zone_doc = self
            .bns
            .get_document(zone_name, BNS_DOC_ZONE)
            .await?
            .as_ref()
            .map(ZoneDocument::from_bns_document)
            .unwrap_or_else(ZoneDocument::empty);

        let boot_doc =
            if let Some(document) = self.bns.get_document(zone_name, BNS_DOC_BOOT).await? {
                BootDocument::from_bns_document(&document)
            } else if let Some(boot_jwt) = zone_doc.boot_jwt.as_deref() {
                BootDocument::from_legacy_boot_jwt(boot_jwt)
            } else if let Some(user) = user.as_ref() {
                if user.zone_config.trim().is_empty() {
                    BootDocument::empty()
                } else {
                    BootDocument::from_legacy_boot_jwt(user.zone_config.as_str())
                }
            } else {
                BootDocument::empty()
            };

        let zone_info = self.auth.get_zone_info(zone_name).await?;
        let self_cert = zone_info
            .as_ref()
            .map(|info| info.self_cert)
            .or_else(|| user.as_ref().map(|u| u.self_cert))
            .unwrap_or(false);

        let relay_sn = self
            .relay_reader
            .get_zone_relay(zone_name)
            .await?
            .map(|assignment| assignment.relay_sn)
            .or_else(|| zone_info.and_then(|info| info.relay_sn));

        Ok(ZoneResolution {
            input: input.to_string(),
            canonical_name: zone_name.to_string(),
            zone_name: zone_name.to_string(),
            owner,
            zone_doc,
            boot_doc,
            user_domain,
            self_cert,
            relay_sn,
            source,
        })
    }

    async fn resolve_gateway_for_zone(
        &self,
        hostname: &str,
        zone: &ZoneResolution,
    ) -> SnResolverResult<GatewayResolution> {
        let gateway_device_name = zone
            .zone_doc
            .gateway_device_name
            .as_deref()
            .or(zone.boot_doc.gateway_device_name.as_deref())
            .unwrap_or(self.config.legacy_gateway_device_name.as_str())
            .to_string();

        let (device_doc, compatibility_device) = self
            .resolve_device_mini_doc(
                zone.zone_name.as_str(),
                gateway_device_name.as_str(),
                Some(&zone.zone_doc),
            )
            .await?;

        let online = self
            .device_online
            .get_device_state_by_name(zone.zone_name.as_str(), gateway_device_name.as_str())
            .await?;

        let addresses = self
            .resolve_gateway_addresses(
                zone,
                &device_doc,
                compatibility_device.as_ref(),
                online.as_ref(),
            )
            .await;

        Ok(GatewayResolution {
            zone_name: zone.zone_name.clone(),
            hostname: hostname.to_string(),
            gateway_device_name,
            gateway_did: device_doc.did.clone(),
            device_doc,
            online,
            addresses,
            relay_sn: zone.relay_sn.clone(),
            self_cert: zone.self_cert,
        })
    }

    /// 按 (zone, device_name) 解析 zone 权威侧登记的设备身份文档，返回其中的
    /// 设备 DID（通常是 `did:dev:<x>`，公钥内嵌）。来源优先级与内部设备解析
    /// 一致：BNS `<device>.<zone>` 单文档 → zone 级 `device_mini_doc` 聚合 →
    /// zone doc devices → 兼容期 devices 表。`sn_authority` 用它锚定设备
    /// token 的公钥，不存在时返回 `DeviceNotFound`。
    pub async fn resolve_zone_device_did(
        &self,
        zone_name: &str,
        device_name: &str,
    ) -> SnResolverResult<String> {
        let (device_doc, _) = self
            .resolve_device_mini_doc(zone_name, device_name, None)
            .await?;
        Ok(device_doc.did)
    }

    async fn resolve_device_mini_doc(
        &self,
        zone_name: &str,
        device_name: &str,
        zone_doc: Option<&ZoneDocument>,
    ) -> SnResolverResult<(DeviceMiniDocument, Option<ResolverDeviceDocument>)> {
        let child_name = format!("{}.{}", device_name, zone_name);
        for doc_type in [BNS_DOC_DEVICE_MINI, "doc"] {
            if let Some(document) = self.bns.get_document(child_name.as_str(), doc_type).await? {
                if let Some(device_doc) = device_doc_from_single(
                    zone_name,
                    device_name,
                    &document,
                    Some(child_name.as_str()),
                ) {
                    return Ok((device_doc, None));
                }
            }
        }

        if let Some(document) = self
            .bns
            .get_document(zone_name, BNS_DOC_DEVICE_MINI)
            .await?
        {
            if let Some(device_doc) = device_doc_from_aggregate(zone_name, device_name, &document) {
                return Ok((device_doc, None));
            }
        }

        if let Some(zone_doc) = zone_doc {
            if let Some(device_doc) = device_doc_from_map(
                zone_name,
                device_name,
                &zone_doc.devices,
                zone_doc.ttl,
                zone_doc.version,
            ) {
                return Ok((device_doc, None));
            }
        } else if let Some(document) = self.bns.get_document(zone_name, BNS_DOC_ZONE).await? {
            let zone_doc = ZoneDocument::from_bns_document(&document);
            if let Some(device_doc) = device_doc_from_map(
                zone_name,
                device_name,
                &zone_doc.devices,
                zone_doc.ttl,
                zone_doc.version,
            ) {
                return Ok((device_doc, None));
            }
        }

        let compatibility_device = self
            .compatibility
            .get_device_by_name(zone_name, device_name)
            .await?
            .ok_or_else(|| {
                SnResolverError::new(
                    SnResolverErrorKind::DeviceNotFound,
                    format!("device {}.{} not found", device_name, zone_name),
                )
            })?;

        let device_doc = compatibility_device.to_device_mini_document();
        Ok((device_doc, Some(compatibility_device)))
    }

    async fn resolve_gateway_addresses(
        &self,
        zone: &ZoneResolution,
        device_doc: &DeviceMiniDocument,
        compatibility_device: Option<&ResolverDeviceDocument>,
        online: Option<&SnDeviceStateView>,
    ) -> Vec<IpAddr> {
        let mut addresses = Vec::new();

        for ip in zone.zone_doc.gateway_ips.iter().copied() {
            push_exportable_ip(&mut addresses, ip);
        }

        // net_id comes from the owner-signed device document and describes the
        // intended ingress topology. Prefer it over IP-shape inference: a NAT
        // device can legitimately report a global IPv6 address that is not an
        // externally reachable gateway endpoint (for example, a host address
        // observed while activating a VM). In that case the online-state
        // heuristic marks the device as WAN, but DNS must still include the SN
        // relay selected by the signed topology.
        let requires_sn_relay = device_document_requires_sn_relay(device_doc)
            .or_else(|| online.map(|online| !online.is_wan_device))
            .unwrap_or(false);
        if requires_sn_relay {
            let sn_ips = self
                .auth
                .get_user_sn_ips(zone.zone_name.as_str())
                .await
                .unwrap_or_default();
            if sn_ips.is_empty() {
                push_exportable_ip(&mut addresses, self.config.server_ip);
            } else {
                for ip in sn_ips {
                    push_exportable_ip(&mut addresses, ip);
                }
            }
        }

        if let Some(online) = online {
            for value in online
                .public_ips
                .iter()
                .chain(online.private_ips.iter())
                .map(|s| s.as_str())
            {
                if let Some(ip) = parse_ip_or_socket_addr(value) {
                    push_exportable_ip(&mut addresses, ip);
                }
            }

            for endpoint in &online.active_endpoints {
                if let Some(ip) = parse_ip_or_socket_addr(endpoint.host.as_str()) {
                    push_exportable_ip(&mut addresses, ip);
                }
            }
        }

        if let Some(compatibility_device) = compatibility_device {
            for ip in compatibility_device.addresses.iter().copied() {
                push_exportable_ip(&mut addresses, ip);
            }
        }

        if let Some(value) = device_doc.document.as_ref() {
            for key in ["ip", "ips", "all_ip", "addresses"] {
                collect_ips_from_value_path(value, &[key], &mut addresses);
            }
        }

        if addresses.is_empty() {
            // 没有任何直接可达地址（设备离线的 LAN/relay 型 zone，或文档
            // 未带 IP）：回退 SN 中继地址（用户 sn_ips 优先，否则本 SN
            // server_ip），与上面"在线但非 WAN 设备"分支同语义——流量落到
            // SN 后经 rtcp 隧道转发。空答案（NXDOMAIN）会让 *.web3 域名在
            // 设备未上线时完全不可达。SN 自身地址与 resolve_self_dns 同
            // 信任级，不做 zonegate 回环过滤（dev-local 的 sn_ip 就是
            // 127.0.0.1）。
            let sn_ips = self
                .auth
                .get_user_sn_ips(zone.zone_name.as_str())
                .await
                .unwrap_or_default();
            let relay_ips = if sn_ips.is_empty() {
                vec![self.config.server_ip]
            } else {
                sn_ips
            };
            for ip in relay_ips {
                if !addresses.contains(&ip) {
                    addresses.push(ip);
                }
            }
        }

        addresses
    }

    async fn resolve_zone_txt(&self, zone: &ZoneResolution) -> SnResolverResult<Vec<String>> {
        let mut txt = Vec::new();

        let legacy_user = self.auth.get_user_info(zone.zone_name.as_str()).await?;
        if let Some(x) = owner_pkx_from_owner_config(&zone.owner).or_else(|| {
            legacy_user
                .as_ref()
                .and_then(|user| pkx_from_public_key(user.public_key.as_str()))
        }) {
            txt.push(format!("PKX={};", x));
        }

        if let Some(jwt) = zone.boot_doc.jwt.as_ref() {
            txt.push(format!("BOOT={};", jwt));
        } else if let Some(raw) = zone.boot_doc.raw.as_ref() {
            txt.push(format!("BOOT={};", raw));
        }

        let mut device_jwt_source_found = false;
        if let Some(document) = self
            .bns
            .get_document(zone.zone_name.as_str(), BNS_DOC_DEVICE_MINI)
            .await?
        {
            device_jwt_source_found = true;
            for jwt in device_jwts_from_bns_document(&document) {
                txt.push(format!("DEV={};", jwt));
            }
        } else if !zone.zone_doc.devices.is_empty() {
            device_jwt_source_found = true;
            for jwt in device_jwts_from_map(&zone.zone_doc.devices) {
                txt.push(format!("DEV={};", jwt));
            }
        }

        if !device_jwt_source_found {
            if let Some(device) = self
                .compatibility
                .get_device_by_name(
                    zone.zone_name.as_str(),
                    zone.zone_doc
                        .gateway_device_name
                        .as_deref()
                        .or(zone.boot_doc.gateway_device_name.as_deref())
                        .unwrap_or(self.config.legacy_gateway_device_name.as_str()),
                )
                .await?
            {
                if let Some(mini_config_jwt) = device.mini_config_jwt {
                    if !mini_config_jwt.trim().is_empty() {
                        txt.push(format!("DEV={};", mini_config_jwt));
                    }
                }
            }
        }

        if let Some(dns_txt_doc) = self
            .bns
            .get_document(zone.zone_name.as_str(), BNS_DOC_DNS_TXT)
            .await?
        {
            txt.extend(txt_records_from_bns_document(&dns_txt_doc));
        }

        Ok(txt)
    }

    fn resolve_self_dns(&self, hostname: &str, record_type: RecordType) -> DnsResolution {
        match record_type {
            RecordType::A | RecordType::AAAA => {
                let mut addresses = Vec::new();
                push_dns_address(&mut addresses, self.config.server_ip, record_type);
                DnsResolution {
                    hostname: hostname.to_string(),
                    record_type,
                    ttl: self.config.default_ttl,
                    addresses,
                    txt: Vec::new(),
                    source: DnsResolutionSource::SnSelf,
                }
            }
            RecordType::TXT => {
                let mut txt = Vec::new();
                if let Some(x) = pkx_from_public_key(self.config.owner_pkx.as_str()) {
                    txt.push(format!("PKX={};", x));
                } else if !self.config.owner_pkx.trim().is_empty() {
                    txt.push(format!("PKX={};", self.config.owner_pkx));
                }
                if !self.config.boot_jwt.trim().is_empty() {
                    txt.push(format!("BOOT={};", self.config.boot_jwt));
                }
                for jwt in &self.config.device_jwts {
                    if !jwt.trim().is_empty() {
                        txt.push(format!("DEV={};", jwt));
                    }
                }
                DnsResolution {
                    hostname: hostname.to_string(),
                    record_type,
                    ttl: self.config.default_ttl,
                    addresses: Vec::new(),
                    txt,
                    source: DnsResolutionSource::SnSelf,
                }
            }
            _ => DnsResolution {
                hostname: hostname.to_string(),
                record_type,
                ttl: self.config.default_ttl,
                addresses: Vec::new(),
                txt: Vec::new(),
                source: DnsResolutionSource::SnSelf,
            },
        }
    }

    async fn resolve_web_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let id = normalize_host_lossy(did.id.as_str());
        let user = self.auth.get_user_by_domain(id.as_str()).await?;
        let Some(user) = user else {
            return Err(SnResolverError::new(
                SnResolverErrorKind::NameNotFound,
                format!("user_domain {} not found", id),
            ));
        };

        let username = user.username.clone().ok_or_else(|| {
            SnResolverError::not_found(format!("user_domain {} has no username", id))
        })?;

        if let Some(domain) = user.user_domain.as_deref() {
            let domain = normalize_host_lossy(domain);
            if id != domain {
                let suffix = format!(".{}", domain);
                if let Some(device_name) = id.strip_suffix(suffix.as_str()) {
                    let mapped =
                        DID::from_str(format!("did:bns:{}.{}", device_name, username).as_str())
                            .map_err(|e| {
                                SnResolverError::new(
                                    SnResolverErrorKind::InvalidDid,
                                    format!("invalid mapped bns did: {}", e),
                                )
                            })?;
                    return self.resolve_bns_did(&mapped, doc_type).await;
                }
            }
        }

        let mapped = DID::from_str(format!("did:bns:{}", username).as_str()).map_err(|e| {
            SnResolverError::new(
                SnResolverErrorKind::InvalidDid,
                format!("invalid mapped bns did: {}", e),
            )
        })?;
        self.resolve_bns_did(&mapped, doc_type).await
    }

    async fn resolve_bns_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let id = did.id.as_str();
        if let Some((obj_name, tail)) = id.split_once('.') {
            let zone_name = if tail.contains('.') {
                self.auth
                    .get_user_by_domain(tail)
                    .await?
                    .and_then(|user| user.username)
                    .ok_or_else(|| {
                        SnResolverError::new(
                            SnResolverErrorKind::NameNotFound,
                            format!("user_domain {} not found", tail),
                        )
                    })?
            } else {
                tail.to_string()
            };

            let doc_type = doc_type.unwrap_or("doc");
            return self
                .resolve_bns_object_doc(did, zone_name.as_str(), obj_name, doc_type)
                .await;
        }

        let zone_name = normalize_bns_name(id)?;
        let doc_type = doc_type.unwrap_or(BNS_DOC_ZONE);
        if let Some(document) = self.bns.get_document(zone_name.as_str(), doc_type).await? {
            return Ok(did_response(
                did,
                doc_type,
                document.content.to_encoded_document(),
                SnDidDocumentSource::BnsDocument,
            ));
        }

        match doc_type {
            BNS_DOC_ZONE | BNS_DOC_BOOT => {
                let user = self.auth.get_user_info(zone_name.as_str()).await?;
                if let Some(user) = user {
                    let document = if doc_type == BNS_DOC_ZONE {
                        build_legacy_zone_config_json(zone_name.as_str(), &user)
                    } else {
                        json!({ "boot": user.zone_config })
                    };
                    return Ok(did_response(
                        did,
                        doc_type,
                        EncodedDocument::JsonLd(document),
                        SnDidDocumentSource::LegacyCompatibilityStore,
                    ));
                }

                let kind = if self.bns.resolve_owner(zone_name.as_str()).await?.is_some() {
                    SnResolverErrorKind::DocumentNotFound
                } else {
                    SnResolverErrorKind::NameNotFound
                };
                Err(SnResolverError::new(
                    kind,
                    format!("BNS document {}/{} not found", zone_name, doc_type),
                ))
            }
            device_name => {
                if let Ok((device_doc, compatibility_device)) = self
                    .resolve_device_mini_doc(zone_name.as_str(), device_name, None)
                    .await
                {
                    let document =
                        device_document_or_fallback(device_doc, compatibility_device.as_ref());
                    return Ok(did_response(
                        did,
                        device_name,
                        EncodedDocument::JsonLd(document),
                        SnDidDocumentSource::DeviceMiniDocument,
                    ));
                }

                self.resolve_legacy_local_did_doc(
                    did,
                    zone_name.as_str(),
                    device_name,
                    Some(device_name),
                )
                .await
            }
        }
    }

    async fn resolve_bns_object_doc(
        &self,
        did: &DID,
        zone_name: &str,
        obj_name: &str,
        doc_type: &str,
    ) -> SnResolverResult<SnDidResolveResponse> {
        match doc_type {
            "doc" => {
                let (device_doc, compatibility_device) = self
                    .resolve_device_mini_doc(zone_name, obj_name, None)
                    .await?;
                let document =
                    device_document_or_fallback(device_doc, compatibility_device.as_ref());
                Ok(did_response(
                    did,
                    doc_type,
                    EncodedDocument::JsonLd(document),
                    SnDidDocumentSource::DeviceMiniDocument,
                ))
            }
            "info" => {
                if let Some(online) = self
                    .device_online
                    .get_device_state_by_name(zone_name, obj_name)
                    .await?
                {
                    return Ok(did_response(
                        did,
                        doc_type,
                        EncodedDocument::JsonLd(device_online_info_document(&online)),
                        SnDidDocumentSource::DeviceOnlineInfo,
                    ));
                }

                if let Ok((device_doc, compatibility_device)) = self
                    .resolve_device_mini_doc(zone_name, obj_name, None)
                    .await
                {
                    return Ok(did_response(
                        did,
                        doc_type,
                        EncodedDocument::JsonLd(device_offline_info_document(
                            &device_doc,
                            compatibility_device.as_ref(),
                        )),
                        SnDidDocumentSource::DeviceMiniDocument,
                    ));
                }

                let compatibility_device = self
                    .compatibility
                    .get_device_by_name(zone_name, obj_name)
                    .await?
                    .ok_or_else(|| {
                        SnResolverError::new(
                            SnResolverErrorKind::DeviceNotFound,
                            format!("device {}.{} not found", obj_name, zone_name),
                        )
                    })?;
                Ok(did_response(
                    did,
                    doc_type,
                    EncodedDocument::JsonLd(device_info_document_or_fallback(
                        &compatibility_device,
                    )),
                    SnDidDocumentSource::LegacyCompatibilityStore,
                ))
            }
            other => {
                let child_name = format!("{}.{}", obj_name, zone_name);
                if let Some(document) = self.bns.get_document(child_name.as_str(), other).await? {
                    return Ok(did_response(
                        did,
                        other,
                        document.content.to_encoded_document(),
                        SnDidDocumentSource::BnsDocument,
                    ));
                }
                self.resolve_legacy_local_did_doc(did, zone_name, obj_name, Some(other))
                    .await
            }
        }
    }

    async fn resolve_dev_did(
        &self,
        did: &DID,
        doc_type: Option<&str>,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let doc_type = doc_type.unwrap_or("doc");
        let did_str = did.to_string();
        let online = self
            .device_online
            .get_device_state(did_str.as_str())
            .await?;
        if doc_type == "info" {
            if let Some(online) = online {
                return Ok(did_response_str(
                    did_str,
                    doc_type,
                    EncodedDocument::JsonLd(device_online_info_document(&online)),
                    SnDidDocumentSource::DeviceOnlineInfo,
                ));
            }
        }

        let compatibility_device = self
            .compatibility
            .get_device_by_did(did_str.as_str())
            .await?;
        if let Some(compatibility_device) = compatibility_device {
            return match doc_type {
                "doc" => Ok(did_response_str(
                    did_str,
                    doc_type,
                    EncodedDocument::JsonLd(device_document_or_fallback(
                        compatibility_device.to_device_mini_document(),
                        Some(&compatibility_device),
                    )),
                    SnDidDocumentSource::DeviceMiniDocument,
                )),
                "info" => Ok(did_response_str(
                    did_str,
                    doc_type,
                    EncodedDocument::JsonLd(device_info_document_or_fallback(
                        &compatibility_device,
                    )),
                    SnDidDocumentSource::LegacyCompatibilityStore,
                )),
                other => Err(SnResolverError::new(
                    SnResolverErrorKind::DocumentNotFound,
                    format!("unsupported doc_type {} for {}", other, did_str),
                )),
            };
        }

        if let Some(online) = online {
            if doc_type == "doc" {
                let (device_doc, _) = self
                    .resolve_device_mini_doc(
                        online.zone.as_str(),
                        online.device_name.as_str(),
                        None,
                    )
                    .await?;
                return Ok(did_response_str(
                    did_str,
                    doc_type,
                    EncodedDocument::JsonLd(device_doc.document.unwrap_or_else(|| {
                        json!({
                            "id": device_doc.did,
                            "name": device_doc.device_name,
                            "zone": device_doc.zone_name,
                            "mini_config_jwt": device_doc.mini_config_jwt,
                        })
                    })),
                    SnDidDocumentSource::DeviceMiniDocument,
                ));
            }
        }

        Err(SnResolverError::new(
            SnResolverErrorKind::DeviceNotFound,
            format!("device {} not found", did_str),
        ))
    }

    async fn resolve_legacy_local_did_doc(
        &self,
        did: &DID,
        owner_user: &str,
        obj_name: &str,
        doc_type: Option<&str>,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let Some(did_document) = self
            .compatibility
            .query_user_did_document(owner_user, obj_name, doc_type)
            .await?
        else {
            return Err(SnResolverError::new(
                SnResolverErrorKind::DocumentNotFound,
                format!("did document not found for {}/{}", owner_user, obj_name),
            ));
        };

        let value = if did_document.document_json.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str::<Value>(did_document.document_json.as_str()).map_err(|e| {
                SnResolverError::new(
                    SnResolverErrorKind::BackendUnavailable,
                    format!("invalid stored did document json: {}", e),
                )
            })?
        };

        Ok(did_response(
            did,
            did_document
                .doc_type
                .unwrap_or_else(|| doc_type.unwrap_or("doc").to_string()),
            EncodedDocument::JsonLd(value),
            SnDidDocumentSource::LegacyCompatibilityStore,
        ))
    }
}

fn did_response(
    did: &DID,
    doc_type: impl Into<String>,
    document: EncodedDocument,
    source: SnDidDocumentSource,
) -> SnDidResolveResponse {
    did_response_str(did.to_string(), doc_type, document, source)
}

fn did_response_str(
    did: impl Into<String>,
    doc_type: impl Into<String>,
    document: EncodedDocument,
    source: SnDidDocumentSource,
) -> SnDidResolveResponse {
    SnDidResolveResponse {
        did: did.into(),
        doc_type: doc_type.into(),
        document,
        source,
        profile: SnDidResolverProfile::PublicSupplement,
        document_status: None,
        metadata: Value::Null,
    }
}

impl DnsResolution {
    pub fn into_name_info(self, query_name: &str) -> NameInfo {
        let mut name_info = NameInfo::new(query_name);
        name_info.ttl = Some(self.ttl);
        name_info.address = self.addresses;
        name_info.txt = self.txt;
        name_info
    }
}

fn is_supported_record_type(record_type: RecordType) -> bool {
    matches!(
        record_type,
        RecordType::A | RecordType::AAAA | RecordType::TXT
    )
}

fn normalize_host_lossy(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_bns_name(name: &str) -> SnResolverResult<String> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    canonical_bns_name(name.as_str()).map_err(|_| {
        SnResolverError::new(
            SnResolverErrorKind::InvalidHostname,
            format!("invalid BNS name {}", name),
        )
    })
}

fn normalize_doc_type(doc_type: Option<&str>) -> Option<String> {
    doc_type.and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

fn legacy_owner(name: &str, user: Option<&SNUserInfo>) -> BnsOwner {
    BnsOwner {
        name: name.to_string(),
        effective_owner: user
            .and_then(|user| pkx_from_public_key(user.public_key.as_str()))
            .or_else(|| user.map(|user| user.public_key.clone())),
        owner_config: None,
    }
}

fn parse_sn_ips(sn_ips: Option<&str>, username: &str) -> Vec<IpAddr> {
    sn_ips
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .filter_map(|value| {
            value
                .parse::<IpAddr>()
                .map_err(|e| warn!("invalid sn_ip {} for {}: {}", value, username, e))
                .ok()
        })
        .collect()
}

fn relay_resolution_from_assignment(
    zone_name: &str,
    assignment: RelayAssignment,
) -> RelayResolution {
    let relay_state = match assignment.state {
        RelayAssignmentState::Active => RelayState::Healthy,
        RelayAssignmentState::Migrating | RelayAssignmentState::Draining => RelayState::Draining,
        RelayAssignmentState::Suspended => RelayState::Offline,
    };

    let migration_hint = if assignment.migrated_from.is_some()
        || assignment.migration_deadline.is_some()
        || assignment.state == RelayAssignmentState::Migrating
    {
        Some(RelayMigrationHint {
            migrated_from: assignment.migrated_from,
            migration_deadline: assignment.migration_deadline,
            generation: Some(assignment.generation),
        })
    } else {
        None
    };

    RelayResolution {
        zone_name: zone_name.to_string(),
        relay_sn: assignment.relay_sn,
        relay_state,
        migration_hint,
    }
}

fn effective_ttl(values: &[Option<u32>], default_ttl: u32) -> u32 {
    values
        .iter()
        .filter_map(|ttl| *ttl)
        .min()
        .unwrap_or(default_ttl)
}

fn explicit_dns_record(
    hostname: &str,
    record_type: RecordType,
    record: &str,
    ttl: u32,
) -> SnResolverResult<DnsResolution> {
    match record_type {
        RecordType::TXT => Ok(DnsResolution {
            hostname: hostname.to_string(),
            record_type,
            ttl,
            addresses: Vec::new(),
            txt: split_record_values(record),
            source: DnsResolutionSource::ExplicitRecord,
        }),
        RecordType::A | RecordType::AAAA => {
            let mut addresses = Vec::new();
            for value in split_record_values(record) {
                if let Some(ip) = parse_ip_or_socket_addr(value.as_str()) {
                    push_dns_address_unfiltered(&mut addresses, ip, record_type);
                }
            }
            Ok(DnsResolution {
                hostname: hostname.to_string(),
                record_type,
                ttl,
                addresses,
                txt: Vec::new(),
                source: DnsResolutionSource::ExplicitRecord,
            })
        }
        _ => Err(SnResolverError::new(
            SnResolverErrorKind::UnsupportedRecordType,
            format!("unsupported record type {}", record_type.to_string()),
        )),
    }
}

fn split_record_values(record: &str) -> Vec<String> {
    record
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn owner_pkx_from_owner_config(owner: &BnsOwner) -> Option<String> {
    owner
        .owner_config
        .as_ref()
        .and_then(|value| {
            find_string_path(value, &["public_key", "x"])
                .or_else(|| find_string_path(value, &["owner_key", "x"]))
                .or_else(|| find_string_path(value, &["default_key", "x"]))
                .or_else(|| find_string_path(value, &["x"]))
        })
        .or_else(|| owner.effective_owner.clone())
}

fn pkx_from_public_key(public_key: &str) -> Option<String> {
    let value = serde_json::from_str::<Value>(public_key).ok()?;
    find_string_path(&value, &["x"])
}

fn device_document_or_fallback(
    device_doc: DeviceMiniDocument,
    compatibility_device: Option<&ResolverDeviceDocument>,
) -> Value {
    compatibility_device
        .and_then(|device| device.document.clone())
        .or(device_doc.document)
        .unwrap_or_else(|| {
            json!({
                "id": device_doc.did,
                "name": device_doc.device_name,
                "zone": device_doc.zone_name,
                "mini_config_jwt": device_doc.mini_config_jwt,
            })
        })
}

fn device_info_document_or_fallback(device: &ResolverDeviceDocument) -> Value {
    device
        .info_document
        .clone()
        .or_else(|| device.document.clone())
        .unwrap_or_else(|| {
            json!({
                "did": device.did,
                "device_name": device.device_name,
                "owner": device.zone_name,
                "mini_config_jwt": device.mini_config_jwt,
                "addresses": device.addresses,
            })
        })
}

fn device_offline_info_document(
    device_doc: &DeviceMiniDocument,
    compatibility_device: Option<&ResolverDeviceDocument>,
) -> Value {
    if let Some(compatibility_device) = compatibility_device {
        return device_info_document_or_fallback(compatibility_device);
    }

    json!({
        "did": device_doc.did.clone(),
        "device_name": device_doc.device_name.clone(),
        "owner": device_doc.zone_name.clone(),
        "zone_name": device_doc.zone_name.clone(),
        "mini_config_jwt": device_doc.mini_config_jwt.clone(),
        "state": "offline",
        "public_ips": [],
        "private_ips": [],
        "active_endpoints": [],
        "preferred_endpoint": null,
        "nat_type": "unknown",
        "is_wan_device": false,
        "last_seen_at": null,
        "expires_at": null,
    })
}

fn device_online_info_document(online: &SnDeviceStateView) -> Value {
    let mut value = serde_json::to_value(online).unwrap_or_else(|_| json!({}));
    if let Some(obj) = value.as_object_mut() {
        obj.entry("owner".to_string())
            .or_insert_with(|| Value::String(online.zone.clone()));
        obj.entry("zone_name".to_string())
            .or_insert_with(|| Value::String(online.zone.clone()));

        let exportable_ips: Vec<Value> = online
            .public_ips
            .iter()
            .chain(online.private_ips.iter())
            .cloned()
            .map(Value::String)
            .collect();

        if let Some(first_ip) = exportable_ips.first().cloned() {
            obj.entry("ip".to_string()).or_insert(first_ip);
        }
        obj.entry("ips".to_string())
            .or_insert_with(|| Value::Array(exportable_ips.clone()));
        obj.entry("all_ip".to_string())
            .or_insert_with(|| Value::Array(exportable_ips));
    }

    value
}

fn find_gateway_device_name(value: &Value) -> Option<String> {
    for path in [
        &["gateway_device_name"][..],
        &["gateway_device"][..],
        &["default_gateway"][..],
        &["gateway", "device_name"][..],
        &["gateway", "name"][..],
        &["gateway", "device"][..],
        &["boot", "gateway_device_name"][..],
    ] {
        if let Some(name) = find_string_path(value, path) {
            return Some(name);
        }
    }

    for path in [&["gateway_devices"][..], &["oods"][..]] {
        if let Some(array) = find_array_path(value, path) {
            for item in array {
                if let Some(name) = item.as_str() {
                    return Some(short_device_name(name));
                }
                if let Some(name) = find_string_path(item, &["device_name"])
                    .or_else(|| find_string_path(item, &["name"]))
                {
                    return Some(short_device_name(name.as_str()));
                }
            }
        }
    }

    None
}

fn find_boot_jwt(value: &Value) -> Option<String> {
    // Shared with the SN controller's write side so the embedded boot_jwt is read
    // back through the exact same locations it was written through.
    bns_client::dns_document::extract_boot_jwt(value)
}

fn find_device_mini_map(value: &Value) -> HashMap<String, Value> {
    let mut result = HashMap::new();
    for path in [
        &["devices"][..],
        &["device_mini_doc", "devices"][..],
        &["device_mini_docs", "devices"][..],
    ] {
        if let Some(devices) = find_object_path(value, path) {
            for (name, device) in devices {
                result.entry(name.clone()).or_insert_with(|| device.clone());
            }
        }
    }
    result
}

fn short_device_name(value: &str) -> String {
    value.split('.').next().unwrap_or(value).to_string()
}

fn find_gateway_ips(value: &Value) -> Vec<IpAddr> {
    let mut result = Vec::new();
    for path in [
        &["gateway_ips"][..],
        &["gateway", "ips"][..],
        &["gateway", "addresses"][..],
        &["addresses"][..],
    ] {
        collect_ips_from_value_path(value, path, &mut result);
    }
    result
}

fn find_ttl(value: &Value) -> Option<u32> {
    value
        .get("ttl")
        .and_then(|ttl| ttl.as_u64())
        .and_then(|ttl| u32::try_from(ttl).ok())
}

fn find_string_path(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(ToOwned::to_owned)
}

fn find_array_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Vec<Value>> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_array()
}

fn find_object_path<'a>(
    value: &'a Value,
    path: &[&str],
) -> Option<&'a serde_json::Map<String, Value>> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_object()
}

fn collect_ips_from_value_path(value: &Value, path: &[&str], result: &mut Vec<IpAddr>) {
    let mut current = value;
    for key in path {
        let Some(next) = current.get(*key) else {
            return;
        };
        current = next;
    }

    if let Some(value) = current.as_str() {
        if let Some(ip) = parse_ip_or_socket_addr(value) {
            push_exportable_ip(result, ip);
        }
        return;
    }

    if let Some(values) = current.as_array() {
        for value in values {
            if let Some(value) = value.as_str() {
                if let Some(ip) = parse_ip_or_socket_addr(value) {
                    push_exportable_ip(result, ip);
                }
            }
        }
    }
}

fn device_jwts_from_bns_document(document: &BnsDocument) -> Vec<String> {
    let mut result = Vec::new();
    let Some(value) = document.content.to_json_value() else {
        if let Some(jwt) = document.content.as_jwt() {
            result.push(jwt);
        }
        return result;
    };

    if let Some(devices) = value.get("devices").and_then(|v| v.as_object()) {
        for device in devices.values() {
            if let Some(jwt) = find_string_path(device, &["device_mini_document_jwt"])
                .or_else(|| find_string_path(device, &["mini_config_jwt"]))
            {
                result.push(jwt);
            }
        }
    }

    if let Some(mini_device_jwts) = value.get("mini_device_jwts").and_then(Value::as_object) {
        result.extend(
            mini_device_jwts
                .values()
                .filter_map(Value::as_str)
                .map(ToString::to_string),
        );
    }

    if let Some(jwt) = find_string_path(&value, &["mini_config_jwt"]) {
        result.push(jwt);
    }

    result
}

fn device_jwts_from_map(devices: &HashMap<String, Value>) -> Vec<String> {
    let mut result = Vec::new();
    for device in devices.values() {
        if let Some(jwt) = find_string_path(device, &["device_mini_document_jwt"])
            .or_else(|| find_string_path(device, &["mini_config_jwt"]))
        {
            result.push(jwt);
        }
    }
    result
}

fn txt_records_from_bns_document(document: &BnsDocument) -> Vec<String> {
    let Some(value) = document.content.to_json_value() else {
        return document
            .content
            .as_jwt()
            .map(|text| vec![text])
            .unwrap_or_default();
    };

    let mut result = Vec::new();
    if let Some(records) = value.as_array() {
        for record in records {
            if let Some(txt) = record.as_str() {
                result.push(txt.to_string());
            } else if let Some(txt) = record.get("value").and_then(|v| v.as_str()) {
                result.push(txt.to_string());
            } else if let Some(values) = record.get("values").and_then(|v| v.as_array()) {
                for value in values.iter().filter_map(|v| v.as_str()) {
                    result.push(value.to_string());
                }
            }
        }
    } else if let Some(records) = value.get("records").and_then(|v| v.as_array()) {
        for record in records {
            if let Some(txt) = record.as_str() {
                result.push(txt.to_string());
            } else if let Some(txt) = record.get("value").and_then(|v| v.as_str()) {
                result.push(txt.to_string());
            }
        }
    } else if let Some(txt) = value.get("txt").and_then(|v| v.as_str()) {
        result.push(txt.to_string());
    }

    result
}

fn device_doc_from_map(
    zone_name: &str,
    device_name: &str,
    devices: &HashMap<String, Value>,
    ttl: Option<u32>,
    version: Option<u64>,
) -> Option<DeviceMiniDocument> {
    let device_value = devices.get(device_name)?;
    device_doc_from_value(zone_name, device_name, device_value, ttl, version)
}

fn device_doc_from_aggregate(
    zone_name: &str,
    device_name: &str,
    document: &BnsDocument,
) -> Option<DeviceMiniDocument> {
    let value = document.content.to_json_value()?;
    let device_value = value
        .get("devices")
        .and_then(|v| v.as_object())
        .and_then(|devices| devices.get(device_name))
        .or_else(|| value.get(device_name))?;

    let mut result = device_doc_from_value(
        zone_name,
        device_name,
        device_value,
        document.meta.ttl,
        document.meta.version,
    )?;
    if result.mini_config_jwt.is_none() {
        result.mini_config_jwt = value
            .get("mini_device_jwts")
            .and_then(Value::as_object)
            .and_then(|jwts| jwts.get(device_name))
            .and_then(Value::as_str)
            .map(ToString::to_string);
    }
    Some(result)
}

fn device_doc_from_single(
    zone_name: &str,
    device_name: &str,
    document: &BnsDocument,
    child_name: Option<&str>,
) -> Option<DeviceMiniDocument> {
    let value = document.content.to_json_value()?;
    let inferred_name = child_name
        .and_then(|name| name.split('.').next())
        .unwrap_or(device_name);
    device_doc_from_value(
        zone_name,
        inferred_name,
        &value,
        document.meta.ttl,
        document.meta.version,
    )
}

fn device_doc_from_value(
    zone_name: &str,
    fallback_device_name: &str,
    value: &Value,
    ttl: Option<u32>,
    version: Option<u64>,
) -> Option<DeviceMiniDocument> {
    let device_name = find_string_path(value, &["device_name"])
        .or_else(|| find_string_path(value, &["name"]))
        .or_else(|| find_string_path(value, &["n"]))
        .unwrap_or_else(|| fallback_device_name.to_string());
    let did = device_public_key_x(value)
        .map(|x| format!("did:dev:{}", x))
        .or_else(|| find_string_path(value, &["did"]))
        .or_else(|| find_string_path(value, &["id"]))
        .or_else(|| find_string_path(value, &["x"]).map(|x| format!("did:dev:{}", x)))?;
    let mini_config_jwt = find_string_path(value, &["mini_config_jwt"])
        .or_else(|| find_string_path(value, &["device_mini_config_jwt"]))
        .or_else(|| find_string_path(value, &["device_mini_document_jwt"]));

    Some(DeviceMiniDocument {
        zone_name: zone_name.to_string(),
        device_name,
        did,
        mini_config_jwt,
        document: Some(value.clone()),
        ttl,
        version,
    })
}

fn device_document_requires_sn_relay(device_doc: &DeviceMiniDocument) -> Option<bool> {
    let net_id = device_doc
        .document
        .as_ref()?
        .get("net_id")?
        .as_str()?
        .trim()
        .to_ascii_lowercase();
    if net_id.is_empty() {
        return None;
    }

    Some(!net_id.starts_with("wan"))
}

fn device_public_key_x(value: &Value) -> Option<String> {
    value
        .get("verificationMethod")
        .and_then(Value::as_array)
        .and_then(|methods| {
            methods
                .iter()
                .find_map(|method| find_string_path(method, &["publicKeyJwk", "x"]))
        })
        .or_else(|| find_string_path(value, &["public_key", "x"]))
}

fn build_legacy_zone_config_json(username: &str, user: &SNUserInfo) -> Value {
    json!({
        "user_name": username,
        "public_key": user.public_key.clone(),
        "boot": user.zone_config.clone(),
        "self_cert": user.self_cert,
        "user_domain": user.user_domain.clone(),
        "sn_ips": user.sn_ips.clone(),
        "state": user.state.to_string(),
    })
}

pub(crate) fn device_config_from_mini_jwt(
    mini_config_jwt: &str,
    owner_public_key_jwk_str: &str,
    owner_username: &str,
) -> SnResolverResult<Value> {
    let owner_public_key_jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_str(owner_public_key_jwk_str).map_err(|e| {
            SnResolverError::new(
                SnResolverErrorKind::BackendUnavailable,
                format!("failed to parse owner public key jwk: {}", e),
            )
        })?;

    let decoding_key = DecodingKey::from_jwk(&owner_public_key_jwk).map_err(|e| {
        SnResolverError::new(
            SnResolverErrorKind::BackendUnavailable,
            format!("failed to build decoding key from jwk: {}", e),
        )
    })?;

    let mini =
        decode_mini_config_with_schema_compat(mini_config_jwt, &decoding_key).map_err(|e| {
            SnResolverError::new(
                SnResolverErrorKind::BackendUnavailable,
                format!("failed to parse mini_config_jwt: {}", e),
            )
        })?;

    let owner_did_str = format!("did:bns:{}", owner_username);
    let zone_did = DID::from_str(owner_did_str.as_str()).map_err(|e| {
        SnResolverError::new(
            SnResolverErrorKind::InvalidDid,
            format!("failed to build zone did: {}", e),
        )
    })?;
    let owner_did = DID::from_str(owner_did_str.as_str()).map_err(|e| {
        SnResolverError::new(
            SnResolverErrorKind::InvalidDid,
            format!("failed to build owner did: {}", e),
        )
    })?;

    let device_config = DeviceConfig::new_by_mini_config(
        &mini_config_jwt.to_string(),
        &mini,
        zone_did,
        owner_did,
    );

    serde_json::to_value(device_config).map_err(|e| {
        SnResolverError::new(
            SnResolverErrorKind::BackendUnavailable,
            format!("failed to encode device_config: {}", e),
        )
    })
}

fn decode_mini_config_with_schema_compat(
    mini_config_jwt: &str,
    user_public_key: &DecodingKey,
) -> Result<NameDeviceMiniConfig, String> {
    match NameDeviceMiniConfig::from_jwt(mini_config_jwt, user_public_key) {
        Ok(config) => Ok(config),
        Err(primary_err) => {
            let primary_err = primary_err.to_string();
            if extract_missing_field_name(primary_err.as_str()).is_none() {
                return Err(primary_err);
            }

            let mut claims = decode_json_from_jwt_with_pk(mini_config_jwt, user_public_key)
                .map_err(|e| format!("jwt-claims compatibility fallback failed: {}", e))?;

            let Some(obj) = claims.as_object_mut() else {
                return Err("jwt-claims compatibility fallback expected object".to_string());
            };

            if !obj.contains_key("n") {
                if let Some(v) = obj.get("name").cloned() {
                    obj.insert("n".to_string(), v);
                }
            }
            if !obj.contains_key("name") {
                if let Some(v) = obj.get("n").cloned() {
                    obj.insert("name".to_string(), v);
                }
            }
            if !obj.contains_key("p") {
                if let Some(v) = obj.get("rtcp_port").cloned() {
                    obj.insert("p".to_string(), v);
                }
            }
            if !obj.contains_key("rtcp_port") {
                if let Some(v) = obj.get("p").cloned() {
                    obj.insert("rtcp_port".to_string(), v);
                }
            }
            if !obj.contains_key("hostname") {
                if let Some(v) = obj.get("name").cloned().or_else(|| obj.get("n").cloned()) {
                    obj.insert("hostname".to_string(), v);
                }
            }

            serde_json::from_value::<NameDeviceMiniConfig>(claims)
                .map_err(|e| format!("fallback mini_config parse failed: {}", e))
        }
    }
}

fn extract_missing_field_name(err: &str) -> Option<String> {
    for marker in ["missing field `", "missing field '"] {
        if let Some(start) = err.find(marker) {
            let value_start = start + marker.len();
            let tail = &err[value_start..];
            if let Some(end) = tail.find(['`', '\'']) {
                let field = tail[..end].trim();
                if !field.is_empty() {
                    return Some(field.to_string());
                }
            }
        }
    }
    None
}

fn parse_ip_or_socket_addr(value: &str) -> Option<IpAddr> {
    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
}

/// BNS 兼容域名映射（SN-Resolver.md "BNS 兼容域名"）：
/// `<name>.web3.<server_host>` 及其子域 -> BNS name `<name>`。
fn bns_compat_name_for(server_host: &str, hostname: &str) -> Option<String> {
    let suffix = format!(".web3.{}", server_host);
    let prefix = hostname.strip_suffix(suffix.as_str())?;
    if prefix.is_empty() {
        return None;
    }
    let name = prefix.rsplit('.').next().unwrap_or(prefix);
    if name.is_empty() {
        return None;
    }
    Some(name.to_string())
}

fn push_dns_address(addresses: &mut Vec<IpAddr>, ip: IpAddr, record_type: RecordType) {
    match record_type {
        RecordType::A if ip.is_ipv4() => push_exportable_ip(addresses, ip),
        RecordType::AAAA if ip.is_ipv6() => push_exportable_ip(addresses, ip),
        _ => {}
    }
}

fn push_dns_address_unfiltered(addresses: &mut Vec<IpAddr>, ip: IpAddr, record_type: RecordType) {
    match record_type {
        RecordType::A if ip.is_ipv4() => {
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        RecordType::AAAA if ip.is_ipv6() => {
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        _ => {}
    }
}

fn push_exportable_ip(addresses: &mut Vec<IpAddr>, ip: IpAddr) {
    if is_filtered_zonegate_ip(ip) {
        return;
    }
    if !addresses.contains(&ip) {
        addresses.push(ip);
    }
}

fn is_filtered_zonegate_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            if ipv4.is_loopback() {
                return true;
            }
            is_docker_bridge_ipv4(&ipv4)
        }
        IpAddr::V6(ipv6) => ipv6.is_loopback(),
    }
}

fn is_docker_bridge_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 172 && (16..=31).contains(&octets[1])
}

fn dedup_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct StaticBnsReader {
        owners: HashMap<String, BnsOwner>,
        documents: HashMap<(String, String), BnsDocument>,
    }

    #[async_trait]
    impl BnsDocumentReader for StaticBnsReader {
        async fn resolve_owner(&self, name: &str) -> SnResolverResult<Option<BnsOwner>> {
            Ok(self.owners.get(name).cloned())
        }

        async fn get_document(
            &self,
            name: &str,
            doc_type: &str,
        ) -> SnResolverResult<Option<BnsDocument>> {
            Ok(self
                .documents
                .get(&(name.to_string(), doc_type.to_string()))
                .cloned())
        }
    }

    fn test_resolver_with_bns(bns: StaticBnsReader) -> SnResolver {
        SnResolver::new(
            SnResolverConfig::new(
                "buckyos.test",
                "192.0.2.10".parse::<IpAddr>().unwrap(),
                "",
                "",
                Vec::new(),
            ),
            Arc::new(EmptySnAuthReader),
        )
        .with_bns_reader(Arc::new(bns))
    }

    #[test]
    fn bns_compat_name_extraction() {
        // <name>.web3.<server_host> 与其子域都映射到末级 name。
        assert_eq!(
            bns_compat_name_for("devtests.org", "alice.web3.devtests.org").as_deref(),
            Some("alice")
        );
        assert_eq!(
            bns_compat_name_for("devtests.org", "home.alice.web3.devtests.org").as_deref(),
            Some("alice")
        );
        // web3.<server_host> 本体不是 BNS 兼容域名（属 SN 自身 hostname 域）。
        assert_eq!(
            bns_compat_name_for("devtests.org", "web3.devtests.org"),
            None
        );
        // 其他后缀不误判。
        assert_eq!(
            bns_compat_name_for("devtests.org", "alice.example.com"),
            None
        );
        assert_eq!(
            bns_compat_name_for("devtests.org", "alice.web3.other.org"),
            None
        );
    }

    #[test]
    fn dns_address_filter_removes_loopback_and_docker_bridge() {
        let mut addresses = Vec::new();
        push_dns_address(&mut addresses, "127.0.0.1".parse().unwrap(), RecordType::A);
        push_dns_address(&mut addresses, "172.17.0.1".parse().unwrap(), RecordType::A);
        push_dns_address(
            &mut addresses,
            "192.168.1.2".parse().unwrap(),
            RecordType::A,
        );
        push_dns_address(
            &mut addresses,
            "192.168.1.2".parse().unwrap(),
            RecordType::A,
        );
        push_dns_address(&mut addresses, "::1".parse().unwrap(), RecordType::AAAA);
        push_dns_address(
            &mut addresses,
            "2001:db8::1".parse().unwrap(),
            RecordType::AAAA,
        );

        assert_eq!(addresses.len(), 2);
        assert!(addresses.contains(&"192.168.1.2".parse::<IpAddr>().unwrap()));
        assert!(addresses.contains(&"2001:db8::1".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parses_gateway_device_from_zone_documents() {
        let value = json!({
            "gateway": { "device_name": "gw1", "ips": ["8.8.8.8", "172.18.0.1"] }
        });
        assert_eq!(find_gateway_device_name(&value).as_deref(), Some("gw1"));
        assert_eq!(
            find_gateway_ips(&value),
            vec!["8.8.8.8".parse::<IpAddr>().unwrap()]
        );

        let value = json!({ "oods": ["ood2.testuser"] });
        assert_eq!(find_gateway_device_name(&value).as_deref(), Some("ood2"));
    }

    #[test]
    fn signed_device_net_id_controls_sn_relay_requirement() {
        let device = |net_id: Option<&str>| DeviceMiniDocument {
            zone_name: "testuser".to_string(),
            device_name: "ood1".to_string(),
            did: "did:dev:test-device".to_string(),
            mini_config_jwt: None,
            document: net_id.map(|net_id| json!({ "net_id": net_id })),
            ttl: None,
            version: None,
        };

        assert_eq!(
            device_document_requires_sn_relay(&device(Some("nat"))),
            Some(true)
        );
        assert_eq!(
            device_document_requires_sn_relay(&device(Some("portmap"))),
            Some(true)
        );
        assert_eq!(
            device_document_requires_sn_relay(&device(Some("wan"))),
            Some(false)
        );
        assert_eq!(
            device_document_requires_sn_relay(&device(Some("wan_dyn"))),
            Some(false)
        );
        assert_eq!(device_document_requires_sn_relay(&device(None)), None);
    }

    #[tokio::test]
    async fn nat_device_includes_sn_even_when_online_state_looks_wan() {
        let resolver = test_resolver_with_bns(StaticBnsReader::default());
        let zone = ZoneResolution {
            input: "testuser.web3.buckyos.test".to_string(),
            canonical_name: "testuser".to_string(),
            zone_name: "testuser".to_string(),
            owner: BnsOwner {
                name: "testuser".to_string(),
                effective_owner: None,
                owner_config: None,
            },
            zone_doc: ZoneDocument::empty(),
            boot_doc: BootDocument::empty(),
            user_domain: None,
            self_cert: false,
            relay_sn: None,
            source: ZoneResolutionSource::BnsName,
        };
        let device_doc = DeviceMiniDocument {
            zone_name: "testuser".to_string(),
            device_name: "ood1".to_string(),
            did: "did:dev:test-device".to_string(),
            mini_config_jwt: None,
            document: Some(json!({
                "net_id": "nat",
                "all_ip": ["2600:1700:1150:9440::49", "192.168.1.143"]
            })),
            ttl: None,
            version: None,
        };
        let online = SnDeviceStateView {
            did: device_doc.did.clone(),
            zone: zone.zone_name.clone(),
            device_name: device_doc.device_name.clone(),
            device_role: crate::SnDeviceRole::Ood,
            state: crate::SnDeviceState::Online,
            public_ips: vec!["2600:1700:1150:9440::49".to_string()],
            private_ips: vec!["192.168.1.143".to_string()],
            active_endpoints: Vec::new(),
            preferred_endpoint: None,
            nat_type: crate::SnNatType::Unknown,
            is_wan_device: true,
            last_seen_at: None,
            expires_at: None,
        };

        let addresses = resolver
            .resolve_gateway_addresses(&zone, &device_doc, None, Some(&online))
            .await;

        assert!(addresses.contains(&"192.0.2.10".parse::<IpAddr>().unwrap()));
        assert!(addresses.contains(&"2600:1700:1150:9440::49".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn parses_boot_jwt_from_zone_document() {
        let value = json!({ "boot_jwt": " inline-boot " });
        assert_eq!(find_boot_jwt(&value).as_deref(), Some("inline-boot"));

        let value = json!({ "boot": { "boot_config_jwt": "nested-boot" } });
        assert_eq!(find_boot_jwt(&value).as_deref(), Some("nested-boot"));

        let value = json!({ "zone_config_jwt": "wrapped-boot" });
        assert_eq!(find_boot_jwt(&value).as_deref(), Some("wrapped-boot"));

        let value = json!({ "boot": "legacy-boot" });
        assert_eq!(find_boot_jwt(&value).as_deref(), Some("legacy-boot"));
    }

    #[test]
    fn parses_device_mini_doc_from_aggregate() {
        let doc = BnsDocument::json(
            "testuser",
            BNS_DOC_DEVICE_MINI,
            json!({
                "devices": {
                    "gw1": {
                        "did": "did:dev:abc",
                        "mini_config_jwt": "jwt"
                    }
                }
            }),
        );

        let device = device_doc_from_aggregate("testuser", "gw1", &doc).unwrap();
        assert_eq!(device.device_name, "gw1");
        assert_eq!(device.did, "did:dev:abc");
        assert_eq!(device.mini_config_jwt.as_deref(), Some("jwt"));
    }

    #[test]
    fn parses_device_mini_map_from_zone_document() {
        let doc = BnsDocument::json(
            "testuser",
            BNS_DOC_ZONE,
            json!({
                "devices": {
                    "gw1": {
                        "did": "did:dev:abc",
                        "mini_config_jwt": "jwt"
                    }
                }
            }),
        );

        let zone_doc = ZoneDocument::from_bns_document(&doc);
        let device = device_doc_from_map(
            "testuser",
            "gw1",
            &zone_doc.devices,
            zone_doc.ttl,
            zone_doc.version,
        )
        .unwrap();

        assert_eq!(device.device_name, "gw1");
        assert_eq!(device.did, "did:dev:abc");
        assert_eq!(device.mini_config_jwt.as_deref(), Some("jwt"));
    }

    #[test]
    fn parses_canonical_zone_document_device_and_mini_jwt_fields() {
        let doc = BnsDocument::json(
            "testuser",
            BNS_DOC_ZONE,
            json!({
                "devices": {
                    "ood1": {
                        "id": "did:dev:canonical",
                        "name": "ood1"
                    }
                },
                "mini_device_jwts": {
                    "ood1": "canonical-mini-jwt"
                }
            }),
        );

        let device = device_doc_from_aggregate("testuser", "ood1", &doc).unwrap();
        assert_eq!(device.did, "did:dev:canonical");
        assert_eq!(
            device.mini_config_jwt.as_deref(),
            Some("canonical-mini-jwt")
        );
        assert_eq!(
            device_jwts_from_bns_document(&doc),
            vec!["canonical-mini-jwt"]
        );
    }

    #[tokio::test]
    async fn resolves_device_key_did_from_canonical_zone_document_jwt() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;

        let device_x = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";
        let payload = json!({
            "boot_jwt": "canonical-boot-jwt",
            "oods": ["ood1"],
            "devices": {
                "ood1": {
                    "id": "did:bns:ood1.testuser",
                    "name": "ood1",
                    "verificationMethod": [{
                        "publicKeyJwk": {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": device_x
                        }
                    }],
                    "device_mini_document_jwt": "canonical-mini-jwt"
                }
            },
            "mini_device_jwts": {
                "ood1": "canonical-mini-jwt"
            }
        });
        let zone_jwt = format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap())
        );
        let document = BnsDocument::jwt("testuser", BNS_DOC_ZONE, zone_jwt);
        let zone = ZoneDocument::from_bns_document(&document);
        assert_eq!(zone.boot_jwt.as_deref(), Some("canonical-boot-jwt"));
        assert_eq!(zone.gateway_device_name.as_deref(), Some("ood1"));
        assert!(device_jwts_from_bns_document(&document)
            .iter()
            .all(|jwt| jwt == "canonical-mini-jwt"));

        let mut bns = StaticBnsReader::default();
        bns.documents
            .insert(("testuser".to_string(), BNS_DOC_ZONE.to_string()), document);
        let resolver = test_resolver_with_bns(bns);
        assert_eq!(
            resolver
                .resolve_zone_device_did("testuser", "ood1")
                .await
                .unwrap(),
            format!("did:dev:{}", device_x)
        );
    }

    #[tokio::test]
    async fn resolves_device_mini_doc_from_embedded_zone_devices() {
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_ZONE,
                json!({
                    "devices": {
                        "ood1": {
                            "did": "did:dev:embedded",
                            "mini_config_jwt": "embedded-jwt"
                        }
                    }
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);

        let (device, compatibility) = resolver
            .resolve_device_mini_doc("testuser", "ood1", None)
            .await
            .unwrap();

        assert!(compatibility.is_none());
        assert_eq!(device.device_name, "ood1");
        assert_eq!(device.did, "did:dev:embedded");
        assert_eq!(device.mini_config_jwt.as_deref(), Some("embedded-jwt"));
    }

    #[tokio::test]
    async fn embedded_and_standalone_device_maps_resolve_equivalently() {
        let device_map = json!({
            "devices": {
                "ood1": {
                    "did": "did:dev:abc",
                    "mini_config_jwt": "jwt",
                    "role": "gateway"
                }
            }
        });

        let mut embedded_bns = StaticBnsReader::default();
        embedded_bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json("testuser", BNS_DOC_ZONE, device_map.clone()),
        );
        let embedded_resolver = test_resolver_with_bns(embedded_bns);

        let mut standalone_bns = StaticBnsReader::default();
        standalone_bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json("testuser", BNS_DOC_DEVICE_MINI, device_map),
        );
        let standalone_resolver = test_resolver_with_bns(standalone_bns);

        let (embedded, _) = embedded_resolver
            .resolve_device_mini_doc("testuser", "ood1", None)
            .await
            .unwrap();
        let (standalone, _) = standalone_resolver
            .resolve_device_mini_doc("testuser", "ood1", None)
            .await
            .unwrap();

        assert_eq!(embedded, standalone);
    }

    #[tokio::test]
    async fn child_device_doc_overrides_aggregate_and_doc_type_doc_is_supported() {
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "devices": {
                        "ood1": {
                            "did": "did:dev:aggregate",
                            "source": "aggregate"
                        }
                    }
                }),
            ),
        );
        bns.documents.insert(
            ("ood1.testuser".to_string(), "doc".to_string()),
            BnsDocument::json(
                "ood1.testuser",
                "doc",
                json!({
                    "did": "did:dev:child",
                    "source": "child"
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);

        let (device, _) = resolver
            .resolve_device_mini_doc("testuser", "ood1", None)
            .await
            .unwrap();

        assert_eq!(device.did, "did:dev:child");
        assert_eq!(
            device
                .document
                .as_ref()
                .and_then(|value| value["source"].as_str()),
            Some("child")
        );
    }

    #[tokio::test]
    async fn resolves_bns_zone_document_without_sn_user() {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "testuser".to_string(),
            BnsOwner {
                name: "testuser".to_string(),
                effective_owner: Some("owner-key".to_string()),
                owner_config: None,
            },
        );
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_ZONE,
                json!({
                    "gateway": { "device_name": "ood1" }
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);
        let did = DID::from_str("did:bns:testuser").unwrap();

        let resolved = resolver
            .resolve_did(&did, Some(BNS_DOC_ZONE), None)
            .await
            .unwrap();

        assert_eq!(resolved.source, SnDidDocumentSource::BnsDocument);
        assert_eq!(resolved.doc_type, BNS_DOC_ZONE);
    }

    #[tokio::test]
    async fn resolves_zone_with_embedded_boot_jwt_without_separate_boot_doc() {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "testuser".to_string(),
            BnsOwner {
                name: "testuser".to_string(),
                effective_owner: Some("owner-key".to_string()),
                owner_config: None,
            },
        );
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_ZONE,
                json!({
                    "gateway": { "device_name": "ood1" },
                    "boot_jwt": "embedded-boot"
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);

        let resolved = resolver
            .resolve_zone_by_bns_owner(
                "testuser",
                "testuser",
                BnsOwner {
                    name: "testuser".to_string(),
                    effective_owner: Some("owner-key".to_string()),
                    owner_config: None,
                },
                ZoneResolutionSource::BnsName,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(resolved.zone_doc.boot_jwt.as_deref(), Some("embedded-boot"));
        assert_eq!(resolved.boot_doc.jwt.as_deref(), Some("embedded-boot"));
    }

    #[tokio::test]
    async fn separate_boot_doc_overrides_embedded_boot_jwt() {
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_ZONE.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_ZONE,
                json!({ "boot_jwt": "embedded-boot" }),
            ),
        );
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_BOOT.to_string()),
            BnsDocument::json("testuser", BNS_DOC_BOOT, json!({ "boot": "separate-boot" })),
        );
        let resolver = test_resolver_with_bns(bns);

        let resolved = resolver
            .resolve_zone_by_bns_owner(
                "testuser",
                "testuser",
                BnsOwner {
                    name: "testuser".to_string(),
                    effective_owner: Some("owner-key".to_string()),
                    owner_config: None,
                },
                ZoneResolutionSource::BnsName,
                None,
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            resolved.boot_doc.raw,
            Some(json!({ "boot": "separate-boot" }))
        );
        assert_eq!(resolved.boot_doc.jwt, None);
    }

    #[tokio::test]
    async fn resolves_bns_device_document_without_sn_user() {
        let mut bns = StaticBnsReader::default();
        bns.owners.insert(
            "testuser".to_string(),
            BnsOwner {
                name: "testuser".to_string(),
                effective_owner: Some("owner-key".to_string()),
                owner_config: None,
            },
        );
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "devices": {
                        "ood1": {
                            "did": "did:dev:abc",
                            "mini_config_jwt": "jwt"
                        }
                    }
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);
        let did = DID::from_str("did:bns:testuser").unwrap();

        let resolved = resolver
            .resolve_did(&did, Some("ood1"), None)
            .await
            .unwrap();

        assert_eq!(resolved.source, SnDidDocumentSource::DeviceMiniDocument);
        assert_eq!(resolved.doc_type, "ood1");
    }

    #[tokio::test]
    async fn resolves_bns_device_info_as_offline_without_runtime_state() {
        let mut bns = StaticBnsReader::default();
        bns.documents.insert(
            ("testuser".to_string(), BNS_DOC_DEVICE_MINI.to_string()),
            BnsDocument::json(
                "testuser",
                BNS_DOC_DEVICE_MINI,
                json!({
                    "devices": {
                        "ood1": {
                            "did": "did:dev:abc",
                            "mini_config_jwt": "jwt"
                        }
                    }
                }),
            ),
        );
        let resolver = test_resolver_with_bns(bns);
        let did = DID::from_str("did:bns:ood1.testuser").unwrap();

        let resolved = resolver
            .resolve_did(&did, Some("info"), None)
            .await
            .unwrap();
        let value = match resolved.document {
            EncodedDocument::JsonLd(value) => value,
            EncodedDocument::Jwt(_) => panic!("expected json document"),
        };

        assert_eq!(resolved.source, SnDidDocumentSource::DeviceMiniDocument);
        assert_eq!(value["state"], "offline");
        assert_eq!(value["did"], "did:dev:abc");
    }
}
