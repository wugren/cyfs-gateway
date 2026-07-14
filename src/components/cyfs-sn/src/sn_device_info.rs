use crate::{into_sn_err, sn_err, SnErrorCode, SnResult};
pub use cyfs_gateway_api::{
    SnDeviceEndpoint, SnDeviceEndpointUpdate, SnDeviceRole, SnDeviceState, SnDeviceStateView,
    SnEndpointProtocol, SnEndpointScope, SnEndpointSource, SnEndpointState, SnNatType,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub type SnDeviceInfoDBRef = Arc<dyn SnDeviceInfoDB>;

macro_rules! string_enum {
    ($name:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        impl $name {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value,)+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str((*self).as_str())
            }
        }

        impl FromStr for $name {
            type Err = String;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(format!("invalid {}: {}", stringify!($name), value)),
                }
            }
        }
    };
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnDeviceStateEventType {
    Registered,
    Rebound,
    Online,
    Offline,
    Stale,
    Blocked,
    Unblocked,
    EndpointChanged,
    ReportRejected,
}

string_enum!(SnDeviceStateEventType {
    Registered => "registered",
    Rebound => "rebound",
    Online => "online",
    Offline => "offline",
    Stale => "stale",
    Blocked => "blocked",
    Unblocked => "unblocked",
    EndpointChanged => "endpoint_changed",
    ReportRejected => "report_rejected",
});

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnDeviceIndex {
    pub did: String,
    pub zone: String,
    pub device_name: String,
    pub device_role: SnDeviceRole,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnDeviceStateUpdate {
    pub did: String,
    pub reported_ip: Option<String>,
    pub reported_ips: Vec<String>,
    pub from_ip: Option<String>,
    pub nat_type: SnNatType,
    pub endpoints: Vec<SnDeviceEndpointUpdate>,
    pub report_seq: Option<u64>,
    pub ttl: u64,
    pub raw_report: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct SnDeviceListOptions {
    pub state: Option<SnDeviceState>,
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SnDeviceStateEvent {
    pub id: u64,
    pub did: String,
    pub event_type: SnDeviceStateEventType,
    pub old_state: Option<SnDeviceState>,
    pub new_state: Option<SnDeviceState>,
    pub reason: Option<String>,
    pub event_at: u64,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
struct RuntimeStateRow {
    state: SnDeviceState,
    reported_ip: Option<String>,
    reported_ips: Vec<String>,
    from_ip: Option<String>,
    wan_ip: Option<String>,
    lan_ips: Vec<String>,
    nat_type: SnNatType,
    is_wan_device: bool,
    last_seen_at: Option<u64>,
    expires_at: Option<u64>,
    report_seq: Option<u64>,
}

#[async_trait::async_trait]
pub trait SnDeviceInfoDB: Send + Sync + 'static {
    async fn upsert_device_index(
        &self,
        did: &str,
        zone: &str,
        device_name: &str,
        device_role: SnDeviceRole,
    ) -> SnResult<()>;
    async fn rebind_device_index(
        &self,
        did: &str,
        new_zone: &str,
        new_device_name: &str,
        new_device_role: SnDeviceRole,
        reason: &str,
    ) -> SnResult<()>;
    async fn remove_device_index(&self, did: &str) -> SnResult<()>;
    async fn update_device_state(&self, update: SnDeviceStateUpdate) -> SnResult<()>;
    async fn get_device_state(&self, did: &str) -> SnResult<Option<SnDeviceStateView>>;
    async fn get_device_state_by_name(
        &self,
        zone: &str,
        device_name: &str,
    ) -> SnResult<Option<SnDeviceStateView>>;
    async fn list_zone_devices(
        &self,
        zone: &str,
        options: SnDeviceListOptions,
    ) -> SnResult<Vec<SnDeviceStateView>>;
    async fn mark_device_offline(&self, did: &str, reason: &str) -> SnResult<()>;
    async fn block_device(&self, did: &str, reason: &str) -> SnResult<()>;
    async fn unblock_device(&self, did: &str, reason: &str) -> SnResult<()>;
    async fn expire_devices(&self, now: u64, batch_size: Option<usize>) -> SnResult<usize>;
}

/// Remote SnDeviceInfoDB backed by the sn_device_info_db S2S KRPC API.
#[derive(Clone)]
pub struct RemoteSnDeviceInfoDB {
    client: crate::s2s_api::SnDeviceInfoDbClient,
}

impl RemoteSnDeviceInfoDB {
    pub fn new(client: crate::s2s_api::SnDeviceInfoDbClient) -> Self {
        Self { client }
    }

    pub fn new_krpc(client: Arc<::kRPC::kRPC>) -> Self {
        Self::new(crate::s2s_api::SnDeviceInfoDbClient::new_krpc(client))
    }

    pub fn new_krpc_url(device_info_db_url: &str, session_token: Option<String>) -> Self {
        Self::new(crate::s2s_api::SnDeviceInfoDbClient::new_krpc_url(
            device_info_db_url,
            session_token,
        ))
    }

    pub fn client(&self) -> &crate::s2s_api::SnDeviceInfoDbClient {
        &self.client
    }
}

#[async_trait::async_trait]
impl SnDeviceInfoDB for RemoteSnDeviceInfoDB {
    async fn upsert_device_index(
        &self,
        did: &str,
        zone: &str,
        device_name: &str,
        device_role: SnDeviceRole,
    ) -> SnResult<()> {
        self.client
            .upsert_device_index(did, zone, device_name, device_role)
            .await
    }

    async fn rebind_device_index(
        &self,
        did: &str,
        new_zone: &str,
        new_device_name: &str,
        new_device_role: SnDeviceRole,
        reason: &str,
    ) -> SnResult<()> {
        self.client
            .rebind_device_index(did, new_zone, new_device_name, new_device_role, reason)
            .await
    }

    async fn remove_device_index(&self, did: &str) -> SnResult<()> {
        self.client.remove_device_index(did).await
    }

    async fn update_device_state(&self, update: SnDeviceStateUpdate) -> SnResult<()> {
        self.client.update_device_state(update).await
    }

    async fn get_device_state(&self, did: &str) -> SnResult<Option<SnDeviceStateView>> {
        self.client.get_device_state(did).await
    }

    async fn get_device_state_by_name(
        &self,
        zone: &str,
        device_name: &str,
    ) -> SnResult<Option<SnDeviceStateView>> {
        self.client
            .get_device_state_by_name(zone, device_name)
            .await
    }

    async fn list_zone_devices(
        &self,
        zone: &str,
        options: SnDeviceListOptions,
    ) -> SnResult<Vec<SnDeviceStateView>> {
        self.client.list_zone_devices(zone, options).await
    }

    async fn mark_device_offline(&self, did: &str, reason: &str) -> SnResult<()> {
        self.client.mark_device_offline(did, reason).await
    }

    async fn block_device(&self, did: &str, reason: &str) -> SnResult<()> {
        self.client.block_device(did, reason).await
    }

    async fn unblock_device(&self, did: &str, reason: &str) -> SnResult<()> {
        self.client.unblock_device(did, reason).await
    }

    async fn expire_devices(&self, now: u64, batch_size: Option<usize>) -> SnResult<usize> {
        self.client.expire_devices(now, batch_size).await
    }
}

pub struct SqliteSnDeviceInfoDB {
    pool: SqlitePool,
}

impl SqliteSnDeviceInfoDB {
    pub async fn new() -> SnResult<Self> {
        let base_dir = PathBuf::from(std::env::current_exe().unwrap().parent().unwrap());
        let db_path = base_dir.join("sn_device_info.sqlite3");

        Self::new_by_path(db_path.to_string_lossy().as_ref()).await
    }

    pub async fn new_by_path(path: &str) -> SnResult<Self> {
        let db_url = if path.starts_with("sqlite:") {
            path.to_string()
        } else {
            format!("sqlite://{}", path)
        };
        let options = SqliteConnectOptions::from_str(db_url.as_str())
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "parse sqlite url failed"
            ))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(300)
            .connect_with(options)
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "open file: {:?}", path))?;

        Ok(Self { pool })
    }

    pub async fn open_local(path: &str) -> SnResult<SnDeviceInfoDBRef> {
        let db = Self::new_by_path(path).await?;
        db.initialize_database().await?;
        Ok(Arc::new(db))
    }

    pub async fn initialize_database(&self) -> SnResult<()> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&mut *conn)
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "enable foreign keys"))?;

        let endpoint_columns = sqlx::query("PRAGMA table_info(device_endpoints)")
            .fetch_all(&mut *conn)
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query device_endpoints schema failed"
            ))?;
        if !endpoint_columns.is_empty()
            && !endpoint_columns
                .iter()
                .any(|row| row.get::<String, _>(1) == "endpoint_id")
        {
            sqlx::query("DROP TABLE device_endpoints")
                .execute(&mut *conn)
                .await
                .map_err(into_sn_err!(
                    SnErrorCode::DBError,
                    "drop legacy device_endpoints failed"
                ))?;
        }

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_indexes (
                did TEXT PRIMARY KEY,
                zone TEXT NOT NULL,
                device_name TEXT NOT NULL,
                device_role TEXT NOT NULL DEFAULT 'unknown',
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(zone, device_name)
            )",
        )
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create device_indexes table failed"
        ))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_runtime_states (
                did TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                reported_ip TEXT NULL,
                reported_ips TEXT NULL,
                from_ip TEXT NULL,
                wan_ip TEXT NULL,
                lan_ips TEXT NULL,
                nat_type TEXT NOT NULL DEFAULT 'unknown',
                is_wan_device INTEGER NOT NULL DEFAULT 0,
                last_seen_at INTEGER NULL,
                last_report_at INTEGER NULL,
                expires_at INTEGER NULL,
                report_seq INTEGER NULL,
                raw_report TEXT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(did) REFERENCES device_indexes(did)
            )",
        )
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create device_runtime_states table failed"
        ))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_endpoints (
                did TEXT NOT NULL,
                endpoint_id TEXT NOT NULL,
                protocol TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NULL,
                scope TEXT NOT NULL DEFAULT 'unknown',
                priority INTEGER NOT NULL DEFAULT 100,
                source TEXT NOT NULL,
                state TEXT NOT NULL,
                last_seen_at INTEGER NULL,
                expires_at INTEGER NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(did, endpoint_id),
                FOREIGN KEY(did) REFERENCES device_indexes(did)
            )",
        )
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create device_endpoints table failed"
        ))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS device_state_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                did TEXT NOT NULL,
                event_type TEXT NOT NULL,
                old_state TEXT NULL,
                new_state TEXT NULL,
                reason TEXT NULL,
                event_at INTEGER NOT NULL,
                detail TEXT NULL
            )",
        )
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create device_state_events table failed"
        ))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_device_indexes_zone_name
                ON device_indexes(zone, device_name)",
        )
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create device index zone/name index failed"
        ))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_device_runtime_state_expires
                ON device_runtime_states(state, expires_at)",
        )
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create runtime expires index failed"
        ))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_device_endpoints_did_state_priority
                ON device_endpoints(did, state, priority)",
        )
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create endpoint state priority index failed"
        ))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_device_state_events_did_time
                ON device_state_events(did, event_at)",
        )
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create state event index failed"
        ))?;

        Ok(())
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn check_non_empty(value: &str, field: &str) -> SnResult<()> {
        if value.trim().is_empty() {
            return Err(sn_err!(SnErrorCode::InvalidInput, "{} is empty", field));
        }

        Ok(())
    }

    fn check_did(did: &str) -> SnResult<()> {
        Self::check_non_empty(did, "device did")
    }

    fn check_zone(zone: &str) -> SnResult<()> {
        Self::check_non_empty(zone, "zone")
    }

    fn check_device_name(device_name: &str) -> SnResult<()> {
        Self::check_non_empty(device_name, "device_name")
    }

    fn check_reason(reason: &str) -> SnResult<()> {
        Self::check_non_empty(reason, "reason")
    }

    fn to_db_time(value: u64, field: &str) -> SnResult<i64> {
        i64::try_from(value).map_err(|_| {
            sn_err!(
                SnErrorCode::InvalidInput,
                "{} is too large for sqlite integer",
                field
            )
        })
    }

    fn opt_to_u64(value: Option<i64>) -> Option<u64> {
        value.and_then(|v| u64::try_from(v).ok())
    }

    fn parse_db_enum<T>(value: String, field: &str) -> SnResult<T>
    where
        T: FromStr<Err = String>,
    {
        value
            .parse()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "invalid {} in db: {}", field, e))
    }

    fn parse_json_string_vec(value: Option<String>, field: &str) -> SnResult<Vec<String>> {
        match value {
            Some(value) if !value.trim().is_empty() => serde_json::from_str(&value)
                .map_err(|e| sn_err!(SnErrorCode::DBError, "invalid {} json: {}", field, e)),
            _ => Ok(Vec::new()),
        }
    }

    fn parse_ip(value: &str, field: &str) -> SnResult<IpAddr> {
        value.trim().parse::<IpAddr>().map_err(|e| {
            sn_err!(
                SnErrorCode::InvalidInput,
                "invalid {} ip {}: {}",
                field,
                value,
                e
            )
        })
    }

    fn normalize_ip_option(value: Option<String>, field: &str) -> SnResult<Option<String>> {
        match value {
            Some(value) => Ok(Some(Self::parse_ip(&value, field)?.to_string())),
            None => Ok(None),
        }
    }

    fn normalize_ip_vec(values: Vec<String>, field: &str) -> SnResult<Vec<String>> {
        let mut seen = HashSet::new();
        let mut result = Vec::new();
        for value in values {
            let ip = Self::parse_ip(&value, field)?.to_string();
            if seen.insert(ip.clone()) {
                result.push(ip);
            }
        }
        Ok(result)
    }

    fn is_public_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => Self::is_public_ipv4(ip),
            IpAddr::V6(ip) => Self::is_public_ipv6(ip),
        }
    }

    fn is_public_ipv4(ip: &Ipv4Addr) -> bool {
        let octets = ip.octets();

        if ip.is_private()
            || ip.is_loopback()
            || ip.is_link_local()
            || ip.is_multicast()
            || ip.is_unspecified()
            || *ip == Ipv4Addr::new(255, 255, 255, 255)
        {
            return false;
        }

        if octets[0] == 100 && (64..=127).contains(&octets[1]) {
            return false;
        }

        if octets[0] == 198 && (18..=19).contains(&octets[1]) {
            return false;
        }

        if octets[0] >= 240 {
            return false;
        }

        true
    }

    fn is_public_ipv6(ip: &Ipv6Addr) -> bool {
        let segments = ip.segments();

        if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
            return false;
        }

        if (segments[0] & 0xfe00) == 0xfc00 {
            return false;
        }

        if (segments[0] & 0xffc0) == 0xfe80 {
            return false;
        }

        if segments[0] == 0x2001 && segments[1] == 0x0db8 {
            return false;
        }

        true
    }

    fn is_private_candidate_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                ip.is_private()
                    || ip.is_link_local()
                    || (ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
            }
            IpAddr::V6(ip) => {
                let segments = ip.segments();
                (segments[0] & 0xfe00) == 0xfc00 || (segments[0] & 0xffc0) == 0xfe80
            }
        }
    }

    fn push_unique_ip(result: &mut Vec<String>, ip: IpAddr) {
        let value = ip.to_string();
        if !result.contains(&value) {
            result.push(value);
        }
    }

    fn classify_ips(
        reported_ip: Option<&str>,
        reported_ips: &[String],
        from_ip: Option<&str>,
    ) -> SnResult<(Option<String>, Vec<String>)> {
        let mut public_ips = Vec::new();
        let mut private_ips = Vec::new();

        for (value, field) in reported_ip
            .into_iter()
            .map(|v| (v, "reported_ip"))
            .chain(reported_ips.iter().map(|v| (v.as_str(), "reported_ips")))
            .chain(from_ip.into_iter().map(|v| (v, "from_ip")))
        {
            let ip = Self::parse_ip(value, field)?;
            if Self::is_public_ip(&ip) {
                Self::push_unique_ip(&mut public_ips, ip);
            } else if Self::is_private_candidate_ip(&ip) {
                Self::push_unique_ip(&mut private_ips, ip);
            }
        }

        Ok((public_ips.into_iter().next(), private_ips))
    }

    fn public_ips_for_view(runtime: Option<&RuntimeStateRow>) -> SnResult<Vec<String>> {
        let Some(runtime) = runtime else {
            return Ok(Vec::new());
        };

        let mut result = Vec::new();
        for value in runtime
            .wan_ip
            .as_deref()
            .into_iter()
            .chain(runtime.reported_ip.as_deref())
            .chain(runtime.reported_ips.iter().map(|v| v.as_str()))
            .chain(runtime.from_ip.as_deref())
        {
            let ip = Self::parse_ip(value, "runtime ip")?;
            if Self::is_public_ip(&ip) {
                Self::push_unique_ip(&mut result, ip);
            }
        }

        Ok(result)
    }

    fn private_ips_for_view(runtime: Option<&RuntimeStateRow>) -> SnResult<Vec<String>> {
        let Some(runtime) = runtime else {
            return Ok(Vec::new());
        };

        let mut result = Vec::new();
        for value in runtime
            .lan_ips
            .iter()
            .map(|v| v.as_str())
            .chain(runtime.reported_ip.as_deref())
            .chain(runtime.reported_ips.iter().map(|v| v.as_str()))
            .chain(runtime.from_ip.as_deref())
        {
            let ip = Self::parse_ip(value, "runtime ip")?;
            if Self::is_private_candidate_ip(&ip) {
                Self::push_unique_ip(&mut result, ip);
            }
        }

        Ok(result)
    }

    fn validate_endpoint(endpoint: &SnDeviceEndpointUpdate) -> SnResult<()> {
        Self::check_non_empty(&endpoint.endpoint_id, "endpoint_id")?;
        Self::check_non_empty(&endpoint.host, "endpoint host")?;

        if endpoint.priority < 0 {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "endpoint priority must be non-negative"
            ));
        }

        if let Some(expires_at) = endpoint.expires_at {
            Self::to_db_time(expires_at, "endpoint expires_at")?;
        }

        Ok(())
    }

    fn endpoint_sort_key(endpoint: &SnDeviceEndpoint) -> (i32, i64, String) {
        let scope_rank = match endpoint.scope {
            SnEndpointScope::Public => 0,
            SnEndpointScope::Relay => 1,
            SnEndpointScope::Private => 2,
            SnEndpointScope::Loopback => 3,
            SnEndpointScope::Unknown => 4,
        };

        (scope_rank, endpoint.priority, endpoint.endpoint_id.clone())
    }

    fn endpoint_signature(endpoint: &SnDeviceEndpoint) -> String {
        format!(
            "{}|{}|{}|{:?}|{}|{}|{}|{}",
            endpoint.endpoint_id,
            endpoint.protocol,
            endpoint.host,
            endpoint.port,
            endpoint.scope,
            endpoint.priority,
            endpoint.source,
            endpoint.state
        )
    }

    fn runtime_state_from_row(row: SqliteRow) -> SnResult<RuntimeStateRow> {
        let state = Self::parse_db_enum::<SnDeviceState>(row.get(1), "state")?;
        let reported_ips = Self::parse_json_string_vec(row.get(3), "reported_ips")?;
        let lan_ips = Self::parse_json_string_vec(row.get(6), "lan_ips")?;
        let nat_type = Self::parse_db_enum::<SnNatType>(row.get(7), "nat_type")?;

        Ok(RuntimeStateRow {
            state,
            reported_ip: row.get(2),
            reported_ips,
            from_ip: row.get(4),
            wan_ip: row.get(5),
            lan_ips,
            nat_type,
            is_wan_device: row.get::<i64, _>(8) != 0,
            last_seen_at: Self::opt_to_u64(row.get(9)),
            expires_at: Self::opt_to_u64(row.get(11)),
            report_seq: Self::opt_to_u64(row.get(12)),
        })
    }

    fn device_index_from_row(row: SqliteRow) -> SnResult<SnDeviceIndex> {
        Ok(SnDeviceIndex {
            did: row.get(0),
            zone: row.get(1),
            device_name: row.get(2),
            device_role: Self::parse_db_enum::<SnDeviceRole>(row.get(3), "device_role")?,
            created_at: u64::try_from(row.get::<i64, _>(4)).unwrap_or_default(),
            updated_at: u64::try_from(row.get::<i64, _>(5)).unwrap_or_default(),
        })
    }

    fn endpoint_from_row(row: SqliteRow) -> SnResult<SnDeviceEndpoint> {
        let port = row
            .get::<Option<i64>, _>(4)
            .and_then(|port| u16::try_from(port).ok());

        Ok(SnDeviceEndpoint {
            did: row.get(0),
            endpoint_id: row.get(1),
            protocol: Self::parse_db_enum::<SnEndpointProtocol>(row.get(2), "protocol")?,
            host: row.get(3),
            port,
            scope: Self::parse_db_enum::<SnEndpointScope>(row.get(5), "scope")?,
            priority: row.get(6),
            source: Self::parse_db_enum::<SnEndpointSource>(row.get(7), "source")?,
            state: Self::parse_db_enum::<SnEndpointState>(row.get(8), "endpoint state")?,
            last_seen_at: Self::opt_to_u64(row.get(9)),
            expires_at: Self::opt_to_u64(row.get(10)),
            created_at: u64::try_from(row.get::<i64, _>(11)).unwrap_or_default(),
            updated_at: u64::try_from(row.get::<i64, _>(12)).unwrap_or_default(),
        })
    }

    async fn fetch_device_index(&self, did: &str) -> SnResult<Option<SnDeviceIndex>> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let rows = sqlx::query(
            "SELECT did, zone, device_name, device_role, created_at, updated_at
                     FROM device_indexes WHERE did = ?1 LIMIT 1",
        )
        .bind(did)
        .fetch_all(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "query device index failed"
        ))?;

        rows.into_iter()
            .next()
            .map(Self::device_index_from_row)
            .transpose()
    }

    async fn fetch_device_index_by_name(
        &self,
        zone: &str,
        device_name: &str,
    ) -> SnResult<Option<SnDeviceIndex>> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let rows = sqlx::query(
            "SELECT did, zone, device_name, device_role, created_at, updated_at
                     FROM device_indexes WHERE zone = ?1 AND device_name = ?2 LIMIT 1",
        )
        .bind(zone)
        .bind(device_name)
        .fetch_all(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "query device index by name failed"
        ))?;

        rows.into_iter()
            .next()
            .map(Self::device_index_from_row)
            .transpose()
    }

    async fn fetch_runtime_state(&self, did: &str) -> SnResult<Option<RuntimeStateRow>> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let rows = sqlx::query(
            "SELECT did, state, reported_ip, reported_ips, from_ip, wan_ip, lan_ips,
                            nat_type, is_wan_device, last_seen_at, last_report_at, expires_at,
                            report_seq, raw_report, created_at, updated_at
                     FROM device_runtime_states WHERE did = ?1 LIMIT 1",
        )
        .bind(did)
        .fetch_all(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "query device runtime state failed"
        ))?;

        rows.into_iter()
            .next()
            .map(Self::runtime_state_from_row)
            .transpose()
    }

    async fn list_active_endpoints(&self, did: &str, now: u64) -> SnResult<Vec<SnDeviceEndpoint>> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let rows = sqlx::query(
            "SELECT did, endpoint_id, protocol, host, port, scope, priority, source,
                            state, last_seen_at, expires_at, created_at, updated_at
                     FROM device_endpoints
                     WHERE did = ?1
                       AND state = 'active'
                       AND (expires_at IS NULL OR expires_at >= ?2)",
        )
        .bind(did)
        .bind(Self::to_db_time(now, "now")?)
        .fetch_all(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "query device endpoints failed"
        ))?;

        let mut endpoints = rows
            .into_iter()
            .map(Self::endpoint_from_row)
            .collect::<SnResult<Vec<_>>>()?;
        endpoints.sort_by_key(Self::endpoint_sort_key);
        Ok(endpoints)
    }

    async fn list_zone_indexes(&self, zone: &str) -> SnResult<Vec<SnDeviceIndex>> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        let rows = sqlx::query(
            "SELECT did, zone, device_name, device_role, created_at, updated_at
                     FROM device_indexes WHERE zone = ?1 ORDER BY device_name ASC",
        )
        .bind(zone)
        .fetch_all(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "query zone device indexes failed"
        ))?;

        rows.into_iter()
            .map(Self::device_index_from_row)
            .collect::<SnResult<Vec<_>>>()
    }

    async fn record_event(
        &self,
        did: &str,
        event_type: SnDeviceStateEventType,
        old_state: Option<SnDeviceState>,
        new_state: Option<SnDeviceState>,
        reason: Option<&str>,
        detail: Option<String>,
    ) -> SnResult<()> {
        let now = Self::now_secs();
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        sqlx::query(
            "INSERT INTO device_state_events
                 (did, event_type, old_state, new_state, reason, event_at, detail)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )
        .bind(did)
        .bind(event_type.as_str())
        .bind(old_state.map(|state| state.as_str().to_string()))
        .bind(new_state.map(|state| state.as_str().to_string()))
        .bind(reason.map(|v| v.to_string()))
        .bind(Self::to_db_time(now, "event_at")?)
        .bind(detail)
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "insert device state event failed"
        ))?;

        Ok(())
    }

    async fn update_state_without_report(
        &self,
        did: &str,
        state: SnDeviceState,
        reason: &str,
        event_type: SnDeviceStateEventType,
    ) -> SnResult<()> {
        Self::check_did(did)?;
        Self::check_reason(reason)?;

        if self.fetch_device_index(did).await?.is_none() {
            return Err(sn_err!(
                SnErrorCode::NotFound,
                "device index not found: {}",
                did
            ));
        }

        let old_state = self.fetch_runtime_state(did).await?.map(|row| row.state);
        let now = Self::now_secs();
        let now_db = Self::to_db_time(now, "now")?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        sqlx::query(
            "INSERT INTO device_runtime_states
                 (did, state, nat_type, is_wan_device, last_seen_at, last_report_at,
                  expires_at, created_at, updated_at)
                 VALUES (?1, ?2, 'unknown', 0, NULL, NULL, NULL, ?3, ?3)
                 ON CONFLICT(did) DO UPDATE SET
                    state = ?2,
                    updated_at = ?3,
                    expires_at = NULL",
        )
        .bind(did)
        .bind(state.as_str())
        .bind(now_db)
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "update device runtime state failed"
        ))?;

        if state == SnDeviceState::Blocked {
            sqlx::query(
                "UPDATE device_endpoints
                     SET state = 'disabled', updated_at = ?2
                     WHERE did = ?1 AND state = 'active'",
            )
            .bind(did)
            .bind(now_db)
            .execute(&mut *conn)
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "disable device endpoints failed"
            ))?;
        } else if state == SnDeviceState::Offline || state == SnDeviceState::Stale {
            sqlx::query(
                "UPDATE device_endpoints
                     SET state = 'stale', updated_at = ?2
                     WHERE did = ?1 AND state = 'active'",
            )
            .bind(did)
            .bind(now_db)
            .execute(&mut *conn)
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "stale device endpoints failed"
            ))?;
        }

        self.record_event(did, event_type, old_state, Some(state), Some(reason), None)
            .await
    }

    async fn mark_stale_if_expired(&self, did: &str, now: u64) -> SnResult<bool> {
        let Some(runtime) = self.fetch_runtime_state(did).await? else {
            return Ok(false);
        };

        if runtime.state != SnDeviceState::Online {
            return Ok(false);
        }

        if !runtime
            .expires_at
            .is_some_and(|expires_at| expires_at < now)
        {
            return Ok(false);
        }

        let now_db = Self::to_db_time(now, "now")?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        sqlx::query(
            "UPDATE device_runtime_states
                 SET state = 'stale', updated_at = ?2
                 WHERE did = ?1 AND state = 'online'",
        )
        .bind(did)
        .bind(now_db)
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "mark expired device stale failed"
        ))?;

        sqlx::query(
            "UPDATE device_endpoints
                 SET state = 'stale', updated_at = ?2
                 WHERE did = ?1 AND state = 'active'
                   AND expires_at IS NOT NULL AND expires_at < ?2",
        )
        .bind(did)
        .bind(now_db)
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "mark expired endpoints stale failed"
        ))?;

        self.record_event(
            did,
            SnDeviceStateEventType::Stale,
            Some(runtime.state),
            Some(SnDeviceState::Stale),
            Some("ttl expired"),
            None,
        )
        .await?;

        Ok(true)
    }

    async fn build_state_view(
        &self,
        index: SnDeviceIndex,
        runtime: Option<RuntimeStateRow>,
        now: u64,
    ) -> SnResult<SnDeviceStateView> {
        let active_endpoints = self.list_active_endpoints(&index.did, now).await?;
        let preferred_endpoint = active_endpoints.first().cloned();
        let public_ips = Self::public_ips_for_view(runtime.as_ref())?;
        let private_ips = Self::private_ips_for_view(runtime.as_ref())?;

        Ok(SnDeviceStateView {
            did: index.did,
            zone: index.zone,
            device_name: index.device_name,
            device_role: index.device_role,
            state: runtime
                .as_ref()
                .map(|runtime| runtime.state)
                .unwrap_or(SnDeviceState::Offline),
            public_ips,
            private_ips,
            active_endpoints,
            preferred_endpoint,
            nat_type: runtime
                .as_ref()
                .map(|runtime| runtime.nat_type)
                .unwrap_or(SnNatType::Unknown),
            is_wan_device: runtime
                .as_ref()
                .map(|runtime| runtime.is_wan_device)
                .unwrap_or(false),
            last_seen_at: runtime.as_ref().and_then(|runtime| runtime.last_seen_at),
            expires_at: runtime.as_ref().and_then(|runtime| runtime.expires_at),
        })
    }
}

#[async_trait::async_trait]
impl SnDeviceInfoDB for SqliteSnDeviceInfoDB {
    async fn upsert_device_index(
        &self,
        did: &str,
        zone: &str,
        device_name: &str,
        device_role: SnDeviceRole,
    ) -> SnResult<()> {
        Self::check_did(did)?;
        Self::check_zone(zone)?;
        Self::check_device_name(device_name)?;

        if let Some(existing) = self.fetch_device_index(did).await? {
            if existing.zone != zone || existing.device_name != device_name {
                return Err(sn_err!(
                    SnErrorCode::Conflict,
                    "device did {} is bound to {}/{}; use rebind_device_index",
                    did,
                    existing.zone,
                    existing.device_name
                ));
            }

            let now = Self::now_secs();
            let mut conn = self
                .pool
                .acquire()
                .await
                .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
            sqlx::query(
                "UPDATE device_indexes
                     SET device_role = ?2, updated_at = ?3
                     WHERE did = ?1",
            )
            .bind(did)
            .bind(device_role.as_str())
            .bind(Self::to_db_time(now, "updated_at")?)
            .execute(&mut *conn)
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "update device index failed"
            ))?;

            return Ok(());
        }

        if let Some(existing) = self.fetch_device_index_by_name(zone, device_name).await? {
            return Err(sn_err!(
                SnErrorCode::Conflict,
                "{}/{} is already bound to {}",
                zone,
                device_name,
                existing.did
            ));
        }

        let now = Self::now_secs();
        let now_db = Self::to_db_time(now, "now")?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        sqlx::query(
            "INSERT INTO device_indexes
                 (did, zone, device_name, device_role, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        )
        .bind(did)
        .bind(zone)
        .bind(device_name)
        .bind(device_role.as_str())
        .bind(now_db)
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "insert device index failed"
        ))?;

        self.record_event(
            did,
            SnDeviceStateEventType::Registered,
            None,
            None,
            None,
            Some(
                json!({
                    "zone": zone,
                    "device_name": device_name,
                    "device_role": device_role.as_str(),
                })
                .to_string(),
            ),
        )
        .await
    }

    async fn rebind_device_index(
        &self,
        did: &str,
        new_zone: &str,
        new_device_name: &str,
        new_device_role: SnDeviceRole,
        reason: &str,
    ) -> SnResult<()> {
        Self::check_did(did)?;
        Self::check_zone(new_zone)?;
        Self::check_device_name(new_device_name)?;
        Self::check_reason(reason)?;

        let existing = self
            .fetch_device_index(did)
            .await?
            .ok_or_else(|| sn_err!(SnErrorCode::NotFound, "device index not found: {}", did))?;

        if let Some(bound) = self
            .fetch_device_index_by_name(new_zone, new_device_name)
            .await?
        {
            if bound.did != did {
                return Err(sn_err!(
                    SnErrorCode::Conflict,
                    "{}/{} is already bound to {}",
                    new_zone,
                    new_device_name,
                    bound.did
                ));
            }
        }

        let now = Self::now_secs();
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        sqlx::query(
            "UPDATE device_indexes
                 SET zone = ?2, device_name = ?3, device_role = ?4, updated_at = ?5
                 WHERE did = ?1",
        )
        .bind(did)
        .bind(new_zone)
        .bind(new_device_name)
        .bind(new_device_role.as_str())
        .bind(Self::to_db_time(now, "updated_at")?)
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "rebind device index failed"
        ))?;

        self.record_event(
            did,
            SnDeviceStateEventType::Rebound,
            None,
            None,
            Some(reason),
            Some(
                json!({
                    "old_zone": existing.zone,
                    "old_device_name": existing.device_name,
                    "old_device_role": existing.device_role.as_str(),
                    "new_zone": new_zone,
                    "new_device_name": new_device_name,
                    "new_device_role": new_device_role.as_str(),
                })
                .to_string(),
            ),
        )
        .await
    }

    async fn remove_device_index(&self, did: &str) -> SnResult<()> {
        Self::check_did(did)?;

        if self.fetch_device_index(did).await?.is_none() {
            return Err(sn_err!(
                SnErrorCode::NotFound,
                "device index not found: {}",
                did
            ));
        }

        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        sqlx::query("DELETE FROM device_runtime_states WHERE did = ?1")
            .bind(did)
            .execute(&mut *conn)
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "delete device runtime state failed"
            ))?;

        sqlx::query("DELETE FROM device_endpoints WHERE did = ?1")
            .bind(did)
            .execute(&mut *conn)
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "delete device endpoints failed"
            ))?;

        sqlx::query("DELETE FROM device_indexes WHERE did = ?1")
            .bind(did)
            .execute(&mut *conn)
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "delete device index failed"
            ))?;

        Ok(())
    }

    async fn update_device_state(&self, mut update: SnDeviceStateUpdate) -> SnResult<()> {
        Self::check_did(&update.did)?;
        if update.ttl == 0 {
            return Err(sn_err!(
                SnErrorCode::InvalidInput,
                "device state ttl must be greater than zero"
            ));
        }

        if self.fetch_device_index(&update.did).await?.is_none() {
            return Err(sn_err!(
                SnErrorCode::NotFound,
                "device index not found: {}",
                update.did
            ));
        }

        update.reported_ip = Self::normalize_ip_option(update.reported_ip, "reported_ip")?;
        update.reported_ips = Self::normalize_ip_vec(update.reported_ips, "reported_ips")?;
        update.from_ip = Self::normalize_ip_option(update.from_ip, "from_ip")?;

        if let Some(raw_report) = update.raw_report.as_ref() {
            serde_json::from_str::<serde_json::Value>(raw_report).map_err(|e| {
                sn_err!(
                    SnErrorCode::InvalidInput,
                    "raw_report is invalid json: {}",
                    e
                )
            })?;
        }

        for endpoint in &update.endpoints {
            Self::validate_endpoint(endpoint)?;
        }

        let old_runtime = self.fetch_runtime_state(&update.did).await?;
        if old_runtime
            .as_ref()
            .is_some_and(|runtime| runtime.state == SnDeviceState::Blocked)
        {
            self.record_event(
                &update.did,
                SnDeviceStateEventType::ReportRejected,
                Some(SnDeviceState::Blocked),
                Some(SnDeviceState::Blocked),
                Some("device is blocked"),
                update.raw_report.clone(),
            )
            .await?;

            return Err(sn_err!(
                SnErrorCode::Blocked,
                "device is blocked: {}",
                update.did
            ));
        }

        if let (Some(current_seq), Some(new_seq)) = (
            old_runtime.as_ref().and_then(|runtime| runtime.report_seq),
            update.report_seq,
        ) {
            if new_seq < current_seq {
                self.record_event(
                    &update.did,
                    SnDeviceStateEventType::ReportRejected,
                    old_runtime.as_ref().map(|runtime| runtime.state),
                    old_runtime.as_ref().map(|runtime| runtime.state),
                    Some("stale report sequence"),
                    Some(
                        json!({
                            "current_report_seq": current_seq,
                            "incoming_report_seq": new_seq,
                        })
                        .to_string(),
                    ),
                )
                .await?;

                return Err(sn_err!(
                    SnErrorCode::StaleReport,
                    "incoming report seq {} is older than current {}",
                    new_seq,
                    current_seq
                ));
            }
        }

        let old_endpoints = self
            .list_active_endpoints(&update.did, Self::now_secs())
            .await?;
        let old_endpoint_signature = old_endpoints
            .iter()
            .map(Self::endpoint_signature)
            .collect::<Vec<_>>();

        let now = Self::now_secs();
        let expires_at = now.checked_add(update.ttl).ok_or_else(|| {
            sn_err!(
                SnErrorCode::InvalidInput,
                "device state expires_at overflows u64"
            )
        })?;
        let (wan_ip, lan_ips) = Self::classify_ips(
            update.reported_ip.as_deref(),
            &update.reported_ips,
            update.from_ip.as_deref(),
        )?;
        let reported_ips_json = serde_json::to_string(&update.reported_ips).map_err(|e| {
            sn_err!(
                SnErrorCode::InvalidInput,
                "serialize reported_ips failed: {}",
                e
            )
        })?;
        let lan_ips_json = serde_json::to_string(&lan_ips)
            .map_err(|e| sn_err!(SnErrorCode::InvalidInput, "serialize lan_ips failed: {}", e))?;

        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        sqlx::query(
            "INSERT INTO device_runtime_states
                 (did, state, reported_ip, reported_ips, from_ip, wan_ip, lan_ips, nat_type,
                  is_wan_device, last_seen_at, last_report_at, expires_at, report_seq,
                  raw_report, created_at, updated_at)
                 VALUES (?1, 'online', ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10, ?11, ?12, ?9, ?9)
                 ON CONFLICT(did) DO UPDATE SET
                    state = 'online',
                    reported_ip = ?2,
                    reported_ips = ?3,
                    from_ip = ?4,
                    wan_ip = ?5,
                    lan_ips = ?6,
                    nat_type = ?7,
                    is_wan_device = ?8,
                    last_seen_at = ?9,
                    last_report_at = ?9,
                    expires_at = ?10,
                    report_seq = ?11,
                    raw_report = ?12,
                    updated_at = ?9",
        )
        .bind(&update.did)
        .bind(update.reported_ip.clone())
        .bind(reported_ips_json)
        .bind(update.from_ip.clone())
        .bind(wan_ip.clone())
        .bind(lan_ips_json)
        .bind(update.nat_type.as_str())
        .bind(if wan_ip.is_some() { 1i64 } else { 0i64 })
        .bind(Self::to_db_time(now, "now")?)
        .bind(Self::to_db_time(expires_at, "expires_at")?)
        .bind(
            update
                .report_seq
                .map(|seq| Self::to_db_time(seq, "report_seq"))
                .transpose()?,
        )
        .bind(update.raw_report.clone())
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "upsert device runtime state failed"
        ))?;

        for endpoint in &update.endpoints {
            sqlx::query(
                "INSERT INTO device_endpoints
                     (did, endpoint_id, protocol, host, port, scope, priority, source, state,
                      last_seen_at, expires_at, created_at, updated_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9, ?10, ?9, ?9)
                     ON CONFLICT(did, endpoint_id) DO UPDATE SET
                        protocol = ?3,
                        host = ?4,
                        port = ?5,
                        scope = ?6,
                        priority = ?7,
                        source = ?8,
                        state = CASE
                            WHEN device_endpoints.state = 'disabled' THEN 'disabled'
                            ELSE 'active'
                        END,
                        last_seen_at = ?9,
                        expires_at = ?10,
                        updated_at = ?9",
            )
            .bind(&update.did)
            .bind(&endpoint.endpoint_id)
            .bind(endpoint.protocol.as_str())
            .bind(&endpoint.host)
            .bind(endpoint.port.map(i64::from))
            .bind(endpoint.scope.as_str())
            .bind(endpoint.priority)
            .bind(endpoint.source.as_str())
            .bind(Self::to_db_time(now, "endpoint last_seen_at")?)
            .bind(
                endpoint
                    .expires_at
                    .or(Some(expires_at))
                    .map(|value| Self::to_db_time(value, "endpoint expires_at"))
                    .transpose()?,
            )
            .execute(&mut *conn)
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "upsert endpoint failed"))?;
        }

        if old_runtime
            .as_ref()
            .map(|runtime| runtime.state)
            .unwrap_or(SnDeviceState::Offline)
            != SnDeviceState::Online
        {
            self.record_event(
                &update.did,
                SnDeviceStateEventType::Online,
                old_runtime.as_ref().map(|runtime| runtime.state),
                Some(SnDeviceState::Online),
                None,
                update.raw_report.clone(),
            )
            .await?;
        }

        let new_endpoint_signature = self
            .list_active_endpoints(&update.did, now)
            .await?
            .iter()
            .map(Self::endpoint_signature)
            .collect::<Vec<_>>();
        if old_endpoint_signature != new_endpoint_signature {
            self.record_event(
                &update.did,
                SnDeviceStateEventType::EndpointChanged,
                Some(SnDeviceState::Online),
                Some(SnDeviceState::Online),
                None,
                Some(
                    json!({
                        "old": old_endpoint_signature,
                        "new": new_endpoint_signature,
                    })
                    .to_string(),
                ),
            )
            .await?;
        }

        Ok(())
    }

    async fn get_device_state(&self, did: &str) -> SnResult<Option<SnDeviceStateView>> {
        Self::check_did(did)?;
        let Some(index) = self.fetch_device_index(did).await? else {
            return Ok(None);
        };

        let now = Self::now_secs();
        self.mark_stale_if_expired(did, now).await?;
        let runtime = self.fetch_runtime_state(did).await?;

        self.build_state_view(index, runtime, now).await.map(Some)
    }

    async fn get_device_state_by_name(
        &self,
        zone: &str,
        device_name: &str,
    ) -> SnResult<Option<SnDeviceStateView>> {
        Self::check_zone(zone)?;
        Self::check_device_name(device_name)?;

        let Some(index) = self.fetch_device_index_by_name(zone, device_name).await? else {
            return Ok(None);
        };

        self.get_device_state(&index.did).await
    }

    async fn list_zone_devices(
        &self,
        zone: &str,
        options: SnDeviceListOptions,
    ) -> SnResult<Vec<SnDeviceStateView>> {
        Self::check_zone(zone)?;

        self.expire_devices(Self::now_secs(), None).await?;

        let now = Self::now_secs();
        let indexes = self.list_zone_indexes(zone).await?;
        let mut views = Vec::new();
        for index in indexes {
            let runtime = self.fetch_runtime_state(&index.did).await?;
            let view = self.build_state_view(index, runtime, now).await?;
            if options
                .state
                .is_some_and(|expected_state| expected_state != view.state)
            {
                continue;
            }

            views.push(view);
        }

        let offset = options.offset.unwrap_or(0);
        let limit = options.limit.unwrap_or(usize::MAX);
        Ok(views.into_iter().skip(offset).take(limit).collect())
    }

    async fn mark_device_offline(&self, did: &str, reason: &str) -> SnResult<()> {
        self.update_state_without_report(
            did,
            SnDeviceState::Offline,
            reason,
            SnDeviceStateEventType::Offline,
        )
        .await
    }

    async fn block_device(&self, did: &str, reason: &str) -> SnResult<()> {
        self.update_state_without_report(
            did,
            SnDeviceState::Blocked,
            reason,
            SnDeviceStateEventType::Blocked,
        )
        .await
    }

    async fn unblock_device(&self, did: &str, reason: &str) -> SnResult<()> {
        self.update_state_without_report(
            did,
            SnDeviceState::Offline,
            reason,
            SnDeviceStateEventType::Unblocked,
        )
        .await?;

        let now = Self::now_secs();
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;
        sqlx::query(
            "UPDATE device_endpoints
                 SET state = 'stale', updated_at = ?2
                 WHERE did = ?1 AND state = 'disabled'",
        )
        .bind(did)
        .bind(Self::to_db_time(now, "updated_at")?)
        .execute(&mut *conn)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "mark unblocked endpoints stale failed"
        ))?;

        Ok(())
    }

    async fn expire_devices(&self, now: u64, batch_size: Option<usize>) -> SnResult<usize> {
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(into_sn_err!(SnErrorCode::DBError, "get conn"))?;

        let mut query = String::from(
            "SELECT did FROM device_runtime_states
             WHERE state = 'online' AND expires_at IS NOT NULL AND expires_at < ?1
             ORDER BY expires_at ASC",
        );
        if batch_size.is_some() {
            query.push_str(" LIMIT ?2");
        }

        let rows =
            if let Some(batch_size) = batch_size {
                sqlx::query(&query)
                    .bind(Self::to_db_time(now, "now")?)
                    .bind(i64::try_from(batch_size).map_err(|_| {
                        sn_err!(SnErrorCode::InvalidInput, "batch_size is too large")
                    })?)
                    .fetch_all(&mut *conn)
                    .await
            } else {
                sqlx::query(&query)
                    .bind(Self::to_db_time(now, "now")?)
                    .fetch_all(&mut *conn)
                    .await
            }
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "query expired devices failed"
            ))?;

        let dids = rows
            .into_iter()
            .map(|row| row.get::<String, _>(0))
            .collect::<Vec<_>>();

        for did in &dids {
            self.mark_stale_if_expired(did, now).await?;
        }

        Ok(dids.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn temp_db() -> SnResult<(tempfile::TempDir, SqliteSnDeviceInfoDB)> {
        let tmp_dir = tempfile::tempdir()
            .map_err(|e| sn_err!(SnErrorCode::DBError, "create temp dir failed: {}", e))?;
        let db_path = tmp_dir.path().join("sn_device_info.sqlite3");
        let db = SqliteSnDeviceInfoDB::new_by_path(db_path.to_string_lossy().as_ref()).await?;
        db.initialize_database().await?;
        Ok((tmp_dir, db))
    }

    fn endpoint(endpoint_id: &str, host: &str, scope: SnEndpointScope) -> SnDeviceEndpointUpdate {
        SnDeviceEndpointUpdate {
            endpoint_id: endpoint_id.to_string(),
            protocol: SnEndpointProtocol::Tcp,
            host: host.to_string(),
            port: Some(8080),
            scope,
            priority: 10,
            source: SnEndpointSource::DeviceReport,
            expires_at: None,
        }
    }

    fn state_update(did: &str, seq: u64, ttl: u64) -> SnDeviceStateUpdate {
        SnDeviceStateUpdate {
            did: did.to_string(),
            reported_ip: Some("192.168.1.10".to_string()),
            reported_ips: vec!["8.8.8.8".to_string(), "10.0.0.2".to_string()],
            from_ip: Some("1.1.1.1".to_string()),
            nat_type: SnNatType::Public,
            endpoints: vec![
                endpoint("private", "192.168.1.10", SnEndpointScope::Private),
                endpoint("public", "8.8.8.8", SnEndpointScope::Public),
            ],
            report_seq: Some(seq),
            ttl,
            raw_report: Some(r#"{"ok":true}"#.to_string()),
        }
    }

    #[tokio::test]
    async fn test_device_state_lifecycle() -> SnResult<()> {
        let (_tmp_dir, db) = temp_db().await?;
        let did = "did:dev:test-device-id";

        assert!(db.get_device_state(did).await?.is_none());
        db.upsert_device_index(did, "example", "ood1", SnDeviceRole::Ood)
            .await?;

        let offline = db.get_device_state(did).await?.unwrap();
        assert_eq!(offline.state, SnDeviceState::Offline);
        assert!(offline.active_endpoints.is_empty());

        db.update_device_state(state_update(did, 10, 60)).await?;
        let online = db
            .get_device_state_by_name("example", "ood1")
            .await?
            .unwrap();
        assert_eq!(online.state, SnDeviceState::Online);
        assert_eq!(online.public_ips, vec!["8.8.8.8", "1.1.1.1"]);
        assert_eq!(online.private_ips, vec!["192.168.1.10", "10.0.0.2"]);
        assert_eq!(online.active_endpoints.len(), 2);
        assert_eq!(
            online.preferred_endpoint.as_ref().unwrap().endpoint_id,
            "public"
        );
        assert!(online.is_wan_device);

        db.mark_device_offline(did, "manual").await?;
        let offline = db.get_device_state(did).await?.unwrap();
        assert_eq!(offline.state, SnDeviceState::Offline);
        assert!(offline.active_endpoints.is_empty());

        Ok(())
    }

    #[tokio::test]
    async fn test_device_index_conflict_and_rebind() -> SnResult<()> {
        let (_tmp_dir, db) = temp_db().await?;
        let did = "did:dev:test-device-id";

        db.upsert_device_index(did, "example", "ood1", SnDeviceRole::Ood)
            .await?;

        assert!(db
            .upsert_device_index(did, "example", "ood2", SnDeviceRole::Ood)
            .await
            .is_err());

        db.upsert_device_index("did:dev:other", "example", "ood2", SnDeviceRole::Ood)
            .await?;
        assert!(db
            .rebind_device_index(did, "example", "ood2", SnDeviceRole::Ood, "move")
            .await
            .is_err());

        db.rebind_device_index(did, "example", "gateway", SnDeviceRole::Gateway, "move")
            .await?;
        assert!(db
            .get_device_state_by_name("example", "ood1")
            .await?
            .is_none());
        assert!(db
            .get_device_state_by_name("example", "gateway")
            .await?
            .is_some());

        Ok(())
    }

    #[tokio::test]
    async fn test_stale_report_block_and_expire() -> SnResult<()> {
        let (_tmp_dir, db) = temp_db().await?;
        let did = "did:dev:test-device-id";
        db.upsert_device_index(did, "example", "ood1", SnDeviceRole::Ood)
            .await?;

        db.update_device_state(state_update(did, 10, 1)).await?;
        assert!(db
            .update_device_state(state_update(did, 9, 1))
            .await
            .is_err());

        let expired_count = db
            .expire_devices(SqliteSnDeviceInfoDB::now_secs() + 2, None)
            .await?;
        assert_eq!(expired_count, 1);
        assert_eq!(
            db.get_device_state(did).await?.unwrap().state,
            SnDeviceState::Stale
        );

        db.block_device(did, "admin").await?;
        assert!(db
            .update_device_state(state_update(did, 11, 60))
            .await
            .is_err());
        assert_eq!(
            db.get_device_state(did).await?.unwrap().state,
            SnDeviceState::Blocked
        );

        db.unblock_device(did, "admin").await?;
        db.update_device_state(state_update(did, 11, 60)).await?;
        let online = db.get_device_state(did).await?.unwrap();
        assert_eq!(online.state, SnDeviceState::Online);
        assert_eq!(online.active_endpoints.len(), 2);

        Ok(())
    }

    // ---- test helpers (raw DB introspection) ----

    async fn event_types(db: &SqliteSnDeviceInfoDB, did: &str) -> Vec<String> {
        let mut conn = db.pool.acquire().await.unwrap();
        let rows = sqlx::query(
            "SELECT event_type FROM device_state_events WHERE did = ?1 ORDER BY id ASC",
        )
        .bind(did)
        .fetch_all(&mut *conn)
        .await
        .unwrap();
        rows.into_iter().map(|r| r.get::<String, _>(0)).collect()
    }

    async fn scalar_i64(db: &SqliteSnDeviceInfoDB, sql: &str, did: &str) -> i64 {
        let mut conn = db.pool.acquire().await.unwrap();
        let row = sqlx::query(sql)
            .bind(did)
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        row.get::<i64, _>(0)
    }

    async fn runtime_pair(
        db: &SqliteSnDeviceInfoDB,
        did: &str,
    ) -> (Option<String>, Option<String>) {
        let mut conn = db.pool.acquire().await.unwrap();
        let row =
            sqlx::query("SELECT reported_ip, from_ip FROM device_runtime_states WHERE did = ?1")
                .bind(did)
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        (
            row.get::<Option<String>, _>(0),
            row.get::<Option<String>, _>(1),
        )
    }

    fn ep_full(endpoint_id: &str, scope: SnEndpointScope, priority: i64) -> SnDeviceEndpoint {
        SnDeviceEndpoint {
            did: "did:dev:x".to_string(),
            endpoint_id: endpoint_id.to_string(),
            protocol: SnEndpointProtocol::Tcp,
            host: "1.2.3.4".to_string(),
            port: Some(80),
            scope,
            priority,
            source: SnEndpointSource::DeviceReport,
            state: SnEndpointState::Active,
            last_seen_at: None,
            expires_at: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    // =====================================================================
    // §4.1 索引与重绑 (device_index)
    // =====================================================================

    #[tokio::test]
    async fn test_upsert_device_index_create_update_and_conflicts() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";

        // 新 DID 创建
        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;
        assert_eq!(
            db.get_device_state(did).await?.unwrap().device_role,
            SnDeviceRole::Ood
        );

        // 同 DID 同 (zone,device_name) → 更新 role
        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Gateway)
            .await?;
        assert_eq!(
            db.get_device_state(did).await?.unwrap().device_role,
            SnDeviceRole::Gateway
        );

        // 同 DID 但 (zone,device_name) 变化 → Conflict（要求 rebind）
        let err = db
            .upsert_device_index(did, "zone1", "ood2", SnDeviceRole::Ood)
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Conflict);

        // 新 (zone,device_name) 已被他 DID 占用 → Conflict
        db.upsert_device_index("did:dev:b", "zone1", "ood3", SnDeviceRole::Ood)
            .await?;
        let err = db
            .upsert_device_index("did:dev:c", "zone1", "ood3", SnDeviceRole::Ood)
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Conflict);

        Ok(())
    }

    #[tokio::test]
    async fn test_rebind_not_found_conflict_and_preserves_runtime() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";

        // DID 不存在 → NotFound
        let err = db
            .rebind_device_index(did, "zone1", "ood1", SnDeviceRole::Ood, "move")
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::NotFound);

        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;
        db.update_device_state(state_update(did, 10, 60)).await?;

        // 目标 (zone,device_name) 已被他 DID 占用 → Conflict
        db.upsert_device_index("did:dev:b", "zone1", "ood2", SnDeviceRole::Ood)
            .await?;
        let err = db
            .rebind_device_index(did, "zone1", "ood2", SnDeviceRole::Ood, "move")
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Conflict);

        // 成功重绑：保留 runtime + endpoint，记 rebound 事件
        db.rebind_device_index(did, "zone1", "gw", SnDeviceRole::Gateway, "promote")
            .await?;
        let view = db.get_device_state(did).await?.unwrap();
        assert_eq!(view.device_name, "gw");
        assert_eq!(view.device_role, SnDeviceRole::Gateway);
        assert_eq!(view.state, SnDeviceState::Online); // runtime 保留
        assert_eq!(view.active_endpoints.len(), 2); // endpoint 保留
        assert!(event_types(&db, did).await.contains(&"rebound".to_string()));

        Ok(())
    }

    #[tokio::test]
    async fn test_remove_device_index_keeps_events() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";

        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;
        db.update_device_state(state_update(did, 10, 60)).await?;

        db.remove_device_index(did).await?;

        // index / runtime / endpoints 删除
        assert!(db.get_device_state(did).await?.is_none());
        assert_eq!(
            scalar_i64(
                &db,
                "SELECT COUNT(*) FROM device_runtime_states WHERE did = ?1",
                did
            )
            .await,
            0
        );
        assert_eq!(
            scalar_i64(
                &db,
                "SELECT COUNT(*) FROM device_endpoints WHERE did = ?1",
                did
            )
            .await,
            0
        );

        // device_state_events 保留
        assert!(
            scalar_i64(
                &db,
                "SELECT COUNT(*) FROM device_state_events WHERE did = ?1",
                did
            )
            .await
                > 0
        );

        // 删除不存在的 DID → NotFound
        let err = db.remove_device_index("did:dev:missing").await.unwrap_err();
        assert_eq!(err.code(), SnErrorCode::NotFound);

        Ok(())
    }

    #[tokio::test]
    async fn test_unique_constraints() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;

        db.upsert_device_index("did:dev:a", "zone1", "ood1", SnDeviceRole::Ood)
            .await?;
        // (zone,device_name) 唯一：他 DID 占用同名 → Conflict
        let err = db
            .upsert_device_index("did:dev:b", "zone1", "ood1", SnDeviceRole::Ood)
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Conflict);

        // did 唯一：同 DID 不同名也无法再创建第二行（走 rebind 语义）
        let err = db
            .upsert_device_index("did:dev:a", "zone2", "ood9", SnDeviceRole::Ood)
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Conflict);
        assert_eq!(
            scalar_i64(
                &db,
                "SELECT COUNT(*) FROM device_indexes WHERE did = ?1",
                "did:dev:a"
            )
            .await,
            1
        );

        Ok(())
    }

    // =====================================================================
    // §4.2 运行态写入 (update_device_state)
    // =====================================================================

    #[tokio::test]
    async fn test_update_device_state_not_found() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let err = db
            .update_device_state(state_update("did:dev:missing", 1, 60))
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::NotFound);
        Ok(())
    }

    #[tokio::test]
    async fn test_stale_report_rejected_records_event() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";
        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;

        db.update_device_state(state_update(did, 20, 60)).await?;

        // report_seq 明显旧于当前 → StaleReport + report_rejected 事件
        let err = db
            .update_device_state(state_update(did, 5, 60))
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::StaleReport);
        assert!(event_types(&db, did)
            .await
            .contains(&"report_rejected".to_string()));

        // 相等 seq 不算 stale（>= 接受）
        db.update_device_state(state_update(did, 20, 60)).await?;
        // 更大 seq 接受
        db.update_device_state(state_update(did, 21, 60)).await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_blocked_device_rejects_report_only_unblock_recovers() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";
        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;
        db.update_device_state(state_update(did, 10, 60)).await?;

        db.block_device(did, "admin").await?;

        // blocked 设备普通上报被拒，不改回 online，记 report_rejected
        let err = db
            .update_device_state(state_update(did, 11, 60))
            .await
            .unwrap_err();
        assert_eq!(err.code(), SnErrorCode::Blocked);
        assert_eq!(
            db.get_device_state(did).await?.unwrap().state,
            SnDeviceState::Blocked
        );
        assert!(event_types(&db, did)
            .await
            .contains(&"report_rejected".to_string()));

        // 仅 unblock_device 可恢复（恢复为 offline 等下次上报）
        db.unblock_device(did, "admin").await?;
        assert_eq!(
            db.get_device_state(did).await?.unwrap().state,
            SnDeviceState::Offline
        );
        db.update_device_state(state_update(did, 11, 60)).await?;
        assert_eq!(
            db.get_device_state(did).await?.unwrap().state,
            SnDeviceState::Online
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_update_device_state_expiry_and_events() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";
        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;

        let before = SqliteSnDeviceInfoDB::now_secs();
        db.update_device_state(state_update(did, 10, 120)).await?;
        let view = db.get_device_state(did).await?.unwrap();
        // expires_at = now + ttl
        let expires = view.expires_at.unwrap();
        assert!(expires >= before + 120 && expires <= SqliteSnDeviceInfoDB::now_secs() + 120);

        // 首次上线记 online + endpoint 变化记 endpoint_changed
        let events = event_types(&db, did).await;
        assert!(events.contains(&"online".to_string()));
        assert!(events.contains(&"endpoint_changed".to_string()));

        // 幂等：相同上报不再追加事件
        let before_count = event_types(&db, did).await.len();
        db.update_device_state(state_update(did, 10, 120)).await?;
        assert_eq!(event_types(&db, did).await.len(), before_count);

        // endpoint 集合变化 → 再次 endpoint_changed
        let mut changed = state_update(did, 11, 120);
        changed.endpoints = vec![endpoint("relay", "9.9.9.9", SnEndpointScope::Relay)];
        db.update_device_state(changed).await?;
        let endpoint_changes = event_types(&db, did)
            .await
            .into_iter()
            .filter(|e| e == "endpoint_changed")
            .count();
        assert!(endpoint_changes >= 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_from_ip_and_reported_ip_stored_separately() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";
        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;

        let mut update = state_update(did, 10, 60);
        update.reported_ip = Some("203.0.113.5".to_string());
        update.from_ip = Some("198.51.100.7".to_string());
        db.update_device_state(update).await?;

        let (reported_ip, from_ip) = runtime_pair(&db, did).await;
        assert_eq!(reported_ip.as_deref(), Some("203.0.113.5"));
        assert_eq!(from_ip.as_deref(), Some("198.51.100.7"));

        Ok(())
    }

    // =====================================================================
    // §4.3 IP / endpoint 规则
    // =====================================================================

    #[tokio::test]
    async fn test_is_public_ipv4_rules() {
        let public = ["8.8.8.8", "1.1.1.1", "203.0.113.1"];
        for ip in public {
            assert!(
                SqliteSnDeviceInfoDB::is_public_ipv4(&ip.parse().unwrap()),
                "{} should be public",
                ip
            );
        }
        let private = [
            "10.0.0.1",        // RFC1918
            "172.16.0.1",      // RFC1918
            "192.168.1.1",     // RFC1918
            "127.0.0.1",       // loopback
            "169.254.1.1",     // link-local
            "224.0.0.1",       // multicast
            "0.0.0.0",         // unspecified
            "255.255.255.255", // broadcast
            "100.64.0.1",      // CGNAT
            "198.18.0.1",      // benchmarking
            "240.0.0.1",       // reserved
        ];
        for ip in private {
            assert!(
                !SqliteSnDeviceInfoDB::is_public_ipv4(&ip.parse().unwrap()),
                "{} should not be public",
                ip
            );
        }
    }

    #[tokio::test]
    async fn test_is_public_ipv6_rules() {
        assert!(SqliteSnDeviceInfoDB::is_public_ipv6(
            &"2606:4700:4700::1111".parse().unwrap()
        ));
        let non_public = [
            "::1",         // loopback
            "ff02::1",     // multicast
            "::",          // unspecified
            "fc00::1",     // ULA
            "fe80::1",     // link-local
            "2001:db8::1", // documentation
        ];
        for ip in non_public {
            assert!(
                !SqliteSnDeviceInfoDB::is_public_ipv6(&ip.parse().unwrap()),
                "{} should not be public",
                ip
            );
        }
    }

    #[tokio::test]
    async fn test_classify_ips_wan_lan() -> SnResult<()> {
        let (wan, lan) = SqliteSnDeviceInfoDB::classify_ips(
            Some("192.168.0.5"),
            &["8.8.8.8".to_string(), "10.0.0.7".to_string()],
            Some("1.1.1.1"),
        )?;
        // 第一个公网作为 wan，私网进 lan（不进 DNS 视图）
        assert_eq!(wan.as_deref(), Some("8.8.8.8"));
        assert_eq!(lan, vec!["192.168.0.5", "10.0.0.7"]);

        // 全私网 → 无 wan
        let (wan, lan) = SqliteSnDeviceInfoDB::classify_ips(Some("10.0.0.1"), &[], None)?;
        assert!(wan.is_none());
        assert_eq!(lan, vec!["10.0.0.1"]);

        Ok(())
    }

    #[tokio::test]
    async fn test_endpoint_sort_key_ordering() {
        let mut endpoints = vec![
            ep_full("unknown", SnEndpointScope::Unknown, 1),
            ep_full("loopback", SnEndpointScope::Loopback, 1),
            ep_full("private", SnEndpointScope::Private, 1),
            ep_full("relay", SnEndpointScope::Relay, 1),
            ep_full("public-hi", SnEndpointScope::Public, 50),
            ep_full("public-lo", SnEndpointScope::Public, 10),
        ];
        endpoints.sort_by_key(SqliteSnDeviceInfoDB::endpoint_sort_key);
        let order: Vec<&str> = endpoints.iter().map(|e| e.endpoint_id.as_str()).collect();
        // public(priority 小优先) < relay < private < loopback < unknown
        assert_eq!(
            order,
            vec![
                "public-lo",
                "public-hi",
                "relay",
                "private",
                "loopback",
                "unknown"
            ]
        );
    }

    #[tokio::test]
    async fn test_expired_and_disabled_endpoints_excluded() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";
        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;

        // 一个过期 endpoint（expires_at 在过去）+ 一个正常 endpoint
        let mut update = state_update(did, 10, 600);
        let mut expired_ep = endpoint("expired", "8.8.4.4", SnEndpointScope::Public);
        expired_ep.expires_at = Some(1);
        update.endpoints = vec![
            expired_ep,
            endpoint("live", "8.8.8.8", SnEndpointScope::Public),
        ];
        db.update_device_state(update).await?;

        let view = db.get_device_state(did).await?.unwrap();
        let ids: Vec<&str> = view
            .active_endpoints
            .iter()
            .map(|e| e.endpoint_id.as_str())
            .collect();
        assert_eq!(ids, vec!["live"]); // 过期 endpoint 不进 active 列表

        // block → endpoint disabled → 不进 active 列表
        db.block_device(did, "admin").await?;
        assert!(db
            .get_device_state(did)
            .await?
            .unwrap()
            .active_endpoints
            .is_empty());
        assert_eq!(
            scalar_i64(
                &db,
                "SELECT COUNT(*) FROM device_endpoints WHERE did = ?1 AND state = 'disabled'",
                did
            )
            .await,
            2
        );

        Ok(())
    }

    // =====================================================================
    // §4.4 查询视图与状态迁移
    // =====================================================================

    #[tokio::test]
    async fn test_get_device_state_marks_stale_on_expiry() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";
        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;
        db.update_device_state(state_update(did, 10, 600)).await?;

        // 强制 runtime 过期
        {
            let mut conn = db.pool.acquire().await.unwrap();
            sqlx::query("UPDATE device_runtime_states SET expires_at = 1 WHERE did = ?1")
                .bind(did)
                .execute(&mut *conn)
                .await
                .unwrap();
        }

        // 读路径先落库 stale 再返回视图
        assert_eq!(
            db.get_device_state(did).await?.unwrap().state,
            SnDeviceState::Stale
        );
        assert_eq!(
            scalar_i64(
                &db,
                "SELECT COUNT(*) FROM device_runtime_states WHERE did = ?1 AND state = 'stale'",
                did
            )
            .await,
            1
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_list_zone_devices_filter_and_pagination() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        for i in 0..3 {
            let did = format!("did:dev:{}", i);
            db.upsert_device_index(&did, "zone1", &format!("ood{}", i), SnDeviceRole::Ood)
                .await?;
            db.update_device_state(state_update(&did, 10, 600)).await?;
        }
        // 另一台保持 offline
        db.upsert_device_index("did:dev:off", "zone1", "ood-off", SnDeviceRole::Ood)
            .await?;

        // state 过滤
        let online = db
            .list_zone_devices(
                "zone1",
                SnDeviceListOptions {
                    state: Some(SnDeviceState::Online),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(online.len(), 3);

        let offline = db
            .list_zone_devices(
                "zone1",
                SnDeviceListOptions {
                    state: Some(SnDeviceState::Offline),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(offline.len(), 1);

        // 分页
        let page = db
            .list_zone_devices(
                "zone1",
                SnDeviceListOptions {
                    offset: Some(1),
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await?;
        assert_eq!(page.len(), 2);

        Ok(())
    }

    #[tokio::test]
    async fn test_mark_device_offline_event_and_endpoints() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";
        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;
        db.update_device_state(state_update(did, 10, 600)).await?;

        db.mark_device_offline(did, "manual").await?;
        let view = db.get_device_state(did).await?.unwrap();
        assert_eq!(view.state, SnDeviceState::Offline);
        assert!(view.active_endpoints.is_empty()); // active endpoint → stale
        assert!(event_types(&db, did).await.contains(&"offline".to_string()));
        assert_eq!(
            scalar_i64(
                &db,
                "SELECT COUNT(*) FROM device_endpoints WHERE did = ?1 AND state = 'stale'",
                did
            )
            .await,
            2
        );

        // 空 reason → InvalidInput
        let err = db.mark_device_offline(did, "").await.unwrap_err();
        assert_eq!(err.code(), SnErrorCode::InvalidInput);

        Ok(())
    }

    #[tokio::test]
    async fn test_block_unblock_events_and_endpoints() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        let did = "did:dev:a";
        db.upsert_device_index(did, "zone1", "ood1", SnDeviceRole::Ood)
            .await?;
        db.update_device_state(state_update(did, 10, 600)).await?;

        // block → blocked + 禁用 endpoint + blocked 事件
        db.block_device(did, "abuse").await?;
        assert_eq!(
            db.get_device_state(did).await?.unwrap().state,
            SnDeviceState::Blocked
        );
        assert!(event_types(&db, did).await.contains(&"blocked".to_string()));
        assert_eq!(
            scalar_i64(
                &db,
                "SELECT COUNT(*) FROM device_endpoints WHERE did = ?1 AND state = 'disabled'",
                did
            )
            .await,
            2
        );

        // unblock → offline 等下次上报 + unblocked 事件 + disabled→stale
        db.unblock_device(did, "appeal").await?;
        assert_eq!(
            db.get_device_state(did).await?.unwrap().state,
            SnDeviceState::Offline
        );
        assert!(event_types(&db, did)
            .await
            .contains(&"unblocked".to_string()));
        assert_eq!(
            scalar_i64(
                &db,
                "SELECT COUNT(*) FROM device_endpoints WHERE did = ?1 AND state = 'disabled'",
                did
            )
            .await,
            0
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_expire_devices_batch_size() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        for i in 0..3 {
            let did = format!("did:dev:{}", i);
            db.upsert_device_index(&did, "zone1", &format!("ood{}", i), SnDeviceRole::Ood)
                .await?;
            db.update_device_state(state_update(&did, 10, 1)).await?;
        }

        let future = SqliteSnDeviceInfoDB::now_secs() + 10;
        // 批量大小生效：只处理 2 台
        let expired = db.expire_devices(future, Some(2)).await?;
        assert_eq!(expired, 2);
        let mut conn = db.pool.acquire().await.unwrap();
        let online_left =
            sqlx::query("SELECT COUNT(*) FROM device_runtime_states WHERE state = 'online'")
                .fetch_one(&mut *conn)
                .await
                .unwrap()
                .get::<i64, _>(0);
        drop(conn);
        assert_eq!(online_left, 1);

        // 再次无限制 → 处理剩余
        let expired = db.expire_devices(future, None).await?;
        assert_eq!(expired, 1);

        Ok(())
    }

    // =====================================================================
    // §4.5 错误语义
    // =====================================================================

    #[tokio::test]
    async fn test_invalid_input_errors() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;

        // 空 DID / zone / device_name
        assert_eq!(
            db.upsert_device_index("", "zone1", "ood1", SnDeviceRole::Ood)
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );
        assert_eq!(
            db.upsert_device_index("did:dev:a", "  ", "ood1", SnDeviceRole::Ood)
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );
        assert_eq!(
            db.upsert_device_index("did:dev:a", "zone1", "", SnDeviceRole::Ood)
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );

        db.upsert_device_index("did:dev:a", "zone1", "ood1", SnDeviceRole::Ood)
            .await?;

        // ttl = 0
        let mut zero_ttl = state_update("did:dev:a", 1, 0);
        assert_eq!(
            db.update_device_state(zero_ttl.clone())
                .await
                .unwrap_err()
                .code(),
            SnErrorCode::InvalidInput
        );

        // 非法 IP
        zero_ttl.ttl = 60;
        zero_ttl.reported_ip = Some("not-an-ip".to_string());
        assert_eq!(
            db.update_device_state(zero_ttl).await.unwrap_err().code(),
            SnErrorCode::InvalidInput
        );

        // 非法 endpoint（空 host）
        let mut bad_ep = state_update("did:dev:a", 1, 60);
        bad_ep.reported_ip = Some("8.8.8.8".to_string());
        bad_ep.reported_ips = vec![];
        bad_ep.from_ip = None;
        bad_ep.endpoints = vec![endpoint("ep", "", SnEndpointScope::Public)];
        assert_eq!(
            db.update_device_state(bad_ep).await.unwrap_err().code(),
            SnErrorCode::InvalidInput
        );

        // 非法 endpoint（priority 为负）
        let mut neg_prio = state_update("did:dev:a", 1, 60);
        neg_prio.reported_ip = Some("8.8.8.8".to_string());
        neg_prio.reported_ips = vec![];
        neg_prio.from_ip = None;
        let mut ep = endpoint("ep", "8.8.8.8", SnEndpointScope::Public);
        ep.priority = -1;
        neg_prio.endpoints = vec![ep];
        assert_eq!(
            db.update_device_state(neg_prio).await.unwrap_err().code(),
            SnErrorCode::InvalidInput
        );

        // 非法 raw_report json
        let mut bad_json = state_update("did:dev:a", 1, 60);
        bad_json.reported_ip = Some("8.8.8.8".to_string());
        bad_json.reported_ips = vec![];
        bad_json.from_ip = None;
        bad_json.endpoints = vec![];
        bad_json.raw_report = Some("{not json".to_string());
        assert_eq!(
            db.update_device_state(bad_json).await.unwrap_err().code(),
            SnErrorCode::InvalidInput
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_db_error_on_closed_pool() -> SnResult<()> {
        let (_tmp, db) = temp_db().await?;
        db.pool.close().await;

        let err = db.get_device_state("did:dev:a").await.unwrap_err();
        assert_eq!(err.code(), SnErrorCode::DBError);

        Ok(())
    }
}
