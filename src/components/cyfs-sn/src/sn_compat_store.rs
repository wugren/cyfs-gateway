use crate::{SnErrorCode, SnResult, into_sn_err};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow};
use sqlx::{Row, SqlitePool};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub type SnCompatibilityStoreRef = Arc<dyn SnCompatibilityStore>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SNDeviceInfo {
    pub owner: String,
    pub device_name: String,
    pub mini_config_jwt: String,
    pub did: String,
    pub ip: String,
    pub description: String,
    pub created_at: u64,
    pub updated_at: u64,
}

#[cfg(test)]
mod tests {
    use super::{SnCompatibilityStore, SqliteSnCompatibilityStore};

    #[tokio::test]
    async fn txt_rrset_is_multivalue_idempotent_and_exactly_removed() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let store = SqliteSnCompatibilityStore::new_by_path(file.path().to_str().unwrap())
            .await
            .unwrap();
        store.initialize_database().await.unwrap();
        let name = "_acme-challenge.alice.example";

        store
            .add_user_domain("alice", name, "TXT", "root-order", 600)
            .await
            .unwrap();
        store
            .add_user_domain("alice", name, "TXT", "wildcard-order", 300)
            .await
            .unwrap();
        store
            .add_user_domain("alice", name, "TXT", "root-order", 120)
            .await
            .unwrap();

        let (records, ttl) = store
            .query_domain_record(name, "TXT")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            records.split(',').collect::<Vec<_>>(),
            vec!["root-order", "wildcard-order"]
        );
        assert_eq!(ttl, 120);

        store
            .remove_user_domain("alice", name, "TXT", Some("root-order"))
            .await
            .unwrap();
        let (records, _) = store
            .query_domain_record(name, "TXT")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(records, "wildcard-order");
    }
}

#[async_trait::async_trait]
pub trait SnCompatibilityStore: Send + Sync + 'static {
    async fn query_device_by_name(
        &self,
        username: &str,
        device_name: &str,
    ) -> SnResult<Option<SNDeviceInfo>>;
    async fn query_device_by_did(&self, did: &str) -> SnResult<Option<SNDeviceInfo>>;
    async fn add_user_domain(
        &self,
        username: &str,
        domain: &str,
        record_type: &str,
        record: &str,
        ttl: u32,
    ) -> SnResult<()>;
    async fn remove_user_domain(
        &self,
        username: &str,
        domain: &str,
        record_type: &str,
        record: Option<&str>,
    ) -> SnResult<()>;
    async fn query_domain_record(
        &self,
        domain: &str,
        record_type: &str,
    ) -> SnResult<Option<(String, u32)>>;
    async fn query_user_domain_records(
        &self,
        username: &str,
    ) -> SnResult<Vec<(String, String, String, u32)>>;
    async fn query_user_did_document(
        &self,
        owner_user: &str,
        obj_name: &str,
        doc_type: Option<&str>,
    ) -> SnResult<Option<(String, String, Option<String>)>>;
}

pub struct SqliteSnCompatibilityStore {
    pool: SqlitePool,
}

impl SqliteSnCompatibilityStore {
    pub async fn new() -> SnResult<Self> {
        let base_dir = PathBuf::from(std::env::current_exe().unwrap().parent().unwrap());
        let db_path = base_dir.join("sn_compat.sqlite3");

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

    pub async fn open_local(path: &str) -> SnResult<SnCompatibilityStoreRef> {
        let store = Self::new_by_path(path).await?;
        store.initialize_database().await?;
        Ok(Arc::new(store))
    }

    pub async fn initialize_database(&self) -> SnResult<()> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS devices (
                owner TEXT NOT NULL,
                device_name TEXT NOT NULL,
                did TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                description TEXT NOT NULL,
                mini_config_jwt TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(owner, device_name)
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create devices table failed"
        ))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS user_dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner TEXT NOT NULL,
                domain TEXT NOT NULL,
                record_type TEXT NOT NULL,
                record TEXT NOT NULL,
                ttl INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create user_dns_records table failed"
        ))?;
        // Beta2.2 changes the legacy single-value row into an RRset. Drop the
        // old index explicitly so existing databases migrate in place.
        sqlx::query("DROP INDEX IF EXISTS idx_user_domain_record_type")
            .execute(&self.pool)
            .await
            .map_err(into_sn_err!(
                SnErrorCode::DBError,
                "drop legacy dns index failed"
            ))?;
        sqlx::query(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_domain_record_value
             ON user_dns_records (owner, domain, record_type, record)",
        )
        .execute(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create unique index on user_dns_records failed"
        ))?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS user_dns_records_domain_index
             ON user_dns_records (domain, id)",
        )
        .execute(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create user_dns_records_domain_index failed"
        ))?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS did_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                obj_id TEXT NOT NULL,
                owner_user TEXT NOT NULL,
                obj_name TEXT NOT NULL,
                did_document TEXT NOT NULL,
                doc_type TEXT NULL,
                update_time INTEGER NOT NULL
            )",
        )
        .execute(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create did_documents table failed"
        ))?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_did_documents_owner_obj
             ON did_documents (owner_user, obj_name, update_time)",
        )
        .execute(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "create did_documents index failed"
        ))?;

        Ok(())
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn device_from_row(row: SqliteRow) -> SNDeviceInfo {
        SNDeviceInfo {
            owner: row.get(0),
            device_name: row.get(1),
            mini_config_jwt: row.get(2),
            did: row.get(3),
            ip: row.get(4),
            description: row.get(5),
            created_at: row.get::<i64, _>(6).max(0) as u64,
            updated_at: row.get::<i64, _>(7).max(0) as u64,
        }
    }
}

#[async_trait::async_trait]
impl SnCompatibilityStore for SqliteSnCompatibilityStore {
    async fn query_device_by_name(
        &self,
        username: &str,
        device_name: &str,
    ) -> SnResult<Option<SNDeviceInfo>> {
        let row = sqlx::query(
            "SELECT owner, device_name, mini_config_jwt, did, ip, description, created_at, updated_at
             FROM devices WHERE device_name = ?1 AND owner = ?2",
        )
        .bind(device_name)
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "query device by name failed"
        ))?;
        Ok(row.map(Self::device_from_row))
    }

    async fn query_device_by_did(&self, did: &str) -> SnResult<Option<SNDeviceInfo>> {
        let row = sqlx::query(
            "SELECT owner, device_name, mini_config_jwt, did, ip, description, created_at, updated_at
             FROM devices WHERE did = ?1",
        )
        .bind(did)
        .fetch_optional(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "query device by did failed"
        ))?;
        Ok(row.map(Self::device_from_row))
    }

    async fn add_user_domain(
        &self,
        username: &str,
        domain: &str,
        record_type: &str,
        record: &str,
        ttl: u32,
    ) -> SnResult<()> {
        let now = Self::now_secs() as i64;
        sqlx::query(
            "INSERT INTO user_dns_records
                (owner, domain, record_type, record, ttl, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(owner, domain, record_type, record)
             DO UPDATE SET ttl = excluded.ttl,
                           updated_at = excluded.updated_at",
        )
        .bind(username)
        .bind(domain)
        .bind(record_type)
        .bind(record)
        .bind(ttl as i64)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "insert on conflict user dns record failed"
        ))?;
        Ok(())
    }

    async fn remove_user_domain(
        &self,
        username: &str,
        domain: &str,
        record_type: &str,
        record: Option<&str>,
    ) -> SnResult<()> {
        let mut query = if record.is_some() {
            sqlx::query(
                "DELETE FROM user_dns_records WHERE owner = ?1 AND domain = ?2 AND record_type = ?3 AND record = ?4",
            )
        } else {
            sqlx::query(
                "DELETE FROM user_dns_records WHERE owner = ?1 AND domain = ?2 AND record_type = ?3",
            )
        };
        query = query.bind(username).bind(domain).bind(record_type);
        if let Some(record) = record {
            query = query.bind(record);
        }
        query.execute(&self.pool).await.map_err(into_sn_err!(
            SnErrorCode::DBError,
            "delete user dns record failed"
        ))?;
        Ok(())
    }

    async fn query_domain_record(
        &self,
        domain: &str,
        record_type: &str,
    ) -> SnResult<Option<(String, u32)>> {
        let rows = sqlx::query(
            "SELECT record, ttl FROM user_dns_records WHERE domain = ?1 AND record_type = ?2 ORDER BY id",
        )
        .bind(domain)
        .bind(record_type)
        .fetch_all(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "query user dns record failed"
        ))?;
        if rows.is_empty() {
            return Ok(None);
        }
        let ttl = rows
            .iter()
            .map(|row| row.get::<i64, _>(1).max(0) as u32)
            .min()
            .unwrap_or(0);
        let records = rows
            .into_iter()
            .map(|row| row.get::<String, _>(0))
            .collect::<Vec<_>>()
            .join(",");
        Ok(Some((records, ttl)))
    }

    async fn query_user_domain_records(
        &self,
        username: &str,
    ) -> SnResult<Vec<(String, String, String, u32)>> {
        let rows = sqlx::query(
            "SELECT domain, record_type, record, ttl FROM user_dns_records WHERE owner = ?1",
        )
        .bind(username)
        .fetch_all(&self.pool)
        .await
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "query user dns records failed"
        ))?;
        Ok(rows
            .into_iter()
            .map(|row| {
                (
                    row.get(0),
                    row.get(1),
                    row.get(2),
                    row.get::<i64, _>(3).max(0) as u32,
                )
            })
            .collect())
    }

    async fn query_user_did_document(
        &self,
        owner_user: &str,
        obj_name: &str,
        doc_type: Option<&str>,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        let row = if let Some(doc_type) = doc_type {
            sqlx::query(
                "SELECT obj_id, did_document, doc_type
                 FROM did_documents
                 WHERE owner_user = ?1 AND obj_name = ?2 AND doc_type = ?3
                 ORDER BY update_time DESC LIMIT 1",
            )
            .bind(owner_user)
            .bind(obj_name)
            .bind(doc_type)
            .fetch_optional(&self.pool)
            .await
        } else {
            sqlx::query(
                "SELECT obj_id, did_document, doc_type
                 FROM did_documents
                 WHERE owner_user = ?1 AND obj_name = ?2
                 ORDER BY update_time DESC LIMIT 1",
            )
            .bind(owner_user)
            .bind(obj_name)
            .fetch_optional(&self.pool)
            .await
        }
        .map_err(into_sn_err!(
            SnErrorCode::DBError,
            "query did document failed"
        ))?;

        row.map(|row| Ok((row.get(0), row.get(1), row.get(2))))
            .transpose()
    }
}
