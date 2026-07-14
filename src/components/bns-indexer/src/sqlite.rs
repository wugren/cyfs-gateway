use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use crate::{
    authority_root, canonical_bns_name, canonical_doc_type, hash_json, AliasState, AuthorityKey,
    AuthoritySetState, BnsRegistryError, BnsRegistryResult, BnsRegistryStore, BnsRegistryStoreTx,
    ControllerRule, DocumentKey, DocumentState, EventLogRecord, IndexerCursor, LogCheckpoint,
    NameState, RegistryEvent, ZERO_HASH,
};

pub struct SqliteBnsRegistryStore {
    conn: Mutex<Connection>,
}

impl SqliteBnsRegistryStore {
    pub fn open(path: impl AsRef<Path>) -> BnsRegistryResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let conn = Connection::open(path)?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.initialize_schema()?;
        Ok(store)
    }

    pub fn open_memory() -> BnsRegistryResult<Self> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.initialize_schema()?;
        Ok(store)
    }

    pub fn initialize_schema(&self) -> BnsRegistryResult<()> {
        let conn = self.conn()?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS bns_names (
                name TEXT PRIMARY KEY,
                asset_owner TEXT NOT NULL,
                status TEXT NOT NULL,
                name_seq INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bns_documents (
                name TEXT NOT NULL,
                doc_type TEXT NOT NULL,
                version INTEGER NOT NULL,
                status TEXT NOT NULL,
                is_current INTEGER NOT NULL,
                content_hash TEXT NOT NULL,
                document_state_hash TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (name, doc_type, version)
            );

            CREATE INDEX IF NOT EXISTS idx_bns_documents_current
                ON bns_documents (name, doc_type, is_current, version);

            CREATE TABLE IF NOT EXISTS bns_authority_keys (
                name TEXT NOT NULL,
                kid TEXT NOT NULL,
                status TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                PRIMARY KEY (name, kid)
            );

            CREATE TABLE IF NOT EXISTS bns_authority_sets (
                name TEXT PRIMARY KEY,
                authority_seq INTEGER NOT NULL,
                authority_root TEXT NOT NULL,
                active_key_count INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bns_controller_policies (
                name TEXT PRIMARY KEY,
                policy_hash TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bns_aliases (
                name TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                target_did TEXT NOT NULL,
                name_seq INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bns_events (
                seq INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                observed_at INTEGER NOT NULL,
                event_hash TEXT NOT NULL,
                previous_log_root TEXT NOT NULL,
                log_root TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_bns_events_type_seq
                ON bns_events (event_type, seq);

            CREATE TABLE IF NOT EXISTS bns_checkpoints (
                last_seq INTEGER PRIMARY KEY,
                log_root TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS bns_indexer_cursors (
                source TEXT PRIMARY KEY,
                block_number INTEGER NOT NULL,
                block_hash TEXT NULL,
                log_index INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            );
            "#,
        )?;

        if !has_column(&conn, "bns_names", "asset_owner")? {
            conn.execute(
                "ALTER TABLE bns_names ADD COLUMN asset_owner TEXT NOT NULL DEFAULT ''",
                [],
            )?;
        }
        // Run the backfill whenever empty index values remain so an interrupted
        // migration can safely resume on the next open.
        let rows = {
            let mut stmt =
                conn.prepare("SELECT name, payload_json FROM bns_names WHERE asset_owner = ''")?;
            let mapped = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        for (name, payload) in rows {
            let state: NameState = from_json(&payload)?;
            conn.execute(
                "UPDATE bns_names SET asset_owner = ?1 WHERE name = ?2",
                params![state.asset_owner, name],
            )?;
        }
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_bns_names_asset_owner_name ON bns_names (asset_owner, name)",
            [],
        )?;
        conn.pragma_update(None, "user_version", 2)?;
        Ok(())
    }

    fn conn(&self) -> BnsRegistryResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| BnsRegistryError::DbLockPoisoned)
    }
}

impl BnsRegistryStore for SqliteBnsRegistryStore {
    fn transact<R>(
        &self,
        op: impl FnOnce(&mut dyn BnsRegistryStoreTx) -> BnsRegistryResult<R>,
    ) -> BnsRegistryResult<R> {
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let result = {
            let mut adapter = SqliteStoreTx { tx: &tx };
            op(&mut adapter)
        };

        match result {
            Ok(value) => {
                tx.commit()?;
                Ok(value)
            }
            Err(err) => Err(err),
        }
    }
}

struct SqliteStoreTx<'a> {
    tx: &'a Transaction<'a>,
}

impl BnsRegistryStoreTx for SqliteStoreTx<'_> {
    fn get_name(&mut self, name: &str) -> BnsRegistryResult<Option<NameState>> {
        let name = canonical_bns_name(name)?;
        let payload = self
            .tx
            .query_row(
                "SELECT payload_json FROM bns_names WHERE name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn put_name(&mut self, state: &NameState) -> BnsRegistryResult<()> {
        state.validate()?;
        self.tx.execute(
            r#"
            INSERT INTO bns_names
                (name, asset_owner, status, name_seq, updated_at, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(name) DO UPDATE SET
                asset_owner = excluded.asset_owner,
                status = excluded.status,
                name_seq = excluded.name_seq,
                updated_at = excluded.updated_at,
                payload_json = excluded.payload_json
            "#,
            params![
                state.name,
                state.asset_owner,
                state.status.as_str(),
                to_i64(state.name_seq, "name_seq")?,
                to_i64(state.updated_at, "updated_at")?,
                to_json(state)?
            ],
        )?;
        Ok(())
    }

    fn list_names(&mut self) -> BnsRegistryResult<Vec<NameState>> {
        let mut stmt = self
            .tx
            .prepare("SELECT payload_json FROM bns_names ORDER BY name")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        collect_json_rows(rows)
    }

    fn list_names_by_asset_owner(
        &mut self,
        asset_owner: &str,
        after_name: Option<&str>,
        limit: usize,
    ) -> BnsRegistryResult<Vec<String>> {
        let limit = to_i64(limit as u64, "limit")?;
        let mut names = Vec::new();
        if let Some(after_name) = after_name {
            let after_name = canonical_bns_name(after_name)?;
            let mut stmt = self.tx.prepare(
                r#"
                SELECT name
                FROM bns_names
                WHERE asset_owner = ?1 AND name > ?2
                ORDER BY name
                LIMIT ?3
                "#,
            )?;
            let rows = stmt.query_map(params![asset_owner, after_name, limit], |row| row.get(0))?;
            for row in rows {
                names.push(row?);
            }
        } else {
            let mut stmt = self.tx.prepare(
                r#"
                SELECT name
                FROM bns_names
                WHERE asset_owner = ?1
                ORDER BY name
                LIMIT ?2
                "#,
            )?;
            let rows = stmt.query_map(params![asset_owner, limit], |row| row.get(0))?;
            for row in rows {
                names.push(row?);
            }
        }
        Ok(names)
    }

    fn get_document(
        &mut self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsRegistryResult<Option<DocumentState>> {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        let payload = self
            .tx
            .query_row(
                r#"
                SELECT payload_json
                FROM bns_documents
                WHERE name = ?1 AND doc_type = ?2 AND version = ?3
                "#,
                params![name, doc_type, to_i64(version, "version")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn get_current_document(
        &mut self,
        name: &str,
        doc_type: &str,
    ) -> BnsRegistryResult<Option<DocumentState>> {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        let payload = self
            .tx
            .query_row(
                r#"
                SELECT payload_json
                FROM bns_documents
                WHERE name = ?1 AND doc_type = ?2
                ORDER BY is_current DESC, version DESC
                LIMIT 1
                "#,
                params![name, doc_type],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn put_document(&mut self, state: &DocumentState) -> BnsRegistryResult<()> {
        state.validate()?;
        let incoming_version = to_i64(state.version, "version")?;
        let max_version = self
            .tx
            .query_row(
                "SELECT MAX(version) FROM bns_documents WHERE name = ?1 AND doc_type = ?2",
                params![state.name, state.doc_type],
                |row| row.get::<_, Option<i64>>(0),
            )?
            .unwrap_or(-1);
        let is_current = incoming_version >= max_version;
        if is_current {
            self.tx.execute(
                "UPDATE bns_documents SET is_current = 0 WHERE name = ?1 AND doc_type = ?2",
                params![state.name, state.doc_type],
            )?;
        }

        self.tx.execute(
            r#"
            INSERT INTO bns_documents
                (name, doc_type, version, status, is_current, content_hash,
                 document_state_hash, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            ON CONFLICT(name, doc_type, version) DO UPDATE SET
                status = excluded.status,
                is_current = excluded.is_current,
                content_hash = excluded.content_hash,
                document_state_hash = excluded.document_state_hash,
                payload_json = excluded.payload_json
            "#,
            params![
                state.name,
                state.doc_type,
                incoming_version,
                state.status.as_str(),
                if is_current { 1 } else { 0 },
                state.document.content_hash,
                state.document_state_hash,
                to_json(state)?
            ],
        )?;
        Ok(())
    }

    fn list_document_keys(&mut self, name: Option<&str>) -> BnsRegistryResult<Vec<DocumentKey>> {
        let mut keys = Vec::new();
        if let Some(name) = name {
            let name = canonical_bns_name(name)?;
            let mut stmt = self.tx.prepare(
                r#"
                SELECT name, doc_type, version
                FROM bns_documents
                WHERE name = ?1
                ORDER BY name, doc_type, version
                "#,
            )?;
            let rows = stmt.query_map(params![name], document_key_from_row)?;
            for row in rows {
                keys.push(row?);
            }
        } else {
            let mut stmt = self.tx.prepare(
                r#"
                SELECT name, doc_type, version
                FROM bns_documents
                ORDER BY name, doc_type, version
                "#,
            )?;
            let rows = stmt.query_map([], document_key_from_row)?;
            for row in rows {
                keys.push(row?);
            }
        }
        Ok(keys)
    }

    fn get_authority_key(
        &mut self,
        name: &str,
        kid: &str,
    ) -> BnsRegistryResult<Option<AuthorityKey>> {
        let name = canonical_bns_name(name)?;
        let payload = self
            .tx
            .query_row(
                "SELECT payload_json FROM bns_authority_keys WHERE name = ?1 AND kid = ?2",
                params![name, kid],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn put_authority_key(&mut self, name: &str, key: &AuthorityKey) -> BnsRegistryResult<()> {
        let name = canonical_bns_name(name)?;
        key.validate()?;
        self.tx.execute(
            r#"
            INSERT INTO bns_authority_keys
                (name, kid, status, payload_json)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(name, kid) DO UPDATE SET
                status = excluded.status,
                payload_json = excluded.payload_json
            "#,
            params![name, key.kid, key.status.as_str(), to_json(key)?],
        )?;
        Ok(())
    }

    fn list_authority_keys(&mut self, name: &str) -> BnsRegistryResult<Vec<AuthorityKey>> {
        let name = canonical_bns_name(name)?;
        let mut stmt = self.tx.prepare(
            r#"
            SELECT payload_json
            FROM bns_authority_keys
            WHERE name = ?1
            ORDER BY kid
            "#,
        )?;
        let rows = stmt.query_map(params![name], |row| row.get::<_, String>(0))?;
        collect_json_rows(rows)
    }

    fn get_authority_set(&mut self, name: &str) -> BnsRegistryResult<Option<AuthoritySetState>> {
        let name = canonical_bns_name(name)?;
        let payload = self
            .tx
            .query_row(
                "SELECT payload_json FROM bns_authority_sets WHERE name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn put_authority_set(&mut self, state: &AuthoritySetState) -> BnsRegistryResult<()> {
        canonical_bns_name(&state.name)?;
        crate::validate_hash(&state.authority_root)?;
        self.tx.execute(
            r#"
            INSERT INTO bns_authority_sets
                (name, authority_seq, authority_root, active_key_count, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(name) DO UPDATE SET
                authority_seq = excluded.authority_seq,
                authority_root = excluded.authority_root,
                active_key_count = excluded.active_key_count,
                payload_json = excluded.payload_json
            "#,
            params![
                state.name,
                to_i64(state.authority_seq, "authority_seq")?,
                state.authority_root,
                to_i64(state.active_key_count as u64, "active_key_count")?,
                to_json(state)?
            ],
        )?;
        Ok(())
    }

    fn get_controller_policy(&mut self, name: &str) -> BnsRegistryResult<Vec<ControllerRule>> {
        let name = canonical_bns_name(name)?;
        let payload = self
            .tx
            .query_row(
                "SELECT payload_json FROM bns_controller_policies WHERE name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload
            .as_deref()
            .map(from_json::<Vec<ControllerRule>>)
            .transpose()
            .map(|rules| rules.unwrap_or_default())
    }

    fn put_controller_policy(
        &mut self,
        name: &str,
        rules: &[ControllerRule],
        policy_hash: &str,
    ) -> BnsRegistryResult<()> {
        let name = canonical_bns_name(name)?;
        crate::validate_hash(policy_hash)?;
        for rule in rules {
            rule.validate()?;
        }
        self.tx.execute(
            r#"
            INSERT INTO bns_controller_policies
                (name, policy_hash, payload_json)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(name) DO UPDATE SET
                policy_hash = excluded.policy_hash,
                payload_json = excluded.payload_json
            "#,
            params![name, policy_hash, to_json(&rules)?],
        )?;
        Ok(())
    }

    fn get_alias(&mut self, name: &str) -> BnsRegistryResult<Option<AliasState>> {
        let name = canonical_bns_name(name)?;
        let payload = self
            .tx
            .query_row(
                "SELECT payload_json FROM bns_aliases WHERE name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn put_alias(&mut self, state: &AliasState) -> BnsRegistryResult<()> {
        state.validate()?;
        self.tx.execute(
            r#"
            INSERT INTO bns_aliases
                (name, kind, target_did, name_seq, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(name) DO UPDATE SET
                kind = excluded.kind,
                target_did = excluded.target_did,
                name_seq = excluded.name_seq,
                payload_json = excluded.payload_json
            "#,
            params![
                state.name,
                state.kind.as_str(),
                state.target_did,
                to_i64(state.name_seq, "name_seq")?,
                to_json(state)?
            ],
        )?;
        Ok(())
    }

    fn append_event(
        &mut self,
        event: &RegistryEvent,
        observed_at: u64,
    ) -> BnsRegistryResult<EventLogRecord> {
        let latest = self.latest_event()?;
        let seq = latest.as_ref().map_or(1, |record| record.seq + 1);
        let previous_log_root = latest
            .as_ref()
            .map_or_else(|| ZERO_HASH.to_string(), |record| record.log_root.clone());
        let payload = to_json(event)?;
        let event_hash = hash_json(&(seq, &previous_log_root, &payload))?;
        let log_root = hash_json(&(&previous_log_root, &event_hash))?;
        let record = EventLogRecord {
            seq,
            event_type: event.event_type().to_string(),
            observed_at,
            event_hash,
            previous_log_root,
            log_root,
            event: event.clone(),
        };

        self.tx.execute(
            r#"
            INSERT INTO bns_events
                (seq, event_type, observed_at, event_hash, previous_log_root, log_root, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                to_i64(record.seq, "seq")?,
                record.event_type,
                to_i64(record.observed_at, "observed_at")?,
                record.event_hash,
                record.previous_log_root,
                record.log_root,
                to_json(&record)?
            ],
        )?;
        Ok(record)
    }

    fn put_event_record(&mut self, record: &EventLogRecord) -> BnsRegistryResult<()> {
        self.tx.execute(
            r#"
            INSERT INTO bns_events
                (seq, event_type, observed_at, event_hash, previous_log_root, log_root, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ON CONFLICT(seq) DO UPDATE SET
                event_type = excluded.event_type,
                observed_at = excluded.observed_at,
                event_hash = excluded.event_hash,
                previous_log_root = excluded.previous_log_root,
                log_root = excluded.log_root,
                payload_json = excluded.payload_json
            "#,
            params![
                to_i64(record.seq, "seq")?,
                record.event_type,
                to_i64(record.observed_at, "observed_at")?,
                record.event_hash,
                record.previous_log_root,
                record.log_root,
                to_json(record)?
            ],
        )?;
        Ok(())
    }

    fn get_event(&mut self, seq: u64) -> BnsRegistryResult<Option<EventLogRecord>> {
        let payload = self
            .tx
            .query_row(
                "SELECT payload_json FROM bns_events WHERE seq = ?1",
                params![to_i64(seq, "seq")?],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn latest_event(&mut self) -> BnsRegistryResult<Option<EventLogRecord>> {
        let payload = self
            .tx
            .query_row(
                "SELECT payload_json FROM bns_events ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn list_events(
        &mut self,
        from_seq: u64,
        limit: usize,
    ) -> BnsRegistryResult<Vec<EventLogRecord>> {
        let mut stmt = self.tx.prepare(
            r#"
            SELECT payload_json
            FROM bns_events
            WHERE seq >= ?1
            ORDER BY seq
            LIMIT ?2
            "#,
        )?;
        let rows = stmt.query_map(
            params![
                to_i64(from_seq, "from_seq")?,
                to_i64(limit as u64, "limit")?
            ],
            |row| row.get::<_, String>(0),
        )?;
        collect_json_rows(rows)
    }

    fn put_checkpoint(&mut self, checkpoint: &LogCheckpoint) -> BnsRegistryResult<()> {
        checkpoint.validate()?;
        self.tx.execute(
            r#"
            INSERT INTO bns_checkpoints
                (last_seq, log_root, issued_at, payload_json)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(last_seq) DO UPDATE SET
                log_root = excluded.log_root,
                issued_at = excluded.issued_at,
                payload_json = excluded.payload_json
            "#,
            params![
                to_i64(checkpoint.last_seq, "last_seq")?,
                checkpoint.log_root,
                to_i64(checkpoint.issued_at, "issued_at")?,
                to_json(checkpoint)?
            ],
        )?;
        Ok(())
    }

    fn latest_checkpoint(&mut self) -> BnsRegistryResult<Option<LogCheckpoint>> {
        let payload = self
            .tx
            .query_row(
                "SELECT payload_json FROM bns_checkpoints ORDER BY last_seq DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn get_indexer_cursor(&mut self, source: &str) -> BnsRegistryResult<Option<IndexerCursor>> {
        let payload = self
            .tx
            .query_row(
                "SELECT payload_json FROM bns_indexer_cursors WHERE source = ?1",
                params![source],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        payload.as_deref().map(from_json).transpose()
    }

    fn put_indexer_cursor(&mut self, cursor: &IndexerCursor) -> BnsRegistryResult<()> {
        self.tx.execute(
            r#"
            INSERT INTO bns_indexer_cursors
                (source, block_number, block_hash, log_index, updated_at, payload_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            ON CONFLICT(source) DO UPDATE SET
                block_number = excluded.block_number,
                block_hash = excluded.block_hash,
                log_index = excluded.log_index,
                updated_at = excluded.updated_at,
                payload_json = excluded.payload_json
            "#,
            params![
                cursor.source.as_str(),
                to_i64(cursor.block_number, "block_number")?,
                cursor.block_hash.as_deref(),
                to_i64(cursor.log_index, "log_index")?,
                to_i64(cursor.updated_at, "updated_at")?,
                to_json(cursor)?
            ],
        )?;
        Ok(())
    }

    fn reset_indexer_projection(&mut self, source: &str) -> BnsRegistryResult<()> {
        self.tx.execute("DELETE FROM bns_names", [])?;
        self.tx.execute("DELETE FROM bns_documents", [])?;
        self.tx.execute("DELETE FROM bns_authority_keys", [])?;
        self.tx.execute("DELETE FROM bns_authority_sets", [])?;
        self.tx.execute("DELETE FROM bns_controller_policies", [])?;
        self.tx.execute("DELETE FROM bns_aliases", [])?;
        self.tx.execute("DELETE FROM bns_events", [])?;
        self.tx.execute("DELETE FROM bns_checkpoints", [])?;
        self.tx.execute(
            "DELETE FROM bns_indexer_cursors WHERE source = ?1",
            params![source],
        )?;
        Ok(())
    }
}

pub(crate) fn recompute_authority_set(
    name: &str,
    current: Option<AuthoritySetState>,
    keys: &[AuthorityKey],
    now: u64,
) -> BnsRegistryResult<AuthoritySetState> {
    let (authority_root, active_key_count) = authority_root(keys, now)?;
    Ok(AuthoritySetState {
        name: canonical_bns_name(name)?,
        authority_seq: current.map_or(1, |state| state.authority_seq + 1),
        authority_root,
        active_key_count,
    })
}

fn to_json<T: Serialize + ?Sized>(value: &T) -> BnsRegistryResult<String> {
    Ok(serde_json::to_string(value)?)
}

fn from_json<T: DeserializeOwned>(value: &str) -> BnsRegistryResult<T> {
    Ok(serde_json::from_str(value)?)
}

fn collect_json_rows<T: DeserializeOwned>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<String>>,
) -> BnsRegistryResult<Vec<T>> {
    let mut values = Vec::new();
    for row in rows {
        values.push(from_json(&row?)?);
    }
    Ok(values)
}

fn has_column(conn: &Connection, table: &str, column: &str) -> BnsRegistryResult<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for candidate in columns {
        if candidate? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn to_i64(value: u64, field: &'static str) -> BnsRegistryResult<i64> {
    if value > i64::MAX as u64 {
        return Err(BnsRegistryError::IntegerOutOfRange { field, value });
    }
    Ok(value as i64)
}

fn document_key_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DocumentKey> {
    let version: i64 = row.get(2)?;
    Ok(DocumentKey {
        name: row.get(0)?,
        doc_type: row.get(1)?,
        version: version as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NameStatus, OwnerSource, Principal};

    const OWNER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn name_state() -> NameState {
        NameState {
            name: "alice".to_string(),
            asset_owner: OWNER.to_string(),
            semantic_owner: Principal::unset(),
            effective_owner: Principal::chain_account(OWNER),
            owner_source: OwnerSource::AssetOwnerFallback,
            standard_transfer_enabled: true,
            status: NameStatus::Active,
            registered_at: 1,
            expire_at: 100,
            grace_until: 200,
            updated_at: 2,
            name_seq: 1,
            owner_document_version: 0,
            min_document_iat: 0,
            owner_policy_seq: 0,
            lineage_epoch: 0,
            renewable: true,
            transferable: true,
            allow_delegated_subnames: false,
            namespace_policy_hash: ZERO_HASH.to_string(),
            payment_policy_hash: ZERO_HASH.to_string(),
            alias_state_hash: ZERO_HASH.to_string(),
        }
    }

    #[test]
    fn schema_v2_backfills_asset_owner_index() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("bns.sqlite");
        let state = name_state();
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                r#"
                CREATE TABLE bns_names (
                    name TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    name_seq INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    payload_json TEXT NOT NULL
                );
                PRAGMA user_version = 1;
                "#,
            )
            .unwrap();
            conn.execute(
                "INSERT INTO bns_names (name, status, name_seq, updated_at, payload_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    &state.name,
                    state.status.as_str(),
                    1i64,
                    2i64,
                    serde_json::to_string(&state).unwrap(),
                ],
            )
            .unwrap();
        }

        let store = SqliteBnsRegistryStore::open(&path).unwrap();
        let names = store
            .transact(|tx| tx.list_names_by_asset_owner(OWNER, None, 10))
            .unwrap();
        assert_eq!(names, ["alice"]);
        assert_eq!(
            store
                .conn()
                .unwrap()
                .pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
                .unwrap(),
            2
        );
    }
}
