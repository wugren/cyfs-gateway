use crate::{
    BnsWriteOperation, BnsWriteRequestState, SnBnsControllerError, SnBnsControllerResult,
    SnBnsWriteRequestRecord, SnBnsWriteRequestStore,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::path::Path;
use std::sync::Mutex;

pub struct SqliteSnBnsWriteRequestStore {
    conn: Mutex<Connection>,
}

impl SqliteSnBnsWriteRequestStore {
    pub fn open(path: impl AsRef<Path>) -> SnBnsControllerResult<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
            }
        }

        let conn =
            Connection::open(path).map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.initialize_schema()?;
        Ok(store)
    }

    fn initialize_schema(&self) -> SnBnsControllerResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS sn_bns_write_requests (
                request_id TEXT PRIMARY KEY,
                operation TEXT NOT NULL,
                name TEXT NOT NULL,
                doc_type TEXT NULL,
                payload_hash TEXT NOT NULL,
                state TEXT NOT NULL,
                result_json TEXT NULL,
                error_code TEXT NULL,
                error_message TEXT NULL,
                evm_chain_id INTEGER NULL,
                evm_nonce INTEGER NULL,
                evm_tx_hash TEXT NULL,
                evm_raw_tx TEXT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sn_bns_write_requests_name
                ON sn_bns_write_requests (name, operation, state);
            "#,
        )
        .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        ensure_column(&conn, "evm_chain_id", "INTEGER NULL")?;
        ensure_column(&conn, "evm_nonce", "INTEGER NULL")?;
        ensure_column(&conn, "evm_tx_hash", "TEXT NULL")?;
        ensure_column(&conn, "evm_raw_tx", "TEXT NULL")?;
        Ok(())
    }

    fn parse_operation(value: String) -> SnBnsControllerResult<BnsWriteOperation> {
        serde_json::from_value(Value::String(value))
            .map_err(|e| SnBnsControllerError::Store(format!("parse operation failed: {}", e)))
    }

    fn parse_state(value: String) -> SnBnsControllerResult<BnsWriteRequestState> {
        serde_json::from_value(Value::String(value))
            .map_err(|e| SnBnsControllerError::Store(format!("parse state failed: {}", e)))
    }
}

impl SnBnsWriteRequestStore for SqliteSnBnsWriteRequestStore {
    fn get(&self, request_id: &str) -> SnBnsControllerResult<Option<SnBnsWriteRequestRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let record = conn
            .query_row(
                "SELECT request_id, operation, name, doc_type, payload_hash, state,
                        result_json, error_code, error_message,
                        evm_chain_id, evm_nonce, evm_tx_hash, evm_raw_tx,
                        created_at, updated_at
                 FROM sn_bns_write_requests
                 WHERE request_id = ?1",
                params![request_id],
                |row| {
                    let result_json: Option<String> = row.get(6)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        result_json,
                        row.get::<_, Option<String>>(7)?,
                        row.get::<_, Option<String>>(8)?,
                        row.get::<_, Option<i64>>(9)?,
                        row.get::<_, Option<i64>>(10)?,
                        row.get::<_, Option<String>>(11)?,
                        row.get::<_, Option<String>>(12)?,
                        row.get::<_, i64>(13)?,
                        row.get::<_, i64>(14)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;

        record
            .map(
                |(
                    request_id,
                    operation,
                    name,
                    doc_type,
                    payload_hash,
                    state,
                    result_json,
                    error_code,
                    error_message,
                    evm_chain_id,
                    evm_nonce,
                    evm_tx_hash,
                    evm_raw_tx,
                    created_at,
                    updated_at,
                )| {
                    Ok(SnBnsWriteRequestRecord {
                        request_id,
                        operation: Self::parse_operation(operation)?,
                        name,
                        doc_type,
                        payload_hash,
                        state: Self::parse_state(state)?,
                        result_json: result_json
                            .map(|value| serde_json::from_str(value.as_str()))
                            .transpose()
                            .map_err(|e| {
                                SnBnsControllerError::Store(format!(
                                    "parse result_json failed: {}",
                                    e
                                ))
                            })?,
                        error_code,
                        error_message,
                        evm_chain_id: evm_chain_id.map(|value| value.max(0) as u64),
                        evm_nonce: evm_nonce.map(|value| value.max(0) as u64),
                        evm_tx_hash,
                        evm_raw_tx,
                        created_at: created_at.max(0) as u64,
                        updated_at: updated_at.max(0) as u64,
                    })
                },
            )
            .transpose()
    }

    fn put(&self, record: SnBnsWriteRequestRecord) -> SnBnsControllerResult<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| SnBnsControllerError::Store("sqlite store lock poisoned".to_string()))?;
        let operation = serde_json::to_value(record.operation)
            .ok()
            .and_then(|value| value.as_str().map(ToString::to_string))
            .unwrap_or_else(|| record.operation.as_str().to_string());
        let state = serde_json::to_value(record.state)
            .ok()
            .and_then(|value| value.as_str().map(ToString::to_string))
            .unwrap_or_else(|| format!("{:?}", record.state).to_ascii_lowercase());
        let result_json = record
            .result_json
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;

        conn.execute(
            "INSERT INTO sn_bns_write_requests
                (request_id, operation, name, doc_type, payload_hash, state,
                 result_json, error_code, error_message,
                 evm_chain_id, evm_nonce, evm_tx_hash, evm_raw_tx,
                 created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(request_id) DO UPDATE SET
                operation = excluded.operation,
                name = excluded.name,
                doc_type = excluded.doc_type,
                payload_hash = excluded.payload_hash,
                state = excluded.state,
                result_json = excluded.result_json,
                error_code = excluded.error_code,
                error_message = excluded.error_message,
                evm_chain_id = excluded.evm_chain_id,
                evm_nonce = excluded.evm_nonce,
                evm_tx_hash = excluded.evm_tx_hash,
                evm_raw_tx = excluded.evm_raw_tx,
                updated_at = excluded.updated_at",
            params![
                record.request_id,
                operation,
                record.name,
                record.doc_type,
                record.payload_hash,
                state,
                result_json,
                record.error_code,
                record.error_message,
                record.evm_chain_id.map(|value| value as i64),
                record.evm_nonce.map(|value| value as i64),
                record.evm_tx_hash,
                record.evm_raw_tx,
                record.created_at as i64,
                record.updated_at as i64,
            ],
        )
        .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
        Ok(())
    }
}

fn ensure_column(conn: &Connection, column: &str, column_def: &str) -> SnBnsControllerResult<()> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM pragma_table_info('sn_bns_write_requests') WHERE name = ?1",
            params![column],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
    if exists.is_none() {
        conn.execute(
            &format!("ALTER TABLE sn_bns_write_requests ADD COLUMN {column} {column_def}"),
            [],
        )
        .map_err(|e| SnBnsControllerError::Store(e.to_string()))?;
    }
    Ok(())
}
