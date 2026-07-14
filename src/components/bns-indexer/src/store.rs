use crate::{
    AliasState, AuthorityKey, AuthoritySetState, BnsRegistryResult, ControllerRule, DocumentKey,
    DocumentState, EventLogRecord, IndexerCursor, LogCheckpoint, NameState, RegistryEvent,
};

pub trait BnsRegistryStore: Send + Sync {
    fn transact<R>(
        &self,
        op: impl FnOnce(&mut dyn BnsRegistryStoreTx) -> BnsRegistryResult<R>,
    ) -> BnsRegistryResult<R>;
}

pub trait BnsRegistryStoreTx {
    fn get_name(&mut self, name: &str) -> BnsRegistryResult<Option<NameState>>;
    fn put_name(&mut self, state: &NameState) -> BnsRegistryResult<()>;
    fn list_names(&mut self) -> BnsRegistryResult<Vec<NameState>>;
    fn list_names_by_asset_owner(
        &mut self,
        asset_owner: &str,
        after_name: Option<&str>,
        limit: usize,
    ) -> BnsRegistryResult<Vec<String>>;

    fn get_document(
        &mut self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsRegistryResult<Option<DocumentState>>;
    fn get_current_document(
        &mut self,
        name: &str,
        doc_type: &str,
    ) -> BnsRegistryResult<Option<DocumentState>>;
    fn put_document(&mut self, state: &DocumentState) -> BnsRegistryResult<()>;
    fn list_document_keys(&mut self, name: Option<&str>) -> BnsRegistryResult<Vec<DocumentKey>>;

    fn get_authority_key(
        &mut self,
        name: &str,
        kid: &str,
    ) -> BnsRegistryResult<Option<AuthorityKey>>;
    fn put_authority_key(&mut self, name: &str, key: &AuthorityKey) -> BnsRegistryResult<()>;
    fn list_authority_keys(&mut self, name: &str) -> BnsRegistryResult<Vec<AuthorityKey>>;
    fn get_authority_set(&mut self, name: &str) -> BnsRegistryResult<Option<AuthoritySetState>>;
    fn put_authority_set(&mut self, state: &AuthoritySetState) -> BnsRegistryResult<()>;

    fn get_controller_policy(&mut self, name: &str) -> BnsRegistryResult<Vec<ControllerRule>>;
    fn put_controller_policy(
        &mut self,
        name: &str,
        rules: &[ControllerRule],
        policy_hash: &str,
    ) -> BnsRegistryResult<()>;

    fn get_alias(&mut self, name: &str) -> BnsRegistryResult<Option<AliasState>>;
    fn put_alias(&mut self, state: &AliasState) -> BnsRegistryResult<()>;

    fn append_event(
        &mut self,
        event: &RegistryEvent,
        observed_at: u64,
    ) -> BnsRegistryResult<EventLogRecord>;
    fn put_event_record(&mut self, record: &EventLogRecord) -> BnsRegistryResult<()>;
    fn get_event(&mut self, seq: u64) -> BnsRegistryResult<Option<EventLogRecord>>;
    fn latest_event(&mut self) -> BnsRegistryResult<Option<EventLogRecord>>;
    fn list_events(
        &mut self,
        from_seq: u64,
        limit: usize,
    ) -> BnsRegistryResult<Vec<EventLogRecord>>;

    fn put_checkpoint(&mut self, checkpoint: &LogCheckpoint) -> BnsRegistryResult<()>;
    fn latest_checkpoint(&mut self) -> BnsRegistryResult<Option<LogCheckpoint>>;

    fn get_indexer_cursor(&mut self, source: &str) -> BnsRegistryResult<Option<IndexerCursor>>;
    fn put_indexer_cursor(&mut self, cursor: &IndexerCursor) -> BnsRegistryResult<()>;
    fn reset_indexer_projection(&mut self, source: &str) -> BnsRegistryResult<()>;
}
