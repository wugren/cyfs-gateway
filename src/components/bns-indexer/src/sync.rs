use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

use bns_evm::{
    decode_bns_call, Address, AliasKind as EvmAliasKind, AliasState as EvmAliasState,
    AuthorityKey as EvmAuthorityKey, AuthorityKeyStatus as EvmAuthorityKeyStatus,
    AuthorityKeyUpdate as EvmAuthorityKeyUpdate, AuthoritySetState as EvmAuthoritySetState,
    BlockRange, Bns, BnsCall, DocumentRef as EvmDocumentRef, DocumentState as EvmDocumentState,
    DocumentStatus as EvmDocumentStatus, EthLog, EthRpcClient, NameState as EvmNameState,
    NameStatus as EvmNameStatus, OwnerSource as EvmOwnerSource, Principal as EvmPrincipal,
    PrincipalKind as EvmPrincipalKind, RpcLogFilter, B256,
};
use serde::{Deserialize, Serialize};

use crate::{
    canonical_bns_name, canonical_doc_type, now_timestamp, AliasKind, AliasState, AuthorityKey,
    AuthorityKeyStatus, AuthoritySetState, BnsRegistryError, BnsRegistryResult, BnsRegistryStore,
    BnsRegistryStoreTx, ContractEventProjector, DocumentRef, DocumentState, DocumentStatus,
    EventLogRecord, IndexerCursor, LogCheckpoint, NameState, NameStatus, OwnerSource, Principal,
    ProjectedContractEvent, RegistryEvent, ZERO_HASH,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsBlockSyncSourceConfig {
    pub network: String,
    pub chain_id: u64,
    pub rpc_endpoint: String,
    pub contract_address: String,
    pub start_block: u64,
}

impl BnsBlockSyncSourceConfig {
    pub fn anvil(
        rpc_endpoint: impl Into<String>,
        contract_address: impl Into<String>,
        start_block: u64,
    ) -> Self {
        Self {
            network: "anvil-local".to_string(),
            chain_id: 31_337,
            rpc_endpoint: rpc_endpoint.into(),
            contract_address: contract_address.into(),
            start_block,
        }
    }

    pub fn source_id(&self) -> BnsRegistryResult<String> {
        let contract = self.contract_address()?;
        self.validate()?;
        Ok(format!(
            "evm:{}:{}:{contract:#x}",
            self.network, self.chain_id
        ))
    }

    pub fn contract_address(&self) -> BnsRegistryResult<Address> {
        Address::from_str(&self.contract_address).map_err(|err| {
            BnsRegistryError::InvalidConfig(format!(
                "invalid BNS contract_address `{}`: {err}",
                self.contract_address
            ))
        })
    }

    pub fn validate(&self) -> BnsRegistryResult<()> {
        if self.network.trim().is_empty() {
            return Err(BnsRegistryError::InvalidConfig(
                "BNS block sync source network must not be empty".to_string(),
            ));
        }
        if self.rpc_endpoint.trim().is_empty() {
            return Err(BnsRegistryError::InvalidConfig(
                "BNS block sync source rpc_endpoint must not be empty".to_string(),
            ));
        }
        if self.chain_id == 0 {
            return Err(BnsRegistryError::InvalidConfig(
                "BNS block sync source chain_id must be non-zero".to_string(),
            ));
        }
        self.contract_address()?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsIndexerSyncConfig {
    pub source: BnsBlockSyncSourceConfig,
    pub confirmations: u64,
    pub max_block_span: u64,
}

impl BnsIndexerSyncConfig {
    pub fn new(source: BnsBlockSyncSourceConfig) -> Self {
        Self {
            source,
            confirmations: 0,
            max_block_span: 1_000,
        }
    }

    pub fn validate(&self) -> BnsRegistryResult<()> {
        self.source.validate()?;
        if self.max_block_span == 0 {
            return Err(BnsRegistryError::InvalidConfig(
                "BNS indexer max_block_span must be non-zero".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BnsIndexerSyncOutcome {
    pub source: String,
    pub chain_id: u64,
    pub contract_address: String,
    pub latest_block: u64,
    pub from_block: u64,
    pub to_block: Option<u64>,
    pub reorg_detected: bool,
    pub logs_seen: usize,
    pub protocol_events_seen: usize,
    pub registry_events_stored: usize,
    pub cursor: Option<IndexerCursor>,
}

pub struct BnsContractEventIndexer<'a, S>
where
    S: BnsRegistryStore,
{
    store: &'a S,
    config: BnsIndexerSyncConfig,
    rpc: EthRpcClient,
    contract: Address,
    source: String,
}

impl<'a, S> BnsContractEventIndexer<'a, S>
where
    S: BnsRegistryStore,
{
    pub fn new(store: &'a S, config: BnsIndexerSyncConfig) -> BnsRegistryResult<Self> {
        config.validate()?;
        let contract = config.source.contract_address()?;
        let source = config.source.source_id()?;
        let rpc = EthRpcClient::new(config.source.rpc_endpoint.clone());
        Ok(Self {
            store,
            config,
            rpc,
            contract,
            source,
        })
    }

    pub fn config(&self) -> &BnsIndexerSyncConfig {
        &self.config
    }

    pub fn source(&self) -> &str {
        &self.source
    }

    pub async fn sync_once(&self) -> BnsRegistryResult<BnsIndexerSyncOutcome> {
        let remote_chain_id = self.rpc.chain_id().await?;
        if remote_chain_id != self.config.source.chain_id {
            return Err(BnsRegistryError::InvalidConfig(format!(
                "BNS indexer configured for chain_id {}, but RPC {} returned chain_id {}",
                self.config.source.chain_id, self.config.source.rpc_endpoint, remote_chain_id
            )));
        }

        let latest_block = self.rpc.block_number().await?;
        let reorg_detected = self.reset_projection_if_reorged(latest_block).await?;
        let target_block = latest_block.saturating_sub(self.config.confirmations);
        let from_block = self.next_block_to_sync()?;
        if from_block > target_block {
            return Ok(BnsIndexerSyncOutcome {
                source: self.source.clone(),
                chain_id: self.config.source.chain_id,
                contract_address: format!("{:#x}", self.contract),
                latest_block,
                from_block,
                to_block: None,
                reorg_detected,
                logs_seen: 0,
                protocol_events_seen: 0,
                registry_events_stored: 0,
                cursor: self.cursor()?,
            });
        }

        let to_block = target_block.min(from_block + self.config.max_block_span - 1);
        let filter = RpcLogFilter {
            address: self.contract,
            from_block: BlockRange::Number(from_block),
            to_block: BlockRange::Number(to_block),
            topics: Vec::new(),
        };
        let logs = self.rpc.get_logs(&filter).await?;
        let mut projector = ContractEventProjector::new();
        let mut decoded_txs: HashMap<B256, Option<BnsCall>> = HashMap::new();
        let mut protocol_events_seen = 0;
        let mut registry_events_stored = 0;

        for log in logs.iter().filter(|log| !log.removed) {
            let observed_at = now_timestamp();
            match projector.project_log(log, observed_at)? {
                ProjectedContractEvent::Protocol(_) => {
                    protocol_events_seen += 1;
                }
                ProjectedContractEvent::Registry(record) => {
                    let decoded_call = self.decoded_call_for_log(log, &mut decoded_txs).await?;
                    let projection = self
                        .projection_for_record(&record, decoded_call.as_ref())
                        .await?;
                    self.store.transact(|tx| {
                        tx.put_event_record(&record)?;
                        projection.apply(tx)
                    })?;
                    registry_events_stored += 1;
                }
            }
        }

        let block_hash = self.block_hash_string(to_block).await?;
        let cursor = IndexerCursor {
            source: self.source.clone(),
            block_number: to_block,
            block_hash: Some(block_hash),
            log_index: i64::MAX as u64,
            updated_at: now_timestamp(),
        };
        self.store.transact(|tx| tx.put_indexer_cursor(&cursor))?;

        Ok(BnsIndexerSyncOutcome {
            source: self.source.clone(),
            chain_id: self.config.source.chain_id,
            contract_address: format!("{:#x}", self.contract),
            latest_block,
            from_block,
            to_block: Some(to_block),
            reorg_detected,
            logs_seen: logs.len(),
            protocol_events_seen,
            registry_events_stored,
            cursor: Some(cursor),
        })
    }

    pub async fn run_polling_loop<F>(&self, interval: Duration, mut on_sync: F)
    where
        F: FnMut(BnsRegistryResult<BnsIndexerSyncOutcome>),
    {
        let interval = if interval.is_zero() {
            Duration::from_millis(1)
        } else {
            interval
        };
        loop {
            on_sync(self.sync_once().await);
            tokio::time::sleep(interval).await;
        }
    }

    fn next_block_to_sync(&self) -> BnsRegistryResult<u64> {
        let cursor = self.cursor()?;
        Ok(cursor
            .map(|cursor| cursor.block_number.saturating_add(1))
            .unwrap_or(self.config.source.start_block)
            .max(self.config.source.start_block))
    }

    fn cursor(&self) -> BnsRegistryResult<Option<IndexerCursor>> {
        self.store
            .transact(|tx| tx.get_indexer_cursor(&self.source))
    }

    async fn reset_projection_if_reorged(&self, latest_block: u64) -> BnsRegistryResult<bool> {
        let Some(mut cursor) = self.cursor()? else {
            return Ok(false);
        };

        let should_reset = if cursor.block_number > latest_block {
            true
        } else if let Some(expected_hash) = cursor.block_hash.as_deref() {
            self.block_hash_string(cursor.block_number).await? != expected_hash
        } else {
            cursor.block_hash = Some(self.block_hash_string(cursor.block_number).await?);
            cursor.updated_at = now_timestamp();
            self.store.transact(|tx| tx.put_indexer_cursor(&cursor))?;
            false
        };

        if should_reset {
            self.store
                .transact(|tx| tx.reset_indexer_projection(&self.source))?;
        }
        Ok(should_reset)
    }

    async fn block_hash_string(&self, block_number: u64) -> BnsRegistryResult<String> {
        let block = self
            .rpc
            .block_by_number(block_number)
            .await?
            .ok_or_else(|| {
                BnsRegistryError::InvalidConfig(format!(
                    "BNS indexer cannot read block {block_number} from RPC {}",
                    self.config.source.rpc_endpoint
                ))
            })?;
        if let Some(actual_number) = block.number {
            if actual_number != block_number {
                return Err(BnsRegistryError::InvalidConfig(format!(
                    "BNS indexer requested block {block_number}, RPC returned block {actual_number}"
                )));
            }
        }
        block.hash.map(hash_string).ok_or_else(|| {
            BnsRegistryError::InvalidConfig(format!(
                "BNS indexer block {block_number} from RPC {} has no hash",
                self.config.source.rpc_endpoint
            ))
        })
    }

    async fn decoded_call_for_log(
        &self,
        log: &EthLog,
        decoded_txs: &mut HashMap<B256, Option<BnsCall>>,
    ) -> BnsRegistryResult<Option<BnsCall>> {
        let Some(tx_hash) = log.transaction_hash else {
            return Ok(None);
        };
        if let Some(decoded) = decoded_txs.get(&tx_hash) {
            return Ok(decoded.clone());
        }

        let decoded = match self.rpc.transaction_by_hash(tx_hash).await? {
            Some(tx) => Some(decode_bns_call(&tx.input)?),
            None => None,
        };
        decoded_txs.insert(tx_hash, decoded.clone());
        Ok(decoded)
    }

    async fn projection_for_record(
        &self,
        record: &EventLogRecord,
        decoded_call: Option<&BnsCall>,
    ) -> BnsRegistryResult<ContractProjectionWrite> {
        let mut write = ContractProjectionWrite::default();
        match &record.event {
            RegistryEvent::NameRegistered { name, .. }
            | RegistryEvent::NameRenewed { name, .. }
            | RegistryEvent::NameAssetTransferred { name, .. }
            | RegistryEvent::NameOwnerUpdated { name, .. }
            | RegistryEvent::NameReleased { name, .. }
            | RegistryEvent::OwnerDocumentIatFloorUpdated { name, .. }
            | RegistryEvent::NamespacePolicyUpdated { name, .. } => {
                self.push_name_state(&mut write, name).await?;
            }
            RegistryEvent::DocumentPublished {
                name,
                doc_type,
                version,
                ..
            } => {
                self.push_name_state(&mut write, name).await?;
                self.push_document_state(&mut write, name, doc_type, *version)
                    .await?;
            }
            RegistryEvent::DocumentRevoked {
                name,
                doc_type,
                new_version,
                ..
            } => {
                self.push_name_state(&mut write, name).await?;
                self.push_document_state(&mut write, name, doc_type, *new_version)
                    .await?;
            }
            RegistryEvent::AuthorityKeysUpdated { name, .. } => {
                let set = self.read_authority_set(name).await?;
                write.authority_sets.push(set);
                for key in authority_keys_from_call(decoded_call, name)? {
                    write.authority_keys.push((canonical_bns_name(name)?, key));
                }
            }
            RegistryEvent::ControllerPolicyUpdated {
                name, policy_hash, ..
            } => {
                self.push_name_state(&mut write, name).await?;
                if let Some(rules) = controller_rules_from_call(decoded_call, name)? {
                    write.controller_policies.push((
                        canonical_bns_name(name)?,
                        rules,
                        policy_hash.clone(),
                    ));
                }
            }
            RegistryEvent::DidAliasSet { name, .. } => {
                self.push_name_state(&mut write, name).await?;
                let alias = self.read_alias(name).await?;
                write.aliases.push(alias);
            }
            RegistryEvent::PaymentTargetUpdated {
                name,
                doc_type,
                version,
                ..
            } => {
                self.push_name_state(&mut write, name).await?;
                self.push_document_state(&mut write, name, doc_type, *version)
                    .await?;
            }
            RegistryEvent::LogCheckpointPublished { .. } => {
                write.checkpoints.push(self.read_latest_checkpoint().await?);
            }
        }
        Ok(write)
    }

    async fn push_name_state(
        &self,
        write: &mut ContractProjectionWrite,
        name: &str,
    ) -> BnsRegistryResult<()> {
        if let Some(state) = self.read_name_state(name).await? {
            write.names.push(state);
        }
        Ok(())
    }

    async fn push_document_state(
        &self,
        write: &mut ContractProjectionWrite,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsRegistryResult<()> {
        if let Some(state) = self.read_document_state(name, doc_type, version).await? {
            write.documents.push(state);
        }
        Ok(())
    }

    async fn read_name_state(&self, name: &str) -> BnsRegistryResult<Option<NameState>> {
        let state = self
            .rpc
            .call_contract(
                self.contract,
                &Bns::queryNameStateCall {
                    name: name.to_string(),
                },
            )
            .await?;
        let state = name_state_from_evm(state)?;
        if state.status == NameStatus::Available {
            Ok(None)
        } else {
            Ok(Some(state))
        }
    }

    async fn read_document_state(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsRegistryResult<Option<DocumentState>> {
        let state = self
            .rpc
            .call_contract(
                self.contract,
                &Bns::getDocumentVersionCall {
                    name: name.to_string(),
                    docType: doc_type.to_string(),
                    version,
                },
            )
            .await?;
        let state = document_state_from_evm(state)?;
        if state.status == DocumentStatus::Missing {
            Ok(None)
        } else {
            Ok(Some(state))
        }
    }

    async fn read_authority_set(&self, name: &str) -> BnsRegistryResult<AuthoritySetState> {
        let state = self
            .rpc
            .call_contract(
                self.contract,
                &Bns::getAuthoritySetCall {
                    name: name.to_string(),
                },
            )
            .await?;
        authority_set_from_evm(state)
    }

    async fn read_alias(&self, name: &str) -> BnsRegistryResult<AliasState> {
        let state = self
            .rpc
            .call_contract(
                self.contract,
                &Bns::getAliasCall {
                    name: name.to_string(),
                },
            )
            .await?;
        alias_state_from_evm(state)
    }

    async fn read_latest_checkpoint(&self) -> BnsRegistryResult<LogCheckpoint> {
        let checkpoint = self
            .rpc
            .call_contract(self.contract, &Bns::latestCheckpointCall {})
            .await?;
        checkpoint_from_evm(checkpoint)
    }
}

pub async fn sync_bns_contract_once<S>(
    store: &S,
    config: BnsIndexerSyncConfig,
) -> BnsRegistryResult<BnsIndexerSyncOutcome>
where
    S: BnsRegistryStore,
{
    BnsContractEventIndexer::new(store, config)?
        .sync_once()
        .await
}

#[derive(Default)]
struct ContractProjectionWrite {
    names: Vec<NameState>,
    documents: Vec<DocumentState>,
    authority_sets: Vec<AuthoritySetState>,
    authority_keys: Vec<(String, AuthorityKey)>,
    controller_policies: Vec<(String, Vec<crate::ControllerRule>, String)>,
    aliases: Vec<AliasState>,
    checkpoints: Vec<LogCheckpoint>,
}

impl ContractProjectionWrite {
    fn apply(self, tx: &mut dyn BnsRegistryStoreTx) -> BnsRegistryResult<()> {
        for name in self.names {
            tx.put_name(&name)?;
        }
        for document in self.documents {
            tx.put_document(&document)?;
        }
        for set in self.authority_sets {
            tx.put_authority_set(&set)?;
        }
        for (name, key) in self.authority_keys {
            tx.put_authority_key(&name, &key)?;
        }
        for (name, rules, policy_hash) in self.controller_policies {
            tx.put_controller_policy(&name, &rules, &policy_hash)?;
        }
        for alias in self.aliases {
            tx.put_alias(&alias)?;
        }
        for checkpoint in self.checkpoints {
            tx.put_checkpoint(&checkpoint)?;
        }
        Ok(())
    }
}

fn authority_keys_from_call(
    decoded_call: Option<&BnsCall>,
    name: &str,
) -> BnsRegistryResult<Vec<AuthorityKey>> {
    let Some(decoded_call) = decoded_call else {
        return Ok(Vec::new());
    };
    let updates = match decoded_call {
        BnsCall::registerName(call) if call.name == name => &call.authorityUpdates,
        BnsCall::updateAuthorityKeys(call) if call.name == name => &call.updates,
        BnsCall::applyMutations(call) if call.name == name => &call.authorityUpdates,
        _ => return Ok(Vec::new()),
    };
    updates.iter().map(authority_key_update_from_evm).collect()
}

fn controller_rules_from_call(
    decoded_call: Option<&BnsCall>,
    name: &str,
) -> BnsRegistryResult<Option<Vec<crate::ControllerRule>>> {
    let Some(decoded_call) = decoded_call else {
        return Ok(None);
    };
    let rules = match decoded_call {
        BnsCall::registerName(call) if call.name == name => &call.controllerPolicy,
        BnsCall::setControllerPolicy(call) if call.name == name => &call.rules,
        _ => return Ok(None),
    };
    rules
        .iter()
        .map(controller_rule_from_evm)
        .collect::<BnsRegistryResult<Vec<_>>>()
        .map(Some)
}

fn authority_key_update_from_evm(
    update: &EvmAuthorityKeyUpdate,
) -> BnsRegistryResult<AuthorityKey> {
    let mut key = authority_key_from_evm(&update.key)?;
    if update.active {
        if key.status == AuthorityKeyStatus::Missing {
            key.status = AuthorityKeyStatus::Active;
        }
    } else {
        key.status = AuthorityKeyStatus::Revoked;
    }
    Ok(key)
}

fn name_state_from_evm(state: EvmNameState) -> BnsRegistryResult<NameState> {
    Ok(NameState {
        name: canonical_bns_name_or_empty(&state.name)?,
        asset_owner: address_or_empty(state.assetOwner),
        semantic_owner: principal_from_evm(state.semanticOwner)?,
        effective_owner: principal_from_evm(state.effectiveOwner)?,
        owner_source: owner_source_from_evm(state.ownerSource)?,
        standard_transfer_enabled: state.standardTransferEnabled,
        status: name_status_from_evm(state.status)?,
        registered_at: state.registeredAt,
        expire_at: state.expireAt,
        grace_until: state.graceUntil,
        updated_at: state.updatedAt,
        name_seq: state.nameSeq,
        owner_document_version: state.ownerDocumentVersion,
        min_document_iat: state.minDocumentIat,
        owner_policy_seq: state.ownerPolicySeq,
        lineage_epoch: state.lineageEpoch,
        renewable: state.renewable,
        transferable: state.transferable,
        allow_delegated_subnames: state.allowDelegatedSubnames,
        namespace_policy_hash: hash_string(state.namespacePolicyHash),
        payment_policy_hash: hash_string(state.paymentPolicyHash),
        alias_state_hash: hash_string(state.aliasStateHash),
    })
}

fn document_state_from_evm(state: EvmDocumentState) -> BnsRegistryResult<DocumentState> {
    Ok(DocumentState {
        name: canonical_bns_name_or_empty(&state.name)?,
        doc_type: canonical_doc_type_or_empty(&state.docType)?,
        version: state.version,
        previous_version: state.previousVersion,
        status: document_status_from_evm(state.status)?,
        document: document_ref_from_evm(state.document)?,
        controller: principal_from_evm(state.controller)?,
        beneficiary: principal_from_evm(state.beneficiary)?,
        payment_target: address_or_empty(state.paymentTarget),
        valid_from: state.validFrom,
        expire_at: state.expireAt,
        revoked_at: state.revokedAt,
        controller_policy_hash: hash_string(state.controllerPolicyHash),
        payment_policy_hash: hash_string(state.paymentPolicyHash),
        split_policy_hash: hash_string(state.splitPolicyHash),
        price_policy_hash: hash_string(state.pricePolicyHash),
        rights_policy_hash: hash_string(state.rightsPolicyHash),
        document_state_hash: hash_string(state.documentStateHash),
    })
}

fn authority_set_from_evm(state: EvmAuthoritySetState) -> BnsRegistryResult<AuthoritySetState> {
    Ok(AuthoritySetState {
        name: canonical_bns_name_or_empty(&state.name)?,
        authority_seq: state.authoritySeq,
        authority_root: hash_string(state.authorityRoot),
        active_key_count: state.activeKeyCount,
    })
}

fn authority_key_from_evm(key: &EvmAuthorityKey) -> BnsRegistryResult<AuthorityKey> {
    Ok(AuthorityKey {
        kid: hash_string(key.kid),
        verification_method: bytes32_label_or_hash(key.verificationMethod),
        key_data: key.keyData.to_vec(),
        purposes: key.purposes,
        valid_from: key.validFrom,
        valid_until: key.validUntil,
        status: authority_key_status_from_evm(key.status)?,
        metadata_hash: hash_string(key.metadataHash),
    })
}

fn controller_rule_from_evm(
    rule: &bns_evm::ControllerRule,
) -> BnsRegistryResult<crate::ControllerRule> {
    Ok(crate::ControllerRule {
        controller: principal_from_evm(rule.controller.clone())?,
        doc_type: canonical_doc_type_or_empty(&rule.docType)?,
        permissions: rule.permissions,
        namespace_scope_hash: hash_string(rule.namespaceScopeHash),
        valid_from: rule.validFrom,
        valid_until: rule.validUntil,
        constraint_hash: hash_string(rule.constraintHash),
    })
}

fn alias_state_from_evm(state: EvmAliasState) -> BnsRegistryResult<AliasState> {
    Ok(AliasState {
        name: canonical_bns_name_or_empty(&state.name)?,
        kind: alias_kind_from_evm(state.kind)?,
        target_did: state.targetDid,
        proof_hash: hash_string(state.proofHash),
        set_at: state.setAt,
        name_seq: state.nameSeq,
    })
}

fn checkpoint_from_evm(checkpoint: bns_evm::LogCheckpoint) -> BnsRegistryResult<LogCheckpoint> {
    Ok(LogCheckpoint {
        log_root: hash_string(checkpoint.logRoot),
        last_seq: checkpoint.lastSeq,
        issued_at: checkpoint.issuedAt,
        issuer: principal_from_evm(checkpoint.issuer)?,
        external_anchor: hash_string(checkpoint.externalAnchor),
    })
}

fn document_ref_from_evm(document: EvmDocumentRef) -> BnsRegistryResult<DocumentRef> {
    Ok(DocumentRef {
        storage_type: bytes32_label_or_hash(document.storageType),
        uri: document.uri,
        inline_document: document.inlineDocument.to_vec(),
        content_hash: hash_string(document.contentHash),
        schema: hash_string(document.schema),
        codec: hash_string(document.codec),
        extra_hash: hash_string(document.extraHash),
    })
}

fn principal_from_evm(principal: EvmPrincipal) -> BnsRegistryResult<Principal> {
    match principal.kind {
        EvmPrincipalKind::Unset => Ok(Principal::unset()),
        EvmPrincipalKind::ChainAccount => {
            let bytes = principal.value.as_ref();
            if bytes.len() != 20 && bytes.len() != 32 {
                return Err(BnsRegistryError::InvalidMutation(format!(
                    "chain account principal has {} bytes",
                    bytes.len()
                )));
            }
            let address_bytes = if bytes.len() == 20 {
                bytes
            } else {
                &bytes[12..]
            };
            Ok(Principal::chain_account(format!(
                "0x{}",
                hex::encode(address_bytes)
            )))
        }
        EvmPrincipalKind::BnsName => {
            let name = String::from_utf8(principal.value.to_vec()).map_err(|err| {
                BnsRegistryError::InvalidMutation(format!(
                    "BnsName principal is not valid UTF-8: {err}"
                ))
            })?;
            Principal::bns_name(name)
        }
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract principal kind".to_string(),
        )),
    }
}

fn name_status_from_evm(status: EvmNameStatus) -> BnsRegistryResult<NameStatus> {
    match status {
        EvmNameStatus::Available => Ok(NameStatus::Available),
        EvmNameStatus::Active => Ok(NameStatus::Active),
        EvmNameStatus::Expired => Ok(NameStatus::Expired),
        EvmNameStatus::Released => Ok(NameStatus::Released),
        EvmNameStatus::Tombstoned => Ok(NameStatus::Tombstoned),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract name status".to_string(),
        )),
    }
}

fn document_status_from_evm(status: EvmDocumentStatus) -> BnsRegistryResult<DocumentStatus> {
    match status {
        EvmDocumentStatus::Missing => Ok(DocumentStatus::Missing),
        EvmDocumentStatus::Active => Ok(DocumentStatus::Active),
        EvmDocumentStatus::Revoked => Ok(DocumentStatus::Revoked),
        EvmDocumentStatus::Expired => Ok(DocumentStatus::Expired),
        EvmDocumentStatus::Migrated => Ok(DocumentStatus::Migrated),
        EvmDocumentStatus::Tombstoned => Ok(DocumentStatus::Tombstoned),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract document status".to_string(),
        )),
    }
}

fn authority_key_status_from_evm(
    status: EvmAuthorityKeyStatus,
) -> BnsRegistryResult<AuthorityKeyStatus> {
    match status {
        EvmAuthorityKeyStatus::Missing => Ok(AuthorityKeyStatus::Missing),
        EvmAuthorityKeyStatus::Active => Ok(AuthorityKeyStatus::Active),
        EvmAuthorityKeyStatus::Revoked => Ok(AuthorityKeyStatus::Revoked),
        EvmAuthorityKeyStatus::Expired => Ok(AuthorityKeyStatus::Expired),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract authority key status".to_string(),
        )),
    }
}

fn owner_source_from_evm(source: EvmOwnerSource) -> BnsRegistryResult<OwnerSource> {
    match source {
        EvmOwnerSource::None => Ok(OwnerSource::None),
        EvmOwnerSource::AssetOwnerFallback => Ok(OwnerSource::AssetOwnerFallback),
        EvmOwnerSource::ExplicitSemanticOwner => Ok(OwnerSource::ExplicitSemanticOwner),
        EvmOwnerSource::ParentInherited => Ok(OwnerSource::ParentInherited),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract owner source".to_string(),
        )),
    }
}

fn alias_kind_from_evm(kind: EvmAliasKind) -> BnsRegistryResult<AliasKind> {
    match kind {
        EvmAliasKind::None => Ok(AliasKind::None),
        EvmAliasKind::Alias => Ok(AliasKind::Alias),
        EvmAliasKind::MigratedTo => Ok(AliasKind::MigratedTo),
        EvmAliasKind::Canonical => Ok(AliasKind::Canonical),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract alias kind".to_string(),
        )),
    }
}

fn canonical_bns_name_or_empty(name: &str) -> BnsRegistryResult<String> {
    if name.is_empty() {
        Ok(String::new())
    } else {
        canonical_bns_name(name)
    }
}

fn canonical_doc_type_or_empty(doc_type: &str) -> BnsRegistryResult<String> {
    if doc_type.is_empty() {
        Ok(String::new())
    } else {
        canonical_doc_type(doc_type)
    }
}

fn address_or_empty(address: Address) -> String {
    if address == Address::ZERO {
        String::new()
    } else {
        format!("{address:#x}")
    }
}

fn hash_string(hash: B256) -> String {
    format!("{hash:#x}")
}

fn bytes32_label_or_hash(value: B256) -> String {
    if value == B256::ZERO {
        return ZERO_HASH.to_string();
    }
    let bytes = value.as_slice();
    let trimmed_len = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if trimmed_len > 0
        && bytes[trimmed_len..].iter().all(|byte| *byte == 0)
        && bytes[..trimmed_len]
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        if let Ok(label) = std::str::from_utf8(&bytes[..trimmed_len]) {
            return label.to_string();
        }
    }
    hash_string(value)
}
