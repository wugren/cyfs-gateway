use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use bns_client::{BnsClientResult, BnsIndexerApi, BnsNamePage, MAX_BNS_NAMES_PAGE_SIZE};
use bns_evm::Address;
use serde_json::Value;

use crate::{
    canonical_bns_name, canonical_doc_type, document_state_hash, ensure_registerable_depth,
    is_top_level_name, now_timestamp, parent_name, validate_did, validate_hash,
    validate_semantic_owner, AliasKind, AliasState, ApplyMutationsResult, AuthorityKey,
    AuthorityKeyStatus, AuthorityKeyUpdate, AuthorityRole, AuthoritySetState, BnsRegistryError,
    BnsRegistryResult, BnsRegistryStore, BnsRegistryStoreTx, BootstrapDocumentVersion,
    BootstrapNameResult, CallAuthority, ControllerRule, DocumentRef, DocumentState, DocumentStatus,
    DocumentUpdate, EventLogRecord, LogCheckpoint, MutationGuard, NameState, NameStatus,
    OwnerPolicyUpdate, OwnerResolution, OwnerSource, PaymentTargetResolution, Principal,
    PrincipalKind, PurchaseContext, RegisterOptions, RegistryEvent, ReleaseMode, ResolveResult,
    KEY_PURPOSE_AUTHENTICATION, MAX_OWNER_REF_DEPTH, PERMISSION_PUBLISH_DOCUMENT,
    PERMISSION_REVOKE_DOCUMENT, PERMISSION_SET_ALIAS, PERMISSION_SET_NAMESPACE,
    PERMISSION_SET_PAYMENT, STORAGE_TYPE_INLINE, ZERO_HASH,
};

use crate::sqlite::recompute_authority_set;

pub struct CentralizedBnsRegistry<S>
where
    S: BnsRegistryStore,
{
    store: S,
    writes_enabled: bool,
}

pub struct CentralizedBnsIndexerHandler<S>
where
    S: BnsRegistryStore,
{
    registry: Arc<CentralizedBnsRegistry<S>>,
}

impl<S> CentralizedBnsIndexerHandler<S>
where
    S: BnsRegistryStore,
{
    pub fn new(registry: Arc<CentralizedBnsRegistry<S>>) -> Self {
        Self { registry }
    }

    pub fn registry(&self) -> &CentralizedBnsRegistry<S> {
        &self.registry
    }
}

#[async_trait]
impl<S> BnsIndexerApi for CentralizedBnsIndexerHandler<S>
where
    S: BnsRegistryStore + 'static,
{
    async fn query_name_state(&self, name: &str) -> BnsClientResult<Option<NameState>> {
        self.registry.query_name_state(name).map_err(Into::into)
    }

    async fn resolve_owner(&self, name: &str) -> BnsClientResult<OwnerResolution> {
        self.registry.resolve_owner(name).map_err(Into::into)
    }

    async fn get_authority_set(&self, name: &str) -> BnsClientResult<AuthoritySetState> {
        self.registry.get_authority_set(name).map_err(Into::into)
    }

    async fn get_authority_key(
        &self,
        name: &str,
        kid: &str,
    ) -> BnsClientResult<Option<AuthorityKey>> {
        self.registry
            .get_authority_key(name, kid)
            .map_err(Into::into)
    }

    async fn resolve_document(&self, name: &str, doc_type: &str) -> BnsClientResult<ResolveResult> {
        self.registry
            .resolve_document(name, doc_type)
            .map_err(Into::into)
    }

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsClientResult<Option<DocumentState>> {
        self.registry
            .get_document_version(name, doc_type, version)
            .map_err(Into::into)
    }

    async fn query_names_by_address(
        &self,
        address: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> BnsClientResult<BnsNamePage> {
        self.registry
            .query_names_by_address(address, cursor, limit)
            .map_err(Into::into)
    }

    async fn list_events(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> BnsClientResult<Vec<EventLogRecord>> {
        self.registry
            .list_events(from_seq, limit)
            .map_err(Into::into)
    }

    async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>> {
        self.registry.latest_checkpoint().map_err(Into::into)
    }
}

impl<S> CentralizedBnsRegistry<S>
where
    S: BnsRegistryStore,
{
    pub fn new(store: S) -> Self {
        Self {
            store,
            writes_enabled: false,
        }
    }

    #[doc(hidden)]
    pub fn new_legacy_state_machine(store: S) -> Self {
        Self {
            store,
            writes_enabled: true,
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    fn ensure_write_path(&self, operation: &'static str) -> BnsRegistryResult<()> {
        if self.writes_enabled {
            Ok(())
        } else {
            Err(BnsRegistryError::UnsupportedOperation(format!(
                "CentralizedBnsRegistry no longer accepts `{operation}` writes; submit a signed EVM raw TX and let bns-indexer rebuild the read projection from contract events"
            )))
        }
    }

    pub fn query_name_state(&self, name: &str) -> BnsRegistryResult<Option<NameState>> {
        let name = canonical_bns_name(name)?;
        self.store.transact(|tx| {
            tx.get_name(&name)?
                .map(|state| self.materialize_name_state(tx, state))
                .transpose()
        })
    }

    pub fn query_names_by_address(
        &self,
        address: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> BnsRegistryResult<BnsNamePage> {
        if limit == 0 || limit > MAX_BNS_NAMES_PAGE_SIZE {
            return Err(BnsRegistryError::InvalidLimit {
                limit,
                max: MAX_BNS_NAMES_PAGE_SIZE,
            });
        }
        let address = Address::from_str(address.trim()).map_err(|error| {
            BnsRegistryError::InvalidAddress {
                address: address.to_string(),
                reason: error.to_string(),
            }
        })?;
        let address = format!("{address:#x}");
        let fetch_limit = limit.saturating_add(1);
        self.store.transact(|tx| {
            let mut names = tx.list_names_by_asset_owner(&address, cursor, fetch_limit)?;
            let has_more = names.len() > limit;
            if has_more {
                names.truncate(limit);
            }
            let next_cursor = has_more.then(|| names.last().cloned()).flatten();
            Ok(BnsNamePage { names, next_cursor })
        })
    }

    pub fn resolve_owner(&self, name: &str) -> BnsRegistryResult<OwnerResolution> {
        let name = canonical_bns_name(name)?;
        self.store
            .transact(|tx| self.resolve_owner_for_name(tx, &name))
    }

    pub fn is_standard_transfer_enabled(&self, name: &str) -> BnsRegistryResult<bool> {
        Ok(self
            .query_name_state(name)?
            .ok_or_else(|| BnsRegistryError::NameNotFound {
                name: name.to_string(),
            })?
            .standard_transfer_enabled)
    }

    pub fn get_authority_set(&self, name: &str) -> BnsRegistryResult<AuthoritySetState> {
        let name = canonical_bns_name(name)?;
        self.store.transact(|tx| self.authority_set(tx, &name))
    }

    pub fn get_authority_key(
        &self,
        name: &str,
        kid: &str,
    ) -> BnsRegistryResult<Option<AuthorityKey>> {
        let name = canonical_bns_name(name)?;
        self.store.transact(|tx| tx.get_authority_key(&name, kid))
    }

    pub fn resolve_document(&self, name: &str, doc_type: &str) -> BnsRegistryResult<ResolveResult> {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        self.store.transact(|tx| {
            let name_state = self
                .load_materialized_name(tx, &name)?
                .ok_or_else(|| BnsRegistryError::NameNotFound { name: name.clone() })?;
            let owner = self.resolve_owner_for_name(tx, &name)?;
            let alias = tx.get_alias(&name)?;
            let proof_root = self.current_proof_root(tx)?;
            let document_state = tx
                .get_current_document(&name, &doc_type)?
                .unwrap_or_else(|| missing_document_state(&name, &doc_type));
            let effective_controller = if document_state.status == DocumentStatus::Missing
                || document_state.controller.is_unset()
            {
                owner.effective_owner.clone()
            } else {
                document_state.controller.clone()
            };
            if document_state.status != DocumentStatus::Missing {
                self.ensure_document_consistent(
                    &name,
                    &doc_type,
                    &document_state,
                    &owner.effective_owner,
                )?;
            }

            Ok(ResolveResult {
                status: document_state.status,
                alias_kind: alias.as_ref().map_or(AliasKind::None, |state| state.kind),
                alias_target_did: alias.map_or_else(String::new, |state| state.target_did),
                name_state,
                document_state,
                owner,
                effective_controller,
                proof_root,
            })
        })
    }

    pub fn resolve_did(&self, did: &str, doc_type: &str) -> BnsRegistryResult<ResolveResult> {
        let name = crate::name_from_did_bns(did)?;
        self.resolve_document(&name, doc_type)
    }

    pub fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsRegistryResult<Option<DocumentState>> {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        self.store.transact(|tx| {
            let document = tx.get_document(&name, &doc_type, version)?;
            if let Some(document_state) = document.as_ref() {
                let owner = self.resolve_owner_for_name(tx, &name)?;
                self.ensure_document_consistent(
                    &name,
                    &doc_type,
                    document_state,
                    &owner.effective_owner,
                )?;
            }
            Ok(document)
        })
    }

    pub fn get_alias(&self, name: &str) -> BnsRegistryResult<Option<AliasState>> {
        let name = canonical_bns_name(name)?;
        self.store.transact(|tx| tx.get_alias(&name))
    }

    pub fn get_purchase_context(
        &self,
        name: &str,
        doc_type: &str,
    ) -> BnsRegistryResult<PurchaseContext> {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        self.store.transact(|tx| {
            let document = tx.get_current_document(&name, &doc_type)?.ok_or_else(|| {
                BnsRegistryError::DocumentNotFound {
                    name: name.clone(),
                    doc_type: doc_type.clone(),
                }
            })?;
            let owner = self.resolve_owner_for_name(tx, &name)?;
            self.ensure_document_consistent(&name, &doc_type, &document, &owner.effective_owner)?;
            let proof_root = self.current_proof_root(tx)?;
            Ok(PurchaseContext {
                name: name.clone(),
                doc_type: doc_type.clone(),
                document_version: document.version,
                beneficiary: document.beneficiary,
                payment_target: document.payment_target,
                payment_policy_hash: document.payment_policy_hash,
                split_policy_hash: document.split_policy_hash,
                price_policy_hash: document.price_policy_hash,
                rights_policy_hash: document.rights_policy_hash,
                status: document.status,
                proof_root,
            })
        })
    }

    pub fn resolve_payment_target(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsRegistryResult<PaymentTargetResolution> {
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        self.store.transact(|tx| {
            let document = tx.get_document(&name, &doc_type, version)?.ok_or_else(|| {
                BnsRegistryError::DocumentNotFound {
                    name: name.clone(),
                    doc_type: doc_type.clone(),
                }
            })?;
            Ok(PaymentTargetResolution {
                beneficiary: document.beneficiary,
                payment_target: document.payment_target,
                payment_policy_hash: document.payment_policy_hash,
                split_policy_hash: document.split_policy_hash,
                price_policy_hash: document.price_policy_hash,
                rights_policy_hash: document.rights_policy_hash,
                proof_root: self.current_proof_root(tx)?,
            })
        })
    }

    pub fn register_name(
        &self,
        name: &str,
        asset_owner: &str,
        options: RegisterOptions,
        initial_documents: Vec<DocumentUpdate>,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<u64> {
        self.ensure_write_path("register_name")?;
        let name = canonical_bns_name(name)?;
        ensure_registerable_depth(&name)?;
        if asset_owner.is_empty() {
            return Err(BnsRegistryError::InvalidMutation(
                "asset owner must not be empty".to_string(),
            ));
        }
        options.validate()?;
        for update in &initial_documents {
            update.validate()?;
            if update.expected_version != 0 {
                return Err(BnsRegistryError::StaleDocumentVersion {
                    name: name.clone(),
                    doc_type: update.doc_type.clone(),
                    expected: update.expected_version,
                    actual: 0,
                });
            }
        }

        self.store.transact(|tx| {
            let now = now_timestamp();
            let existing = tx.get_name(&name)?;
            if matches!(
                existing.as_ref().map(|state| state.status),
                Some(NameStatus::Active | NameStatus::Expired | NameStatus::Tombstoned)
            ) {
                return Err(BnsRegistryError::NameAlreadyExists { name: name.clone() });
            }

            if let Some(parent) = parent_name(&name) {
                let parent_state = self.required_active_name(tx, parent)?;
                if guard.expected_parent_name_seq != parent_state.name_seq {
                    return Err(BnsRegistryError::StaleParentNameSeq {
                        name: parent.to_string(),
                        expected: guard.expected_parent_name_seq,
                        actual: parent_state.name_seq,
                    });
                }
                self.authorize_owner_for_loaded(tx, &parent_state, &authority)?;
            } else if authority.role != AuthorityRole::None {
                return Err(BnsRegistryError::InvalidMutation(
                    "root registration does not use registry owner/controller authority"
                        .to_string(),
                ));
            }

            self.validate_semantic_owner_target(tx, &options.initial_semantic_owner)?;

            let lineage_epoch = existing.as_ref().map_or(0, |state| state.lineage_epoch + 1);
            let next_seq = existing.as_ref().map_or(1, |state| state.name_seq + 1);
            let mut state = NameState {
                name: name.clone(),
                asset_owner: asset_owner.to_string(),
                semantic_owner: options.initial_semantic_owner.clone(),
                effective_owner: Principal::unset(),
                owner_source: OwnerSource::None,
                standard_transfer_enabled: false,
                status: NameStatus::Active,
                registered_at: now,
                expire_at: now + options.duration,
                grace_until: now + options.duration + options.grace_period,
                updated_at: now,
                name_seq: next_seq,
                owner_document_version: 0,
                min_document_iat: 0,
                owner_policy_seq: 0,
                lineage_epoch,
                renewable: options.renewable,
                transferable: options.transferable,
                allow_delegated_subnames: options.allow_delegated_subnames,
                namespace_policy_hash: options.initial_namespace_policy_hash.clone(),
                payment_policy_hash: options.initial_payment_policy_hash.clone(),
                alias_state_hash: ZERO_HASH.to_string(),
            };

            self.validate_owner_graph_with(tx, Some(&state))?;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;
            tx.append_event(
                &RegistryEvent::NameRegistered {
                    name: name.clone(),
                    asset_owner: asset_owner.to_string(),
                    expire_at: state.expire_at,
                    lineage_epoch,
                    name_seq: state.name_seq,
                },
                now,
            )?;

            for update in initial_documents {
                self.publish_document_internal(tx, &name, update, false, now)?;
            }

            Ok(state.name_seq)
        })
    }

    pub fn bootstrap_name(
        &self,
        name: &str,
        asset_owner: &str,
        options: RegisterOptions,
        initial_documents: Vec<DocumentUpdate>,
        authority_key_updates: Vec<AuthorityKeyUpdate>,
        semantic_owner_after_authority: Option<Principal>,
        controller_policy: Vec<ControllerRule>,
        controller_policy_hash: &str,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<BootstrapNameResult> {
        self.ensure_write_path("bootstrap_name")?;
        let name = canonical_bns_name(name)?;
        ensure_registerable_depth(&name)?;
        if asset_owner.is_empty() {
            return Err(BnsRegistryError::InvalidMutation(
                "asset owner must not be empty".to_string(),
            ));
        }
        options.validate()?;
        for update in &initial_documents {
            update.validate()?;
            if update.expected_version != 0 {
                return Err(BnsRegistryError::StaleDocumentVersion {
                    name: name.clone(),
                    doc_type: update.doc_type.clone(),
                    expected: update.expected_version,
                    actual: 0,
                });
            }
        }
        for update in &authority_key_updates {
            update.key.validate()?;
        }
        if let Some(owner) = &semantic_owner_after_authority {
            validate_semantic_owner(owner)?;
        }
        validate_hash(controller_policy_hash)?;
        for rule in &controller_policy {
            rule.validate()?;
        }

        self.store.transact(|tx| {
            let now = now_timestamp();
            let existing = tx.get_name(&name)?;
            if matches!(
                existing.as_ref().map(|state| state.status),
                Some(NameStatus::Active | NameStatus::Expired | NameStatus::Tombstoned)
            ) {
                return Err(BnsRegistryError::NameAlreadyExists { name: name.clone() });
            }

            if let Some(parent) = parent_name(&name) {
                let parent_state = self.required_active_name(tx, parent)?;
                if guard.expected_parent_name_seq != parent_state.name_seq {
                    return Err(BnsRegistryError::StaleParentNameSeq {
                        name: parent.to_string(),
                        expected: guard.expected_parent_name_seq,
                        actual: parent_state.name_seq,
                    });
                }
                self.authorize_owner_for_loaded(tx, &parent_state, &authority)?;
            } else if authority.role != AuthorityRole::None {
                return Err(BnsRegistryError::InvalidMutation(
                    "root registration does not use registry owner/controller authority"
                        .to_string(),
                ));
            }

            self.validate_semantic_owner_target(tx, &options.initial_semantic_owner)?;

            let lineage_epoch = existing.as_ref().map_or(0, |state| state.lineage_epoch + 1);
            let next_seq = existing.as_ref().map_or(1, |state| state.name_seq + 1);
            let mut state = NameState {
                name: name.clone(),
                asset_owner: asset_owner.to_string(),
                semantic_owner: options.initial_semantic_owner.clone(),
                effective_owner: Principal::unset(),
                owner_source: OwnerSource::None,
                standard_transfer_enabled: false,
                status: NameStatus::Active,
                registered_at: now,
                expire_at: now + options.duration,
                grace_until: now + options.duration + options.grace_period,
                updated_at: now,
                name_seq: next_seq,
                owner_document_version: 0,
                min_document_iat: 0,
                owner_policy_seq: 0,
                lineage_epoch,
                renewable: options.renewable,
                transferable: options.transferable,
                allow_delegated_subnames: options.allow_delegated_subnames,
                namespace_policy_hash: options.initial_namespace_policy_hash.clone(),
                payment_policy_hash: options.initial_payment_policy_hash.clone(),
                alias_state_hash: ZERO_HASH.to_string(),
            };

            self.validate_owner_graph_with(tx, Some(&state))?;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;
            tx.append_event(
                &RegistryEvent::NameRegistered {
                    name: name.clone(),
                    asset_owner: asset_owner.to_string(),
                    expire_at: state.expire_at,
                    lineage_epoch,
                    name_seq: state.name_seq,
                },
                now,
            )?;

            let mut initial_document_versions = Vec::with_capacity(initial_documents.len());
            for update in initial_documents {
                let doc_type = update.doc_type.clone();
                let version = self.publish_document_internal(tx, &name, update, false, now)?;
                let document = tx.get_document(&name, &doc_type, version)?.ok_or_else(|| {
                    BnsRegistryError::DocumentNotFound {
                        name: name.clone(),
                        doc_type: doc_type.clone(),
                    }
                })?;
                initial_document_versions.push(BootstrapDocumentVersion {
                    doc_type,
                    version,
                    content_hash: document.document.content_hash,
                    document_state_hash: document.document_state_hash,
                });
            }

            if !authority_key_updates.is_empty() {
                self.apply_authority_updates(tx, &name, authority_key_updates, now)?;
            }

            if let Some(semantic_owner) = semantic_owner_after_authority {
                let mut state = self.required_active_name(tx, &name)?;
                self.validate_semantic_owner_target(tx, &semantic_owner)?;
                state.semantic_owner = semantic_owner;
                state.name_seq += 1;
                state.updated_at = now;
                self.validate_owner_graph_with(tx, Some(&state))?;
                state = self.materialize_name_state(tx, state)?;
                tx.put_name(&state)?;
                tx.append_event(
                    &RegistryEvent::NameOwnerUpdated {
                        name: name.clone(),
                        owner: state.semantic_owner.clone(),
                        owner_source: state.owner_source,
                        standard_transfer_enabled: state.standard_transfer_enabled,
                        name_seq: state.name_seq,
                    },
                    now,
                )?;
            }

            for rule in &controller_policy {
                if rule.controller.kind == PrincipalKind::BnsName {
                    self.require_active_authority_set(tx, &rule.controller.value)?;
                }
            }
            tx.put_controller_policy(&name, &controller_policy, controller_policy_hash)?;
            let mut state = self.required_active_name(tx, &name)?;
            state.name_seq += 1;
            state.updated_at = now;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;
            tx.append_event(
                &RegistryEvent::ControllerPolicyUpdated {
                    name: name.clone(),
                    policy_hash: controller_policy_hash.to_string(),
                    name_seq: state.name_seq,
                },
                now,
            )?;

            Ok(BootstrapNameResult {
                name_seq: state.name_seq,
                initial_documents: initial_document_versions,
                authority_set: self.authority_set(tx, &name)?,
                controller_policy_hash: controller_policy_hash.to_string(),
            })
        })
    }

    pub fn renew_name(&self, name: &str, duration: u64) -> BnsRegistryResult<u64> {
        self.ensure_write_path("renew_name")?;
        let name = canonical_bns_name(name)?;
        if duration == 0 {
            return Err(BnsRegistryError::InvalidMutation(
                "renew duration must be greater than zero".to_string(),
            ));
        }
        self.store.transact(|tx| {
            let now = now_timestamp();
            let mut state = self.required_raw_name(tx, &name)?;
            if !state.renewable
                || matches!(state.status, NameStatus::Released | NameStatus::Tombstoned)
            {
                return Err(BnsRegistryError::InvalidMutation(format!(
                    "name `{name}` is not renewable"
                )));
            }
            let grace_delta = state.grace_until.saturating_sub(state.expire_at);
            state.expire_at = state.expire_at.max(now) + duration;
            state.grace_until = state.expire_at + grace_delta;
            state.updated_at = now;
            state.name_seq += 1;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;
            tx.append_event(
                &RegistryEvent::NameRenewed {
                    name: name.clone(),
                    expire_at: state.expire_at,
                    name_seq: state.name_seq,
                },
                now,
            )?;
            Ok(state.expire_at)
        })
    }

    pub fn transfer_name(
        &self,
        name: &str,
        new_asset_owner: &str,
        new_semantic_owner: Principal,
        atomic_document_updates: Vec<DocumentUpdate>,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<u64> {
        self.ensure_write_path("transfer_name")?;
        let name = canonical_bns_name(name)?;
        if new_asset_owner.is_empty() {
            return Err(BnsRegistryError::InvalidMutation(
                "new asset owner must not be empty".to_string(),
            ));
        }
        validate_semantic_owner(&new_semantic_owner)?;
        for update in &atomic_document_updates {
            update.validate()?;
        }

        self.store.transact(|tx| {
            let now = now_timestamp();
            let mut state = self.required_active_name(tx, &name)?;
            self.check_guard(&state, &guard)?;
            self.authorize_owner_for_loaded(tx, &state, &authority)?;
            self.validate_semantic_owner_target(tx, &new_semantic_owner)?;

            let old_asset_owner = state.asset_owner.clone();
            state.asset_owner = new_asset_owner.to_string();
            state.semantic_owner = new_semantic_owner;
            state.name_seq += 1;
            state.updated_at = now;
            self.validate_owner_graph_with(tx, Some(&state))?;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;

            tx.append_event(
                &RegistryEvent::NameAssetTransferred {
                    name: name.clone(),
                    old_asset_owner,
                    new_asset_owner: new_asset_owner.to_string(),
                    standard_transfer: false,
                    name_seq: state.name_seq,
                },
                now,
            )?;
            tx.append_event(
                &RegistryEvent::NameOwnerUpdated {
                    name: name.clone(),
                    owner: state.semantic_owner.clone(),
                    owner_source: state.owner_source,
                    standard_transfer_enabled: state.standard_transfer_enabled,
                    name_seq: state.name_seq,
                },
                now,
            )?;

            for update in atomic_document_updates {
                self.publish_document_internal(tx, &name, update, false, now)?;
            }

            Ok(state.name_seq)
        })
    }

    pub fn standard_transfer_name(
        &self,
        name: &str,
        new_asset_owner: &str,
    ) -> BnsRegistryResult<u64> {
        self.ensure_write_path("standard_transfer_name")?;
        let name = canonical_bns_name(name)?;
        if new_asset_owner.is_empty() {
            return Err(BnsRegistryError::InvalidMutation(
                "new asset owner must not be empty".to_string(),
            ));
        }
        self.store.transact(|tx| {
            let now = now_timestamp();
            let mut state = self.required_active_name(tx, &name)?;
            state = self.materialize_name_state(tx, state)?;
            if !state.standard_transfer_enabled {
                return Err(BnsRegistryError::StandardTransferDisabled { name: name.clone() });
            }
            let old_asset_owner = state.asset_owner.clone();
            state.asset_owner = new_asset_owner.to_string();
            state.name_seq += 1;
            state.updated_at = now;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;
            tx.append_event(
                &RegistryEvent::NameAssetTransferred {
                    name,
                    old_asset_owner,
                    new_asset_owner: new_asset_owner.to_string(),
                    standard_transfer: true,
                    name_seq: state.name_seq,
                },
                now,
            )?;
            Ok(state.name_seq)
        })
    }

    pub fn set_name_owner(
        &self,
        name: &str,
        semantic_owner: Principal,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<u64> {
        self.ensure_write_path("set_name_owner")?;
        let name = canonical_bns_name(name)?;
        validate_semantic_owner(&semantic_owner)?;
        self.store.transact(|tx| {
            let now = now_timestamp();
            let mut state = self.required_active_name(tx, &name)?;
            self.check_guard(&state, &guard)?;
            self.authorize_owner_for_loaded(tx, &state, &authority)?;
            self.validate_semantic_owner_target(tx, &semantic_owner)?;
            state.semantic_owner = semantic_owner;
            state.name_seq += 1;
            state.updated_at = now;
            self.validate_owner_graph_with(tx, Some(&state))?;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;
            tx.append_event(
                &RegistryEvent::NameOwnerUpdated {
                    name,
                    owner: state.semantic_owner.clone(),
                    owner_source: state.owner_source,
                    standard_transfer_enabled: state.standard_transfer_enabled,
                    name_seq: state.name_seq,
                },
                now,
            )?;
            Ok(state.name_seq)
        })
    }

    pub fn release_name(
        &self,
        name: &str,
        mode: ReleaseMode,
        reason_hash: &str,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<u64> {
        self.ensure_write_path("release_name")?;
        let name = canonical_bns_name(name)?;
        validate_hash(reason_hash)?;
        self.store.transact(|tx| {
            let now = now_timestamp();
            let mut state = self.required_active_name(tx, &name)?;
            self.check_guard(&state, &guard)?;
            self.authorize_owner_for_loaded(tx, &state, &authority)?;
            state.status = match mode {
                ReleaseMode::ReleaseAfterGrace => NameStatus::Released,
                ReleaseMode::TombstoneForever => NameStatus::Tombstoned,
            };
            state.name_seq += 1;
            state.updated_at = now;
            self.validate_owner_graph_with(tx, Some(&state))?;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;
            tx.append_event(
                &RegistryEvent::NameReleased {
                    name,
                    mode,
                    reason_hash: reason_hash.to_string(),
                    name_seq: state.name_seq,
                },
                now,
            )?;
            Ok(state.name_seq)
        })
    }

    pub fn set_namespace_policy(
        &self,
        name: &str,
        allow_delegated_subnames: bool,
        namespace_policy_hash: &str,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<u64> {
        self.ensure_write_path("set_namespace_policy")?;
        let name = canonical_bns_name(name)?;
        validate_hash(namespace_policy_hash)?;
        self.store.transact(|tx| {
            let now = now_timestamp();
            let mut state = self.required_active_name(tx, &name)?;
            self.authorize_update(
                tx,
                &state,
                "",
                PERMISSION_SET_NAMESPACE,
                "set_namespace",
                &authority,
                &guard,
            )?;
            state.allow_delegated_subnames = allow_delegated_subnames;
            state.namespace_policy_hash = namespace_policy_hash.to_string();
            state.name_seq += 1;
            state.updated_at = now;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;
            tx.append_event(
                &RegistryEvent::NamespacePolicyUpdated {
                    name,
                    allow_delegated_subnames,
                    namespace_policy_hash: namespace_policy_hash.to_string(),
                    name_seq: state.name_seq,
                },
                now,
            )?;
            Ok(state.name_seq)
        })
    }

    pub fn update_authority_keys(
        &self,
        name: &str,
        updates: Vec<AuthorityKeyUpdate>,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<AuthoritySetState> {
        self.ensure_write_path("update_authority_keys")?;
        let name = canonical_bns_name(name)?;
        for update in &updates {
            update.key.validate()?;
        }
        self.store.transact(|tx| {
            let now = now_timestamp();
            let state = self.required_active_name(tx, &name)?;
            self.check_guard(&state, &guard)?;
            self.authorize_owner_for_loaded(tx, &state, &authority)?;
            self.apply_authority_updates(tx, &name, updates, now)
        })
    }

    pub fn apply_mutations(
        &self,
        name: &str,
        authority_updates: Vec<AuthorityKeyUpdate>,
        documents: Vec<DocumentUpdate>,
        owner_policy: OwnerPolicyUpdate,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<ApplyMutationsResult> {
        self.ensure_write_path("apply_mutations")?;
        if authority_updates.is_empty()
            && documents.is_empty()
            && !owner_policy.update_min_document_iat
        {
            return Err(BnsRegistryError::InvalidMutation(
                "mutation batch must not be empty".to_string(),
            ));
        }
        let name = canonical_bns_name(name)?;
        owner_policy.validate()?;
        for update in &authority_updates {
            update.key.validate()?;
        }
        let mut doc_types = HashSet::with_capacity(documents.len());
        for update in &documents {
            update.validate()?;
            let doc_type = canonical_doc_type(&update.doc_type)?;
            if !doc_types.insert(doc_type) {
                return Err(BnsRegistryError::InvalidMutation(
                    "mutation batch contains duplicate document type".to_string(),
                ));
            }
        }

        self.store.transact(|tx| {
            let now = now_timestamp();
            let state = self.required_active_name(tx, &name)?;
            self.check_guard(&state, &guard)?;

            let owner_only = !authority_updates.is_empty()
                || owner_policy.update_min_document_iat
                || documents.iter().any(|update| update.doc_type == "owner");
            if owner_only {
                self.authorize_owner_for_loaded(tx, &state, &authority)?;
            } else {
                for update in &documents {
                    self.authorize_update_no_guard(
                        tx,
                        &state,
                        &update.doc_type,
                        PERMISSION_PUBLISH_DOCUMENT,
                        "publish_document",
                        &authority,
                    )?;
                }
            }

            if !authority_updates.is_empty() {
                self.apply_authority_updates(tx, &name, authority_updates, now)?;
            }

            let mut document_versions = Vec::with_capacity(documents.len());
            if !documents.is_empty() || owner_policy.update_min_document_iat {
                let mut state = self.required_active_name(tx, &name)?;
                state.name_seq += 1;
                state.updated_at = now;
                state = self.materialize_name_state(tx, state)?;
                tx.put_name(&state)?;
            }

            if !documents.is_empty() {
                for update in documents {
                    let doc_type = update.doc_type.clone();
                    let version = self.publish_document_internal(tx, &name, update, false, now)?;
                    let document =
                        tx.get_document(&name, &doc_type, version)?.ok_or_else(|| {
                            BnsRegistryError::DocumentNotFound {
                                name: name.clone(),
                                doc_type: doc_type.clone(),
                            }
                        })?;
                    document_versions.push(BootstrapDocumentVersion {
                        doc_type,
                        version,
                        content_hash: document.document.content_hash,
                        document_state_hash: document.document_state_hash,
                    });
                }
            }
            if owner_policy.update_min_document_iat {
                self.set_min_document_iat_internal(
                    tx,
                    &name,
                    owner_policy.min_document_iat,
                    &owner_policy.reason_hash,
                    false,
                    now,
                )?;
            }

            let state = self.required_active_name(tx, &name)?;
            Ok(ApplyMutationsResult {
                name_seq: state.name_seq,
                documents: document_versions,
                authority_set: self.authority_set(tx, &name)?,
                owner_policy_seq: state.owner_policy_seq,
            })
        })
    }

    pub fn rotate_authority_and_owner_document(
        &self,
        name: &str,
        updates: Vec<AuthorityKeyUpdate>,
        owner_document_update: DocumentUpdate,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<(AuthoritySetState, u64)> {
        self.ensure_write_path("rotate_authority_and_owner_document")?;
        let name = canonical_bns_name(name)?;
        if owner_document_update.doc_type != "owner" {
            return Err(BnsRegistryError::InvalidMutation(
                "rotateAuthorityAndOwnerDocument requires doc_type=owner".to_string(),
            ));
        }
        for update in &updates {
            update.key.validate()?;
        }
        owner_document_update.validate()?;

        self.store.transact(|tx| {
            let now = now_timestamp();
            let state = self.required_active_name(tx, &name)?;
            self.check_guard(&state, &guard)?;
            self.authorize_owner_for_loaded(tx, &state, &authority)?;
            let authority_set = self.apply_authority_updates(tx, &name, updates, now)?;
            let version =
                self.publish_document_internal(tx, &name, owner_document_update, true, now)?;
            Ok((authority_set, version))
        })
    }

    pub fn publish_document(
        &self,
        name: &str,
        update: DocumentUpdate,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<u64> {
        self.ensure_write_path("publish_document")?;
        let name = canonical_bns_name(name)?;
        update.validate()?;
        self.store.transact(|tx| {
            let now = now_timestamp();
            let state = self.required_active_name(tx, &name)?;
            self.authorize_update(
                tx,
                &state,
                &update.doc_type,
                PERMISSION_PUBLISH_DOCUMENT,
                "publish_document",
                &authority,
                &guard,
            )?;
            self.publish_document_internal(tx, &name, update, true, now)
        })
    }

    pub fn revoke_document(
        &self,
        name: &str,
        doc_type: &str,
        expected_version: u64,
        reason_hash: &str,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<(u64, u64)> {
        self.ensure_write_path("revoke_document")?;
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        validate_hash(reason_hash)?;

        self.store.transact(|tx| {
            let now = now_timestamp();
            let mut name_state = self.required_active_name(tx, &name)?;
            self.authorize_update(
                tx,
                &name_state,
                &doc_type,
                PERMISSION_REVOKE_DOCUMENT,
                "revoke_document",
                &authority,
                &guard,
            )?;

            let current = tx.get_current_document(&name, &doc_type)?;
            let actual_version = current.as_ref().map_or(0, |state| state.version);
            if actual_version != expected_version {
                return Err(BnsRegistryError::StaleDocumentVersion {
                    name: name.clone(),
                    doc_type: doc_type.clone(),
                    expected: expected_version,
                    actual: actual_version,
                });
            }

            let new_version = actual_version + 1;
            let mut document = DocumentState {
                name: name.clone(),
                doc_type: doc_type.clone(),
                version: new_version,
                previous_version: actual_version,
                status: DocumentStatus::Revoked,
                document: DocumentRef::new(ZERO_HASH, "", ZERO_HASH),
                controller: Principal::unset(),
                beneficiary: Principal::unset(),
                payment_target: String::new(),
                valid_from: now,
                expire_at: 0,
                revoked_at: now,
                controller_policy_hash: ZERO_HASH.to_string(),
                payment_policy_hash: ZERO_HASH.to_string(),
                split_policy_hash: ZERO_HASH.to_string(),
                price_policy_hash: ZERO_HASH.to_string(),
                rights_policy_hash: ZERO_HASH.to_string(),
                document_state_hash: ZERO_HASH.to_string(),
            };
            document.document_state_hash = document_state_hash(&document)?;
            tx.put_document(&document)?;

            if doc_type == "owner" {
                name_state.owner_document_version = new_version;
            }

            name_state.name_seq += 1;
            name_state.updated_at = now;
            name_state = self.materialize_name_state(tx, name_state)?;
            tx.put_name(&name_state)?;
            tx.append_event(
                &RegistryEvent::DocumentRevoked {
                    name,
                    doc_type,
                    previous_version: actual_version,
                    new_version,
                    reason_hash: reason_hash.to_string(),
                },
                now,
            )?;
            Ok((new_version, name_state.name_seq))
        })
    }

    pub fn set_min_document_iat(
        &self,
        name: &str,
        min_document_iat: u64,
        reason_hash: &str,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<(u64, u64)> {
        self.ensure_write_path("set_min_document_iat")?;
        let name = canonical_bns_name(name)?;
        validate_hash(reason_hash)?;

        self.store.transact(|tx| {
            let now = now_timestamp();
            let state = self.required_active_name(tx, &name)?;
            self.check_guard(&state, &guard)?;
            self.authorize_owner_for_loaded(tx, &state, &authority)?;
            self.set_min_document_iat_internal(tx, &name, min_document_iat, reason_hash, true, now)
        })
    }

    pub fn set_controller_policy(
        &self,
        name: &str,
        rules: Vec<ControllerRule>,
        policy_hash: &str,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<u64> {
        self.ensure_write_path("set_controller_policy")?;
        let name = canonical_bns_name(name)?;
        validate_hash(policy_hash)?;
        for rule in &rules {
            rule.validate()?;
        }
        self.store.transact(|tx| {
            let now = now_timestamp();
            let mut state = self.required_active_name(tx, &name)?;
            self.check_guard(&state, &guard)?;
            self.authorize_owner_for_loaded(tx, &state, &authority)?;
            for rule in &rules {
                if rule.controller.kind == PrincipalKind::BnsName {
                    self.require_active_authority_set(tx, &rule.controller.value)?;
                }
            }
            tx.put_controller_policy(&name, &rules, policy_hash)?;
            state.name_seq += 1;
            state.updated_at = now;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;
            tx.append_event(
                &RegistryEvent::ControllerPolicyUpdated {
                    name,
                    policy_hash: policy_hash.to_string(),
                    name_seq: state.name_seq,
                },
                now,
            )?;
            Ok(state.name_seq)
        })
    }

    pub fn set_did_alias(
        &self,
        name: &str,
        target_did: &str,
        kind: AliasKind,
        proof_hash: &str,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<u64> {
        self.ensure_write_path("set_did_alias")?;
        let name = canonical_bns_name(name)?;
        if kind != AliasKind::None {
            validate_did(target_did)?;
        }
        validate_hash(proof_hash)?;
        self.store.transact(|tx| {
            let now = now_timestamp();
            let mut state = self.required_active_name(tx, &name)?;
            self.authorize_update(
                tx,
                &state,
                "",
                PERMISSION_SET_ALIAS,
                "set_alias",
                &authority,
                &guard,
            )?;
            state.name_seq += 1;
            state.alias_state_hash = proof_hash.to_string();
            state.updated_at = now;
            state = self.materialize_name_state(tx, state)?;
            tx.put_name(&state)?;
            let alias = AliasState {
                name: name.clone(),
                kind,
                target_did: target_did.to_string(),
                proof_hash: proof_hash.to_string(),
                set_at: now,
                name_seq: state.name_seq,
            };
            tx.put_alias(&alias)?;
            tx.append_event(
                &RegistryEvent::DidAliasSet {
                    name,
                    target_did: target_did.to_string(),
                    kind,
                    proof_hash: proof_hash.to_string(),
                    name_seq: state.name_seq,
                },
                now,
            )?;
            Ok(state.name_seq)
        })
    }

    pub fn set_payment_target(
        &self,
        name: &str,
        doc_type: &str,
        expected_version: u64,
        payment_target: &str,
        beneficiary: Principal,
        payment_policy_hash: &str,
        split_policy_hash: &str,
        price_policy_hash: &str,
        rights_policy_hash: &str,
        authority: CallAuthority,
        guard: MutationGuard,
    ) -> BnsRegistryResult<u64> {
        self.ensure_write_path("set_payment_target")?;
        let name = canonical_bns_name(name)?;
        let doc_type = canonical_doc_type(doc_type)?;
        beneficiary.validate()?;
        validate_hash(payment_policy_hash)?;
        validate_hash(split_policy_hash)?;
        validate_hash(price_policy_hash)?;
        validate_hash(rights_policy_hash)?;
        self.store.transact(|tx| {
            let now = now_timestamp();
            let mut name_state = self.required_active_name(tx, &name)?;
            self.authorize_update(
                tx,
                &name_state,
                &doc_type,
                PERMISSION_SET_PAYMENT,
                "set_payment",
                &authority,
                &guard,
            )?;
            let mut document = tx.get_current_document(&name, &doc_type)?.ok_or_else(|| {
                BnsRegistryError::DocumentNotFound {
                    name: name.clone(),
                    doc_type: doc_type.clone(),
                }
            })?;
            if document.version != expected_version {
                return Err(BnsRegistryError::StaleDocumentVersion {
                    name: name.clone(),
                    doc_type: doc_type.clone(),
                    expected: expected_version,
                    actual: document.version,
                });
            }
            document.payment_target = payment_target.to_string();
            document.beneficiary = beneficiary;
            document.payment_policy_hash = payment_policy_hash.to_string();
            document.split_policy_hash = split_policy_hash.to_string();
            document.price_policy_hash = price_policy_hash.to_string();
            document.rights_policy_hash = rights_policy_hash.to_string();
            document.document_state_hash = document_state_hash(&document)?;
            tx.put_document(&document)?;

            name_state.payment_policy_hash = payment_policy_hash.to_string();
            name_state.name_seq += 1;
            name_state.updated_at = now;
            name_state = self.materialize_name_state(tx, name_state)?;
            tx.put_name(&name_state)?;
            tx.append_event(
                &RegistryEvent::PaymentTargetUpdated {
                    name,
                    doc_type,
                    payment_target: payment_target.to_string(),
                    payment_policy_hash: payment_policy_hash.to_string(),
                    version: document.version,
                },
                now,
            )?;
            Ok(document.version)
        })
    }

    pub fn publish_log_checkpoint(
        &self,
        issuer: Principal,
        external_anchor: &str,
    ) -> BnsRegistryResult<LogCheckpoint> {
        self.ensure_write_path("publish_log_checkpoint")?;
        issuer.validate()?;
        validate_hash(external_anchor)?;
        self.store.transact(|tx| {
            let latest_event = tx.latest_event()?;
            let (last_seq, log_root) = latest_event
                .as_ref()
                .map_or((0, ZERO_HASH.to_string()), |record| {
                    (record.seq, record.log_root.clone())
                });
            let now = now_timestamp();
            let checkpoint = LogCheckpoint {
                log_root: log_root.clone(),
                last_seq,
                issued_at: now,
                issuer,
                external_anchor: external_anchor.to_string(),
            };
            tx.put_checkpoint(&checkpoint)?;
            tx.append_event(
                &RegistryEvent::LogCheckpointPublished {
                    log_root,
                    last_seq,
                    issued_at: now,
                    external_anchor: external_anchor.to_string(),
                },
                now,
            )?;
            Ok(checkpoint)
        })
    }

    pub fn latest_checkpoint(&self) -> BnsRegistryResult<Option<LogCheckpoint>> {
        self.store.transact(|tx| tx.latest_checkpoint())
    }

    pub fn list_events(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> BnsRegistryResult<Vec<EventLogRecord>> {
        self.store.transact(|tx| tx.list_events(from_seq, limit))
    }

    fn apply_authority_updates(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        name: &str,
        updates: Vec<AuthorityKeyUpdate>,
        now: u64,
    ) -> BnsRegistryResult<AuthoritySetState> {
        let mut by_kid: HashMap<String, AuthorityKey> = tx
            .list_authority_keys(name)?
            .into_iter()
            .map(|key| (key.kid.clone(), key))
            .collect();

        for update in updates {
            let mut key = update.key;
            if update.active {
                if key.status == AuthorityKeyStatus::Missing {
                    key.status = AuthorityKeyStatus::Active;
                }
                by_kid.insert(key.kid.clone(), key);
            } else {
                let mut revoked = by_kid.remove(&key.kid).unwrap_or_else(|| key.clone());
                revoked.status = AuthorityKeyStatus::Revoked;
                by_kid.insert(revoked.kid.clone(), revoked);
            }
        }

        let mut keys: Vec<AuthorityKey> = by_kid.into_values().collect();
        keys.sort_by(|left, right| left.kid.cmp(&right.kid));
        let current = tx.get_authority_set(name)?;
        let set = recompute_authority_set(name, current, &keys, now)?;
        if set.active_key_count == 0 && self.name_is_authority_owner(tx, name)? {
            return Err(BnsRegistryError::NoConcreteSigner);
        }

        for key in &keys {
            tx.put_authority_key(name, key)?;
        }
        tx.put_authority_set(&set)?;
        tx.append_event(
            &RegistryEvent::AuthorityKeysUpdated {
                name: name.to_string(),
                authority_seq: set.authority_seq,
                authority_root: set.authority_root.clone(),
            },
            now,
        )?;
        Ok(set)
    }

    fn publish_document_internal(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        name: &str,
        update: DocumentUpdate,
        bump_name_seq: bool,
        now: u64,
    ) -> BnsRegistryResult<u64> {
        let current = tx.get_current_document(name, &update.doc_type)?;
        let actual_version = current.as_ref().map_or(0, |state| state.version);
        if actual_version != update.expected_version {
            return Err(BnsRegistryError::StaleDocumentVersion {
                name: name.to_string(),
                doc_type: update.doc_type.clone(),
                expected: update.expected_version,
                actual: actual_version,
            });
        }

        let version = actual_version + 1;
        let mut document = DocumentState {
            name: name.to_string(),
            doc_type: update.doc_type.clone(),
            version,
            previous_version: actual_version,
            status: DocumentStatus::Active,
            document: update.document,
            controller: update.controller,
            beneficiary: update.beneficiary,
            payment_target: update.payment_target,
            valid_from: now,
            expire_at: update.expire_at,
            revoked_at: 0,
            controller_policy_hash: update.controller_policy_hash,
            payment_policy_hash: update.payment_policy_hash,
            split_policy_hash: update.split_policy_hash,
            price_policy_hash: update.price_policy_hash,
            rights_policy_hash: update.rights_policy_hash,
            document_state_hash: ZERO_HASH.to_string(),
        };
        document.document_state_hash = document_state_hash(&document)?;
        tx.put_document(&document)?;

        let mut name_state = self.required_active_name(tx, name)?;
        if document.doc_type == "owner" {
            name_state.owner_document_version = document.version;
        }
        if bump_name_seq {
            name_state.name_seq += 1;
        }
        name_state.updated_at = now;
        name_state = self.materialize_name_state(tx, name_state)?;
        tx.put_name(&name_state)?;

        tx.append_event(
            &RegistryEvent::DocumentPublished {
                name: name.to_string(),
                doc_type: document.doc_type,
                version: document.version,
                content_hash: document.document.content_hash,
                document_state_hash: document.document_state_hash,
            },
            now,
        )?;
        Ok(version)
    }

    fn set_min_document_iat_internal(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        name: &str,
        min_document_iat: u64,
        reason_hash: &str,
        bump_name_seq: bool,
        now: u64,
    ) -> BnsRegistryResult<(u64, u64)> {
        let mut state = self.required_active_name(tx, name)?;
        if min_document_iat < state.min_document_iat {
            return Err(BnsRegistryError::InvalidMutation(
                "min_document_iat cannot decrease".to_string(),
            ));
        }
        let previous_min_document_iat = state.min_document_iat;
        if bump_name_seq {
            state.name_seq += 1;
        }
        state.min_document_iat = min_document_iat;
        state.owner_policy_seq += 1;
        state.updated_at = now;
        state = self.materialize_name_state(tx, state)?;
        tx.put_name(&state)?;
        tx.append_event(
            &RegistryEvent::OwnerDocumentIatFloorUpdated {
                name: name.to_string(),
                previous_min_document_iat,
                new_min_document_iat: min_document_iat,
                owner_policy_seq: state.owner_policy_seq,
                name_seq: state.name_seq,
                reason_hash: reason_hash.to_string(),
            },
            now,
        )?;
        Ok((state.name_seq, state.owner_policy_seq))
    }

    fn authorize_update(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        state: &NameState,
        doc_type: &str,
        permission: u32,
        operation: &'static str,
        authority: &CallAuthority,
        guard: &MutationGuard,
    ) -> BnsRegistryResult<()> {
        self.check_guard(state, guard)?;
        match authority.role {
            AuthorityRole::Owner => self.authorize_owner_for_loaded(tx, state, authority),
            AuthorityRole::Controller => {
                let now = now_timestamp();
                authority.actor.validate()?;
                if authority.actor.kind == PrincipalKind::BnsName {
                    self.validate_actor_key(tx, &authority.actor, &authority.kid, now)?;
                }
                let rules = tx.get_controller_policy(&state.name)?;
                if rules
                    .iter()
                    .any(|rule| rule.permits(&authority.actor, doc_type, permission, now))
                {
                    Ok(())
                } else {
                    Err(BnsRegistryError::ControllerScopeDenied {
                        name: state.name.clone(),
                        doc_type: doc_type.to_string(),
                        operation,
                    })
                }
            }
            AuthorityRole::None => Err(BnsRegistryError::NotEffectiveOwner {
                name: state.name.clone(),
            }),
        }
    }

    fn authorize_update_no_guard(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        state: &NameState,
        doc_type: &str,
        permission: u32,
        operation: &'static str,
        authority: &CallAuthority,
    ) -> BnsRegistryResult<()> {
        match authority.role {
            AuthorityRole::Owner => self.authorize_owner_for_loaded(tx, state, authority),
            AuthorityRole::Controller => {
                let now = now_timestamp();
                authority.actor.validate()?;
                if authority.actor.kind == PrincipalKind::BnsName {
                    self.validate_actor_key(tx, &authority.actor, &authority.kid, now)?;
                }
                let rules = tx.get_controller_policy(&state.name)?;
                if rules
                    .iter()
                    .any(|rule| rule.permits(&authority.actor, doc_type, permission, now))
                {
                    Ok(())
                } else {
                    Err(BnsRegistryError::ControllerScopeDenied {
                        name: state.name.clone(),
                        doc_type: doc_type.to_string(),
                        operation,
                    })
                }
            }
            AuthorityRole::None => Err(BnsRegistryError::NotEffectiveOwner {
                name: state.name.clone(),
            }),
        }
    }

    fn authorize_owner_for_loaded(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        state: &NameState,
        authority: &CallAuthority,
    ) -> BnsRegistryResult<()> {
        if authority.role != AuthorityRole::Owner {
            return Err(BnsRegistryError::NotEffectiveOwner {
                name: state.name.clone(),
            });
        }
        authority.actor.validate()?;
        let owner = self.resolve_owner_for_name(tx, &state.name)?;
        if authority.actor != owner.effective_owner {
            return Err(BnsRegistryError::NotEffectiveOwner {
                name: state.name.clone(),
            });
        }
        self.validate_actor_key(tx, &authority.actor, &authority.kid, now_timestamp())
    }

    fn validate_actor_key(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        actor: &Principal,
        kid: &str,
        now: u64,
    ) -> BnsRegistryResult<()> {
        match actor.kind {
            PrincipalKind::Unset => Err(BnsRegistryError::invalid_principal(
                "",
                "unset actor cannot authorize calls",
            )),
            PrincipalKind::ChainAccount => Ok(()),
            PrincipalKind::BnsName => {
                let key = tx
                    .get_authority_key(&actor.value, kid)?
                    .ok_or_else(|| BnsRegistryError::invalid_kid(kid, "authority key not found"))?;
                if key.is_active_for(KEY_PURPOSE_AUTHENTICATION, now) {
                    Ok(())
                } else {
                    Err(BnsRegistryError::invalid_kid(
                        kid,
                        "authority key is not active for authentication",
                    ))
                }
            }
        }
    }

    fn check_guard(&self, state: &NameState, guard: &MutationGuard) -> BnsRegistryResult<()> {
        if guard.expected_name_seq != state.name_seq {
            return Err(BnsRegistryError::StaleNameSeq {
                name: state.name.clone(),
                expected: guard.expected_name_seq,
                actual: state.name_seq,
            });
        }
        Ok(())
    }

    fn required_raw_name(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        name: &str,
    ) -> BnsRegistryResult<NameState> {
        tx.get_name(name)?
            .ok_or_else(|| BnsRegistryError::NameNotFound {
                name: name.to_string(),
            })
    }

    fn required_active_name(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        name: &str,
    ) -> BnsRegistryResult<NameState> {
        let state = self.required_raw_name(tx, name)?;
        self.ensure_active_name(&state)?;
        self.materialize_name_state(tx, state)
    }

    fn ensure_active_name(&self, state: &NameState) -> BnsRegistryResult<()> {
        if state.status == NameStatus::Active {
            Ok(())
        } else {
            Err(BnsRegistryError::InvalidMutation(format!(
                "name `{}` is not active: {}",
                state.name, state.status
            )))
        }
    }

    fn load_materialized_name(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        name: &str,
    ) -> BnsRegistryResult<Option<NameState>> {
        tx.get_name(name)?
            .map(|state| self.materialize_name_state(tx, state))
            .transpose()
    }

    fn materialize_name_state(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        mut state: NameState,
    ) -> BnsRegistryResult<NameState> {
        let owner = self.resolve_owner_from_state(tx, &state)?;
        state.effective_owner = owner.effective_owner;
        state.owner_source = owner.source;
        state.standard_transfer_enabled = state.transferable
            && state.status == NameStatus::Active
            && owner.source == OwnerSource::AssetOwnerFallback;
        Ok(state)
    }

    fn resolve_owner_for_name(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        name: &str,
    ) -> BnsRegistryResult<OwnerResolution> {
        let state = tx
            .get_name(name)?
            .ok_or_else(|| BnsRegistryError::NameNotFound {
                name: name.to_string(),
            })?;
        self.resolve_owner_from_state(tx, &state)
    }

    fn resolve_owner_from_state(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        state: &NameState,
    ) -> BnsRegistryResult<OwnerResolution> {
        if state.semantic_owner.kind == PrincipalKind::BnsName {
            let authority = if state.status == NameStatus::Active {
                self.require_active_authority_set(tx, &state.semantic_owner.value)?
            } else {
                self.authority_set(tx, &state.semantic_owner.value)?
            };
            return Ok(OwnerResolution {
                effective_owner: state.semantic_owner.clone(),
                source: OwnerSource::ExplicitSemanticOwner,
                authority_root: authority.authority_root,
                authority_seq: authority.authority_seq,
            });
        }

        if is_top_level_name(&state.name) {
            let authority = self.authority_set(tx, &state.name)?;
            Ok(OwnerResolution {
                effective_owner: Principal::chain_account(state.asset_owner.clone()),
                source: OwnerSource::AssetOwnerFallback,
                authority_root: authority.authority_root,
                authority_seq: authority.authority_seq,
            })
        } else {
            let parent = parent_name(&state.name).ok_or_else(|| {
                BnsRegistryError::InvalidMutation("second-level name has no parent".to_string())
            })?;
            let mut owner = if state.status == NameStatus::Active {
                let parent_state = self.load_materialized_name(tx, parent)?.ok_or_else(|| {
                    BnsRegistryError::NameNotFound {
                        name: parent.to_string(),
                    }
                })?;
                self.ensure_active_name(&parent_state)?;
                self.resolve_owner_from_state(tx, &parent_state)?
            } else {
                self.resolve_owner_for_name(tx, parent)?
            };
            owner.source = OwnerSource::ParentInherited;
            Ok(owner)
        }
    }

    fn authority_set(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        name: &str,
    ) -> BnsRegistryResult<AuthoritySetState> {
        Ok(tx
            .get_authority_set(name)?
            .unwrap_or_else(|| AuthoritySetState::empty(name)))
    }

    fn validate_semantic_owner_target(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        owner: &Principal,
    ) -> BnsRegistryResult<()> {
        validate_semantic_owner(owner)?;
        if owner.kind == PrincipalKind::BnsName {
            self.require_active_authority_set(tx, &owner.value)?;
        }
        Ok(())
    }

    fn require_active_authority_set(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        name: &str,
    ) -> BnsRegistryResult<AuthoritySetState> {
        let state = tx
            .get_name(name)?
            .ok_or_else(|| BnsRegistryError::NameNotFound {
                name: name.to_string(),
            })?;
        if state.status != NameStatus::Active {
            return Err(BnsRegistryError::NoConcreteSigner);
        }
        let set = self.authority_set(tx, name)?;
        if set.active_key_count == 0 {
            return Err(BnsRegistryError::NoConcreteSigner);
        }
        Ok(set)
    }

    fn current_proof_root(&self, tx: &mut dyn BnsRegistryStoreTx) -> BnsRegistryResult<String> {
        Ok(tx
            .latest_event()?
            .map_or_else(|| ZERO_HASH.to_string(), |record| record.log_root))
    }

    fn ensure_document_consistent(
        &self,
        name: &str,
        doc_type: &str,
        document: &DocumentState,
        effective_owner: &Principal,
    ) -> BnsRegistryResult<()> {
        let assertions = document_owner_assertions(doc_type, document).map_err(|reason| {
            BnsRegistryError::DocumentInconsistent {
                name: name.to_string(),
                doc_type: doc_type.to_string(),
                reason,
            }
        })?;

        for assertion in assertions {
            if !principals_match(&assertion.principal, effective_owner) {
                return Err(BnsRegistryError::DocumentInconsistent {
                    name: name.to_string(),
                    doc_type: doc_type.to_string(),
                    reason: format!(
                        "{} declares {} `{}` but on-chain effective owner is `{}`",
                        assertion.document_label,
                        assertion.field,
                        principal_display(&assertion.principal),
                        principal_display(effective_owner)
                    ),
                });
            }
        }

        Ok(())
    }

    fn name_is_authority_owner(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        authority_name: &str,
    ) -> BnsRegistryResult<bool> {
        for state in tx.list_names()? {
            if state.status == NameStatus::Active
                && state.semantic_owner.kind == PrincipalKind::BnsName
                && state.semantic_owner.value == authority_name
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn validate_owner_graph_with(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        changed: Option<&NameState>,
    ) -> BnsRegistryResult<()> {
        let mut names: HashMap<String, NameState> = tx
            .list_names()?
            .into_iter()
            .map(|state| (state.name.clone(), state))
            .collect();
        if let Some(state) = changed {
            names.insert(state.name.clone(), state.clone());
        }

        for state in names.values() {
            if state.status == NameStatus::Active {
                self.validate_owner_path(tx, &names, &state.name)?;
            }
        }
        Ok(())
    }

    fn validate_owner_path(
        &self,
        tx: &mut dyn BnsRegistryStoreTx,
        names: &HashMap<String, NameState>,
        start: &str,
    ) -> BnsRegistryResult<()> {
        let mut current = start.to_string();
        let mut visited = HashSet::new();
        let mut concrete = false;

        for depth in 0..=MAX_OWNER_REF_DEPTH {
            if !visited.insert(current.clone()) {
                return Err(BnsRegistryError::OwnerGraphCycle);
            }
            let state = names
                .get(&current)
                .ok_or_else(|| BnsRegistryError::NameNotFound {
                    name: current.clone(),
                })?;
            if state.status != NameStatus::Active {
                return Err(BnsRegistryError::NoConcreteSigner);
            }

            if state.semantic_owner.kind == PrincipalKind::BnsName {
                let owner_name = state.semantic_owner.value.clone();
                let authority = self.authority_set(tx, &owner_name)?;
                if owner_name == current {
                    if authority.active_key_count > 0 {
                        concrete = true;
                        break;
                    }
                    return Err(BnsRegistryError::NoConcreteSigner);
                }
                if authority.active_key_count > 0 {
                    concrete = true;
                }
                current = owner_name;
            } else if is_top_level_name(&state.name) {
                concrete = !state.asset_owner.is_empty();
                break;
            } else {
                current = parent_name(&state.name)
                    .ok_or(BnsRegistryError::NoConcreteSigner)?
                    .to_string();
            }

            if depth == MAX_OWNER_REF_DEPTH {
                return Err(BnsRegistryError::OwnerGraphTooDeep {
                    max_depth: MAX_OWNER_REF_DEPTH,
                });
            }
        }

        if concrete {
            Ok(())
        } else {
            Err(BnsRegistryError::NoConcreteSigner)
        }
    }
}

fn missing_document_state(name: &str, doc_type: &str) -> DocumentState {
    DocumentState {
        name: name.to_string(),
        doc_type: doc_type.to_string(),
        version: 0,
        previous_version: 0,
        status: DocumentStatus::Missing,
        document: DocumentRef::new(ZERO_HASH, "", ZERO_HASH),
        controller: Principal::unset(),
        beneficiary: Principal::unset(),
        payment_target: String::new(),
        valid_from: 0,
        expire_at: 0,
        revoked_at: 0,
        controller_policy_hash: ZERO_HASH.to_string(),
        payment_policy_hash: ZERO_HASH.to_string(),
        split_policy_hash: ZERO_HASH.to_string(),
        price_policy_hash: ZERO_HASH.to_string(),
        rights_policy_hash: ZERO_HASH.to_string(),
        document_state_hash: ZERO_HASH.to_string(),
    }
}

#[derive(Clone, Copy)]
enum DocumentAssertionSchema {
    Owner,
    Did,
}

struct DocumentOwnerAssertion {
    document_label: &'static str,
    field: &'static str,
    principal: Principal,
}

fn document_owner_assertions(
    doc_type: &str,
    document: &DocumentState,
) -> Result<Vec<DocumentOwnerAssertion>, String> {
    let Some(schema) = document_assertion_schema(doc_type) else {
        return Ok(Vec::new());
    };
    if document.document.storage_type != STORAGE_TYPE_INLINE
        || document.document.inline_document.is_empty()
    {
        return Ok(Vec::new());
    }

    let value = match serde_json::from_slice::<Value>(&document.document.inline_document) {
        Ok(value) => value,
        Err(_) => return Ok(Vec::new()),
    };
    if !value.is_object() {
        return Ok(Vec::new());
    }

    let mut assertions = Vec::new();
    match schema {
        DocumentAssertionSchema::Owner => {
            collect_principal_assertions(
                &mut assertions,
                "owner document",
                "owner",
                value.get("owner"),
            )?;
            collect_principal_assertions(
                &mut assertions,
                "owner document",
                "controller",
                value.get("controller"),
            )?;
        }
        DocumentAssertionSchema::Did => {
            collect_principal_assertions(
                &mut assertions,
                "DID document",
                "controller",
                value.get("controller"),
            )?;
            collect_did_verification_method_controllers(&mut assertions, &value)?;
        }
    }

    Ok(assertions)
}

fn document_assertion_schema(doc_type: &str) -> Option<DocumentAssertionSchema> {
    match doc_type {
        "owner" => Some(DocumentAssertionSchema::Owner),
        "did" | "doc" => Some(DocumentAssertionSchema::Did),
        _ => None,
    }
}

fn collect_did_verification_method_controllers(
    assertions: &mut Vec<DocumentOwnerAssertion>,
    value: &Value,
) -> Result<(), String> {
    let Some(methods) = value.get("verificationMethod") else {
        return Ok(());
    };

    match methods {
        Value::Array(items) => {
            for item in items {
                collect_principal_assertions(
                    assertions,
                    "DID document",
                    "verificationMethod.controller",
                    item.get("controller"),
                )?;
            }
        }
        Value::Object(_) => {
            collect_principal_assertions(
                assertions,
                "DID document",
                "verificationMethod.controller",
                methods.get("controller"),
            )?;
        }
        _ => {}
    }

    Ok(())
}

fn collect_principal_assertions(
    assertions: &mut Vec<DocumentOwnerAssertion>,
    document_label: &'static str,
    field: &'static str,
    value: Option<&Value>,
) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    collect_principal_assertion_value(assertions, document_label, field, value)
}

fn collect_principal_assertion_value(
    assertions: &mut Vec<DocumentOwnerAssertion>,
    document_label: &'static str,
    field: &'static str,
    value: &Value,
) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::Array(items) => {
            for item in items {
                collect_principal_assertion_value(assertions, document_label, field, item)?;
            }
            Ok(())
        }
        Value::String(raw) => {
            let principal = principal_from_document_string(raw).map_err(|reason| {
                format!("{document_label} declares {field} `{raw}` but {reason}")
            })?;
            assertions.push(DocumentOwnerAssertion {
                document_label,
                field,
                principal,
            });
            Ok(())
        }
        Value::Object(_) => {
            let principal = principal_from_document_object(value).map_err(|reason| {
                format!("{document_label} declares {field} object but {reason}")
            })?;
            assertions.push(DocumentOwnerAssertion {
                document_label,
                field,
                principal,
            });
            Ok(())
        }
        other => Err(format!(
            "{document_label} declares {field} with unsupported JSON {}",
            json_type_name(other)
        )),
    }
}

fn principal_from_document_object(value: &Value) -> Result<Principal, String> {
    let principal = serde_json::from_value::<Principal>(value.clone())
        .map_err(|err| format!("it is not a Principal object: {err}"))?;
    canonicalize_document_principal(principal)
}

fn principal_from_document_string(raw: &str) -> Result<Principal, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("principal is empty".to_string());
    }

    if let Some(name) = value.strip_prefix("did:bns:") {
        return Principal::bns_name(name).map_err(|err| err.to_string());
    }
    if let Some(account) = normalize_prefixed_evm_address(value) {
        return Ok(Principal::chain_account(account));
    }

    Principal::bns_name(value).map_err(|_| {
        "expected did:bns:<name>, a BNS name, a 0x-prefixed EVM address, or a Principal object"
            .to_string()
    })
}

fn canonicalize_document_principal(principal: Principal) -> Result<Principal, String> {
    match principal.kind {
        PrincipalKind::Unset => {
            principal.validate().map_err(|err| err.to_string())?;
            Ok(Principal::unset())
        }
        PrincipalKind::ChainAccount => {
            principal.validate().map_err(|err| err.to_string())?;
            Ok(Principal::chain_account(
                normalize_prefixed_evm_address(&principal.value).unwrap_or(principal.value),
            ))
        }
        PrincipalKind::BnsName => {
            Principal::bns_name(&principal.value).map_err(|err| err.to_string())
        }
    }
}

fn principals_match(left: &Principal, right: &Principal) -> bool {
    if left.kind != right.kind {
        return false;
    }

    match left.kind {
        PrincipalKind::Unset => left.value == right.value,
        PrincipalKind::BnsName => left.value == right.value,
        PrincipalKind::ChainAccount => {
            let left =
                normalize_prefixed_evm_address(&left.value).unwrap_or_else(|| left.value.clone());
            let right =
                normalize_prefixed_evm_address(&right.value).unwrap_or_else(|| right.value.clone());
            left.eq_ignore_ascii_case(&right)
        }
    }
}

fn normalize_prefixed_evm_address(value: &str) -> Option<String> {
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    if hex.len() == 40 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(format!("0x{}", hex.to_ascii_lowercase()))
    } else {
        None
    }
}

fn principal_display(principal: &Principal) -> String {
    match principal.kind {
        PrincipalKind::Unset => "unset".to_string(),
        PrincipalKind::ChainAccount => principal.value.clone(),
        PrincipalKind::BnsName => format!("did:bns:{}", principal.value),
    }
}

fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
