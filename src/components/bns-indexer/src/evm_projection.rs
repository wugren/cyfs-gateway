use std::collections::VecDeque;

use bns_evm::{
    decode_bns_event, AliasKind as EvmAliasKind, BnsEvent, EthLog, OwnerSource as EvmOwnerSource,
    PrincipalKind as EvmPrincipalKind, ReleaseMode as EvmReleaseMode,
};

use crate::{
    hash_json, sha256_hex, AliasKind, BnsRegistryError, BnsRegistryResult, BnsRegistryStore,
    EventLogRecord, LogCheckpoint, OwnerSource, Principal, RegistryEvent, ReleaseMode, ZERO_HASH,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractProtocolEvent {
    pub seq: u64,
    pub event_type_hash: String,
    pub actor: String,
    pub previous_log_root: String,
    pub log_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectedContractEvent {
    Protocol(ContractProtocolEvent),
    Registry(EventLogRecord),
}

#[derive(Debug, Default)]
pub struct ContractEventProjector {
    pending_protocol: VecDeque<ContractProtocolEvent>,
}

impl ContractEventProjector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pending_protocol_len(&self) -> usize {
        self.pending_protocol.len()
    }

    pub fn project_log(
        &mut self,
        log: &EthLog,
        observed_at: u64,
    ) -> BnsRegistryResult<ProjectedContractEvent> {
        let decoded = decode_bns_event(&log.as_alloy_log())
            .map_err(|err| BnsRegistryError::InvalidMutation(err.to_string()))?;
        self.project_event(decoded.data, observed_at)
    }

    pub fn project_event(
        &mut self,
        event: BnsEvent,
        observed_at: u64,
    ) -> BnsRegistryResult<ProjectedContractEvent> {
        match event {
            BnsEvent::ProtocolEvent(event) => {
                let protocol = ContractProtocolEvent {
                    seq: event.seq,
                    event_type_hash: hash_string(event.eventType),
                    actor: address_string(event.actor),
                    previous_log_root: hash_string(event.previousLogRoot),
                    log_root: hash_string(event.logRoot),
                };
                self.pending_protocol.push_back(protocol.clone());
                Ok(ProjectedContractEvent::Protocol(protocol))
            }
            other => {
                let registry_event = registry_event_from_contract_event(other)?;
                let protocol = self.pending_protocol.pop_front().ok_or_else(|| {
                    BnsRegistryError::InvalidMutation(format!(
                        "contract event `{}` has no preceding ProtocolEvent",
                        registry_event.event_type()
                    ))
                })?;
                let event_hash = hash_json(&(
                    protocol.seq,
                    &protocol.event_type_hash,
                    &protocol.previous_log_root,
                    &protocol.log_root,
                    &registry_event,
                ))?;
                Ok(ProjectedContractEvent::Registry(EventLogRecord {
                    seq: protocol.seq,
                    event_type: registry_event.event_type().to_string(),
                    observed_at,
                    event_hash,
                    previous_log_root: protocol.previous_log_root,
                    log_root: protocol.log_root,
                    event: registry_event,
                }))
            }
        }
    }
}

pub fn store_event_record<S: BnsRegistryStore>(
    store: &S,
    record: &EventLogRecord,
) -> BnsRegistryResult<()> {
    store.transact(|tx| tx.put_event_record(record))
}

pub fn checkpoint_from_event(record: &EventLogRecord) -> Option<LogCheckpoint> {
    match &record.event {
        RegistryEvent::LogCheckpointPublished {
            log_root,
            last_seq,
            issued_at,
            external_anchor,
        } => Some(LogCheckpoint {
            log_root: log_root.clone(),
            last_seq: *last_seq,
            issued_at: *issued_at,
            issuer: Principal::unset(),
            external_anchor: external_anchor.clone(),
        }),
        _ => None,
    }
}

fn registry_event_from_contract_event(event: BnsEvent) -> BnsRegistryResult<RegistryEvent> {
    match event {
        BnsEvent::ProtocolEvent(_) => Err(BnsRegistryError::InvalidMutation(
            "ProtocolEvent cannot be projected as a registry event".to_string(),
        )),
        BnsEvent::NameRegistered(event) => Ok(RegistryEvent::NameRegistered {
            name: event.name,
            asset_owner: address_string(event.assetOwner),
            expire_at: event.expireAt,
            lineage_epoch: event.lineageEpoch,
            name_seq: event.nameSeq,
        }),
        BnsEvent::NameRenewed(event) => Ok(RegistryEvent::NameRenewed {
            name: event.name,
            expire_at: event.expireAt,
            name_seq: event.nameSeq,
        }),
        BnsEvent::NameAssetTransferred(event) => Ok(RegistryEvent::NameAssetTransferred {
            name: event.name,
            old_asset_owner: address_string(event.oldAssetOwner),
            new_asset_owner: address_string(event.newAssetOwner),
            standard_transfer: event.standardTransfer,
            name_seq: event.nameSeq,
        }),
        BnsEvent::NameOwnerUpdated(event) => Ok(RegistryEvent::NameOwnerUpdated {
            name: event.name,
            owner: principal_from_contract(event.ownerKind, event.ownerValue)?,
            owner_source: owner_source_from_contract(event.ownerSource)?,
            standard_transfer_enabled: event.standardTransferEnabled,
            name_seq: event.nameSeq,
        }),
        BnsEvent::AuthorityKeysUpdated(event) => Ok(RegistryEvent::AuthorityKeysUpdated {
            name: event.name,
            authority_seq: event.authoritySeq,
            authority_root: hash_string(event.authorityRoot),
        }),
        BnsEvent::NameReleased(event) => Ok(RegistryEvent::NameReleased {
            name: event.name,
            mode: release_mode_from_contract(event.mode)?,
            reason_hash: hash_string(event.reasonHash),
            name_seq: event.nameSeq,
        }),
        BnsEvent::DocumentPublished(event) => Ok(RegistryEvent::DocumentPublished {
            name: event.name,
            doc_type: event.docType,
            version: event.version,
            content_hash: hash_string(event.contentHash),
            document_state_hash: hash_string(event.documentStateHash),
        }),
        BnsEvent::DocumentRevoked(event) => Ok(RegistryEvent::DocumentRevoked {
            name: event.name,
            doc_type: event.docType,
            previous_version: event.previousVersion,
            new_version: event.newVersion,
            reason_hash: hash_string(event.reasonHash),
        }),
        BnsEvent::OwnerDocumentIatFloorUpdated(event) => {
            Ok(RegistryEvent::OwnerDocumentIatFloorUpdated {
                name: event.name,
                previous_min_document_iat: event.previousMinDocumentIat,
                new_min_document_iat: event.newMinDocumentIat,
                owner_policy_seq: event.ownerPolicySeq,
                name_seq: event.nameSeq,
                reason_hash: hash_string(event.reasonHash),
            })
        }
        BnsEvent::ControllerPolicyUpdated(event) => Ok(RegistryEvent::ControllerPolicyUpdated {
            name: event.name,
            policy_hash: hash_string(event.policyHash),
            name_seq: event.nameSeq,
        }),
        BnsEvent::NamespacePolicyUpdated(event) => Ok(RegistryEvent::NamespacePolicyUpdated {
            name: event.name,
            allow_delegated_subnames: event.allowDelegatedSubnames,
            namespace_policy_hash: hash_string(event.namespacePolicyHash),
            name_seq: event.nameSeq,
        }),
        BnsEvent::DidAliasSet(event) => Ok(RegistryEvent::DidAliasSet {
            name: event.name,
            target_did: event.targetDid,
            kind: alias_kind_from_contract(event.kind)?,
            proof_hash: hash_string(event.proofHash),
            name_seq: event.nameSeq,
        }),
        BnsEvent::PaymentTargetUpdated(event) => Ok(RegistryEvent::PaymentTargetUpdated {
            name: event.name,
            doc_type: event.docType,
            payment_target: address_string(event.paymentTarget),
            payment_policy_hash: hash_string(event.paymentPolicyHash),
            version: event.version,
        }),
        BnsEvent::LogCheckpointPublished(event) => Ok(RegistryEvent::LogCheckpointPublished {
            log_root: hash_string(event.logRoot),
            last_seq: event.lastSeq,
            issued_at: event.issuedAt,
            external_anchor: hash_string(event.externalAnchor),
        }),
    }
}

fn principal_from_contract(
    kind: EvmPrincipalKind,
    value: bns_evm::Bytes,
) -> BnsRegistryResult<Principal> {
    match kind {
        EvmPrincipalKind::Unset => {
            if !value.is_empty() {
                return Err(BnsRegistryError::InvalidMutation(
                    "unset contract principal has non-empty value".to_string(),
                ));
            }
            Ok(Principal::unset())
        }
        EvmPrincipalKind::ChainAccount => {
            if value.len() != 20 && value.len() != 32 {
                return Err(BnsRegistryError::InvalidMutation(format!(
                    "chain account principal has {} bytes",
                    value.len()
                )));
            }
            let address_bytes = if value.len() == 20 {
                value.as_ref()
            } else {
                &value.as_ref()[12..]
            };
            Ok(Principal::chain_account(format!(
                "0x{}",
                hex::encode(address_bytes)
            )))
        }
        EvmPrincipalKind::BnsName => {
            let name = String::from_utf8(value.to_vec()).map_err(|err| {
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

fn owner_source_from_contract(value: EvmOwnerSource) -> BnsRegistryResult<OwnerSource> {
    match value {
        EvmOwnerSource::None => Ok(OwnerSource::None),
        EvmOwnerSource::AssetOwnerFallback => Ok(OwnerSource::AssetOwnerFallback),
        EvmOwnerSource::ExplicitSemanticOwner => Ok(OwnerSource::ExplicitSemanticOwner),
        EvmOwnerSource::ParentInherited => Ok(OwnerSource::ParentInherited),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract owner source".to_string(),
        )),
    }
}

fn release_mode_from_contract(value: EvmReleaseMode) -> BnsRegistryResult<ReleaseMode> {
    match value {
        EvmReleaseMode::ReleaseAfterGrace => Ok(ReleaseMode::ReleaseAfterGrace),
        EvmReleaseMode::TombstoneForever => Ok(ReleaseMode::TombstoneForever),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract release mode".to_string(),
        )),
    }
}

fn alias_kind_from_contract(value: EvmAliasKind) -> BnsRegistryResult<AliasKind> {
    match value {
        EvmAliasKind::None => Ok(AliasKind::None),
        EvmAliasKind::Alias => Ok(AliasKind::Alias),
        EvmAliasKind::MigratedTo => Ok(AliasKind::MigratedTo),
        EvmAliasKind::Canonical => Ok(AliasKind::Canonical),
        _ => Err(BnsRegistryError::InvalidMutation(
            "unknown contract alias kind".to_string(),
        )),
    }
}

fn address_string(address: bns_evm::Address) -> String {
    format!("{address:#x}")
}

fn hash_string(hash: bns_evm::B256) -> String {
    format!("{hash:#x}")
}

#[allow(dead_code)]
fn empty_event_record(seq: u64, event: RegistryEvent) -> EventLogRecord {
    EventLogRecord {
        seq,
        event_type: event.event_type().to_string(),
        observed_at: 0,
        event_hash: sha256_hex(event.event_type().as_bytes()),
        previous_log_root: ZERO_HASH.to_string(),
        log_root: ZERO_HASH.to_string(),
        event,
    }
}
