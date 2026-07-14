use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{BnsRegistryError, BnsRegistryResult};

macro_rules! string_enum {
    ($ty:ident { $($variant:ident => $value:literal),+ $(,)? }) => {
        impl $ty {
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $value,)+
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl FromStr for $ty {
            type Err = BnsRegistryError;

            fn from_str(value: &str) -> BnsRegistryResult<Self> {
                match value {
                    $($value => Ok(Self::$variant),)+
                    _ => Err(BnsRegistryError::InvalidMutation(format!(
                        "unknown {} value `{}`",
                        stringify!($ty),
                        value
                    ))),
                }
            }
        }
    };
}

pub const DID_BNS_PREFIX: &str = "did:bns:";
pub const STORAGE_TYPE_INLINE: &str = "inline";
pub const ZERO_HASH: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
pub const MAX_BNS_NAME_LEN: usize = 253;
pub const MAX_BNS_LABEL_LEN: usize = 126;
pub const MAX_INLINE_DOCUMENT: usize = 4 * 1024;
pub const MAX_OWNER_REF_DEPTH: usize = 8;

pub const KEY_PURPOSE_AUTHENTICATION: u32 = 1 << 0;
pub const KEY_PURPOSE_RECOVERY: u32 = 1 << 1;
pub const KEY_PURPOSE_SIGN_DOCUMENT: u32 = 1 << 2;

pub const PERMISSION_PUBLISH_DOCUMENT: u32 = 1 << 0;
pub const PERMISSION_REVOKE_DOCUMENT: u32 = 1 << 1;
pub const PERMISSION_SET_PAYMENT: u32 = 1 << 2;
pub const PERMISSION_SET_ALIAS: u32 = 1 << 3;
pub const PERMISSION_SET_NAMESPACE: u32 = 1 << 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameStatus {
    Available,
    Active,
    Expired,
    Released,
    Tombstoned,
}

string_enum!(NameStatus {
    Available => "available",
    Active => "active",
    Expired => "expired",
    Released => "released",
    Tombstoned => "tombstoned",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentStatus {
    Missing,
    Active,
    Revoked,
    Expired,
    Migrated,
    Tombstoned,
}

string_enum!(DocumentStatus {
    Missing => "missing",
    Active => "active",
    Revoked => "revoked",
    Expired => "expired",
    Migrated => "migrated",
    Tombstoned => "tombstoned",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AliasKind {
    None,
    Alias,
    MigratedTo,
    Canonical,
}

string_enum!(AliasKind {
    None => "none",
    Alias => "alias",
    MigratedTo => "migrated_to",
    Canonical => "canonical",
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseMode {
    ReleaseAfterGrace,
    TombstoneForever,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Unset,
    ChainAccount,
    BnsName,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnerSource {
    None,
    AssetOwnerFallback,
    ExplicitSemanticOwner,
    ParentInherited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityRole {
    None,
    Owner,
    Controller,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityKeyStatus {
    Missing,
    Active,
    Revoked,
    Expired,
}

string_enum!(AuthorityKeyStatus {
    Missing => "missing",
    Active => "active",
    Revoked => "revoked",
    Expired => "expired",
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub kind: PrincipalKind,
    pub value: String,
}

impl Principal {
    pub fn unset() -> Self {
        Self {
            kind: PrincipalKind::Unset,
            value: String::new(),
        }
    }

    pub fn chain_account(value: impl Into<String>) -> Self {
        Self {
            kind: PrincipalKind::ChainAccount,
            value: value.into(),
        }
    }

    pub fn bns_name(value: impl AsRef<str>) -> BnsRegistryResult<Self> {
        Ok(Self {
            kind: PrincipalKind::BnsName,
            value: canonical_bns_name(value.as_ref())?,
        })
    }

    pub fn is_unset(&self) -> bool {
        self.kind == PrincipalKind::Unset
    }

    pub fn validate(&self) -> BnsRegistryResult<()> {
        match self.kind {
            PrincipalKind::Unset => {
                if !self.value.is_empty() {
                    return Err(BnsRegistryError::invalid_principal(
                        &self.value,
                        "unset principal must have empty value",
                    ));
                }
            }
            PrincipalKind::ChainAccount => {
                if self.value.is_empty() {
                    return Err(BnsRegistryError::invalid_principal(
                        &self.value,
                        "chain account principal must not be empty",
                    ));
                }
            }
            PrincipalKind::BnsName => {
                canonical_bns_name(&self.value)?;
            }
        }

        Ok(())
    }
}

impl Default for Principal {
    fn default() -> Self {
        Self::unset()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallAuthority {
    pub role: AuthorityRole,
    pub actor: Principal,
    pub kid: String,
}

impl CallAuthority {
    pub fn public() -> Self {
        Self {
            role: AuthorityRole::None,
            actor: Principal::unset(),
            kid: String::new(),
        }
    }

    pub fn owner(actor: Principal, kid: impl Into<String>) -> Self {
        Self {
            role: AuthorityRole::Owner,
            actor,
            kid: kid.into(),
        }
    }

    pub fn controller(actor: Principal, kid: impl Into<String>) -> Self {
        Self {
            role: AuthorityRole::Controller,
            actor,
            kid: kid.into(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MutationGuard {
    pub expected_name_seq: u64,
    pub expected_parent_name_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityKey {
    pub kid: String,
    pub verification_method: String,
    pub key_data: Vec<u8>,
    pub purposes: u32,
    pub valid_from: u64,
    pub valid_until: u64,
    pub status: AuthorityKeyStatus,
    pub metadata_hash: String,
}

impl AuthorityKey {
    pub fn authentication_key(kid: impl Into<String>, key_data: impl Into<Vec<u8>>) -> Self {
        Self {
            kid: kid.into(),
            verification_method: "custom-verifier".to_string(),
            key_data: key_data.into(),
            purposes: KEY_PURPOSE_AUTHENTICATION,
            valid_from: 0,
            valid_until: 0,
            status: AuthorityKeyStatus::Active,
            metadata_hash: ZERO_HASH.to_string(),
        }
    }

    pub fn validate(&self) -> BnsRegistryResult<()> {
        validate_kid(&self.kid)?;
        if self.verification_method.is_empty() {
            return Err(BnsRegistryError::invalid_kid(
                &self.kid,
                "verification method must not be empty",
            ));
        }
        validate_hash(&self.metadata_hash)?;
        Ok(())
    }

    pub fn is_active_for(&self, purpose: u32, now: u64) -> bool {
        self.status == AuthorityKeyStatus::Active
            && (self.purposes & purpose) != 0
            && self.valid_from <= now
            && (self.valid_until == 0 || now < self.valid_until)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityKeyUpdate {
    pub key: AuthorityKey,
    pub active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoritySetState {
    pub name: String,
    pub authority_seq: u64,
    pub authority_root: String,
    pub active_key_count: u32,
}

impl AuthoritySetState {
    pub fn empty(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            authority_seq: 0,
            authority_root: ZERO_HASH.to_string(),
            active_key_count: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentRef {
    pub storage_type: String,
    pub uri: String,
    pub inline_document: Vec<u8>,
    pub content_hash: String,
    pub schema: String,
    pub codec: String,
    pub extra_hash: String,
}

impl DocumentRef {
    pub fn new(
        storage_type: impl Into<String>,
        uri: impl Into<String>,
        content_hash: impl Into<String>,
    ) -> Self {
        Self {
            storage_type: storage_type.into(),
            uri: uri.into(),
            inline_document: Vec::new(),
            content_hash: normalize_hash_or_zero(content_hash.into()),
            schema: ZERO_HASH.to_string(),
            codec: ZERO_HASH.to_string(),
            extra_hash: ZERO_HASH.to_string(),
        }
    }

    pub fn inline(inline_document: impl Into<Vec<u8>>) -> Self {
        let inline_document = inline_document.into();
        let content_hash = sha256_hex(&inline_document);
        Self {
            storage_type: STORAGE_TYPE_INLINE.to_string(),
            uri: String::new(),
            inline_document,
            content_hash,
            schema: ZERO_HASH.to_string(),
            codec: ZERO_HASH.to_string(),
            extra_hash: ZERO_HASH.to_string(),
        }
    }

    pub fn validate_shape(&self) -> BnsRegistryResult<()> {
        if self.storage_type.is_empty() {
            return Err(BnsRegistryError::InvalidMutation(
                "document storage_type must not be empty".to_string(),
            ));
        }
        validate_hash(&self.content_hash)?;
        validate_hash(&self.schema)?;
        validate_hash(&self.codec)?;
        validate_hash(&self.extra_hash)?;

        if self.storage_type == STORAGE_TYPE_INLINE {
            if !self.uri.is_empty() {
                return Err(BnsRegistryError::InvalidMutation(
                    "inline document uri must be empty".to_string(),
                ));
            }
            if self.inline_document.is_empty() {
                return Err(BnsRegistryError::InvalidMutation(
                    "inline document must not be empty".to_string(),
                ));
            }
            if self.inline_document.len() > MAX_INLINE_DOCUMENT {
                return Err(BnsRegistryError::InlineDocumentTooLarge {
                    len: self.inline_document.len(),
                    max: MAX_INLINE_DOCUMENT,
                });
            }
            if !self.matches_sha256_content_hash() {
                return Err(BnsRegistryError::invalid_hash(
                    &self.content_hash,
                    "inline document content_hash must be sha256(inline_document)",
                ));
            }
        } else if !self.inline_document.is_empty() {
            return Err(BnsRegistryError::InvalidMutation(
                "inline_document must be empty for non-inline storage".to_string(),
            ));
        }

        Ok(())
    }

    pub fn matches_sha256_content_hash(&self) -> bool {
        sha256_hex(&self.inline_document) == self.content_hash
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameState {
    pub name: String,
    pub asset_owner: String,
    pub semantic_owner: Principal,
    pub effective_owner: Principal,
    pub owner_source: OwnerSource,
    pub standard_transfer_enabled: bool,
    pub status: NameStatus,
    pub registered_at: u64,
    pub expire_at: u64,
    pub grace_until: u64,
    pub updated_at: u64,
    pub name_seq: u64,
    pub owner_document_version: u64,
    #[serde(default)]
    pub min_document_iat: u64,
    #[serde(default)]
    pub owner_policy_seq: u64,
    pub lineage_epoch: u64,
    pub renewable: bool,
    pub transferable: bool,
    pub allow_delegated_subnames: bool,
    pub namespace_policy_hash: String,
    pub payment_policy_hash: String,
    pub alias_state_hash: String,
}

impl NameState {
    pub fn validate(&self) -> BnsRegistryResult<()> {
        canonical_bns_name(&self.name)?;
        if self.asset_owner.is_empty() {
            return Err(BnsRegistryError::InvalidMutation(
                "asset owner must not be empty".to_string(),
            ));
        }
        validate_semantic_owner(&self.semantic_owner)?;
        self.effective_owner.validate()?;
        validate_hash(&self.namespace_policy_hash)?;
        validate_hash(&self.payment_policy_hash)?;
        validate_hash(&self.alias_state_hash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentState {
    pub name: String,
    pub doc_type: String,
    pub version: u64,
    pub previous_version: u64,
    pub status: DocumentStatus,
    pub document: DocumentRef,
    pub controller: Principal,
    pub beneficiary: Principal,
    pub payment_target: String,
    pub valid_from: u64,
    pub expire_at: u64,
    pub revoked_at: u64,
    pub controller_policy_hash: String,
    pub payment_policy_hash: String,
    pub split_policy_hash: String,
    pub price_policy_hash: String,
    pub rights_policy_hash: String,
    pub document_state_hash: String,
}

impl DocumentState {
    pub fn validate(&self) -> BnsRegistryResult<()> {
        canonical_bns_name(&self.name)?;
        canonical_doc_type(&self.doc_type)?;
        self.document.validate_shape()?;
        self.controller.validate()?;
        self.beneficiary.validate()?;
        validate_hash(&self.controller_policy_hash)?;
        validate_hash(&self.payment_policy_hash)?;
        validate_hash(&self.split_policy_hash)?;
        validate_hash(&self.price_policy_hash)?;
        validate_hash(&self.rights_policy_hash)?;
        validate_hash(&self.document_state_hash)?;
        Ok(())
    }

    pub fn key(&self) -> DocumentKey {
        DocumentKey {
            name: self.name.clone(),
            doc_type: self.doc_type.clone(),
            version: self.version,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControllerRule {
    pub controller: Principal,
    pub doc_type: String,
    pub permissions: u32,
    pub namespace_scope_hash: String,
    pub valid_from: u64,
    pub valid_until: u64,
    pub constraint_hash: String,
}

impl ControllerRule {
    pub fn validate(&self) -> BnsRegistryResult<()> {
        self.controller.validate()?;
        if self.controller.is_unset() {
            return Err(BnsRegistryError::invalid_principal(
                "",
                "controller rule cannot use unset principal",
            ));
        }
        if !self.doc_type.is_empty() {
            canonical_doc_type(&self.doc_type)?;
        }
        validate_hash(&self.namespace_scope_hash)?;
        validate_hash(&self.constraint_hash)?;
        Ok(())
    }

    pub fn permits(&self, actor: &Principal, doc_type: &str, permission: u32, now: u64) -> bool {
        &self.controller == actor
            && (self.doc_type.is_empty() || self.doc_type == doc_type)
            && (self.permissions & permission) != 0
            && self.valid_from <= now
            && (self.valid_until == 0 || now < self.valid_until)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterOptions {
    pub duration: u64,
    pub grace_period: u64,
    pub renewable: bool,
    pub transferable: bool,
    pub initial_semantic_owner: Principal,
    pub allow_delegated_subnames: bool,
    pub initial_payment_target: String,
    pub initial_payment_policy_hash: String,
    pub initial_namespace_policy_hash: String,
}

impl Default for RegisterOptions {
    fn default() -> Self {
        Self {
            duration: 365 * 24 * 60 * 60,
            grace_period: 30 * 24 * 60 * 60,
            renewable: true,
            transferable: true,
            initial_semantic_owner: Principal::unset(),
            allow_delegated_subnames: false,
            initial_payment_target: String::new(),
            initial_payment_policy_hash: ZERO_HASH.to_string(),
            initial_namespace_policy_hash: ZERO_HASH.to_string(),
        }
    }
}

impl RegisterOptions {
    pub fn validate(&self) -> BnsRegistryResult<()> {
        if self.duration == 0 {
            return Err(BnsRegistryError::InvalidMutation(
                "registration duration must be greater than zero".to_string(),
            ));
        }
        validate_semantic_owner(&self.initial_semantic_owner)?;
        validate_hash(&self.initial_payment_policy_hash)?;
        validate_hash(&self.initial_namespace_policy_hash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentUpdate {
    pub doc_type: String,
    pub expected_version: u64,
    pub document: DocumentRef,
    pub controller: Principal,
    pub beneficiary: Principal,
    pub payment_target: String,
    pub expire_at: u64,
    pub controller_policy_hash: String,
    pub payment_policy_hash: String,
    pub split_policy_hash: String,
    pub price_policy_hash: String,
    pub rights_policy_hash: String,
}

impl DocumentUpdate {
    pub fn validate(&self) -> BnsRegistryResult<()> {
        canonical_doc_type(&self.doc_type)?;
        self.document.validate_shape()?;
        self.controller.validate()?;
        self.beneficiary.validate()?;
        validate_hash(&self.controller_policy_hash)?;
        validate_hash(&self.payment_policy_hash)?;
        validate_hash(&self.split_policy_hash)?;
        validate_hash(&self.price_policy_hash)?;
        validate_hash(&self.rights_policy_hash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerPolicyUpdate {
    pub update_min_document_iat: bool,
    pub min_document_iat: u64,
    pub reason_hash: String,
}

impl Default for OwnerPolicyUpdate {
    fn default() -> Self {
        Self::none()
    }
}

impl OwnerPolicyUpdate {
    pub fn none() -> Self {
        Self {
            update_min_document_iat: false,
            min_document_iat: 0,
            reason_hash: ZERO_HASH.to_string(),
        }
    }

    pub fn validate(&self) -> BnsRegistryResult<()> {
        if self.update_min_document_iat || !self.reason_hash.is_empty() {
            validate_hash(&self.reason_hash)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerResolution {
    pub effective_owner: Principal,
    pub source: OwnerSource,
    pub authority_root: String,
    pub authority_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveResult {
    pub name_state: NameState,
    pub document_state: DocumentState,
    pub owner: OwnerResolution,
    pub effective_controller: Principal,
    pub status: DocumentStatus,
    pub alias_kind: AliasKind,
    pub alias_target_did: String,
    pub proof_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapDocumentVersion {
    pub doc_type: String,
    pub version: u64,
    pub content_hash: String,
    pub document_state_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapNameResult {
    pub name_seq: u64,
    pub initial_documents: Vec<BootstrapDocumentVersion>,
    pub authority_set: AuthoritySetState,
    pub controller_policy_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyMutationsResult {
    pub name_seq: u64,
    pub documents: Vec<BootstrapDocumentVersion>,
    pub authority_set: AuthoritySetState,
    pub owner_policy_seq: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DocumentKey {
    pub name: String,
    pub doc_type: String,
    pub version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AliasState {
    pub name: String,
    pub kind: AliasKind,
    pub target_did: String,
    pub proof_hash: String,
    pub set_at: u64,
    pub name_seq: u64,
}

impl AliasState {
    pub fn validate(&self) -> BnsRegistryResult<()> {
        canonical_bns_name(&self.name)?;
        if self.kind != AliasKind::None {
            validate_did(&self.target_did)?;
        }
        validate_hash(&self.proof_hash)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurchaseContext {
    pub name: String,
    pub doc_type: String,
    pub document_version: u64,
    pub beneficiary: Principal,
    pub payment_target: String,
    pub payment_policy_hash: String,
    pub split_policy_hash: String,
    pub price_policy_hash: String,
    pub rights_policy_hash: String,
    pub status: DocumentStatus,
    pub proof_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentTargetResolution {
    pub beneficiary: Principal,
    pub payment_target: String,
    pub payment_policy_hash: String,
    pub split_policy_hash: String,
    pub price_policy_hash: String,
    pub rights_policy_hash: String,
    pub proof_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogCheckpoint {
    pub log_root: String,
    pub last_seq: u64,
    pub issued_at: u64,
    pub issuer: Principal,
    pub external_anchor: String,
}

impl LogCheckpoint {
    pub fn validate(&self) -> BnsRegistryResult<()> {
        validate_hash(&self.log_root)?;
        self.issuer.validate()?;
        validate_hash(&self.external_anchor)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum RegistryEvent {
    NameRegistered {
        name: String,
        asset_owner: String,
        expire_at: u64,
        lineage_epoch: u64,
        name_seq: u64,
    },
    NameRenewed {
        name: String,
        expire_at: u64,
        name_seq: u64,
    },
    NameAssetTransferred {
        name: String,
        old_asset_owner: String,
        new_asset_owner: String,
        standard_transfer: bool,
        name_seq: u64,
    },
    NameOwnerUpdated {
        name: String,
        owner: Principal,
        owner_source: OwnerSource,
        standard_transfer_enabled: bool,
        name_seq: u64,
    },
    AuthorityKeysUpdated {
        name: String,
        authority_seq: u64,
        authority_root: String,
    },
    NameReleased {
        name: String,
        mode: ReleaseMode,
        reason_hash: String,
        name_seq: u64,
    },
    DocumentPublished {
        name: String,
        doc_type: String,
        version: u64,
        content_hash: String,
        document_state_hash: String,
    },
    DocumentRevoked {
        name: String,
        doc_type: String,
        previous_version: u64,
        new_version: u64,
        reason_hash: String,
    },
    OwnerDocumentIatFloorUpdated {
        name: String,
        previous_min_document_iat: u64,
        new_min_document_iat: u64,
        owner_policy_seq: u64,
        name_seq: u64,
        reason_hash: String,
    },
    ControllerPolicyUpdated {
        name: String,
        policy_hash: String,
        name_seq: u64,
    },
    NamespacePolicyUpdated {
        name: String,
        allow_delegated_subnames: bool,
        namespace_policy_hash: String,
        name_seq: u64,
    },
    DidAliasSet {
        name: String,
        target_did: String,
        kind: AliasKind,
        proof_hash: String,
        name_seq: u64,
    },
    PaymentTargetUpdated {
        name: String,
        doc_type: String,
        payment_target: String,
        payment_policy_hash: String,
        version: u64,
    },
    LogCheckpointPublished {
        log_root: String,
        last_seq: u64,
        issued_at: u64,
        external_anchor: String,
    },
}

impl RegistryEvent {
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::NameRegistered { .. } => "name_registered",
            Self::NameRenewed { .. } => "name_renewed",
            Self::NameAssetTransferred { .. } => "name_asset_transferred",
            Self::NameOwnerUpdated { .. } => "name_owner_updated",
            Self::AuthorityKeysUpdated { .. } => "authority_keys_updated",
            Self::NameReleased { .. } => "name_released",
            Self::DocumentPublished { .. } => "document_published",
            Self::DocumentRevoked { .. } => "document_revoked",
            Self::OwnerDocumentIatFloorUpdated { .. } => "owner_iat_floor_updated",
            Self::ControllerPolicyUpdated { .. } => "controller_policy_updated",
            Self::NamespacePolicyUpdated { .. } => "namespace_policy_updated",
            Self::DidAliasSet { .. } => "did_alias_set",
            Self::PaymentTargetUpdated { .. } => "payment_target_updated",
            Self::LogCheckpointPublished { .. } => "log_checkpoint_published",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventLogRecord {
    pub seq: u64,
    pub event_type: String,
    pub observed_at: u64,
    pub event_hash: String,
    pub previous_log_root: String,
    pub log_root: String,
    pub event: RegistryEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerCursor {
    pub source: String,
    pub block_number: u64,
    pub block_hash: Option<String>,
    pub log_index: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruthSource {
    BnsDb,
    Contract,
}

impl Default for TruthSource {
    fn default() -> Self {
        Self::BnsDb
    }
}

pub fn now_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn canonical_bns_name(name: &str) -> BnsRegistryResult<String> {
    if name.is_empty() {
        return Err(BnsRegistryError::invalid_name(name, "name is empty"));
    }
    if name.trim() != name {
        return Err(BnsRegistryError::invalid_name(
            name,
            "name must not contain leading or trailing whitespace",
        ));
    }
    if name.starts_with(DID_BNS_PREFIX) {
        return Err(BnsRegistryError::invalid_name(
            name,
            "contract names must not include did:bns: prefix",
        ));
    }
    if name.len() > MAX_BNS_NAME_LEN {
        return Err(BnsRegistryError::invalid_name(
            name,
            format!("name must be at most {} bytes", MAX_BNS_NAME_LEN),
        ));
    }

    for label in name.split('.') {
        if label.is_empty() {
            return Err(BnsRegistryError::invalid_name(name, "empty label"));
        }
        if label.len() > MAX_BNS_LABEL_LEN {
            return Err(BnsRegistryError::invalid_name(
                name,
                format!("label must be at most {} bytes", MAX_BNS_LABEL_LEN),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(BnsRegistryError::invalid_name(
                name,
                "label must not start or end with '-'",
            ));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(BnsRegistryError::invalid_name(
                name,
                "only lower-case ASCII letters, digits, '-' and '.' are supported",
            ));
        }
    }

    Ok(name.to_string())
}

pub fn canonical_doc_type(doc_type: &str) -> BnsRegistryResult<String> {
    if doc_type.is_empty() {
        return Err(BnsRegistryError::invalid_doc_type(
            doc_type,
            "doc_type is empty",
        ));
    }
    if doc_type.len() > 32 {
        return Err(BnsRegistryError::invalid_doc_type(
            doc_type,
            "doc_type must be at most 32 bytes",
        ));
    }
    if !doc_type
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
    {
        return Err(BnsRegistryError::invalid_doc_type(
            doc_type,
            "only lower-case ASCII letters, digits, '-' and '_' are supported",
        ));
    }

    Ok(doc_type.to_string())
}

pub fn name_from_did_bns(did: &str) -> BnsRegistryResult<String> {
    let name = did
        .strip_prefix(DID_BNS_PREFIX)
        .ok_or_else(|| BnsRegistryError::invalid_name(did, "DID must start with did:bns:"))?;
    canonical_bns_name(name)
}

pub fn did_bns_from_name(name: &str) -> BnsRegistryResult<String> {
    Ok(format!("{}{}", DID_BNS_PREFIX, canonical_bns_name(name)?))
}

pub fn validate_did(did: &str) -> BnsRegistryResult<()> {
    if did.starts_with(DID_BNS_PREFIX) {
        name_from_did_bns(did)?;
        return Ok(());
    }
    if did.starts_with("did:") && did.len() > 4 {
        return Ok(());
    }
    Err(BnsRegistryError::invalid_name(did, "invalid DID"))
}

pub fn validate_hash(value: &str) -> BnsRegistryResult<()> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.len() != 64 {
        return Err(BnsRegistryError::invalid_hash(
            value,
            "bytes32 hash must contain 64 hex chars",
        ));
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(BnsRegistryError::invalid_hash(
            value,
            "bytes32 hash must be hex encoded",
        ));
    }
    Ok(())
}

pub fn validate_kid(kid: &str) -> BnsRegistryResult<()> {
    if kid.is_empty() {
        return Err(BnsRegistryError::invalid_kid(kid, "kid must not be empty"));
    }
    validate_hash(kid)
}

pub fn validate_semantic_owner(owner: &Principal) -> BnsRegistryResult<()> {
    match owner.kind {
        PrincipalKind::Unset | PrincipalKind::BnsName => owner.validate(),
        PrincipalKind::ChainAccount => Err(BnsRegistryError::invalid_principal(
            &owner.value,
            "semantic owner only supports unset or BnsName",
        )),
    }
}

pub fn normalize_hash_or_zero(value: String) -> String {
    if value.is_empty() {
        ZERO_HASH.to_string()
    } else {
        value
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("0x{}", hex::encode(digest))
}

pub fn hash_json<T: Serialize + ?Sized>(value: &T) -> BnsRegistryResult<String> {
    Ok(sha256_hex(&serde_json::to_vec(value)?))
}

pub fn authority_root(keys: &[AuthorityKey], now: u64) -> BnsRegistryResult<(String, u32)> {
    let mut active: Vec<&AuthorityKey> = keys
        .iter()
        .filter(|key| key.is_active_for(KEY_PURPOSE_AUTHENTICATION, now))
        .collect();
    active.sort_by(|left, right| left.kid.cmp(&right.kid));

    if active.is_empty() {
        return Ok((ZERO_HASH.to_string(), 0));
    }

    let mut canonical = BTreeMap::new();
    for key in active {
        canonical.insert(key.kid.clone(), key);
    }
    Ok((hash_json(&canonical)?, canonical.len() as u32))
}

pub fn document_state_hash(state: &DocumentState) -> BnsRegistryResult<String> {
    let mut copy = state.clone();
    copy.document_state_hash = ZERO_HASH.to_string();
    hash_json(&copy)
}

pub fn parent_name(name: &str) -> Option<&str> {
    name.split_once('.').map(|(_, parent)| parent)
}

pub fn is_top_level_name(name: &str) -> bool {
    !name.contains('.')
}

pub fn ensure_registerable_depth(name: &str) -> BnsRegistryResult<()> {
    if name.split('.').count() > 2 {
        return Err(BnsRegistryError::invalid_name(
            name,
            "registry only supports first-level and second-level exact names",
        ));
    }
    Ok(())
}

pub fn default_document_update(
    doc_type: &str,
    expected_version: u64,
    document: DocumentRef,
) -> BnsRegistryResult<DocumentUpdate> {
    Ok(DocumentUpdate {
        doc_type: canonical_doc_type(doc_type)?,
        expected_version,
        document,
        controller: Principal::unset(),
        beneficiary: Principal::unset(),
        payment_target: String::new(),
        expire_at: 0,
        controller_policy_hash: ZERO_HASH.to_string(),
        payment_policy_hash: ZERO_HASH.to_string(),
        split_policy_hash: ZERO_HASH.to_string(),
        price_policy_hash: ZERO_HASH.to_string(),
        rights_policy_hash: ZERO_HASH.to_string(),
    })
}

pub fn controller_rule(
    controller: Principal,
    doc_type: impl Into<String>,
    permissions: u32,
) -> ControllerRule {
    ControllerRule {
        controller,
        doc_type: doc_type.into(),
        permissions,
        namespace_scope_hash: ZERO_HASH.to_string(),
        valid_from: 0,
        valid_until: 0,
        constraint_hash: ZERO_HASH.to_string(),
    }
}

pub fn policy_hash_from_rules(rules: &[ControllerRule]) -> BnsRegistryResult<String> {
    hash_json(rules)
}
