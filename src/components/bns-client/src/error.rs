use thiserror::Error;

#[derive(Debug, Error)]
pub enum BnsRegistryError {
    #[error("invalid BNS name `{name}`: {reason}")]
    InvalidName { name: String, reason: String },

    #[error("invalid BNS document type `{doc_type}`: {reason}")]
    InvalidDocType { doc_type: String, reason: String },

    #[error("invalid EVM address `{address}`: {reason}")]
    InvalidAddress { address: String, reason: String },

    #[error("invalid page limit {limit}; expected 1..={max}")]
    InvalidLimit { limit: usize, max: usize },

    #[error("invalid BNS hash `{value}`: {reason}")]
    InvalidHash { value: String, reason: String },

    #[error("invalid BNS principal `{value}`: {reason}")]
    InvalidPrincipal { value: String, reason: String },

    #[error("invalid authority key `{kid}`: {reason}")]
    InvalidKid { kid: String, reason: String },

    #[error("name `{name}` already exists")]
    NameAlreadyExists { name: String },

    #[error("name `{name}` was not found")]
    NameNotFound { name: String },

    #[error("document `{name}/{doc_type}` was not found")]
    DocumentNotFound { name: String, doc_type: String },

    #[error("document `{name}/{doc_type}` is inconsistent with on-chain state: {reason}")]
    DocumentInconsistent {
        name: String,
        doc_type: String,
        reason: String,
    },

    #[error("stale name sequence for `{name}`: expected {expected}, actual {actual}")]
    StaleNameSeq {
        name: String,
        expected: u64,
        actual: u64,
    },

    #[error("stale parent name sequence for `{name}`: expected {expected}, actual {actual}")]
    StaleParentNameSeq {
        name: String,
        expected: u64,
        actual: u64,
    },

    #[error(
        "stale document version for `{name}/{doc_type}`: expected {expected}, actual {actual}"
    )]
    StaleDocumentVersion {
        name: String,
        doc_type: String,
        expected: u64,
        actual: u64,
    },

    #[error("caller is not the effective owner of `{name}`")]
    NotEffectiveOwner { name: String },

    #[error("controller is not permitted to perform `{operation}` on `{name}/{doc_type}`")]
    ControllerScopeDenied {
        name: String,
        doc_type: String,
        operation: &'static str,
    },

    #[error("standard transfer is disabled for `{name}`")]
    StandardTransferDisabled { name: String },

    #[error("semantic owner graph would contain a cycle")]
    OwnerGraphCycle,

    #[error("semantic owner graph has no reachable concrete signer")]
    NoConcreteSigner,

    #[error("semantic owner graph exceeds max depth {max_depth}")]
    OwnerGraphTooDeep { max_depth: usize },

    #[error("inline document is {len} bytes, exceeding max {max} bytes")]
    InlineDocumentTooLarge { len: usize, max: usize },

    #[error("invalid mutation: {0}")]
    InvalidMutation(String),

    #[error("invalid BNS indexer config: {0}")]
    InvalidConfig(String),

    #[error("unsupported BNS operation: {0}")]
    UnsupportedOperation(String),

    #[error("integer value for `{field}` is outside sqlite INTEGER range: {value}")]
    IntegerOutOfRange { field: &'static str, value: u64 },

    #[error("BNS sqlite database lock is poisoned")]
    DbLockPoisoned,

    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("EVM RPC/ABI error: {0}")]
    Evm(#[from] bns_evm::BnsEvmError),
}

pub type BnsRegistryResult<T> = Result<T, BnsRegistryError>;

impl BnsRegistryError {
    pub fn invalid_name(name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidName {
            name: name.into(),
            reason: reason.into(),
        }
    }

    pub fn invalid_doc_type(doc_type: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidDocType {
            doc_type: doc_type.into(),
            reason: reason.into(),
        }
    }

    pub fn invalid_hash(value: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidHash {
            value: value.into(),
            reason: reason.into(),
        }
    }

    pub fn invalid_principal(value: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidPrincipal {
            value: value.into(),
            reason: reason.into(),
        }
    }

    pub fn invalid_kid(kid: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::InvalidKid {
            kid: kid.into(),
            reason: reason.into(),
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidName { .. } => "INVALID_NAME",
            Self::InvalidDocType { .. } => "INVALID_DOC_TYPE",
            Self::InvalidAddress { .. } => "INVALID_ADDRESS",
            Self::InvalidLimit { .. } => "INVALID_LIMIT",
            Self::InvalidHash { .. } => "INVALID_HASH",
            Self::InvalidPrincipal { .. } => "INVALID_PRINCIPAL",
            Self::InvalidKid { .. } => "INVALID_KID",
            Self::NameAlreadyExists { .. } => "NAME_ALREADY_EXISTS",
            Self::NameNotFound { .. } => "NAME_NOT_FOUND",
            Self::DocumentNotFound { .. } => "DOCUMENT_NOT_FOUND",
            Self::DocumentInconsistent { .. } => "DOCUMENT_INCONSISTENT",
            Self::StaleNameSeq { .. } => "STALE_NAME_SEQ",
            Self::StaleParentNameSeq { .. } => "STALE_PARENT_NAME_SEQ",
            Self::StaleDocumentVersion { .. } => "STALE_DOCUMENT_VERSION",
            Self::NotEffectiveOwner { .. } => "NOT_EFFECTIVE_OWNER",
            Self::ControllerScopeDenied { .. } => "CONTROLLER_SCOPE_DENIED",
            Self::StandardTransferDisabled { .. } => "STANDARD_TRANSFER_DISABLED",
            Self::OwnerGraphCycle => "OWNER_GRAPH_CYCLE",
            Self::NoConcreteSigner => "NO_CONCRETE_SIGNER",
            Self::OwnerGraphTooDeep { .. } => "OWNER_GRAPH_TOO_DEEP",
            Self::InlineDocumentTooLarge { .. } => "INLINE_DOCUMENT_TOO_LARGE",
            Self::InvalidMutation(_) => "INVALID_MUTATION",
            Self::InvalidConfig(_) => "INVALID_CONFIG",
            Self::UnsupportedOperation(_) => "UNSUPPORTED_OPERATION",
            Self::IntegerOutOfRange { .. } => "INTEGER_OUT_OF_RANGE",
            Self::DbLockPoisoned => "DB_LOCK_POISONED",
            Self::Sqlite(_) => "SQLITE_ERROR",
            Self::Json(_) => "JSON_ERROR",
            Self::Io(_) => "IO_ERROR",
            Self::Evm(_) => "EVM_ERROR",
        }
    }
}
