use serde::{Deserialize, Serialize};

use crate::{
    default_document_update, BnsRegistryError, BnsRegistryResult, DocumentRef, DocumentState,
    DocumentUpdate, STORAGE_TYPE_INLINE,
};

pub const DNS_TXT_DOC_TYPE: &str = "dns_txt";

/// One TXT record entry in a `dns_txt` document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsTxtRecord {
    pub ttl: u32,
    pub value: String,
}

impl DnsTxtRecord {
    pub fn new(ttl: u32, value: impl Into<String>) -> BnsRegistryResult<Self> {
        let value = value.into();
        if value.is_empty() {
            return Err(BnsRegistryError::InvalidMutation(
                "DNS TXT record value must not be empty".to_string(),
            ));
        }

        Ok(Self { ttl, value })
    }
}

/// Builds a `dns_txt` document update with one TXT record appended.
///
/// Pass `None` to create the first `dns_txt` document version, or pass the
/// current `dns_txt` [`DocumentState`] to append to the existing inline JSON
/// record array. The returned [`DocumentUpdate`] can be passed directly to
/// `CentralizedBnsRegistry::publish_document`.
pub fn add_txt_record(
    current: Option<&DocumentState>,
    ttl: u32,
    value: impl Into<String>,
) -> BnsRegistryResult<DocumentUpdate> {
    let mut records = match current {
        Some(state) => txt_records_from_document(state)?,
        None => Vec::new(),
    };
    let expected_version = current.map_or(0, |state| state.version);

    records.push(DnsTxtRecord::new(ttl, value)?);
    txt_records_update(expected_version, &records)
}

/// Parses an inline `dns_txt` document into TXT records.
pub fn txt_records_from_document(state: &DocumentState) -> BnsRegistryResult<Vec<DnsTxtRecord>> {
    if state.doc_type != DNS_TXT_DOC_TYPE {
        return Err(BnsRegistryError::InvalidMutation(format!(
            "expected doc_type={}, got {}",
            DNS_TXT_DOC_TYPE, state.doc_type
        )));
    }

    if state.document.storage_type != STORAGE_TYPE_INLINE {
        return Err(BnsRegistryError::InvalidMutation(
            "DNS TXT helper can only update inline documents".to_string(),
        ));
    }

    serde_json::from_slice(&state.document.inline_document).map_err(Into::into)
}

/// Builds a `dns_txt` document update from a complete TXT record array.
pub fn txt_records_update(
    expected_version: u64,
    records: &[DnsTxtRecord],
) -> BnsRegistryResult<DocumentUpdate> {
    if records.is_empty() {
        return Err(BnsRegistryError::InvalidMutation(
            "DNS TXT document must contain at least one record".to_string(),
        ));
    }

    let document = DocumentRef::inline(serde_json::to_vec(records)?);
    let update = default_document_update(DNS_TXT_DOC_TYPE, expected_version, document)?;
    update.validate()?;
    Ok(update)
}

/// Extracts a boot config JWT embedded in a zone or boot config JSON value.
///
/// Zone configs may carry the boot config inline as a JWT string — a compromise
/// for the 256-byte DNS TXT record limit, not the canonical model (boot is
/// normally its own atomic document). Both the SN controller (write side, when
/// embedding into the zone document) and the resolver (read side, as a fallback
/// when no standalone boot document exists) call this, so the embedded
/// `boot_jwt` is written and read through the exact same set of locations.
///
/// Recognizes a bare JWT string and the known nested keys, returning the first
/// non-empty JWT found. Returns `None` when no JWT is present (e.g. a structured
/// boot object that is not a JWT).
pub fn extract_boot_jwt(value: &serde_json::Value) -> Option<String> {
    fn non_empty_jwt(value: &serde_json::Value) -> Option<String> {
        let jwt = value.as_str()?.trim();
        (!jwt.is_empty()).then(|| jwt.to_string())
    }

    if let Some(jwt) = non_empty_jwt(value) {
        return Some(jwt);
    }

    const PATHS: &[&[&str]] = &[
        &["boot_jwt"],
        &["boot_config_jwt"],
        &["zone_config_jwt"],
        &["boot", "boot_jwt"],
        &["boot", "boot_config_jwt"],
        &["boot", "zone_config_jwt"],
        &["boot", "jwt"],
        &["boot"],
        &["zone_config_ref", "boot_jwt"],
        &["zone_config_ref", "boot_config_jwt"],
        &["zone_config_ref", "zone_config_jwt"],
        &["zone_config_ref", "boot"],
    ];

    PATHS.iter().find_map(|path| {
        let mut current = value;
        for key in *path {
            current = current.get(*key)?;
        }
        non_empty_jwt(current)
    })
}

#[cfg(test)]
mod boot_jwt_tests {
    use super::extract_boot_jwt;
    use serde_json::json;

    #[test]
    fn extracts_bare_and_nested_boot_jwt() {
        assert_eq!(
            extract_boot_jwt(&json!(" inline-boot ")).as_deref(),
            Some("inline-boot")
        );
        assert_eq!(
            extract_boot_jwt(&json!({ "boot_jwt": "top" })).as_deref(),
            Some("top")
        );
        assert_eq!(
            extract_boot_jwt(&json!({ "boot": { "boot_config_jwt": "nested" } })).as_deref(),
            Some("nested")
        );
        assert_eq!(
            extract_boot_jwt(&json!({ "boot": "legacy" })).as_deref(),
            Some("legacy")
        );
        assert_eq!(
            extract_boot_jwt(&json!({ "zone_config_ref": { "boot_jwt": "ref" } })).as_deref(),
            Some("ref")
        );
    }

    #[test]
    fn returns_none_for_non_jwt_boot_object() {
        assert_eq!(extract_boot_jwt(&json!({ "boot": { "foo": 1 } })), None);
        assert_eq!(extract_boot_jwt(&json!({ "gateway": "x" })), None);
        assert_eq!(extract_boot_jwt(&json!(null)), None);
    }
}
