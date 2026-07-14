use crate::sn_resolver::{
    SnAuthReaderRef, SnResolverError, SnResolverErrorKind, SnResolverRef, SnResolverResult,
    ZoneResolution, ZoneResolutionSource, BNS_DOC_ZONE, DEFAULT_SN_RESOLVER_TTL_SECS,
};
use async_trait::async_trait;
use jsonwebtoken::jwk::Jwk;
use name_lib::{create_jwt_by_x, EncodedDocument, OwnerConfig, DID};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::net::IpAddr;
use std::sync::Arc;

pub const SN_DID_RESOLVER_ROUTE_PREFIX: &str = "/1.0/identifiers/";
pub const DID_RESOLUTION_CONTENT_TYPE: &str = "application/did-resolution+json";

pub type SnDidResolverRef = Arc<dyn SnDidResolver>;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnDidResolverProfile {
    PublicSupplement,
    InternalZoneResolver,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnDidDocumentStatus {
    Active,
    Missing,
    Revoked,
    Tombstoned,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnDidDocumentSource {
    BnsDocument,
    DeviceMiniDocument,
    DeviceOnlineInfo,
    LegacyCompatibilityStore,
    SynthesizedOwnerDocument,
    InternalCache,
}

#[derive(Debug, Clone)]
pub struct SnDidResolveRequest {
    pub did: DID,
    pub doc_type: Option<String>,
    pub from_ip: Option<IpAddr>,
    pub profile: SnDidResolverProfile,
    pub accept: Option<String>,
    pub iat: Option<String>,
}

impl SnDidResolveRequest {
    pub fn new(
        did: DID,
        doc_type: Option<String>,
        from_ip: Option<IpAddr>,
        profile: SnDidResolverProfile,
    ) -> Self {
        Self {
            did,
            doc_type: normalize_sn_did_doc_type(doc_type.as_deref()),
            from_ip,
            profile,
            accept: None,
            iat: None,
        }
    }

    pub fn doc_type(&self) -> Option<&str> {
        self.doc_type.as_deref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDidResolveResponse {
    pub did: String,
    pub doc_type: String,
    pub document: EncodedDocument,
    pub source: SnDidDocumentSource,
    pub profile: SnDidResolverProfile,
    pub document_status: Option<SnDidDocumentStatus>,
    pub metadata: Value,
}

impl SnDidResolveResponse {
    pub fn content_type(&self) -> &'static str {
        match self.document {
            EncodedDocument::JsonLd(_) => "application/json",
            EncodedDocument::Jwt(_) => "application/jwt",
        }
    }

    pub fn body(&self) -> String {
        self.document.to_string()
    }

    pub fn content_type_for_accept(&self, accept: Option<&str>) -> &'static str {
        if accepts_did_resolution(accept) {
            DID_RESOLUTION_CONTENT_TYPE
        } else {
            self.content_type()
        }
    }

    pub fn body_for_accept(&self, accept: Option<&str>) -> String {
        if accepts_did_resolution(accept) {
            self.did_resolution_body()
        } else {
            self.body()
        }
    }

    fn did_resolution_body(&self) -> String {
        let did_document = self
            .document
            .clone()
            .to_json_value()
            .unwrap_or_else(|_| Value::String(self.document.to_string()));
        let mut buckyos = self
            .metadata
            .get("buckyos")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if let Some(status) = self.document_status {
            if let Some(obj) = buckyos.as_object_mut() {
                obj.insert("documentStatus".to_string(), json!(status));
            }
        }

        serde_json::to_string(&json!({
            "didResolutionMetadata": {
                "contentType": self.content_type(),
            },
            "didDocument": did_document,
            "didDocumentMetadata": {
                "buckyos": buckyos,
            }
        }))
        .unwrap()
    }
}

#[async_trait]
pub trait SnDidResolver: Send + Sync + 'static {
    async fn resolve(&self, request: SnDidResolveRequest)
        -> SnResolverResult<SnDidResolveResponse>;
}

pub struct SnResolverBackedDidResolver {
    resolver: SnResolverRef,
    auth: SnAuthReaderRef,
}

impl SnResolverBackedDidResolver {
    pub fn new(resolver: SnResolverRef, auth: SnAuthReaderRef) -> Self {
        Self { resolver, auth }
    }

    pub fn new_ref(resolver: SnResolverRef, auth: SnAuthReaderRef) -> SnDidResolverRef {
        Arc::new(Self::new(resolver, auth))
    }

    async fn resolve_request(
        &self,
        request: &SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        if request.iat.is_some() {
            return Err(SnResolverError::new(
                SnResolverErrorKind::InvalidDid,
                "historical DID resolution by iat is not supported",
            ));
        }

        match request.did.method.as_str() {
            "web" => self.resolve_web_did(request).await,
            "bns" => self.resolve_bns_did(request).await,
            "dev" => self.resolve_passthrough(request).await,
            other => Err(SnResolverError::new(
                SnResolverErrorKind::UnsupportedDidMethod,
                format!("unsupported did method {}", other),
            )),
        }
    }

    async fn resolve_passthrough(
        &self,
        request: &SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let mut response = self
            .resolver
            .resolve_did(&request.did, request.doc_type(), request.from_ip)
            .await?;
        self.apply_profile(request, &mut response, None);
        Ok(response)
    }

    async fn resolve_bns_did(
        &self,
        request: &SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let doc_type = effective_bns_doc_type(&request.did, request.doc_type());
        if is_root_bns_did(&request.did) && doc_type == "owner" {
            match self.resolve_passthrough(request).await {
                Ok(response) => return Ok(response),
                Err(error)
                    if matches!(
                        error.kind(),
                        SnResolverErrorKind::DocumentNotFound
                            | SnResolverErrorKind::DeviceNotFound
                            | SnResolverErrorKind::NameNotFound
                    ) => {}
                Err(error) => return Err(error),
            }

            let zone = self
                .resolver
                .resolve_zone_by_bns_name(
                    request.did.id.as_str(),
                    request.did.id.as_str(),
                    ZoneResolutionSource::BnsName,
                    None,
                )
                .await?;
            let owner_did = request.did.to_string();
            let mut response = self.synthesize_owner_response(&owner_did, &zone, "owner")?;
            self.apply_profile(
                request,
                &mut response,
                Some(json!({
                    "canonicalZone": format!("did:bns:{}", zone.canonical_name),
                })),
            );
            return Ok(response);
        }

        self.resolve_passthrough(request).await
    }

    async fn resolve_web_did(
        &self,
        request: &SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let id = normalize_host_lossy(request.did.id.as_str());
        if id.is_empty() {
            return Err(SnResolverError::new(
                SnResolverErrorKind::InvalidDid,
                "did:web id is empty",
            ));
        }

        let Some(binding) = self.find_user_domain_binding(id.as_str()).await? else {
            return Err(SnResolverError::new(
                SnResolverErrorKind::NotManaged,
                format!("did:web:{} is not managed by this SN", id),
            ));
        };

        if binding.device_name.is_none() && request.doc_type().unwrap_or(BNS_DOC_ZONE) == "owner" {
            let owner_did = request.did.to_string();
            let mut response =
                self.synthesize_owner_response(&owner_did, &binding.zone, "owner")?;
            self.apply_profile(
                request,
                &mut response,
                Some(json!({
                    "canonicalZone": binding.canonical_zone_did(),
                    "userDomain": binding.user_domain,
                })),
            );
            return Ok(response);
        }

        let mapped = binding.mapped_bns_did(request.doc_type())?;
        let mapped_doc_type = request.doc_type().or_else(|| {
            if binding.device_name.is_some() {
                Some("doc")
            } else {
                Some(BNS_DOC_ZONE)
            }
        });
        let mut response = self
            .resolver
            .resolve_did(&mapped, mapped_doc_type, request.from_ip)
            .await?;

        let owner_did = format!("did:web:{}", binding.user_domain);
        rewrite_web_document_identity(
            &mut response.document,
            request.did.to_string().as_str(),
            owner_did.as_str(),
            binding.canonical_zone_did().as_str(),
            binding.device_name.as_deref(),
        );

        response.did = request.did.to_string();
        self.apply_profile(
            request,
            &mut response,
            Some(json!({
                "canonicalZone": binding.canonical_zone_did(),
                "userDomain": binding.user_domain,
                "mappedDid": mapped.to_string(),
            })),
        );
        Ok(response)
    }

    async fn find_user_domain_binding(
        &self,
        host: &str,
    ) -> SnResolverResult<Option<WebDomainBinding>> {
        let Some(user) = self.auth.get_user_by_domain(host).await? else {
            return Ok(None);
        };
        let Some(username) = user.username.clone() else {
            return Err(SnResolverError::not_found(format!(
                "user_domain {} has no username",
                host
            )));
        };
        let Some(user_domain) = user.user_domain.as_deref().map(normalize_host_lossy) else {
            return Ok(None);
        };
        if user_domain.is_empty() {
            return Ok(None);
        }

        let device_name = if host == user_domain {
            None
        } else {
            let suffix = format!(".{}", user_domain);
            host.strip_suffix(suffix.as_str())
                .filter(|name| !name.is_empty() && !name.contains('.'))
                .map(ToOwned::to_owned)
        };

        if host != user_domain && device_name.is_none() {
            return Ok(None);
        }

        let zone = self
            .resolver
            .resolve_zone_by_bns_name(
                username.as_str(),
                user_domain.as_str(),
                ZoneResolutionSource::UserDomain,
                Some(user_domain.clone()),
            )
            .await?;

        Ok(Some(WebDomainBinding {
            username,
            user_domain,
            device_name,
            zone,
        }))
    }

    fn synthesize_owner_response(
        &self,
        owner_did: &str,
        zone: &ZoneResolution,
        doc_type: &str,
    ) -> SnResolverResult<SnDidResolveResponse> {
        let canonical_zone = format!("did:bns:{}", zone.canonical_name);
        let (document, key_source) = synthesize_owner_document(owner_did, &canonical_zone, zone)?;
        Ok(SnDidResolveResponse {
            did: owner_did.to_string(),
            doc_type: doc_type.to_string(),
            document: EncodedDocument::JsonLd(document),
            source: SnDidDocumentSource::SynthesizedOwnerDocument,
            profile: SnDidResolverProfile::PublicSupplement,
            document_status: None,
            metadata: json!({
                "buckyos": {
                    "docType": doc_type,
                    "source": SnDidDocumentSource::SynthesizedOwnerDocument,
                    "ownerKeySource": key_source,
                    "canonicalZone": canonical_zone,
                    "ttl": DEFAULT_SN_RESOLVER_TTL_SECS,
                }
            }),
        })
    }

    fn apply_profile(
        &self,
        request: &SnDidResolveRequest,
        response: &mut SnDidResolveResponse,
        extra_buckyos: Option<Value>,
    ) {
        response.profile = request.profile;
        response.document_status = match request.profile {
            SnDidResolverProfile::PublicSupplement => None,
            SnDidResolverProfile::InternalZoneResolver => Some(SnDidDocumentStatus::Active),
        };

        let mut buckyos = response
            .metadata
            .get("buckyos")
            .and_then(|value| value.as_object())
            .cloned()
            .unwrap_or_default();

        buckyos.insert(
            "docType".to_string(),
            Value::String(response.doc_type.clone()),
        );
        buckyos.insert("source".to_string(), json!(response.source));
        buckyos.insert(
            "resolverRole".to_string(),
            Value::String(
                match request.profile {
                    SnDidResolverProfile::PublicSupplement => "supplement",
                    SnDidResolverProfile::InternalZoneResolver => "zone_resolver",
                }
                .to_string(),
            ),
        );
        buckyos.insert("profile".to_string(), json!(request.profile));

        if let Some(Value::Object(extra)) = extra_buckyos {
            for (key, value) in extra {
                buckyos.insert(key, value);
            }
        }

        if let Some(status) = response.document_status {
            buckyos.insert("documentStatus".to_string(), json!(status));
        } else {
            buckyos.remove("documentStatus");
        }

        response.metadata = json!({ "buckyos": buckyos });
    }
}

#[async_trait]
impl SnDidResolver for SnResolverBackedDidResolver {
    async fn resolve(
        &self,
        request: SnDidResolveRequest,
    ) -> SnResolverResult<SnDidResolveResponse> {
        self.resolve_request(&request).await
    }
}

pub fn normalize_sn_did_doc_type(doc_type: Option<&str>) -> Option<String> {
    doc_type.and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    })
}

struct WebDomainBinding {
    username: String,
    user_domain: String,
    device_name: Option<String>,
    zone: ZoneResolution,
}

impl WebDomainBinding {
    fn canonical_zone_did(&self) -> String {
        format!("did:bns:{}", self.zone.canonical_name)
    }

    fn mapped_bns_did(&self, doc_type: Option<&str>) -> SnResolverResult<DID> {
        let did = if let Some(device_name) = self.device_name.as_deref() {
            format!("did:bns:{}.{}", device_name, self.username)
        } else {
            format!("did:bns:{}", self.username)
        };
        DID::from_str(did.as_str()).map_err(|e| {
            SnResolverError::new(
                SnResolverErrorKind::InvalidDid,
                format!(
                    "invalid mapped BNS DID for doc_type {}: {}",
                    doc_type.unwrap_or(""),
                    e
                ),
            )
        })
    }
}

fn effective_bns_doc_type(did: &DID, doc_type: Option<&str>) -> String {
    doc_type.map(ToOwned::to_owned).unwrap_or_else(|| {
        if is_root_bns_did(did) {
            BNS_DOC_ZONE
        } else {
            "doc"
        }
        .to_string()
    })
}

fn is_root_bns_did(did: &DID) -> bool {
    did.method == "bns" && !did.id.contains('.')
}

fn normalize_host_lossy(hostname: &str) -> String {
    hostname.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn accepts_did_resolution(accept: Option<&str>) -> bool {
    accept
        .unwrap_or_default()
        .split(',')
        .map(|item| item.split(';').next().unwrap_or_default().trim())
        .any(|item| {
            item.eq_ignore_ascii_case("application/did-resolution")
                || item.eq_ignore_ascii_case(DID_RESOLUTION_CONTENT_TYPE)
        })
}

fn synthesize_owner_document(
    owner_did: &str,
    canonical_zone: &str,
    zone: &ZoneResolution,
) -> SnResolverResult<(Value, &'static str)> {
    if let Some(owner_config) = zone.owner.owner_config.as_ref() {
        if owner_config.get("verificationMethod").is_some() {
            let mut document = normalize_owner_config_document(
                owner_config.clone(),
                owner_did,
                canonical_zone,
                "bns-owner-config",
            );
            insert_document_provenance(
                &mut document,
                canonical_zone,
                "bns-owner-config",
                DEFAULT_SN_RESOLVER_TTL_SECS,
            );
            return Ok((document, "bns-owner-config"));
        }

        if let Some(jwk) = owner_key_from_config(owner_config) {
            let mut document =
                build_owner_document_from_jwk(owner_did, canonical_zone, jwk, "bns-owner-config")?;
            insert_document_provenance(
                &mut document,
                canonical_zone,
                "bns-owner-config",
                DEFAULT_SN_RESOLVER_TTL_SECS,
            );
            return Ok((document, "bns-owner-config"));
        }
    }

    if let Some(effective_owner) = zone.owner.effective_owner.as_deref() {
        if let Some(jwk) = key_like_string_to_jwk(effective_owner) {
            let mut document =
                build_owner_document_from_jwk(owner_did, canonical_zone, jwk, "effective-owner")?;
            insert_document_provenance(
                &mut document,
                canonical_zone,
                "effective-owner",
                DEFAULT_SN_RESOLVER_TTL_SECS,
            );
            return Ok((document, "effective-owner"));
        }
    }

    Err(SnResolverError::new(
        SnResolverErrorKind::DocumentNotFound,
        format!("owner key not found for {}", canonical_zone),
    ))
}

fn build_owner_document_from_jwk(
    owner_did: &str,
    canonical_zone: &str,
    jwk: Jwk,
    source: &'static str,
) -> SnResolverResult<Value> {
    let owner = DID::from_str(owner_did).map_err(|e| {
        SnResolverError::new(
            SnResolverErrorKind::InvalidDid,
            format!("invalid owner DID {}: {}", owner_did, e),
        )
    })?;
    let zone = DID::from_str(canonical_zone).map_err(|e| {
        SnResolverError::new(
            SnResolverErrorKind::InvalidDid,
            format!("invalid canonical zone DID {}: {}", canonical_zone, e),
        )
    })?;

    let mut config = OwnerConfig::new(
        owner.clone(),
        owner.id.clone(),
        format!("{}@{}", owner.id, owner_did),
        jwk,
    );
    config.set_default_zone_did(zone);
    config.extra_info.insert(
        "buckyos".to_string(),
        json!({
            "canonicalZone": canonical_zone,
            "source": source,
            "ttl": DEFAULT_SN_RESOLVER_TTL_SECS,
        }),
    );

    serde_json::to_value(config).map_err(|e| {
        SnResolverError::new(
            SnResolverErrorKind::BackendUnavailable,
            format!("encode synthesized owner document failed: {}", e),
        )
    })
}

fn normalize_owner_config_document(
    mut document: Value,
    owner_did: &str,
    canonical_zone: &str,
    source: &'static str,
) -> Value {
    if let Some(obj) = document.as_object_mut() {
        obj.insert("id".to_string(), Value::String(owner_did.to_string()));
        obj.entry("name".to_string())
            .or_insert_with(|| Value::String(owner_did.to_string()));
        obj.entry("full_name".to_string())
            .or_insert_with(|| Value::String(format!("{}@{}", owner_did, owner_did)));
        obj.entry("display_name".to_string())
            .or_insert_with(|| Value::String(format!("{}@{}", owner_did, owner_did)));
        obj.insert(
            "default_zone_did".to_string(),
            Value::String(canonical_zone.to_string()),
        );
        obj.insert(
            "binded_zone_list".to_string(),
            Value::Array(vec![Value::String(canonical_zone.to_string())]),
        );

        if let Some(methods) = obj
            .get_mut("verificationMethod")
            .and_then(Value::as_array_mut)
        {
            for method in methods {
                if let Some(method) = method.as_object_mut() {
                    method.insert(
                        "controller".to_string(),
                        Value::String(owner_did.to_string()),
                    );
                }
            }
        }

        merge_buckyos_object(
            obj,
            json!({
                "canonicalZone": canonical_zone,
                "source": source,
                "ttl": DEFAULT_SN_RESOLVER_TTL_SECS,
            }),
        );
    }
    document
}

fn insert_document_provenance(
    document: &mut Value,
    canonical_zone: &str,
    source: &'static str,
    ttl: u32,
) {
    if let Some(obj) = document.as_object_mut() {
        merge_buckyos_object(
            obj,
            json!({
                "canonicalZone": canonical_zone,
                "source": source,
                "ttl": ttl,
            }),
        );
    }
}

fn merge_buckyos_object(obj: &mut Map<String, Value>, value: Value) {
    let Some(extra) = value.as_object() else {
        return;
    };
    let buckyos = obj
        .entry("buckyos".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(buckyos) = buckyos.as_object_mut() {
        for (key, value) in extra {
            buckyos.insert(key.clone(), value.clone());
        }
    }
}

pub(crate) fn owner_key_from_config(value: &Value) -> Option<Jwk> {
    first_jwk_path(
        value,
        &[
            &["public_key"][..],
            &["owner_key"][..],
            &["default_key"][..],
            &["key"][..],
            &["verificationMethod", "0", "publicKeyJwk"][..],
        ],
    )
}

fn first_jwk_path(value: &Value, paths: &[&[&str]]) -> Option<Jwk> {
    for path in paths {
        if let Some(value) = value_path(value, path) {
            if let Some(jwk) = value_to_jwk(value) {
                return Some(jwk);
            }
        }
    }
    None
}

fn value_path<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        if let Ok(index) = key.parse::<usize>() {
            current = current.as_array()?.get(index)?;
        } else {
            current = current.get(*key)?;
        }
    }
    Some(current)
}

fn value_to_jwk(value: &Value) -> Option<Jwk> {
    match value {
        Value::Object(_) => serde_json::from_value(value.clone()).ok(),
        Value::String(value) => key_like_string_to_jwk(value.as_str()),
        _ => None,
    }
}

pub(crate) fn key_like_string_to_jwk(value: &str) -> Option<Jwk> {
    let value = value.trim().trim_end_matches(';');
    if value.is_empty() {
        return None;
    }

    if let Ok(jwk) = serde_json::from_str::<Jwk>(value) {
        return Some(jwk);
    }

    let value = value.strip_prefix("PKX=").unwrap_or(value);
    let x = value.split(':').next().unwrap_or(value);
    create_jwt_by_x(x).ok()
}

fn rewrite_web_document_identity(
    document: &mut EncodedDocument,
    request_did: &str,
    owner_did: &str,
    canonical_zone: &str,
    device_name: Option<&str>,
) {
    let EncodedDocument::JsonLd(value) = document else {
        return;
    };

    let Some(obj) = value.as_object_mut() else {
        return;
    };

    if let Some(existing_id) = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| *id != request_did)
        .map(ToOwned::to_owned)
    {
        obj.entry("did".to_string())
            .or_insert_with(|| Value::String(existing_id.clone()));
        obj.entry("canonical_did".to_string())
            .or_insert_with(|| Value::String(existing_id));
    }

    obj.insert("id".to_string(), Value::String(request_did.to_string()));
    obj.insert("owner".to_string(), Value::String(owner_did.to_string()));
    obj.insert(
        "canonical_zone".to_string(),
        Value::String(canonical_zone.to_string()),
    );

    if let Some(device_name) = device_name {
        obj.entry("device_name".to_string())
            .or_insert_with(|| Value::String(device_name.to_string()));
        obj.entry("name".to_string())
            .or_insert_with(|| Value::String(device_name.to_string()));
    }

    for key in ["zone_did", "zone"] {
        if obj
            .get(key)
            .and_then(Value::as_str)
            .map(|value| value.starts_with("did:bns:") || value == canonical_zone)
            .unwrap_or(false)
        {
            obj.insert(key.to_string(), Value::String(owner_did.to_string()));
        }
    }

    merge_buckyos_object(
        obj,
        json!({
            "canonicalZone": canonical_zone,
            "ownerConstraint": owner_did,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sn_resolver::{BnsOwner, BootDocument, ZoneDocument};
    use std::collections::HashMap;

    fn empty_zone_document() -> ZoneDocument {
        ZoneDocument {
            raw: None,
            jwt: None,
            boot_jwt: None,
            devices: HashMap::new(),
            gateway_device_name: None,
            gateway_ips: Vec::new(),
            ttl: None,
            version: None,
        }
    }

    fn empty_boot_document() -> BootDocument {
        BootDocument {
            raw: None,
            jwt: None,
            gateway_device_name: None,
            ttl: None,
            version: None,
        }
    }

    #[test]
    fn rewrites_web_device_document_identity_and_keeps_canonical_device_did() {
        let mut document = EncodedDocument::JsonLd(json!({
            "id": "did:dev:abc",
            "zone_did": "did:bns:alice",
            "name": "ood1"
        }));

        rewrite_web_document_identity(
            &mut document,
            "did:web:ood1.example.com",
            "did:web:example.com",
            "did:bns:alice",
            Some("ood1"),
        );

        let value = document.to_json_value().unwrap();
        assert_eq!(value["id"], "did:web:ood1.example.com");
        assert_eq!(value["did"], "did:dev:abc");
        assert_eq!(value["canonical_did"], "did:dev:abc");
        assert_eq!(value["owner"], "did:web:example.com");
        assert_eq!(value["zone_did"], "did:web:example.com");
        assert_eq!(value["buckyos"]["canonicalZone"], "did:bns:alice");
    }

    #[test]
    fn synthesizes_owner_document_from_effective_owner_key() {
        let zone = ZoneResolution {
            input: "example.com".to_string(),
            canonical_name: "alice".to_string(),
            zone_name: "alice".to_string(),
            owner: BnsOwner {
                name: "alice".to_string(),
                effective_owner: Some("T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8".to_string()),
                owner_config: None,
            },
            zone_doc: empty_zone_document(),
            boot_doc: empty_boot_document(),
            user_domain: Some("example.com".to_string()),
            self_cert: true,
            relay_sn: None,
            source: ZoneResolutionSource::UserDomain,
        };

        let (document, source) =
            synthesize_owner_document("did:web:example.com", "did:bns:alice", &zone).unwrap();

        assert_eq!(source, "effective-owner");
        assert_eq!(document["id"], "did:web:example.com");
        assert_eq!(document["binded_zone_list"][0], "did:bns:alice");
        assert_eq!(
            document["verificationMethod"][0]["controller"],
            "did:web:example.com"
        );
        assert_eq!(document["buckyos"]["canonicalZone"], "did:bns:alice");
    }

    #[test]
    fn parses_pkx_style_owner_key_strings() {
        let jwk =
            key_like_string_to_jwk("PKX=T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8:bns:alice;")
                .unwrap();
        let value = serde_json::to_value(jwk).unwrap();

        assert_eq!(value["x"], "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8");
    }

    #[test]
    fn emits_did_resolution_envelope_when_requested() {
        let response = SnDidResolveResponse {
            did: "did:web:example.com".to_string(),
            doc_type: "owner".to_string(),
            document: EncodedDocument::JsonLd(json!({ "id": "did:web:example.com" })),
            source: SnDidDocumentSource::SynthesizedOwnerDocument,
            profile: SnDidResolverProfile::InternalZoneResolver,
            document_status: Some(SnDidDocumentStatus::Active),
            metadata: json!({
                "buckyos": {
                    "resolverRole": "zone_resolver",
                    "canonicalZone": "did:bns:alice",
                }
            }),
        };

        assert_eq!(
            response.content_type_for_accept(Some("application/did-resolution")),
            DID_RESOLUTION_CONTENT_TYPE
        );
        let body: Value = serde_json::from_str(
            response
                .body_for_accept(Some("application/did-resolution"))
                .as_str(),
        )
        .unwrap();

        assert_eq!(body["didDocument"]["id"], "did:web:example.com");
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["documentStatus"],
            "active"
        );
        assert_eq!(
            body["didDocumentMetadata"]["buckyos"]["canonicalZone"],
            "did:bns:alice"
        );
    }
}
