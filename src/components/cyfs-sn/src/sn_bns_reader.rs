use crate::sn_resolver::{
    BnsDocument, BnsDocumentContent, BnsDocumentMeta, BnsDocumentReader, BnsOwner, SnResolverError,
    SnResolverResult,
};
use async_trait::async_trait;
use bns_client::{BnsClientError, BnsRpcApi, BnsRpcClient, DocumentStatus};
use serde_json::Value;

pub struct BnsRpcDocumentReader {
    client: BnsRpcClient,
}

impl BnsRpcDocumentReader {
    pub fn new(client: BnsRpcClient) -> Self {
        Self { client }
    }

    fn is_name_not_found(error: &BnsClientError) -> bool {
        error.is_registry_code("NAME_NOT_FOUND")
    }

    fn is_document_not_found(error: &BnsClientError) -> bool {
        error.is_registry_code("NAME_NOT_FOUND")
            || error.is_registry_code("DOCUMENT_NOT_FOUND")
            || error.is_registry_code("DOCUMENT_INCONSISTENT")
    }

    fn backend_error(context: &str, error: impl std::fmt::Display) -> SnResolverError {
        SnResolverError::backend(format!("{}: {}", context, error))
    }

    async fn owner_config(&self, name: &str) -> SnResolverResult<Option<Value>> {
        match self.client.resolve_document(name, "owner").await {
            Ok(result) => {
                if result.status != DocumentStatus::Active {
                    return Ok(None);
                }
                Ok(Self::decode_inline_document_value(
                    result.document_state.document.inline_document.as_slice(),
                    name,
                    "owner",
                )?)
            }
            Err(error) if Self::is_document_not_found(&error) => Ok(None),
            Err(error) => Err(Self::backend_error(
                format!("resolve BNS owner document {}", name).as_str(),
                error,
            )),
        }
    }

    fn decode_inline_document_value(
        bytes: &[u8],
        name: &str,
        doc_type: &str,
    ) -> SnResolverResult<Option<Value>> {
        if bytes.is_empty() {
            return Ok(None);
        }

        serde_json::from_slice::<Value>(bytes)
            .map(Some)
            .map_err(|e| {
                Self::backend_error(
                    format!("decode BNS inline JSON document {}/{}", name, doc_type).as_str(),
                    e,
                )
            })
    }

    fn decode_document_content(
        name: &str,
        doc_type: &str,
        storage_type: &str,
        inline_document: &[u8],
    ) -> SnResolverResult<BnsDocumentContent> {
        if storage_type != "inline" {
            return Err(SnResolverError::backend(format!(
                "BNS document {}/{} uses unsupported storage type {}",
                name, doc_type, storage_type
            )));
        }

        if let Ok(value) = serde_json::from_slice::<Value>(inline_document) {
            return Ok(BnsDocumentContent::Json(value));
        }

        let text = String::from_utf8(inline_document.to_vec()).map_err(|e| {
            Self::backend_error(
                format!("decode BNS inline text document {}/{}", name, doc_type).as_str(),
                e,
            )
        })?;
        Ok(BnsDocumentContent::Text(text))
    }
}

#[async_trait]
impl BnsDocumentReader for BnsRpcDocumentReader {
    async fn resolve_owner(&self, name: &str) -> SnResolverResult<Option<BnsOwner>> {
        let owner = match self.client.resolve_owner(name).await {
            Ok(owner) => owner,
            Err(error) if Self::is_name_not_found(&error) => return Ok(None),
            Err(error) => {
                return Err(Self::backend_error(
                    format!("resolve BNS owner {}", name).as_str(),
                    error,
                ))
            }
        };

        let owner_config = self.owner_config(name).await?;
        let effective_owner = if owner.effective_owner.value.is_empty() {
            None
        } else {
            Some(owner.effective_owner.value)
        };

        Ok(Some(BnsOwner {
            name: name.to_string(),
            effective_owner,
            owner_config,
        }))
    }

    async fn get_document(
        &self,
        name: &str,
        doc_type: &str,
    ) -> SnResolverResult<Option<BnsDocument>> {
        let result = match self.client.resolve_document(name, doc_type).await {
            Ok(result) => result,
            Err(error) if Self::is_document_not_found(&error) => return Ok(None),
            Err(error) => {
                return Err(Self::backend_error(
                    format!("resolve BNS document {}/{}", name, doc_type).as_str(),
                    error,
                ))
            }
        };

        let state = result.document_state;
        if result.status != DocumentStatus::Active {
            return Ok(None);
        }
        let content = Self::decode_document_content(
            state.name.as_str(),
            state.doc_type.as_str(),
            state.document.storage_type.as_str(),
            state.document.inline_document.as_slice(),
        )?;

        Ok(Some(BnsDocument {
            name: state.name,
            doc_type: state.doc_type,
            content,
            meta: BnsDocumentMeta {
                version: Some(state.version),
                name_seq: Some(result.name_state.name_seq),
                updated_at: Some(result.name_state.updated_at),
                ttl: None,
            },
        }))
    }
}
