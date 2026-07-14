//! `/kapi/sn/bns-proxy` RPC：SN 代付 gas 的受限 BNS 写入口。
//!
//! - `publish_dns_txt` / `publish_document`：需要 SN access token，`name` 必须
//!   等于 token 用户；
//! - `publish_relay_assignment` / `register_name_bootstrap`：internal/admin
//!   only（`preferred_rpc_path` 钉在 InternalRoot，外部 HTTP 路径不可达）。
//!
//! 所有参数结构 `deny_unknown_fields`：客户端不能塞入 `controller_address` /
//! `authority` 之类的字段来影响服务端的 controller 选择。成功返回只代表
//! TX 已投递（`status = submitted`），不等待 receipt。

use super::common::{
    normalize_evm_address, normalize_username, ok_response, parse_params,
    resolve_self_scoped_username, RpcCallResult,
};
use super::errors::{bns_proxy_error, parse_error, SnApiErrorCode};
use crate::sn_bns_proxy::{SnBnsProxy, SnBnsProxyInitialDocuments, SnBnsProxyRegisterParams};
use crate::SNServer;
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use bns_client::dns_document::DnsTxtRecord;
use bns_client::DnsTxtUpdate;
use cyfs_gateway_api::SnBnsProxyResp;
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;

const DEFAULT_DNS_TXT_TTL: u32 = 600;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishDnsTxtReq {
    #[serde(default)]
    request_id: Option<String>,
    #[allow(dead_code)]
    name: String,
    mode: String,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    records: Option<Vec<PublishDnsTxtRecord>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishDocumentReq {
    #[serde(default)]
    request_id: Option<String>,
    #[allow(dead_code)]
    name: String,
    doc_type: String,
    document: Value,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishDnsTxtRecord {
    #[serde(default)]
    ttl: Option<u32>,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishRelayAssignmentReq {
    #[serde(default)]
    request_id: Option<String>,
    name: String,
    relay_assignment: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisterNameBootstrapReq {
    #[serde(default)]
    request_id: Option<String>,
    name: String,
    asset_owner: String,
    #[serde(default)]
    owner_config: Option<Value>,
    #[serde(default)]
    initial_documents: Option<SnBnsProxyInitialDocuments>,
}

fn require_bns_proxy(server: &SNServer) -> RpcCallResult<Arc<SnBnsProxy>> {
    Ok(server.bns_proxy())
}

/// request_id 是幂等键：客户端未提供时生成随机 id（每次调用视为新意图）。
fn generate_request_id(operation: &str, name: &str) -> String {
    let mut random = [0u8; 8];
    rand::rng().fill_bytes(&mut random);
    format!("sn:{}:{}:{}", operation, name, hex::encode(random))
}

fn dns_txt_update_from_params(params: &PublishDnsTxtReq) -> RpcCallResult<DnsTxtUpdate> {
    match params.mode.trim() {
        "add" => {
            let value = params
                .value
                .clone()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    parse_error(
                        SnApiErrorCode::InvalidParams,
                        "publish_dns_txt mode=add requires value",
                    )
                })?;
            Ok(DnsTxtUpdate::Add {
                ttl: params.ttl.unwrap_or(DEFAULT_DNS_TXT_TTL),
                value,
            })
        }
        "remove" => {
            let value = params
                .value
                .clone()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    parse_error(
                        SnApiErrorCode::InvalidParams,
                        "publish_dns_txt mode=remove requires value",
                    )
                })?;
            Ok(DnsTxtUpdate::Remove { value })
        }
        "replace" => {
            let records = params.records.clone().ok_or_else(|| {
                parse_error(
                    SnApiErrorCode::InvalidParams,
                    "publish_dns_txt mode=replace requires records",
                )
            })?;
            let records = records
                .into_iter()
                .map(|record| DnsTxtRecord {
                    ttl: record.ttl.unwrap_or(DEFAULT_DNS_TXT_TTL),
                    value: record.value,
                })
                .collect();
            Ok(DnsTxtUpdate::Replace { records })
        }
        other => Err(parse_error(
            SnApiErrorCode::InvalidParams,
            format!("publish_dns_txt mode `{}` is not supported", other),
        )),
    }
}

pub(crate) async fn handle_bns_proxy(
    server: &SNServer,
    req: RPCRequest,
) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "publish_dns_txt" => {
            let params: PublishDnsTxtReq = parse_params(&req)?;
            // token 必须存在且 `name` == token 用户（cross-user 一律拒绝）。
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let update = dns_txt_update_from_params(&params)?;
            let request_id = params
                .request_id
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| generate_request_id("dns_txt", username.as_str()));
            let proxy = require_bns_proxy(server)?;
            let outcome = proxy
                .publish_dns_txt(username.as_str(), request_id, update)
                .await
                .map_err(bns_proxy_error)?;
            // 投递成功只做本地 DNS 缓存失效；权威状态等 bns-indexer 投影。
            server.invalidate_bns_name_dns_cache(username.as_str());
            ok_response(&req, SnBnsProxyResp { code: 0, outcome })
        }
        "publish_document" => {
            let params: PublishDocumentReq = parse_params(&req)?;
            // token 必须存在且 `name` == token 用户（cross-user 一律拒绝）。
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let is_object = params.document.is_object();
            let is_jwt = params
                .document
                .as_str()
                .is_some_and(is_non_empty_compact_jwt);
            if !is_object && !is_jwt {
                return Err(parse_error(
                    SnApiErrorCode::InvalidParams,
                    "document must be a JSON object or non-empty compact JWT string",
                ));
            }
            if params.doc_type.trim().eq_ignore_ascii_case("owner") && !is_object {
                return Err(parse_error(
                    SnApiErrorCode::InvalidParams,
                    "owner document must be a JSON object",
                ));
            }
            let request_id = params
                .request_id
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| generate_request_id("document", username.as_str()));
            let proxy = require_bns_proxy(server)?;
            let outcome = proxy
                .publish_document(
                    username.as_str(),
                    request_id,
                    params.doc_type,
                    params.document,
                )
                .await
                .map_err(bns_proxy_error)?;
            server.invalidate_bns_name_dns_cache(username.as_str());
            ok_response(&req, SnBnsProxyResp { code: 0, outcome })
        }
        "publish_relay_assignment" => {
            let params: PublishRelayAssignmentReq = parse_params(&req)?;
            let name = normalize_username(params.name.as_str())?;
            if !params.relay_assignment.is_object() {
                return Err(parse_error(
                    SnApiErrorCode::InvalidParams,
                    "relay_assignment must be a JSON object",
                ));
            }
            let request_id = params
                .request_id
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| generate_request_id("relay", name.as_str()));
            let proxy = require_bns_proxy(server)?;
            let outcome = proxy
                .publish_relay_assignment(name.as_str(), request_id, params.relay_assignment)
                .await
                .map_err(bns_proxy_error)?;
            server.invalidate_bns_name_dns_cache(name.as_str());
            ok_response(&req, SnBnsProxyResp { code: 0, outcome })
        }
        "register_name_bootstrap" => {
            // internal/admin 恢复与重放路径：不创建本地 SN 用户，只补 BNS name。
            let params: RegisterNameBootstrapReq = parse_params(&req)?;
            let name = normalize_username(params.name.as_str())?;
            SNServer::validate_registration_username(name.as_str())
                .map_err(|message| parse_error(SnApiErrorCode::InvalidUsername, message))?;
            let asset_owner = normalize_evm_address(params.asset_owner.as_str(), "asset_owner")?;
            let request_id = params
                .request_id
                .clone()
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| format!("sn:register:{}", name));
            let proxy = require_bns_proxy(server)?;
            let outcome = proxy
                .register_bootstrap(SnBnsProxyRegisterParams {
                    request_id,
                    name: name.clone(),
                    asset_owner,
                    owner_config: params
                        .owner_config
                        .clone()
                        .unwrap_or_else(|| super::auth::default_owner_config(name.as_str())),
                    initial_documents: params.initial_documents.clone().unwrap_or_default(),
                })
                .await
                .map_err(bns_proxy_error)?;
            server.invalidate_bns_name_dns_cache(name.as_str());
            ok_response(&req, SnBnsProxyResp { code: 0, outcome })
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}

fn is_non_empty_compact_jwt(value: &str) -> bool {
    let mut parts = value.trim().split('.');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next()),
        (Some(header), Some(payload), Some(signature), None)
            if !header.is_empty() && !payload.is_empty() && !signature.is_empty()
    )
}
