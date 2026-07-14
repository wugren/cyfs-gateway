use crate::SNServer;
use ::kRPC::*;
use cyfs_gateway_api::SnUserProfileResp;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use super::errors::{SnApiErrorCode, parse_error, reason_error};

pub(crate) type RpcCallResult<T> = std::result::Result<T, RPCErrors>;

pub(crate) trait IntoRpcResult<T> {
    fn into_rpc(self) -> RpcCallResult<T>;
}

impl<T> IntoRpcResult<T> for crate::SnResult<T> {
    fn into_rpc(self) -> RpcCallResult<T> {
        self.map_err(|e| reason_error(SnApiErrorCode::InternalError, e.to_string()))
    }
}

#[derive(Deserialize)]
pub(crate) struct NameReq {
    pub(crate) name: String,
}

#[derive(Deserialize)]
pub(crate) struct ActiveCodeReq {
    pub(crate) active_code: String,
}

#[derive(Deserialize)]
pub(crate) struct RegisterReq {
    pub(crate) name: String,
    /// 必填。使用 default 让缺字段也走稳定的 `invalid_email` 业务错误。
    #[serde(default)]
    pub(crate) email: String,
    pub(crate) pwd_hash: String,
    pub(crate) active_code: String,
    /// 非可信的 relay 地区偏好；具体节点只能由 relay manager 选择。
    #[serde(default)]
    pub(crate) region: Option<String>,
    #[serde(default)]
    pub(crate) request_id: Option<String>,
    /// 用户 owner EVM 地址。bns proxy 生产模式必填；devtest
    /// （require_user_asset_owner=false）缺省时回落为绑定 controller 地址。
    #[serde(default)]
    pub(crate) asset_owner: Option<String>,
    #[serde(default)]
    pub(crate) owner_config: Option<Value>,
    /// 注册时随 registerName 原子发布的初始 documents（zone/boot/dns_txt）。
    #[serde(default)]
    pub(crate) initial_documents: Option<crate::sn_bns_proxy::SnBnsProxyInitialDocuments>,
}

#[derive(Deserialize)]
pub(crate) struct LoginReq {
    pub(crate) name: String,
    pub(crate) pwd_hash: String,
}

#[derive(Deserialize)]
pub(crate) struct RefreshReq {
    pub(crate) refresh_token: String,
}

#[derive(Deserialize)]
pub(crate) struct SetSelfCertReq {
    pub(crate) self_cert: bool,
    #[serde(default)]
    pub(crate) device_did: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct QueryByDidReq {
    pub(crate) source_device_id: String,
}

#[derive(Deserialize)]
pub(crate) struct QueryByHostnameReq {
    pub(crate) dest_host: String,
}

#[derive(Deserialize)]
pub(crate) struct AddDnsRecordReq {
    pub(crate) device_did: String,
    pub(crate) domain: String,
    pub(crate) record_type: String,
    pub(crate) record: String,
    #[serde(default)]
    pub(crate) ttl: Option<u32>,
    #[serde(default, rename = "has_cert")]
    pub(crate) _has_cert: Option<bool>,
}

#[derive(Deserialize)]
pub(crate) struct RemoveDnsRecordReq {
    pub(crate) device_did: String,
    pub(crate) domain: String,
    pub(crate) record_type: String,
    #[serde(default)]
    pub(crate) record: Option<String>,
    #[serde(default, rename = "has_cert")]
    pub(crate) _has_cert: Option<bool>,
}

pub(crate) fn parse_params<T>(req: &RPCRequest) -> RpcCallResult<T>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_value(req.params.clone()).map_err(|e| {
        parse_error(
            SnApiErrorCode::InvalidParams,
            format!("{}: {}", req.method, e),
        )
    })
}

pub(crate) fn ok_response<T>(req: &RPCRequest, value: T) -> RpcCallResult<RPCResponse>
where
    T: Serialize,
{
    let value = serde_json::to_value(value).map_err(|e| {
        reason_error(
            SnApiErrorCode::InternalError,
            format!("serialize {} response failed: {e}", req.method),
        )
    })?;
    Ok(RPCResponse::create_by_req(RPCResult::Success(value), req))
}

pub(crate) fn normalize_username(username: &str) -> RpcCallResult<String> {
    let username = username.trim().to_lowercase();
    if username.is_empty() {
        return Err(parse_error(
            SnApiErrorCode::InvalidUsername,
            "username is empty",
        ));
    }
    if SNServer::contains_special_chars(username.as_str()) {
        return Err(parse_error(
            SnApiErrorCode::InvalidUsername,
            "username contains special characters",
        ));
    }
    Ok(username)
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn is_evm_address(value: &str) -> bool {
    value
        .strip_prefix("0x")
        .is_some_and(|hex| hex.len() == 40 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

pub(crate) fn normalize_evm_address(value: &str, field: &str) -> RpcCallResult<String> {
    let value = value.trim();
    if is_evm_address(value) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err(parse_error(
            SnApiErrorCode::InvalidParams,
            format!("{field} must be a 0x-prefixed EVM address"),
        ))
    }
}

pub(crate) fn build_profile_response(
    username: &str,
    user: &crate::SNUserInfo,
) -> SnUserProfileResp {
    SnUserProfileResp {
        code: 0,
        name: username.to_string(),
        owner_key_bound: !user.public_key.trim().is_empty(),
        user_domain: user.user_domain.clone(),
        self_cert: user.self_cert,
        sn_ips: user
            .sn_ips
            .as_ref()
            .and_then(|value| serde_json::from_str::<Vec<String>>(value).ok()),
        zone_config: user.zone_config.clone(),
    }
}

pub(crate) async fn require_account_username(
    server: &SNServer,
    req: &RPCRequest,
) -> RpcCallResult<String> {
    let context = crate::sn_authority::require_sn_user(server, req).await?;
    context
        .sn_username()
        .map(ToString::to_string)
        .ok_or_else(|| parse_error(SnApiErrorCode::AuthRequired, "session token is not a user"))
}

pub(crate) async fn resolve_self_scoped_username(
    server: &SNServer,
    req: &RPCRequest,
    allow_anonymous_name: bool,
) -> RpcCallResult<String> {
    let requested_name = req
        .params
        .get("name")
        .and_then(|value| value.as_str())
        .map(normalize_username)
        .transpose()?;

    match req.token.as_ref() {
        Some(_) => {
            let username = require_account_username(server, req).await?;
            if let Some(requested_name) = requested_name {
                if requested_name != username {
                    return Err(parse_error(
                        SnApiErrorCode::CrossUserAccessDenied,
                        "cross-user access is not allowed",
                    ));
                }
            }
            Ok(username)
        }
        None if allow_anonymous_name => requested_name.ok_or_else(|| {
            parse_error(
                SnApiErrorCode::InvalidParams,
                "name is required when token is absent",
            )
        }),
        None => Err(parse_error(
            SnApiErrorCode::AuthRequired,
            "session_token is none",
        )),
    }
}
