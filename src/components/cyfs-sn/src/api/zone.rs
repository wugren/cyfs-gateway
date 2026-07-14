use super::common::{ok_response, IntoRpcResult, RpcCallResult};
use super::errors::{parse_error, SnApiErrorCode};
use crate::sn_authority::{require_sn_user_or_device, AuthContext};
use crate::{SNServer, ZoneInfo};
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use cyfs_gateway_api::SnZoneInfoResp;
use serde_json::Value;

/// `zone.get_info` 参数固定为 `{}`：zone 只能从已验证 token 推导。拒绝而非
/// 忽略 `zone`/`username` 等字段，否则调用方会误以为查询了指定的 zone。
fn ensure_empty_params(req: &RPCRequest) -> RpcCallResult<()> {
    match &req.params {
        Value::Null => Ok(()),
        Value::Object(map) if map.is_empty() => Ok(()),
        _ => Err(parse_error(
            SnApiErrorCode::InvalidParams,
            "zone.get_info takes no params; zone is derived from the verified token",
        )),
    }
}

pub(crate) async fn handle_zone(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "get_info" => {
            ensure_empty_params(&req)?;
            let zone = match require_sn_user_or_device(server, &req).await? {
                AuthContext::SnUser { username, .. } => username,
                AuthContext::Device { zone, .. } => zone,
            };
            let info = server
                .auth_db()
                .get_zone_info(zone.as_str())
                .await
                .into_rpc()?
                .unwrap_or_else(|| ZoneInfo::default_for(zone.as_str()));
            // 只暴露客户端可见的稳定运行态；relay_id、负载、backup relay 等
            // 调度内部状态不出现在该视图。
            ok_response(
                &req,
                SnZoneInfoResp {
                    code: 0,
                    zone,
                    bns_name: info.bns_name,
                    relay_sn: info.relay_sn,
                    self_cert: info.self_cert,
                    cert_checked_at: info.cert_checked_at,
                    cert_expires_at: info.cert_expires_at,
                    source_version: info.source_version,
                    updated_at: info.updated_at,
                },
            )
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
