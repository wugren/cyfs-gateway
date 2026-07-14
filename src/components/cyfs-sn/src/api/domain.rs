use super::common::{
    ok_response, parse_params, require_account_username, IntoRpcResult, RpcCallResult,
};
use super::errors::{parse_error, reason_error, SnApiErrorCode};
use crate::{canonical_user_domain, pkx_record_name, txt_matches_pkx};
use crate::{SNServer, SnError, SnErrorCode};
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use cyfs_gateway_api::{SnBindDomainResp, SnSuccessResp};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct DomainReq {
    domain: String,
    // breaking change：客户端传入的 txt_records/txt_record/record 不再是
    // 信任边界的一部分——proof 只认 SN 服务端自己的外部 DNS 查询结果。
    // 未知字段直接忽略（serde 默认行为），旧客户端携带也不会生效。
}

fn map_domain_error(error: SnError) -> RPCErrors {
    match error.code() {
        SnErrorCode::InvalidInput | SnErrorCode::Conflict | SnErrorCode::Blocked => {
            parse_error(SnApiErrorCode::InvalidDomain, error.to_string())
        }
        SnErrorCode::NotFound => {
            if error.to_string().contains("user not found") {
                parse_error(SnApiErrorCode::UserNotFound, error.to_string())
            } else {
                parse_error(SnApiErrorCode::InvalidDomain, error.to_string())
            }
        }
        SnErrorCode::DBError | SnErrorCode::RemoteError | SnErrorCode::Failed => {
            reason_error(SnApiErrorCode::InternalError, error.to_string())
        }
        SnErrorCode::StaleReport => reason_error(SnApiErrorCode::InternalError, error.to_string()),
    }
}

/// proof 失败/暂不可判定的可重试错误：携带待配置的 `pkx_record_name` 与期望
/// `pkx`，不写入或修改任何 binding。
fn domain_proof_error(
    domain: &str,
    record_name: &str,
    expected_pkx: &str,
    reason: impl AsRef<str>,
) -> RPCErrors {
    parse_error(
        SnApiErrorCode::DomainProofFailed,
        json!({
            "domain": domain,
            "pkx_record_name": record_name,
            "pkx": expected_pkx,
            "retryable": true,
            "reason": reason.as_ref(),
        })
        .to_string(),
    )
}

/// 一站式绑定：规范化域名 → 校验用户 active → 从 `did:bns:<username>` 链上
/// owner document / authority key（回落本地缓存）计算期望 PKX → SN 服务端
/// 自己查外部 DNS TXT → 命中后在同一事务内激活绑定（supersede 旧 owner）。
async fn handle_bind(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    let username = require_account_username(server, &req).await?;
    let params: DomainReq = parse_params(&req)?;
    let canonical_domain = canonical_user_domain(params.domain.as_str()).ok_or_else(|| {
        parse_error(
            SnApiErrorCode::InvalidDomain,
            format!("invalid domain: {}", params.domain),
        )
    })?;

    let user = server
        .auth_db()
        .get_user_info(username.as_str())
        .await
        .into_rpc()?
        .ok_or_else(|| parse_error(SnApiErrorCode::UserNotFound, "user not found"))?;
    if !matches!(user.state, crate::UserState::Active) {
        return Err(parse_error(
            SnApiErrorCode::UserNotActivated,
            "user is not active",
        ));
    }

    let (expected_pkx, pkx_source) = server
        .expected_user_domain_pkx(username.as_str(), &user)
        .await
        .map_err(map_domain_error)?;
    let record_name = pkx_record_name(canonical_domain.as_str());

    // 外部 DNS proof path：只信 SN 自己的 DoH 查询结果。
    let txt_records = match server.pkx_txt_resolver().query_txt(record_name.as_str()).await {
        Ok(records) => records,
        Err(e) => {
            log::warn!(
                "domain.bind {} for {}: external DNS query via {} failed: {}",
                canonical_domain,
                username,
                server.pkx_txt_resolver().describe(),
                e
            );
            return Err(domain_proof_error(
                canonical_domain.as_str(),
                record_name.as_str(),
                expected_pkx.as_str(),
                format!("external DNS query failed: {}", e),
            ));
        }
    };

    if !txt_records
        .iter()
        .any(|txt| txt_matches_pkx(txt.as_str(), expected_pkx.as_str()))
    {
        return Err(domain_proof_error(
            canonical_domain.as_str(),
            record_name.as_str(),
            expected_pkx.as_str(),
            format!(
                "expected PKX TXT record not found at {} ({} TXT records observed)",
                record_name,
                txt_records.len()
            ),
        ));
    }

    let binding = server
        .auth_db()
        .activate_user_domain_binding(
            username.as_str(),
            canonical_domain.as_str(),
            expected_pkx.as_str(),
        )
        .await
        .map_err(map_domain_error)?;
    log::info!(
        "domain.bind {} activated for {} (pkx source: {})",
        binding.domain,
        username,
        pkx_source
    );
    server
        .invalidate_name_info_cache_for_username(username.as_str())
        .await;
    ok_response(
        &req,
        SnBindDomainResp {
            code: 0,
            domain: binding.domain,
            pkx: binding.pkx,
            pkx_record_name: binding.pkx_record_name,
            pkx_source: pkx_source.to_string(),
            verified_at: binding.verified_at,
        },
    )
}

pub(crate) async fn handle_domain(
    server: &SNServer,
    req: RPCRequest,
) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "bind" => handle_bind(server, req).await,
        "unbind" => {
            let username = require_account_username(server, &req).await?;
            let params: DomainReq = parse_params(&req)?;
            server
                .auth_db()
                .unbind_user_domain(username.as_str(), params.domain.as_str())
                .await
                .into_rpc()?;
            server
                .invalidate_name_info_cache_for_username(username.as_str())
                .await;
            ok_response(&req, SnSuccessResp { code: 0 })
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
