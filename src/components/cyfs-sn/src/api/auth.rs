use super::common::{
    build_profile_response, normalize_evm_address, normalize_username, now_secs, ok_response,
    parse_params, require_account_username, ActiveCodeReq, IntoRpcResult, LoginReq, NameReq,
    RefreshReq, RegisterReq, RpcCallResult,
};
use super::errors::{bns_proxy_error, parse_error, reason_error, SnApiErrorCode};
use crate::sn_auth_manager::{hash_password, verify_password, PASSWORD_ALGO};
use crate::sn_bns_proxy::SnBnsProxyRegisterParams;
use crate::{AllocateZoneRelayReq, SNServer};
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use cyfs_gateway_api::{
    SnAuthRefreshResp, SnAuthSessionResp, SnBnsProxyTxOutcome, SnCheckUsernameReason,
    SnCheckUsernameResp, SnSuccessResp,
};
use log::{info, warn};
use serde_json::{json, Value};
use std::net::IpAddr;

async fn build_auth_success_response(
    server: &SNServer,
    req: &RPCRequest,
    username: &str,
    need_bind_owner_key: bool,
    bns: Option<SnBnsProxyTxOutcome>,
) -> RpcCallResult<RPCResponse> {
    let access_token = server.auth().issue_access_session(username)?;
    let refresh_token = server.auth().issue_refresh_session(username)?;
    server
        .auth_db()
        .create_account_session(
            access_token.session_id.as_str(),
            username,
            access_token.token_aud.as_str(),
            access_token.issued_at,
            access_token.expires_at,
        )
        .await
        .into_rpc()?;
    server
        .auth_db()
        .create_account_session(
            refresh_token.session_id.as_str(),
            username,
            refresh_token.token_aud.as_str(),
            refresh_token.issued_at,
            refresh_token.expires_at,
        )
        .await
        .into_rpc()?;
    ok_response(
        req,
        SnAuthSessionResp {
            code: 0,
            access_token: access_token.token,
            refresh_token: refresh_token.token,
            need_bind_owner_key,
            bns,
        },
    )
}

pub(crate) fn default_owner_config(username: &str) -> Value {
    json!({
        "name": username,
        "created_by": "cyfs-sn",
        "created_at": now_secs(),
    })
}

pub(crate) async fn handle_auth(
    server: &SNServer,
    req: RPCRequest,
    source_ip: Option<IpAddr>,
) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "check_username" => {
            let params: NameReq = parse_params(&req)?;
            let username = params.name.trim().to_lowercase();
            let (valid, reason, message) =
                if let Err(message) = SNServer::validate_registration_username(username.as_str()) {
                    (false, SnCheckUsernameReason::InvalidUsername, message)
                } else {
                    let exists = server
                        .auth_db()
                        .is_user_exist(username.as_str())
                        .await
                        .into_rpc()?;
                    if exists {
                        (
                            false,
                            SnCheckUsernameReason::AlreadyExists,
                            format!("username {} already exists", username),
                        )
                    } else {
                        (true, SnCheckUsernameReason::Ok, String::new())
                    }
                };

            ok_response(
                &req,
                SnCheckUsernameResp {
                    valid,
                    reason,
                    message,
                    normalized_name: username,
                },
            )
        }
        "check_active_code" => {
            let params: ActiveCodeReq = parse_params(&req)?;
            let proxy_req = RPCRequest {
                params: json!({ "active_code": params.active_code }),
                ..req
            };
            server.check_active_code(proxy_req).await
        }
        "register" => {
            let params: RegisterReq = parse_params(&req)?;
            let username = normalize_username(params.name.as_str())?;
            SNServer::validate_registration_username(username.as_str())
                .map_err(|message| parse_error(SnApiErrorCode::InvalidUsername, message))?;
            let email = crate::canonical_email(params.email.as_str())
                .map_err(|error| parse_error(SnApiErrorCode::InvalidEmail, error.msg()))?;
            let request_id = params
                .request_id
                .clone()
                .unwrap_or_else(|| format!("sn:register:{}", username));
            info!(
                "sn auth register started: username={} request_id={} bns_enabled={} asset_owner_supplied={} initial_documents_empty={}",
                username,
                request_id,
                true,
                params.asset_owner.is_some(),
                params
                    .initial_documents
                    .as_ref()
                    .map_or(true, |documents| documents.is_empty())
            );
            // 锁覆盖预查、可选 BNS bootstrap 和本地事务，避免同进程并发请求
            // 在邮箱冲突已知前产生两次外部注册副作用。SQLite UNIQUE 索引仍兜底。
            let _email_locker =
                async_named_locker::Locker::get_locker(format!("sn_auth_register_email_{}", email))
                    .await;
            if server
                .auth_db()
                .is_user_exist(username.as_str())
                .await
                .into_rpc()?
                || server
                    .auth_db()
                    .get_auth(username.as_str())
                    .await
                    .into_rpc()?
                    .is_some()
            {
                return Err(parse_error(
                    SnApiErrorCode::UsernameAlreadyExists,
                    format!("username {} already exists", username),
                ));
            }
            if server
                .auth_db()
                .get_user_by_email(email.as_str())
                .await
                .into_rpc()?
                .is_some()
            {
                return Err(parse_error(
                    SnApiErrorCode::EmailAlreadyBound,
                    "email is already bound to another account",
                ));
            }
            if !server
                .auth_db()
                .check_active_code(params.active_code.as_str())
                .await
                .into_rpc()?
            {
                return Err(parse_error(
                    SnApiErrorCode::InvalidActiveCode,
                    "register failed, invalid activation code",
                ));
            }
            info!(
                "sn auth register prechecks passed: username={} request_id={}",
                username, request_id
            );
            let (password_hash, password_salt) = hash_password(params.pwd_hash.as_str())?;
            let need_bind_owner_key = false;
            // BNS bootstrap 在本地建号之前执行：失败则不创建本地用户，避免
            // 本地账号与 BNS name 不一致（同 request_id 重试幂等）。
            let bns_info = {
                let proxy = server.bns_proxy();
                let asset_owner = match params.asset_owner.as_deref() {
                    Some(value) => normalize_evm_address(value, "asset_owner")?,
                    None if proxy.require_user_asset_owner() => {
                        return Err(parse_error(
                            SnApiErrorCode::InvalidParams,
                            "asset_owner is required: upload the user's owner EVM address",
                        ));
                    }
                    // devtest 回落：使用该用户绑定 controller 的地址。
                    None => proxy
                        .default_asset_owner_for_user(username.as_str())
                        .await
                        .map_err(bns_proxy_error)?,
                };
                info!(
                    "sn auth register submitting BNS registerName: username={} request_id={}",
                    username, request_id
                );
                let outcome = proxy
                    .register_bootstrap_and_wait(SnBnsProxyRegisterParams {
                        request_id: request_id.clone(),
                        name: username.clone(),
                        asset_owner,
                        owner_config: params
                            .owner_config
                            .clone()
                            .unwrap_or_else(|| default_owner_config(username.as_str())),
                        initial_documents: params.initial_documents.clone().unwrap_or_default(),
                    })
                    .await
                    .map_err(bns_proxy_error)?;
                server.invalidate_bns_name_dns_cache(username.as_str());
                info!(
                    "sn auth register BNS bootstrap confirmed: username={} request_id={} tx_hash={} reused={}",
                    username,
                    request_id,
                    outcome.tx_hash.as_deref().unwrap_or("-"),
                    outcome.reused
                );
                Some(outcome)
            };
            let ok = server
                .auth_db()
                .register_user(
                    params.active_code.as_str(),
                    username.as_str(),
                    email.as_str(),
                    password_hash.as_str(),
                    password_salt.as_str(),
                    PASSWORD_ALGO,
                )
                .await
                .map_err(|error| {
                    if error.code() == crate::SnErrorCode::Conflict
                        && error.msg().starts_with("email already bound:")
                    {
                        parse_error(
                            SnApiErrorCode::EmailAlreadyBound,
                            "email is already bound to another account",
                        )
                    } else {
                        reason_error(SnApiErrorCode::InternalError, error.to_string())
                    }
                })?;
            if !ok {
                return Err(parse_error(
                    SnApiErrorCode::InvalidActiveCode,
                    "register failed, invalid activation code",
                ));
            }
            info!(
                "sn auth register local account created: username={} request_id={}",
                username, request_id
            );
            server
                .invalidate_name_info_cache_for_username(username.as_str())
                .await;
            // BNS 和本地账号创建都可能已产生不可回滚状态。Relay 暂不可用、
            // GeoIP 失败或调度存储失败时只记录 pending，不让注册失败。
            match server
                .relay_manager()
                .allocate_zone_relay(AllocateZoneRelayReq {
                    zone: username.clone(),
                    preferred_region: params.region,
                    source_ip,
                    reason: "register".to_string(),
                    source_version: None,
                })
                .await
            {
                Ok(assignment) => info!(
                    "sn auth register relay assigned: username={} request_id={} relay_id={} generation={}",
                    username, request_id, assignment.relay_id, assignment.generation
                ),
                Err(error) => warn!(
                    "sn auth register relay assignment pending: username={} request_id={} error_code={:?} error={}",
                    username,
                    request_id,
                    error.code(),
                    error.msg()
                ),
            }
            let response = build_auth_success_response(
                server,
                &req,
                username.as_str(),
                need_bind_owner_key,
                bns_info,
            )
            .await?;
            info!(
                "sn auth register completed: username={} request_id={} need_bind_owner_key={}",
                username, request_id, need_bind_owner_key
            );
            Ok(response)
        }
        "login" => {
            let params: LoginReq = parse_params(&req)?;
            let username = normalize_username(params.name.as_str())?;
            let auth = server
                .auth_db()
                .get_auth(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| {
                    parse_error(SnApiErrorCode::UserAuthNotFound, "user auth not found")
                })?;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| {
                    parse_error(SnApiErrorCode::UserNotActivated, "user not activated")
                })?;
            if !matches!(user.state, crate::UserState::Active) {
                return Err(parse_error(
                    SnApiErrorCode::UserNotActivated,
                    "user is not active",
                ));
            }
            if !verify_password(params.pwd_hash.as_str(), &auth)? {
                return Err(parse_error(
                    SnApiErrorCode::InvalidPassword,
                    "invalid password",
                ));
            }
            server
                .auth_db()
                .update_last_login(username.as_str(), now_secs())
                .await
                .into_rpc()?;
            build_auth_success_response(server, &req, username.as_str(), false, None).await
        }
        "refresh" => {
            let params: RefreshReq = parse_params(&req)?;
            let refresh_session = server
                .auth()
                .verify_refresh_session(params.refresh_token.as_str())?;
            crate::sn_authority::validate_refresh_session(
                server,
                &refresh_session,
                params.refresh_token.as_str(),
            )
            .await?;
            let username = refresh_session
                .sub
                .ok_or_else(|| parse_error(SnApiErrorCode::InvalidToken, "subject is none"))?;
            let access_token = server.auth().issue_access_session(username.as_str())?;
            server
                .auth_db()
                .create_account_session(
                    access_token.session_id.as_str(),
                    username.as_str(),
                    access_token.token_aud.as_str(),
                    access_token.issued_at,
                    access_token.expires_at,
                )
                .await
                .into_rpc()?;
            ok_response(
                &req,
                SnAuthRefreshResp {
                    code: 0,
                    access_token: access_token.token,
                },
            )
        }
        "logout" => {
            if let Some(token) = req.token.as_deref() {
                if let Ok(session) = server.auth().verify_access_session(token) {
                    if let Some(session_id) = crate::sn_authority::session_id(&session, token) {
                        server
                            .auth_db()
                            .revoke_account_session(session_id.as_str(), now_secs())
                            .await
                            .into_rpc()?;
                    }
                }
            }
            if let Some(refresh_token) = req
                .params
                .get("refresh_token")
                .and_then(|value| value.as_str())
            {
                if let Ok(session) = server.auth().verify_refresh_session(refresh_token) {
                    if let Some(session_id) =
                        crate::sn_authority::session_id(&session, refresh_token)
                    {
                        server
                            .auth_db()
                            .revoke_account_session(session_id.as_str(), now_secs())
                            .await
                            .into_rpc()?;
                    }
                }
            }
            ok_response(&req, SnSuccessResp { code: 0 })
        }
        "me" => {
            let username = require_account_username(server, &req).await?;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnApiErrorCode::UserNotFound, "user not found"))?;
            ok_response(&req, build_profile_response(username.as_str(), &user))
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}
