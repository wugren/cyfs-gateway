use crate::api::{parse_error, reason_error, RpcCallResult, SnApiErrorCode};
use crate::{SNServer, SnResolverErrorKind, UserState};
use cyfs_gateway_api::SN_DEVICE_TOKEN_AUD;
use jsonwebtoken::DecodingKey;
use kRPC::{RPCRequest, RPCSessionToken};
use name_lib::DID;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

/// 设备 token exp 的服务端硬上限：签发方（node_daemon）默认 10 分钟，
/// 这里放宽到 24h 容忍时钟偏差与低频上报，但拒绝事实上的长寿命凭证。
const MAX_DEVICE_TOKEN_TTL_SECS: u64 = 60 * 60 * 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum AuthContext {
    SnUser {
        username: String,
        session_id: Option<String>,
    },
    /// 设备私钥签名 token 校验出的设备上下文（SN-Auth.md「权限原则」）。
    /// 只代表「zone 内某台已登记设备」，不等价于 SnUser，也不携带任何
    /// BNS owner 权限。
    Device {
        /// 设备所属 zone 的 sn_user username。
        zone: String,
        device_name: String,
        /// 设备 key DID（`did:dev:<x>`），已与 zone 权威侧登记的设备公钥锚定。
        did: String,
    },
}

impl AuthContext {
    pub(crate) fn sn_username(&self) -> Option<&str> {
        match self {
            Self::SnUser { username, .. } => Some(username),
            Self::Device { .. } => None,
        }
    }
}

pub(crate) async fn require_sn_user(
    server: &SNServer,
    req: &RPCRequest,
) -> RpcCallResult<AuthContext> {
    let token = req
        .token
        .as_ref()
        .ok_or_else(|| parse_error(SnApiErrorCode::AuthRequired, "session_token is none"))?;
    let session = server.auth().verify_access_session(token.as_str())?;
    validate_account_session(server, &session, token.as_str()).await?;
    let username = session
        .sub
        .clone()
        .ok_or_else(|| parse_error(SnApiErrorCode::InvalidToken, "subject is none"))?;
    Ok(AuthContext::SnUser {
        username,
        session_id: session_id(&session, token.as_str()),
    })
}

/// 校验设备私钥签名的 SN 设备 token，输出 `AuthContext::Device`。
///
/// token 形状由 `cyfs_gateway_api::generate_sn_device_token` 约定：
/// `sub` 是 `did:dev:<x>`（公钥内嵌，签名自证持有设备私钥），`iss` 是设备的
/// zone 域名层级 DID（如 `did:bns:ood1.alice`）。信任链闭环在服务端完成：
/// `iss` 解析出 (zone, device_name) 后，从 zone 权威侧登记的设备身份文档
/// （BNS device_mini_doc / zone doc / 兼容设备表，owner 授权发布）取出该
/// 设备名下的公钥，与 `sub` 中的公钥比对，防止任意 key 冒名 zone 内设备。
pub(crate) async fn require_sn_device(
    server: &SNServer,
    req: &RPCRequest,
) -> RpcCallResult<AuthContext> {
    let token = req
        .token
        .as_ref()
        .ok_or_else(|| parse_error(SnApiErrorCode::AuthRequired, "session_token is none"))?;
    let mut session = RPCSessionToken::from_string(token.as_str())
        .map_err(|e| parse_error(SnApiErrorCode::InvalidToken, e.to_string()))?;
    if session.aud.as_deref() != Some(SN_DEVICE_TOKEN_AUD) {
        return Err(parse_error(
            SnApiErrorCode::InvalidToken,
            format!(
                "invalid aud {:?}, expect {} for device token",
                session.aud, SN_DEVICE_TOKEN_AUD
            ),
        ));
    }

    let device_key_did = session
        .sub
        .clone()
        .ok_or_else(|| parse_error(SnApiErrorCode::InvalidToken, "device token sub is none"))?;
    let key_x = device_key_x(device_key_did.as_str()).ok_or_else(|| {
        parse_error(
            SnApiErrorCode::InvalidToken,
            format!(
                "device token sub {} is not a did:dev DID with an ed25519 key",
                device_key_did
            ),
        )
    })?;
    let decoding_key = decoding_key_from_x(key_x.as_str())?;
    session
        .verify_by_key(&decoding_key)
        .map_err(|e| parse_error(SnApiErrorCode::InvalidToken, e.to_string()))?;

    let exp = session
        .exp
        .ok_or_else(|| parse_error(SnApiErrorCode::InvalidToken, "device token exp is none"))?;
    if exp > now_secs() + MAX_DEVICE_TOKEN_TTL_SECS {
        return Err(parse_error(
            SnApiErrorCode::InvalidToken,
            "device token exp is too far in the future",
        ));
    }

    let scoped_did = session
        .iss
        .as_deref()
        .ok_or_else(|| parse_error(SnApiErrorCode::InvalidToken, "device token iss is none"))?;
    let device_key = server
        .registered_device_key_from_did(scoped_did)
        .await?
        .ok_or_else(|| {
            parse_error(
                SnApiErrorCode::DevicePermissionDenied,
                format!("device token iss {} is not a zone-scoped device DID", scoped_did),
            )
        })?;

    let user = server
        .auth_db()
        .get_user_info(device_key.zone.as_str())
        .await
        .map_err(|e| reason_error(SnApiErrorCode::InternalError, e.to_string()))?
        .ok_or_else(|| {
            parse_error(
                SnApiErrorCode::DevicePermissionDenied,
                format!("zone user {} not found", device_key.zone),
            )
        })?;
    if !matches!(user.state, UserState::Active) {
        return Err(parse_error(
            SnApiErrorCode::DevicePermissionDenied,
            format!("zone user {} is not active", device_key.zone),
        ));
    }

    let registered_did = server
        .resolver()
        .resolve_zone_device_did(device_key.zone.as_str(), device_key.device_name.as_str())
        .await
        .map_err(|e| {
            if e.kind() == SnResolverErrorKind::DeviceNotFound {
                parse_error(
                    SnApiErrorCode::DevicePermissionDenied,
                    format!(
                        "device {}.{} is not registered",
                        device_key.device_name, device_key.zone
                    ),
                )
            } else {
                reason_error(
                    SnApiErrorCode::InternalError,
                    format!(
                        "resolve registered device {}.{} failed: {}",
                        device_key.device_name, device_key.zone, e
                    ),
                )
            }
        })?;
    if !device_key_matches(registered_did.as_str(), key_x.as_str()) {
        return Err(parse_error(
            SnApiErrorCode::DevicePermissionDenied,
            format!(
                "device token key does not match the registered key of {}.{}",
                device_key.device_name, device_key.zone
            ),
        ));
    }

    Ok(AuthContext::Device {
        zone: device_key.zone,
        device_name: device_key.device_name,
        did: format!("did:dev:{}", key_x),
    })
}

/// 账号 token 与设备 token 的统一入口：按 `aud` 分流（账号 token `aud=sn`
/// 或历史无 aud，设备 token `aud=sn-device`），各走各的完整校验。
pub(crate) async fn require_sn_user_or_device(
    server: &SNServer,
    req: &RPCRequest,
) -> RpcCallResult<AuthContext> {
    let token = req
        .token
        .as_ref()
        .ok_or_else(|| parse_error(SnApiErrorCode::AuthRequired, "session_token is none"))?;
    let is_device_token = RPCSessionToken::from_string(token.as_str())
        .map(|session| session.aud.as_deref() == Some(SN_DEVICE_TOKEN_AUD))
        .unwrap_or(false);
    if is_device_token {
        require_sn_device(server, req).await
    } else {
        require_sn_user(server, req).await
    }
}

/// 从 `did:dev:<x>` 提取 ed25519 公钥 x 分量（含合理性检查）。
fn device_key_x(did: &str) -> Option<String> {
    let did = DID::from_str(did).ok()?;
    if did.method != "dev" {
        return None;
    }
    if !SNServer::is_plausible_ed25519_x(did.id.as_str()) {
        return None;
    }
    Some(did.id)
}

fn decoding_key_from_x(x: &str) -> RpcCallResult<DecodingKey> {
    let jwk = serde_json::from_value::<jsonwebtoken::jwk::Jwk>(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
    }))
    .map_err(|e| reason_error(SnApiErrorCode::InternalError, e.to_string()))?;
    DecodingKey::from_jwk(&jwk)
        .map_err(|e| parse_error(SnApiErrorCode::InvalidToken, e.to_string()))
}

/// 登记侧设备 DID 与 token 公钥比对。登记侧通常也是 `did:dev:<x>`，比 x；
/// 个别历史文档可能存别的 DID 形态，此时只能整串比对（比不中即拒绝）。
fn device_key_matches(registered_did: &str, token_x: &str) -> bool {
    if let Some(registered_x) = device_key_x(registered_did) {
        return registered_x == token_x;
    }
    registered_did.trim() == format!("did:dev:{}", token_x)
}

pub(crate) fn session_id(session: &RPCSessionToken, token: &str) -> Option<String> {
    session.jti.clone().or_else(|| {
        if token.trim().is_empty() {
            None
        } else {
            let mut hasher = Sha256::new();
            hasher.update(token.as_bytes());
            Some(hex::encode(hasher.finalize()))
        }
    })
}

async fn validate_account_session(
    server: &SNServer,
    session: &RPCSessionToken,
    token: &str,
) -> RpcCallResult<()> {
    let Some(session_id) = session_id(session, token) else {
        return Ok(());
    };
    let Some(stored) = server
        .auth_db()
        .get_account_session(session_id.as_str())
        .await
        .map_err(|e| reason_error(SnApiErrorCode::InternalError, e.to_string()))?
    else {
        return Ok(());
    };

    if stored.state != "active" {
        return Err(parse_error(
            SnApiErrorCode::InvalidToken,
            "session has been revoked",
        ));
    }
    if stored.expires_at < now_secs() {
        return Err(parse_error(SnApiErrorCode::InvalidToken, "session expired"));
    }
    if session.sub.as_deref() != Some(stored.username.as_str()) {
        return Err(parse_error(
            SnApiErrorCode::InvalidToken,
            "session subject mismatch",
        ));
    }

    Ok(())
}

pub(crate) async fn validate_refresh_session(
    server: &SNServer,
    session: &RPCSessionToken,
    token: &str,
) -> RpcCallResult<()> {
    validate_account_session(server, session, token).await
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
