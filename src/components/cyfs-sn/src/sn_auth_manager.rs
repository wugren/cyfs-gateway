use crate::api::{parse_error, reason_error, RpcCallResult, SnApiErrorCode};
use crate::SnAuthInfo;
use ::kRPC::RPCSessionToken;
use buckyos_kit::get_buckyos_service_data_dir;
use jsonwebtoken::{jwk::Jwk, DecodingKey, EncodingKey};
use name_lib::{generate_ed25519_key_pair, load_private_key};
use ring::pbkdf2::{self, PBKDF2_HMAC_SHA256};
use serde::Serialize;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const ACCESS_AUD: &str = "sn";
const REFRESH_AUD: &str = "sn-refresh";
const ACCESS_TOKEN_EXPIRE_SECS: u64 = 60 * 60;
const REFRESH_TOKEN_EXPIRE_SECS: u64 = 60 * 60 * 24;
pub(crate) const PASSWORD_ALGO: &str = "pbkdf2-sha256-100000";
const PASSWORD_ITERATIONS: u32 = 100_000;

#[derive(Clone)]
pub(crate) struct SnAuthManager {
    token_encode_key: EncodingKey,
    token_decode_key: DecodingKey,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IssuedRpcToken {
    pub(crate) token: String,
    pub(crate) session_id: String,
    pub(crate) token_aud: String,
    pub(crate) issued_at: u64,
    pub(crate) expires_at: u64,
}

impl SnAuthManager {
    pub(crate) async fn new(configured_dir: Option<&str>) -> std::result::Result<Self, String> {
        let data_dir = resolve_auth_dir(configured_dir);
        std::fs::create_dir_all(&data_dir)
            .map_err(|e| format!("failed to create sn auth dir {}: {}", data_dir.display(), e))?;

        let private_key = data_dir.join("private_key.pem");
        let public_key = data_dir.join("public_key.json");
        let (encode_key, decode_key) = if private_key.exists() && public_key.exists() {
            let encode_key = load_private_key(private_key.as_path()).map_err(|e| e.to_string())?;
            let public_key = std::fs::read_to_string(public_key.as_path())
                .map_err(|e| format!("read public key failed: {}", e))?;
            let public_key: Jwk = serde_json::from_str(public_key.as_str())
                .map_err(|e| format!("parse public key failed: {}", e))?;
            let decode_key =
                DecodingKey::from_jwk(&public_key).map_err(|e| format!("decode key: {}", e))?;
            (encode_key, decode_key)
        } else {
            let (sign_key, public_key_value) = generate_ed25519_key_pair();
            std::fs::write(private_key.as_path(), sign_key.as_bytes())
                .map_err(|e| format!("write private key failed: {}", e))?;
            std::fs::write(
                public_key.as_path(),
                serde_json::to_string(&public_key_value).unwrap(),
            )
            .map_err(|e| format!("write public key failed: {}", e))?;
            let jwk = serde_json::from_value::<Jwk>(public_key_value)
                .map_err(|e| format!("parse generated jwk failed: {}", e))?;
            let encode_key = load_private_key(private_key.as_path()).map_err(|e| e.to_string())?;
            let decode_key =
                DecodingKey::from_jwk(&jwk).map_err(|e| format!("decode key: {}", e))?;
            (encode_key, decode_key)
        };

        Ok(Self {
            token_encode_key: encode_key,
            token_decode_key: decode_key,
        })
    }

    pub(crate) fn issue_access_session(&self, username: &str) -> RpcCallResult<IssuedRpcToken> {
        issue_rpc_jwt(
            username,
            ACCESS_AUD,
            ACCESS_TOKEN_EXPIRE_SECS,
            &self.token_encode_key,
        )
    }

    pub(crate) fn issue_refresh_session(&self, username: &str) -> RpcCallResult<IssuedRpcToken> {
        issue_rpc_jwt(
            username,
            REFRESH_AUD,
            REFRESH_TOKEN_EXPIRE_SECS,
            &self.token_encode_key,
        )
    }

    pub(crate) fn verify_access_session(&self, token: &str) -> RpcCallResult<RPCSessionToken> {
        verify_rpc_session(token, ACCESS_AUD, &self.token_decode_key)
    }

    pub(crate) fn verify_refresh_session(&self, token: &str) -> RpcCallResult<RPCSessionToken> {
        verify_rpc_session(token, REFRESH_AUD, &self.token_decode_key)
    }
}

pub(crate) fn hash_password(password: &str) -> RpcCallResult<(String, String)> {
    let salt = rand::random::<[u8; 16]>();
    let salt_hex = hex::encode(salt);
    let password_hash = derive_password_hash(password, salt_hex.as_str())?;
    Ok((password_hash, salt_hex))
}

pub(crate) fn verify_password(password: &str, auth: &SnAuthInfo) -> RpcCallResult<bool> {
    if auth.password_algo != PASSWORD_ALGO {
        return Err(reason_error(
            SnApiErrorCode::UnsupportedPasswordAlgo,
            format!("unsupported password algo {}", auth.password_algo),
        ));
    }
    let salt = hex::decode(auth.password_salt.as_str()).map_err(|e| {
        reason_error(
            SnApiErrorCode::InvalidPasswordStorage,
            format!("invalid password salt: {}", e),
        )
    })?;
    let expected = hex::decode(auth.password_hash.as_str()).map_err(|e| {
        reason_error(
            SnApiErrorCode::InvalidPasswordStorage,
            format!("invalid password hash: {}", e),
        )
    })?;
    Ok(pbkdf2::verify(
        PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PASSWORD_ITERATIONS).unwrap(),
        &salt,
        password.as_bytes(),
        &expected,
    )
    .is_ok())
}

fn resolve_auth_dir(configured_dir: Option<&str>) -> PathBuf {
    if let Some(path) = configured_dir {
        let configured = PathBuf::from(path);
        if configured.is_absolute() {
            return configured;
        }
        return std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(configured);
    }
    get_buckyos_service_data_dir("cyfs_gateway").join("sn_token_key")
}

fn issue_rpc_jwt(
    username: &str,
    aud: &str,
    expire_secs: u64,
    key: &EncodingKey,
) -> RpcCallResult<IssuedRpcToken> {
    let (_, mut session) =
        RPCSessionToken::generate_jwt_token(username, aud, None, key).map_err(|e| {
            reason_error(
                SnApiErrorCode::InternalError,
                format!("generate jwt token failed: {}", e),
            )
        })?;
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_at = issued_at + expire_secs;
    session.aud = Some(aud.to_string());
    session.exp = Some(expires_at);
    session.jti = Some(hex::encode(rand::random::<[u8; 16]>()));
    let token = session.generate_jwt(None, key).map_err(|e| {
        reason_error(
            SnApiErrorCode::InternalError,
            format!("generate jwt token failed: {}", e),
        )
    })?;
    Ok(IssuedRpcToken {
        token,
        session_id: session.jti.unwrap_or_default(),
        token_aud: aud.to_string(),
        issued_at,
        expires_at,
    })
}

fn verify_rpc_session(
    token: &str,
    expected_aud: &str,
    key: &DecodingKey,
) -> RpcCallResult<RPCSessionToken> {
    let mut session = RPCSessionToken::from_string(token)
        .map_err(|e| parse_error(SnApiErrorCode::InvalidToken, e.to_string()))?;
    session
        .verify_by_key(key)
        .map_err(|e| parse_error(SnApiErrorCode::InvalidToken, e.to_string()))?;
    if session.aud.as_deref() != Some(expected_aud) {
        return Err(parse_error(
            SnApiErrorCode::InvalidToken,
            format!("invalid aud {:?}, expect {}", session.aud, expected_aud),
        ));
    }
    Ok(session)
}

fn derive_password_hash(password: &str, salt_hex: &str) -> RpcCallResult<String> {
    let salt = hex::decode(salt_hex).map_err(|e| {
        reason_error(
            SnApiErrorCode::InvalidPasswordStorage,
            format!("invalid password salt: {}", e),
        )
    })?;
    let mut hash = [0u8; 32];
    pbkdf2::derive(
        PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PASSWORD_ITERATIONS).unwrap(),
        &salt,
        password.as_bytes(),
        &mut hash,
    );
    Ok(hex::encode(hash))
}
