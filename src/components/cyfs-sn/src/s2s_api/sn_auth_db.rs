use crate::{
    sn_err, AccountSession, DomainBinding, SNUserInfo, SnAuthDB, SnAuthInfo, SnClearStateResult,
    SnError, SnErrorCode, SnResult, UserState, ZoneInfo, ZoneInfoPatch,
};
use ::kRPC::{kRPC, RPCErrors, RPCHandler, RPCRequest, RPCResponse, RPCResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;

pub const SN_AUTH_DB_RPC_PATH: &str = "/kapi/sn/s2s/auth-db";

pub const METHOD_GET_ACTIVATION_CODES: &str = "sn_auth_db.get_activation_codes";
pub const METHOD_INSERT_ACTIVATION_CODE: &str = "sn_auth_db.insert_activation_code";
pub const METHOD_GENERATE_ACTIVATION_CODES: &str = "sn_auth_db.generate_activation_codes";
pub const METHOD_CHECK_ACTIVE_CODE: &str = "sn_auth_db.check_active_code";
pub const METHOD_CLEAR_STATE_BY_ACTIVE_CODE: &str = "sn_auth_db.clear_state_by_active_code";
pub const METHOD_REGISTER_USER: &str = "sn_auth_db.register_user";
pub const METHOD_CREATE_AUTH: &str = "sn_auth_db.create_auth";
pub const METHOD_IS_USER_EXIST: &str = "sn_auth_db.is_user_exist";
pub const METHOD_GET_USER_BY_EMAIL: &str = "sn_auth_db.get_user_by_email";
pub const METHOD_REGISTER_USER_WITH_OWNER_KEY: &str = "sn_auth_db.register_user_with_owner_key";
pub const METHOD_GET_USER_BY_PUBLIC_KEY: &str = "sn_auth_db.get_user_by_public_key";
pub const METHOD_GET_USER_INFO: &str = "sn_auth_db.get_user_info";
pub const METHOD_GET_USER_BY_DOMAIN: &str = "sn_auth_db.get_user_by_domain";
pub const METHOD_SET_USER_STATE: &str = "sn_auth_db.set_user_state";
pub const METHOD_UPDATE_USER_PUBLIC_KEY: &str = "sn_auth_db.update_user_public_key";
pub const METHOD_UPDATE_USER_ZONE_CONFIG: &str = "sn_auth_db.update_user_zone_config";
pub const METHOD_UPDATE_USER_SELF_CERT: &str = "sn_auth_db.update_user_self_cert";
pub const METHOD_UPDATE_USER_DOMAIN: &str = "sn_auth_db.update_user_domain";
pub const METHOD_GET_USER_SN_IPS: &str = "sn_auth_db.get_user_sn_ips";
pub const METHOD_GET_AUTH: &str = "sn_auth_db.get_auth";
pub const METHOD_UPDATE_LAST_LOGIN: &str = "sn_auth_db.update_last_login";
pub const METHOD_ACTIVATE_USER_DOMAIN_BINDING: &str = "sn_auth_db.activate_user_domain_binding";
pub const METHOD_UNBIND_USER_DOMAIN: &str = "sn_auth_db.unbind_user_domain";
pub const METHOD_GET_ZONE_INFO: &str = "sn_auth_db.get_zone_info";
pub const METHOD_UPDATE_ZONE_INFO: &str = "sn_auth_db.update_zone_info";
pub const METHOD_UPDATE_ZONE_RELAY_SN: &str = "sn_auth_db.update_zone_relay_sn";
pub const METHOD_CREATE_ACCOUNT_SESSION: &str = "sn_auth_db.create_account_session";
pub const METHOD_REVOKE_ACCOUNT_SESSION: &str = "sn_auth_db.revoke_account_session";
pub const METHOD_REVOKE_USER_SESSIONS: &str = "sn_auth_db.revoke_user_sessions";
pub const METHOD_GET_ACCOUNT_SESSION: &str = "sn_auth_db.get_account_session";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRpcErrorInfo {
    pub code: SnErrorCode,
    pub message: String,
}

impl SnAuthDbRpcErrorInfo {
    pub fn from_sn_error(error: SnError) -> Self {
        Self {
            code: error.code(),
            message: error.msg().to_string(),
        }
    }

    pub fn into_sn_error(self) -> SnError {
        SnError::new(self.code, self.message)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRpcEnvelope<T> {
    pub ok: bool,
    pub result: Option<T>,
    pub error: Option<SnAuthDbRpcErrorInfo>,
}

impl<T> SnAuthDbRpcEnvelope<T> {
    pub fn success(result: T) -> Self {
        Self {
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(error: SnError) -> Self {
        Self {
            ok: false,
            result: None,
            error: Some(SnAuthDbRpcErrorInfo::from_sn_error(error)),
        }
    }

    pub fn into_result(self) -> SnResult<T> {
        if self.ok {
            self.result.ok_or_else(|| {
                sn_err!(
                    SnErrorCode::RemoteError,
                    "SnAuthDB RPC envelope missing result"
                )
            })
        } else {
            Err(self
                .error
                .map(SnAuthDbRpcErrorInfo::into_sn_error)
                .unwrap_or_else(|| {
                    sn_err!(
                        SnErrorCode::RemoteError,
                        "SnAuthDB RPC envelope missing error"
                    )
                }))
        }
    }
}

macro_rules! impl_req_from_json {
    ($ty:ident) => {
        pub fn from_json(value: Value) -> Result<Self, RPCErrors> {
            serde_json::from_value(value).map_err(|e| {
                RPCErrors::ParseRequestError(format!("Failed to parse {}: {}", stringify!($ty), e))
            })
        }
    };
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbGetActivationCodesReq {}

impl SnAuthDbGetActivationCodesReq {
    pub fn new() -> Self {
        Self {}
    }

    impl_req_from_json!(SnAuthDbGetActivationCodesReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbInsertActivationCodeReq {
    pub code: String,
}

impl SnAuthDbInsertActivationCodeReq {
    pub fn new(code: &str) -> Self {
        Self {
            code: code.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbInsertActivationCodeReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbGenerateActivationCodesReq {
    pub count: usize,
}

impl SnAuthDbGenerateActivationCodesReq {
    pub fn new(count: usize) -> Self {
        Self { count }
    }

    impl_req_from_json!(SnAuthDbGenerateActivationCodesReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbCheckActiveCodeReq {
    pub active_code: String,
}

impl SnAuthDbCheckActiveCodeReq {
    pub fn new(active_code: &str) -> Self {
        Self {
            active_code: active_code.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbCheckActiveCodeReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbClearStateByActiveCodeReq {
    pub active_code: String,
}

impl SnAuthDbClearStateByActiveCodeReq {
    pub fn new(active_code: &str) -> Self {
        Self {
            active_code: active_code.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbClearStateByActiveCodeReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRegisterUserReq {
    pub active_code: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub password_salt: String,
    pub password_algo: String,
}

impl SnAuthDbRegisterUserReq {
    pub fn new(
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> Self {
        Self {
            active_code: active_code.to_string(),
            username: username.to_string(),
            email: email.to_string(),
            password_hash: password_hash.to_string(),
            password_salt: password_salt.to_string(),
            password_algo: password_algo.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbRegisterUserReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbCreateAuthReq {
    pub username: String,
    pub password_hash: String,
    pub password_salt: String,
    pub password_algo: String,
}

impl SnAuthDbCreateAuthReq {
    pub fn new(
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> Self {
        Self {
            username: username.to_string(),
            password_hash: password_hash.to_string(),
            password_salt: password_salt.to_string(),
            password_algo: password_algo.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbCreateAuthReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUsernameReq {
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbEmailReq {
    pub email: String,
}

impl SnAuthDbEmailReq {
    pub fn new(email: &str) -> Self {
        Self {
            email: email.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbEmailReq);
}

impl SnAuthDbUsernameReq {
    pub fn new(username: &str) -> Self {
        Self {
            username: username.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbUsernameReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRegisterUserWithOwnerKeyReq {
    pub active_code: String,
    pub username: String,
    pub email: String,
    pub public_key: String,
    pub zone_config: String,
    pub user_domain: Option<String>,
    pub sn_ips: Option<String>,
}

impl SnAuthDbRegisterUserWithOwnerKeyReq {
    pub fn new(
        active_code: &str,
        username: &str,
        email: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> Self {
        Self {
            active_code: active_code.to_string(),
            username: username.to_string(),
            email: email.to_string(),
            public_key: public_key.to_string(),
            zone_config: zone_config.to_string(),
            user_domain,
            sn_ips,
        }
    }

    impl_req_from_json!(SnAuthDbRegisterUserWithOwnerKeyReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbPublicKeyReq {
    pub public_key: String,
}

impl SnAuthDbPublicKeyReq {
    pub fn new(public_key: &str) -> Self {
        Self {
            public_key: public_key.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbPublicKeyReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbDomainReq {
    pub domain: String,
}

impl SnAuthDbDomainReq {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbDomainReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbSetUserStateReq {
    pub username: String,
    pub state: UserState,
}

impl SnAuthDbSetUserStateReq {
    pub fn new(username: &str, state: UserState) -> Self {
        Self {
            username: username.to_string(),
            state,
        }
    }

    impl_req_from_json!(SnAuthDbSetUserStateReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateUserPublicKeyReq {
    pub username: String,
    pub public_key: String,
}

impl SnAuthDbUpdateUserPublicKeyReq {
    pub fn new(username: &str, public_key: &str) -> Self {
        Self {
            username: username.to_string(),
            public_key: public_key.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbUpdateUserPublicKeyReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateUserZoneConfigReq {
    pub username: String,
    pub zone_config: String,
}

impl SnAuthDbUpdateUserZoneConfigReq {
    pub fn new(username: &str, zone_config: &str) -> Self {
        Self {
            username: username.to_string(),
            zone_config: zone_config.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbUpdateUserZoneConfigReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateUserSelfCertReq {
    pub username: String,
    pub self_cert: bool,
}

impl SnAuthDbUpdateUserSelfCertReq {
    pub fn new(username: &str, self_cert: bool) -> Self {
        Self {
            username: username.to_string(),
            self_cert,
        }
    }

    impl_req_from_json!(SnAuthDbUpdateUserSelfCertReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateUserDomainReq {
    pub username: String,
    pub user_domain: Option<String>,
}

impl SnAuthDbUpdateUserDomainReq {
    pub fn new(username: &str, user_domain: Option<String>) -> Self {
        Self {
            username: username.to_string(),
            user_domain,
        }
    }

    impl_req_from_json!(SnAuthDbUpdateUserDomainReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateLastLoginReq {
    pub username: String,
    pub last_login_at: u64,
}

impl SnAuthDbUpdateLastLoginReq {
    pub fn new(username: &str, last_login_at: u64) -> Self {
        Self {
            username: username.to_string(),
            last_login_at,
        }
    }

    impl_req_from_json!(SnAuthDbUpdateLastLoginReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbActivateUserDomainBindingReq {
    pub username: String,
    pub domain: String,
    pub pkx: String,
}

impl SnAuthDbActivateUserDomainBindingReq {
    pub fn new(username: &str, domain: &str, pkx: &str) -> Self {
        Self {
            username: username.to_string(),
            domain: domain.to_string(),
            pkx: pkx.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbActivateUserDomainBindingReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUnbindUserDomainReq {
    pub username: String,
    pub domain: String,
}

impl SnAuthDbUnbindUserDomainReq {
    pub fn new(username: &str, domain: &str) -> Self {
        Self {
            username: username.to_string(),
            domain: domain.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbUnbindUserDomainReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateZoneInfoReq {
    pub username: String,
    pub patch: ZoneInfoPatch,
}

impl SnAuthDbUpdateZoneInfoReq {
    pub fn new(username: &str, patch: ZoneInfoPatch) -> Self {
        Self {
            username: username.to_string(),
            patch,
        }
    }

    impl_req_from_json!(SnAuthDbUpdateZoneInfoReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbUpdateZoneRelaySnReq {
    pub zone: String,
    pub relay_sn: String,
    pub source_version: Option<String>,
}

impl SnAuthDbUpdateZoneRelaySnReq {
    pub fn new(zone: &str, relay_sn: &str, source_version: Option<&str>) -> Self {
        Self {
            zone: zone.to_string(),
            relay_sn: relay_sn.to_string(),
            source_version: source_version.map(ToString::to_string),
        }
    }

    impl_req_from_json!(SnAuthDbUpdateZoneRelaySnReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbCreateAccountSessionReq {
    pub session_id: String,
    pub username: String,
    pub token_aud: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl SnAuthDbCreateAccountSessionReq {
    pub fn new(
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            session_id: session_id.to_string(),
            username: username.to_string(),
            token_aud: token_aud.to_string(),
            issued_at,
            expires_at,
        }
    }

    impl_req_from_json!(SnAuthDbCreateAccountSessionReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRevokeAccountSessionReq {
    pub session_id: String,
    pub revoked_at: u64,
}

impl SnAuthDbRevokeAccountSessionReq {
    pub fn new(session_id: &str, revoked_at: u64) -> Self {
        Self {
            session_id: session_id.to_string(),
            revoked_at,
        }
    }

    impl_req_from_json!(SnAuthDbRevokeAccountSessionReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbRevokeUserSessionsReq {
    pub username: String,
    pub revoked_at: u64,
}

impl SnAuthDbRevokeUserSessionsReq {
    pub fn new(username: &str, revoked_at: u64) -> Self {
        Self {
            username: username.to_string(),
            revoked_at,
        }
    }

    impl_req_from_json!(SnAuthDbRevokeUserSessionsReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnAuthDbSessionIdReq {
    pub session_id: String,
}

impl SnAuthDbSessionIdReq {
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
        }
    }

    impl_req_from_json!(SnAuthDbSessionIdReq);
}

#[derive(Clone)]
pub enum SnAuthDbClient {
    InProcess(Arc<dyn SnAuthDB>),
    KRPC(Arc<kRPC>),
}

impl SnAuthDbClient {
    pub fn new_in_process(handler: Arc<dyn SnAuthDB>) -> Self {
        Self::InProcess(handler)
    }

    pub fn new_krpc(client: Arc<kRPC>) -> Self {
        Self::KRPC(client)
    }

    pub fn new_krpc_url(auth_db_url: &str, session_token: Option<String>) -> Self {
        let endpoint = normalize_sn_auth_db_url(auth_db_url);
        Self::KRPC(Arc::new(kRPC::new(endpoint.as_str(), session_token)))
    }

    async fn call<Req, Resp>(&self, method: &str, req: &Req) -> SnResult<Resp>
    where
        Req: Serialize + Sync,
        Resp: for<'de> Deserialize<'de>,
    {
        match self {
            Self::InProcess(_) => Err(sn_err!(
                SnErrorCode::RemoteError,
                "generic call is only available for KRPC clients"
            )),
            Self::KRPC(client) => {
                let req_json = serde_json::to_value(req).map_err(|e| {
                    sn_err!(
                        SnErrorCode::RemoteError,
                        "failed to serialize SnAuthDB RPC {} request: {}",
                        method,
                        e
                    )
                })?;
                let result = client.call(method, req_json).await.map_err(|e| {
                    sn_err!(
                        SnErrorCode::RemoteError,
                        "SnAuthDB RPC {} transport failed: {}",
                        method,
                        e
                    )
                })?;
                let envelope: SnAuthDbRpcEnvelope<Resp> =
                    serde_json::from_value(result).map_err(|e| {
                        sn_err!(
                            SnErrorCode::RemoteError,
                            "failed to parse SnAuthDB RPC {} response: {}",
                            method,
                            e
                        )
                    })?;
                envelope.into_result()
            }
        }
    }
}

#[async_trait]
impl SnAuthDB for SnAuthDbClient {
    async fn get_activation_codes(&self) -> SnResult<Vec<String>> {
        match self {
            Self::InProcess(handler) => handler.get_activation_codes().await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_ACTIVATION_CODES,
                    &SnAuthDbGetActivationCodesReq::new(),
                )
                .await
            }
        }
    }

    async fn insert_activation_code(&self, code: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.insert_activation_code(code).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_INSERT_ACTIVATION_CODE,
                    &SnAuthDbInsertActivationCodeReq::new(code),
                )
                .await
            }
        }
    }

    async fn generate_activation_codes(&self, count: usize) -> SnResult<Vec<String>> {
        match self {
            Self::InProcess(handler) => handler.generate_activation_codes(count).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GENERATE_ACTIVATION_CODES,
                    &SnAuthDbGenerateActivationCodesReq::new(count),
                )
                .await
            }
        }
    }

    async fn check_active_code(&self, active_code: &str) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => handler.check_active_code(active_code).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_CHECK_ACTIVE_CODE,
                    &SnAuthDbCheckActiveCodeReq::new(active_code),
                )
                .await
            }
        }
    }

    async fn clear_state_by_active_code(&self, active_code: &str) -> SnResult<SnClearStateResult> {
        match self {
            Self::InProcess(handler) => handler.clear_state_by_active_code(active_code).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_CLEAR_STATE_BY_ACTIVE_CODE,
                    &SnAuthDbClearStateByActiveCodeReq::new(active_code),
                )
                .await
            }
        }
    }

    async fn register_user(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .register_user(
                        active_code,
                        username,
                        email,
                        password_hash,
                        password_salt,
                        password_algo,
                    )
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_REGISTER_USER,
                    &SnAuthDbRegisterUserReq::new(
                        active_code,
                        username,
                        email,
                        password_hash,
                        password_salt,
                        password_algo,
                    ),
                )
                .await
            }
        }
    }

    async fn create_auth(
        &self,
        username: &str,
        password_hash: &str,
        password_salt: &str,
        password_algo: &str,
    ) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .create_auth(username, password_hash, password_salt, password_algo)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_CREATE_AUTH,
                    &SnAuthDbCreateAuthReq::new(
                        username,
                        password_hash,
                        password_salt,
                        password_algo,
                    ),
                )
                .await
            }
        }
    }

    async fn is_user_exist(&self, username: &str) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => handler.is_user_exist(username).await,
            Self::KRPC(_) => {
                self.call(METHOD_IS_USER_EXIST, &SnAuthDbUsernameReq::new(username))
                    .await
            }
        }
    }

    async fn get_user_by_email(&self, email: &str) -> SnResult<Option<SNUserInfo>> {
        match self {
            Self::InProcess(handler) => handler.get_user_by_email(email).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_USER_BY_EMAIL, &SnAuthDbEmailReq::new(email))
                    .await
            }
        }
    }

    async fn register_user_with_owner_key(
        &self,
        active_code: &str,
        username: &str,
        email: &str,
        public_key: &str,
        zone_config: &str,
        user_domain: Option<String>,
        sn_ips: Option<String>,
    ) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .register_user_with_owner_key(
                        active_code,
                        username,
                        email,
                        public_key,
                        zone_config,
                        user_domain,
                        sn_ips,
                    )
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_REGISTER_USER_WITH_OWNER_KEY,
                    &SnAuthDbRegisterUserWithOwnerKeyReq::new(
                        active_code,
                        username,
                        email,
                        public_key,
                        zone_config,
                        user_domain,
                        sn_ips,
                    ),
                )
                .await
            }
        }
    }

    async fn get_user_by_public_key(
        &self,
        public_key: &str,
    ) -> SnResult<Option<(String, String, Option<String>)>> {
        match self {
            Self::InProcess(handler) => handler.get_user_by_public_key(public_key).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_USER_BY_PUBLIC_KEY,
                    &SnAuthDbPublicKeyReq::new(public_key),
                )
                .await
            }
        }
    }

    async fn get_user_info(&self, username: &str) -> SnResult<Option<SNUserInfo>> {
        match self {
            Self::InProcess(handler) => handler.get_user_info(username).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_USER_INFO, &SnAuthDbUsernameReq::new(username))
                    .await
            }
        }
    }

    async fn get_user_by_domain(&self, domain: &str) -> SnResult<Option<SNUserInfo>> {
        match self {
            Self::InProcess(handler) => handler.get_user_by_domain(domain).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_USER_BY_DOMAIN, &SnAuthDbDomainReq::new(domain))
                    .await
            }
        }
    }

    async fn set_user_state(&self, username: &str, state: UserState) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.set_user_state(username, state).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_SET_USER_STATE,
                    &SnAuthDbSetUserStateReq::new(username, state),
                )
                .await
            }
        }
    }

    async fn update_user_public_key(&self, username: &str, public_key: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_user_public_key(username, public_key).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_USER_PUBLIC_KEY,
                    &SnAuthDbUpdateUserPublicKeyReq::new(username, public_key),
                )
                .await
            }
        }
    }

    async fn update_user_zone_config(&self, username: &str, zone_config: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => {
                handler.update_user_zone_config(username, zone_config).await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_USER_ZONE_CONFIG,
                    &SnAuthDbUpdateUserZoneConfigReq::new(username, zone_config),
                )
                .await
            }
        }
    }

    async fn update_user_self_cert(&self, username: &str, self_cert: bool) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_user_self_cert(username, self_cert).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_USER_SELF_CERT,
                    &SnAuthDbUpdateUserSelfCertReq::new(username, self_cert),
                )
                .await
            }
        }
    }

    async fn update_user_domain(
        &self,
        username: &str,
        user_domain: Option<String>,
    ) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_user_domain(username, user_domain).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_USER_DOMAIN,
                    &SnAuthDbUpdateUserDomainReq::new(username, user_domain),
                )
                .await
            }
        }
    }

    async fn get_user_sn_ips(&self, username: &str) -> SnResult<Option<String>> {
        match self {
            Self::InProcess(handler) => handler.get_user_sn_ips(username).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_USER_SN_IPS, &SnAuthDbUsernameReq::new(username))
                    .await
            }
        }
    }

    async fn get_auth(&self, username: &str) -> SnResult<Option<SnAuthInfo>> {
        match self {
            Self::InProcess(handler) => handler.get_auth(username).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_AUTH, &SnAuthDbUsernameReq::new(username))
                    .await
            }
        }
    }

    async fn update_last_login(&self, username: &str, last_login_at: u64) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_last_login(username, last_login_at).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_LAST_LOGIN,
                    &SnAuthDbUpdateLastLoginReq::new(username, last_login_at),
                )
                .await
            }
        }
    }

    async fn activate_user_domain_binding(
        &self,
        username: &str,
        domain: &str,
        pkx: &str,
    ) -> SnResult<DomainBinding> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .activate_user_domain_binding(username, domain, pkx)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_ACTIVATE_USER_DOMAIN_BINDING,
                    &SnAuthDbActivateUserDomainBindingReq::new(username, domain, pkx),
                )
                .await
            }
        }
    }

    async fn unbind_user_domain(&self, username: &str, domain: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.unbind_user_domain(username, domain).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UNBIND_USER_DOMAIN,
                    &SnAuthDbUnbindUserDomainReq::new(username, domain),
                )
                .await
            }
        }
    }

    async fn get_zone_info(&self, username: &str) -> SnResult<Option<ZoneInfo>> {
        match self {
            Self::InProcess(handler) => handler.get_zone_info(username).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_ZONE_INFO, &SnAuthDbUsernameReq::new(username))
                    .await
            }
        }
    }

    async fn update_zone_info(&self, username: &str, patch: ZoneInfoPatch) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_zone_info(username, patch).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_ZONE_INFO,
                    &SnAuthDbUpdateZoneInfoReq::new(username, patch),
                )
                .await
            }
        }
    }

    async fn update_zone_relay_sn(
        &self,
        zone: &str,
        relay_sn: &str,
        source_version: Option<&str>,
    ) -> SnResult<bool> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .update_zone_relay_sn(zone, relay_sn, source_version)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_UPDATE_ZONE_RELAY_SN,
                    &SnAuthDbUpdateZoneRelaySnReq::new(zone, relay_sn, source_version),
                )
                .await
            }
        }
    }

    async fn create_account_session(
        &self,
        session_id: &str,
        username: &str,
        token_aud: &str,
        issued_at: u64,
        expires_at: u64,
    ) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .create_account_session(session_id, username, token_aud, issued_at, expires_at)
                    .await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_CREATE_ACCOUNT_SESSION,
                    &SnAuthDbCreateAccountSessionReq::new(
                        session_id, username, token_aud, issued_at, expires_at,
                    ),
                )
                .await
            }
        }
    }

    async fn revoke_account_session(&self, session_id: &str, revoked_at: u64) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => {
                handler.revoke_account_session(session_id, revoked_at).await
            }
            Self::KRPC(_) => {
                self.call(
                    METHOD_REVOKE_ACCOUNT_SESSION,
                    &SnAuthDbRevokeAccountSessionReq::new(session_id, revoked_at),
                )
                .await
            }
        }
    }

    async fn revoke_user_sessions(&self, username: &str, revoked_at: u64) -> SnResult<u64> {
        match self {
            Self::InProcess(handler) => handler.revoke_user_sessions(username, revoked_at).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_REVOKE_USER_SESSIONS,
                    &SnAuthDbRevokeUserSessionsReq::new(username, revoked_at),
                )
                .await
            }
        }
    }

    async fn get_account_session(&self, session_id: &str) -> SnResult<Option<AccountSession>> {
        match self {
            Self::InProcess(handler) => handler.get_account_session(session_id).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_ACCOUNT_SESSION,
                    &SnAuthDbSessionIdReq::new(session_id),
                )
                .await
            }
        }
    }
}

pub struct SnAuthDbRpcHandler<T: SnAuthDB>(pub T);

impl<T: SnAuthDB> SnAuthDbRpcHandler<T> {
    pub fn new(handler: T) -> Self {
        Self(handler)
    }
}

#[async_trait]
impl<T> RPCHandler for SnAuthDbRpcHandler<T>
where
    T: SnAuthDB,
{
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        _ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        match req.method.as_str() {
            METHOD_GET_ACTIVATION_CODES | "get_activation_codes" => {
                let _parsed = SnAuthDbGetActivationCodesReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_activation_codes().await, &req)
            }
            METHOD_INSERT_ACTIVATION_CODE | "insert_activation_code" => {
                let parsed = SnAuthDbInsertActivationCodeReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.insert_activation_code(&parsed.code).await, &req)
            }
            METHOD_GENERATE_ACTIVATION_CODES | "generate_activation_codes" => {
                let parsed = SnAuthDbGenerateActivationCodesReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.generate_activation_codes(parsed.count).await, &req)
            }
            METHOD_CHECK_ACTIVE_CODE | "check_active_code" => {
                let parsed = SnAuthDbCheckActiveCodeReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.check_active_code(&parsed.active_code).await, &req)
            }
            METHOD_CLEAR_STATE_BY_ACTIVE_CODE | "clear_state_by_active_code" => {
                let parsed = SnAuthDbClearStateByActiveCodeReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0.clear_state_by_active_code(&parsed.active_code).await,
                    &req,
                )
            }
            METHOD_REGISTER_USER | "register_user" => {
                let parsed = SnAuthDbRegisterUserReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .register_user(
                            &parsed.active_code,
                            &parsed.username,
                            &parsed.email,
                            &parsed.password_hash,
                            &parsed.password_salt,
                            &parsed.password_algo,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_CREATE_AUTH | "create_auth" => {
                let parsed = SnAuthDbCreateAuthReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .create_auth(
                            &parsed.username,
                            &parsed.password_hash,
                            &parsed.password_salt,
                            &parsed.password_algo,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_IS_USER_EXIST | "is_user_exist" => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.is_user_exist(&parsed.username).await, &req)
            }
            METHOD_GET_USER_BY_EMAIL | "get_user_by_email" => {
                let parsed = SnAuthDbEmailReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_user_by_email(&parsed.email).await, &req)
            }
            METHOD_REGISTER_USER_WITH_OWNER_KEY | "register_user_with_owner_key" => {
                let parsed = SnAuthDbRegisterUserWithOwnerKeyReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .register_user_with_owner_key(
                            &parsed.active_code,
                            &parsed.username,
                            &parsed.email,
                            &parsed.public_key,
                            &parsed.zone_config,
                            parsed.user_domain,
                            parsed.sn_ips,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_GET_USER_BY_PUBLIC_KEY | "get_user_by_public_key" => {
                let parsed = SnAuthDbPublicKeyReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0.get_user_by_public_key(&parsed.public_key).await,
                    &req,
                )
            }
            METHOD_GET_USER_INFO | "get_user_info" => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_user_info(&parsed.username).await, &req)
            }
            METHOD_GET_USER_BY_DOMAIN | "get_user_by_domain" => {
                let parsed = SnAuthDbDomainReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_user_by_domain(&parsed.domain).await, &req)
            }
            METHOD_SET_USER_STATE | "set_user_state" => {
                let parsed = SnAuthDbSetUserStateReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0.set_user_state(&parsed.username, parsed.state).await,
                    &req,
                )
            }
            METHOD_UPDATE_USER_PUBLIC_KEY | "update_user_public_key" => {
                let parsed = SnAuthDbUpdateUserPublicKeyReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_user_public_key(&parsed.username, &parsed.public_key)
                        .await,
                    &req,
                )
            }
            METHOD_UPDATE_USER_ZONE_CONFIG | "update_user_zone_config" => {
                let parsed = SnAuthDbUpdateUserZoneConfigReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_user_zone_config(&parsed.username, &parsed.zone_config)
                        .await,
                    &req,
                )
            }
            METHOD_UPDATE_USER_SELF_CERT | "update_user_self_cert" => {
                let parsed = SnAuthDbUpdateUserSelfCertReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_user_self_cert(&parsed.username, parsed.self_cert)
                        .await,
                    &req,
                )
            }
            METHOD_UPDATE_USER_DOMAIN | "update_user_domain" => {
                let parsed = SnAuthDbUpdateUserDomainReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_user_domain(&parsed.username, parsed.user_domain)
                        .await,
                    &req,
                )
            }
            METHOD_GET_USER_SN_IPS | "get_user_sn_ips" => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_user_sn_ips(&parsed.username).await, &req)
            }
            METHOD_GET_AUTH | "get_auth" => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_auth(&parsed.username).await, &req)
            }
            METHOD_UPDATE_LAST_LOGIN | "update_last_login" => {
                let parsed = SnAuthDbUpdateLastLoginReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_last_login(&parsed.username, parsed.last_login_at)
                        .await,
                    &req,
                )
            }
            METHOD_ACTIVATE_USER_DOMAIN_BINDING | "activate_user_domain_binding" => {
                let parsed = SnAuthDbActivateUserDomainBindingReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .activate_user_domain_binding(
                            &parsed.username,
                            &parsed.domain,
                            &parsed.pkx,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_UNBIND_USER_DOMAIN | "unbind_user_domain" => {
                let parsed = SnAuthDbUnbindUserDomainReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .unbind_user_domain(&parsed.username, &parsed.domain)
                        .await,
                    &req,
                )
            }
            METHOD_GET_ZONE_INFO | "get_zone_info" => {
                let parsed = SnAuthDbUsernameReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_zone_info(&parsed.username).await, &req)
            }
            METHOD_UPDATE_ZONE_INFO | "update_zone_info" => {
                let parsed = SnAuthDbUpdateZoneInfoReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_zone_info(&parsed.username, parsed.patch)
                        .await,
                    &req,
                )
            }
            METHOD_UPDATE_ZONE_RELAY_SN | "update_zone_relay_sn" => {
                let parsed = SnAuthDbUpdateZoneRelaySnReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .update_zone_relay_sn(
                            &parsed.zone,
                            &parsed.relay_sn,
                            parsed.source_version.as_deref(),
                        )
                        .await,
                    &req,
                )
            }
            METHOD_CREATE_ACCOUNT_SESSION | "create_account_session" => {
                let parsed = SnAuthDbCreateAccountSessionReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .create_account_session(
                            &parsed.session_id,
                            &parsed.username,
                            &parsed.token_aud,
                            parsed.issued_at,
                            parsed.expires_at,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_REVOKE_ACCOUNT_SESSION | "revoke_account_session" => {
                let parsed = SnAuthDbRevokeAccountSessionReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .revoke_account_session(&parsed.session_id, parsed.revoked_at)
                        .await,
                    &req,
                )
            }
            METHOD_REVOKE_USER_SESSIONS | "revoke_user_sessions" => {
                let parsed = SnAuthDbRevokeUserSessionsReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .revoke_user_sessions(&parsed.username, parsed.revoked_at)
                        .await,
                    &req,
                )
            }
            METHOD_GET_ACCOUNT_SESSION | "get_account_session" => {
                let parsed = SnAuthDbSessionIdReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_account_session(&parsed.session_id).await, &req)
            }
            _ => Err(RPCErrors::UnknownMethod(req.method.clone())),
        }
    }
}

pub fn normalize_sn_auth_db_url(auth_db_url: &str) -> String {
    let trimmed = auth_db_url.trim_end_matches('/');
    if let Some(base) = trimmed.strip_suffix(SN_AUTH_DB_RPC_PATH) {
        return format!("{}{}", base, SN_AUTH_DB_RPC_PATH);
    }
    format!("{}{}", trimmed, SN_AUTH_DB_RPC_PATH)
}

fn rpc_envelope_response<T: Serialize>(
    result: SnResult<T>,
    req: &RPCRequest,
) -> Result<RPCResponse, RPCErrors> {
    let envelope = match result {
        Ok(value) => SnAuthDbRpcEnvelope::success(value),
        Err(error) => SnAuthDbRpcEnvelope::failure(error),
    };
    let value = serde_json::to_value(envelope).map_err(|e| {
        RPCErrors::ParserResponseError(format!("Failed to serialize SnAuthDB RPC envelope: {}", e))
    })?;
    Ok(RPCResponse::create_by_req(RPCResult::Success(value), req))
}
