use crate::sn_bns_proxy::SnBnsProxyError;
use bns_client::{BnsClientError, SnBnsControllerError};
use kRPC::RPCErrors;
use serde_json::json;

#[derive(Clone, Copy, Debug)]
pub(crate) enum SnApiErrorCode {
    InvalidParams = 1000,
    InvalidUsername = 1001,
    UsernameAlreadyExists = 1002,
    InvalidActiveCode = 1003,
    UserAuthNotFound = 1004,
    InvalidPassword = 1005,
    AuthRequired = 1006,
    InvalidToken = 1007,
    UserNotFound = 1008,
    DeviceNotFound = 1012,
    DevicePermissionDenied = 1013,
    InvalidDeviceDid = 1014,
    InvalidDomain = 1015,
    /// user_domain PKX proof 未通过（DNS TXT 缺失/不匹配或外部 DNS 查询失败）。
    /// message 为 JSON：含 `pkx_record_name` / `pkx` / `retryable` / `reason`，
    /// 客户端按提示配置 TXT 后可重试 `domain.bind`。
    DomainProofFailed = 1016,
    HostnameNotFound = 1017,
    CrossUserAccessDenied = 1018,
    UnsupportedPasswordAlgo = 1019,
    InvalidPasswordStorage = 1020,
    UserNotActivated = 1022,
    BnsPermissionDenied = 1023,
    BnsNameAlreadyExists = 1024,
    BnsWriteFailed = 1025,
    /// BNS proxy 未启用或该 operation 不在白名单内。
    BnsProxyUnavailable = 1026,
    /// 用户绑定的 controller 已不在当前配置（需人工迁移，不静默重分配）。
    BnsControllerUnavailable = 1027,
    InvalidEmail = 1028,
    EmailAlreadyBound = 1029,
    InternalError = 1099,
}

impl SnApiErrorCode {
    pub(crate) fn code(self) -> u32 {
        self as u32
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid_params",
            Self::InvalidUsername => "invalid_username",
            Self::UsernameAlreadyExists => "username_already_exists",
            Self::InvalidActiveCode => "invalid_active_code",
            Self::UserAuthNotFound => "user_auth_not_found",
            Self::InvalidPassword => "invalid_password",
            Self::AuthRequired => "auth_required",
            Self::InvalidToken => "invalid_token",
            Self::UserNotFound => "user_not_found",
            Self::DeviceNotFound => "device_not_found",
            Self::DevicePermissionDenied => "device_permission_denied",
            Self::InvalidDeviceDid => "invalid_device_did",
            Self::InvalidDomain => "invalid_domain",
            Self::DomainProofFailed => "domain_proof_failed",
            Self::HostnameNotFound => "hostname_not_found",
            Self::CrossUserAccessDenied => "cross_user_access_denied",
            Self::UnsupportedPasswordAlgo => "unsupported_password_algo",
            Self::InvalidPasswordStorage => "invalid_password_storage",
            Self::UserNotActivated => "user_not_activated",
            Self::BnsPermissionDenied => "bns_permission_denied",
            Self::BnsNameAlreadyExists => "bns_name_already_exists",
            Self::BnsWriteFailed => "bns_write_failed",
            Self::BnsProxyUnavailable => "bns_proxy_unavailable",
            Self::BnsControllerUnavailable => "bns_controller_unavailable",
            Self::InvalidEmail => "invalid_email",
            Self::EmailAlreadyBound => "email_already_bound",
            Self::InternalError => "internal_error",
        }
    }

    pub(crate) fn format(self, message: impl AsRef<str>) -> String {
        format!("[SN:{}:{}] {}", self.code(), self.name(), message.as_ref())
    }
}

pub(crate) fn parse_error(code: SnApiErrorCode, message: impl AsRef<str>) -> RPCErrors {
    RPCErrors::ParseRequestError(code.format(message))
}

pub(crate) fn reason_error(code: SnApiErrorCode, message: impl AsRef<str>) -> RPCErrors {
    RPCErrors::ReasonError(code.format(message))
}

pub(crate) fn bns_write_error(error: SnBnsControllerError) -> RPCErrors {
    let (code, bns_code, expected, actual) = match &error {
        SnBnsControllerError::Bns(BnsClientError::Registry(info)) => {
            let code = match info.code.as_str() {
                "CONTROLLER_SCOPE_DENIED" | "NOT_EFFECTIVE_OWNER" => {
                    SnApiErrorCode::BnsPermissionDenied
                }
                "NAME_ALREADY_EXISTS" => SnApiErrorCode::BnsNameAlreadyExists,
                _ => SnApiErrorCode::BnsWriteFailed,
            };
            (code, info.code.as_str(), info.expected, info.actual)
        }
        other => (SnApiErrorCode::BnsWriteFailed, other.code(), None, None),
    };

    reason_error(
        code,
        json!({
            "bns_code": bns_code,
            "expected": expected,
            "actual": actual,
            "message": error.to_string(),
        })
        .to_string(),
    )
}

pub(crate) fn bns_proxy_error(error: SnBnsProxyError) -> RPCErrors {
    match error {
        SnBnsProxyError::Write(SnBnsControllerError::InvalidInput(message)) => {
            parse_error(SnApiErrorCode::InvalidParams, message)
        }
        SnBnsProxyError::Write(inner) => bns_write_error(inner),
        SnBnsProxyError::InvalidInput(message) => {
            parse_error(SnApiErrorCode::InvalidParams, message)
        }
        SnBnsProxyError::OperationNotAllowed(operation) => reason_error(
            SnApiErrorCode::BnsProxyUnavailable,
            format!("bns proxy operation `{}` is not allowed", operation),
        ),
        error @ SnBnsProxyError::ControllerUnavailable { .. } => {
            reason_error(SnApiErrorCode::BnsControllerUnavailable, error.to_string())
        }
        SnBnsProxyError::Store(message) => reason_error(SnApiErrorCode::InternalError, message),
    }
}
