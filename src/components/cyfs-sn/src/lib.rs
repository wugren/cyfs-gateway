mod api;
pub mod name_info_cache;
mod relay_mgr;
pub mod s2s_api;
mod sn_auth;
mod sn_auth_manager;
mod sn_authority;
mod sn_bns_proxy;
mod sn_bns_reader;
mod sn_bns_signer;
mod sn_compat_store;
mod sn_device_info;
pub mod sn_did_resolver;
mod sn_dns_proof;
pub mod sn_resolver;
mod sn_seed;
mod sn_server;

pub use name_info_cache::*;
pub use relay_mgr::*;
pub use s2s_api::*;
pub use sn_auth::*;
pub use sn_bns_proxy::*;
pub use sn_bns_signer::*;
pub use sn_compat_store::*;
pub use sn_device_info::*;
pub use sn_did_resolver::*;
pub use sn_dns_proof::*;
pub use sn_resolver::*;
pub use sn_seed::*;
pub use sn_server::*;

pub use sfo_result::err as sn_err;
pub use sfo_result::into_err as into_sn_err;

#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnErrorCode {
    Failed,
    InvalidInput,
    NotFound,
    Conflict,
    StaleReport,
    Blocked,
    DBError,
    RemoteError,
}

pub type SnResult<T> = sfo_result::Result<T, SnErrorCode>;
pub type SnError = sfo_result::Error<SnErrorCode>;
