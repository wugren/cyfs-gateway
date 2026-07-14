use super::common::{
    AddDnsRecordReq, IntoRpcResult, RemoveDnsRecordReq, RpcCallResult, ok_response, parse_params,
    resolve_self_scoped_username,
};
use super::errors::{SnApiErrorCode, parse_error};
use crate::SNServer;
use crate::sn_authority::{AuthContext, require_sn_user_or_device};
use ::kRPC::{RPCErrors, RPCRequest, RPCResponse};
use cyfs_gateway_api::{SnAddDnsRecordResp, SnDnsRecord, SnDnsRecordListResp, SnSuccessResp};

fn normalize_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn is_same_or_subdomain(domain: &str, zone: &str) -> bool {
    domain == zone || domain.ends_with(format!(".{}", zone).as_str())
}

fn ensure_user_dns_domain(
    username: &str,
    user_domain: Option<&str>,
    server_host: &str,
    domain: &str,
) -> RpcCallResult<()> {
    let domain = normalize_domain(domain);
    if let Some(user_domain) = user_domain {
        let user_domain = normalize_domain(user_domain);
        if !user_domain.is_empty() && is_same_or_subdomain(domain.as_str(), user_domain.as_str()) {
            return Ok(());
        }
    }

    // Transitional web3 bridge compatibility: records under the SN-provided
    // `<username>.web3.<server_host>` namespace stay in the local compatibility
    // store. In particular, ACME challenges must not require a temporary BNS
    // document update and its associated on-chain gas cost.
    let bridge_domain = format!(
        "{}.web3.{}",
        normalize_domain(username),
        normalize_domain(server_host)
    );
    if is_same_or_subdomain(domain.as_str(), bridge_domain.as_str()) {
        return Ok(());
    }

    Err(parse_error(
        SnApiErrorCode::InvalidDomain,
        format!(
            "invalid domain, expect {} or its subdomain, or an active user_domain",
            bridge_domain
        ),
    ))
}

struct DnsMutationIdentity {
    username: String,
    device_name: String,
    is_device: bool,
}

async fn resolve_dns_mutation_identity(
    server: &SNServer,
    req: &RPCRequest,
    requested_device_did: &str,
) -> RpcCallResult<DnsMutationIdentity> {
    match require_sn_user_or_device(server, req).await? {
        AuthContext::SnUser { username, .. } => Ok(DnsMutationIdentity {
            device_name: ensure_owned_runtime_device(server, &username, requested_device_did)
                .await?,
            username,
            is_device: false,
        }),
        AuthContext::Device {
            zone, device_name, ..
        } => Ok(DnsMutationIdentity {
            username: zone,
            device_name,
            is_device: true,
        }),
    }
}

fn ensure_device_acme_record(domain: &str, record_type: &str) -> RpcCallResult<()> {
    if !record_type.eq_ignore_ascii_case("TXT") {
        return Err(parse_error(
            SnApiErrorCode::DevicePermissionDenied,
            "device DNS mutation only allows TXT",
        ));
    }
    let domain = normalize_domain(domain);
    if !domain.starts_with("_acme-challenge.") || domain.len() == "_acme-challenge.".len() {
        return Err(parse_error(
            SnApiErrorCode::DevicePermissionDenied,
            "device DNS mutation only allows _acme-challenge names",
        ));
    }
    Ok(())
}

pub(crate) async fn handle_dns(server: &SNServer, req: RPCRequest) -> RpcCallResult<RPCResponse> {
    match req.method.as_str() {
        "add_record" => {
            let params: AddDnsRecordReq = parse_params(&req)?;
            let identity =
                resolve_dns_mutation_identity(server, &req, params.device_did.as_str()).await?;
            let username = identity.username;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnApiErrorCode::UserNotFound, "user not found"))?;
            if identity.is_device {
                ensure_device_acme_record(&params.domain, &params.record_type)?;
            }
            ensure_user_dns_domain(
                username.as_str(),
                user.user_domain.as_deref(),
                server.resolver().config().server_host.as_str(),
                params.domain.as_str(),
            )?;
            server
                .compat_store()
                .add_user_domain(
                    username.as_str(),
                    params.domain.as_str(),
                    params.record_type.as_str(),
                    params.record.as_str(),
                    params.ttl.unwrap_or(600),
                )
                .await
                .into_rpc()?;
            if let Some(record_type) =
                crate::SNServer::parse_name_record_type(params.record_type.as_str())
            {
                server.remove_name_info_cache(params.domain.as_str(), record_type);
            }
            ok_response(
                &req,
                SnAddDnsRecordResp {
                    code: 0,
                    device_name: identity.device_name,
                },
            )
        }
        "remove_record" => {
            let params: RemoveDnsRecordReq = parse_params(&req)?;
            let identity =
                resolve_dns_mutation_identity(server, &req, params.device_did.as_str()).await?;
            let username = identity.username;
            let user = server
                .auth_db()
                .get_user_info(username.as_str())
                .await
                .into_rpc()?
                .ok_or_else(|| parse_error(SnApiErrorCode::UserNotFound, "user not found"))?;
            if identity.is_device {
                ensure_device_acme_record(&params.domain, &params.record_type)?;
                if params.record.as_deref().map(str::is_empty).unwrap_or(true) {
                    return Err(parse_error(
                        SnApiErrorCode::InvalidParams,
                        "device DNS removal requires an exact record value",
                    ));
                }
            }
            ensure_user_dns_domain(
                username.as_str(),
                user.user_domain.as_deref(),
                server.resolver().config().server_host.as_str(),
                params.domain.as_str(),
            )?;
            server
                .compat_store()
                .remove_user_domain(
                    username.as_str(),
                    params.domain.as_str(),
                    params.record_type.as_str(),
                    params.record.as_deref(),
                )
                .await
                .into_rpc()?;
            if let Some(record_type) =
                crate::SNServer::parse_name_record_type(params.record_type.as_str())
            {
                server.remove_name_info_cache(params.domain.as_str(), record_type);
            }
            ok_response(&req, SnSuccessResp { code: 0 })
        }
        "list_records" => {
            let username = resolve_self_scoped_username(server, &req, false).await?;
            let items = server
                .compat_store()
                .query_user_domain_records(username.as_str())
                .await
                .into_rpc()?;
            ok_response(
                &req,
                SnDnsRecordListResp {
                    code: 0,
                    items: items
                        .into_iter()
                        .map(|(domain, record_type, record, ttl)| SnDnsRecord {
                            domain,
                            record_type,
                            record,
                            ttl,
                        })
                        .collect(),
                },
            )
        }
        _ => Err(RPCErrors::UnknownMethod(req.method)),
    }
}

async fn ensure_owned_runtime_device(
    server: &SNServer,
    username: &str,
    device_did: &str,
) -> RpcCallResult<String> {
    if let Some(view) = server
        .device_info_db()
        .get_device_state(device_did)
        .await
        .into_rpc()?
    {
        if view.zone == username {
            return Ok(view.device_name);
        }
        return Err(parse_error(
            SnApiErrorCode::DevicePermissionDenied,
            "device has no permission",
        ));
    }

    if let Some(device) = server
        .compat_store()
        .query_device_by_did(device_did)
        .await
        .into_rpc()?
    {
        if device.owner == username {
            return Ok(device.device_name);
        }
    }

    Err(parse_error(
        SnApiErrorCode::DevicePermissionDenied,
        "device has no permission",
    ))
}

#[cfg(test)]
mod tests {
    use super::ensure_user_dns_domain;

    #[test]
    fn test_ensure_user_dns_domain_allows_own_web3_bridge_domain_without_user_domain() {
        assert!(
            ensure_user_dns_domain("alice", None, "buckyos.ai", "alice.web3.buckyos.ai").is_ok()
        );
        assert!(
            ensure_user_dns_domain(
                "alice",
                None,
                "buckyos.ai",
                "_acme-challenge.alice.web3.buckyos.ai"
            )
            .is_ok()
        );

        let err = ensure_user_dns_domain("alice", None, "buckyos.ai", "home.bob.web3.buckyos.ai")
            .unwrap_err()
            .to_string();
        assert!(err.contains("[SN:1015:invalid_domain]"));
    }

    #[test]
    fn test_ensure_user_dns_domain_for_custom_user_domain() {
        assert!(
            ensure_user_dns_domain(
                "alice",
                Some("alice.example.com"),
                "buckyos.ai",
                "home.alice.example.com",
            )
            .is_ok()
        );
        assert!(
            ensure_user_dns_domain(
                "alice",
                Some("alice.example.com"),
                "buckyos.ai",
                "alice.example.com",
            )
            .is_ok()
        );

        let err = ensure_user_dns_domain(
            "alice",
            Some("alice.example.com"),
            "buckyos.ai",
            "home.bob.example.com",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("[SN:1015:invalid_domain]"));
    }
}
