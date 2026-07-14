use crate::nameinfo_to_map_collection;
use clap::{Arg, Command};
use cyfs_gateway_lib::ServerErrorCode;
use cyfs_gateway_lib::ServerManagerWeakRef;
use cyfs_process_chain::{
    command_help, CollectionValue, CommandArgs, CommandHelpType, CommandResult, Context, EnvLevel,
    ExternalCommand, MemoryMapCollection,
};
use hickory_proto::xfer::Protocol;
use log::error;
use name_client::{DnsProvider, NameInfo, NsProvider, RecordType};
use name_lib::{EncodedDocument, DID};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

pub(crate) const DNS_AUTH_LOOPBACK_SUPPRESSED_MSG: &str =
    "authoritative_loopback_recursion_suppressed";

//todo:implement the cmd_resolve_did

pub struct CmdResolve {
    name: String,
    cmd: Command,
    server_mgr: ServerManagerWeakRef,
}

impl CmdResolve {
    pub fn new(server_mgr: ServerManagerWeakRef) -> Self {
        let cmd = Command::new("resolve")
            .about("resolve a domain name")
            .after_help(
                r#"
Examples:
    resolve example.com A
    resolve example.com AAAA
    resolve 192.168.1.1 PTR
    resolve example.com A 127.0.0.1
    resolve example.com A sn
                "#
            )
            .arg(
                Arg::new("domain")
                    .help("domain name")
                    .required(true)
                    .index(1),
            )
            .arg(
                Arg::new("record_type")
                    .help("The type of record to query")
                    .required(true)
                    .index(2),
            )
            .arg(
                Arg::new("server_address")
                    .help("Server address can be either a DNS server address or an inner service name. The local DNS server is used by default.")
                    .required(false)
                    .index(3),
            );

        Self {
            name: "resolve".to_string(),
            cmd,
            server_mgr,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }
}

fn parse_ipv4_arpa_name(domain: &str) -> Option<IpAddr> {
    let normalized = domain.trim_end_matches('.').to_lowercase();
    let suffix = ".in-addr.arpa";
    if !normalized.ends_with(suffix) {
        return None;
    }

    let prefix = normalized.strip_suffix(suffix)?;
    if prefix.is_empty() {
        return None;
    }

    let octets: Vec<&str> = prefix.split('.').collect();
    if octets.len() != 4 {
        return None;
    }

    let a = octets[3].parse::<u8>().ok()?;
    let b = octets[2].parse::<u8>().ok()?;
    let c = octets[1].parse::<u8>().ok()?;
    let d = octets[0].parse::<u8>().ok()?;
    Some(IpAddr::V4(Ipv4Addr::new(a, b, c, d)))
}

fn parse_ipv6_arpa_name(domain: &str) -> Option<IpAddr> {
    let normalized = domain.trim_end_matches('.').to_lowercase();
    let suffix = ".ip6.arpa";
    if !normalized.ends_with(suffix) {
        return None;
    }

    let prefix = normalized.strip_suffix(suffix)?;
    if prefix.is_empty() {
        return None;
    }

    let nibbles: Vec<&str> = prefix.split('.').collect();
    if nibbles.len() != 32 {
        return None;
    }

    let mut hex = String::with_capacity(32);
    for nibble in nibbles.iter().rev() {
        if nibble.len() != 1 {
            return None;
        }
        let c = nibble.chars().next()?;
        if !c.is_ascii_hexdigit() {
            return None;
        }
        hex.push(c);
    }

    u128::from_str_radix(hex.as_str(), 16)
        .ok()
        .map(Ipv6Addr::from)
        .map(IpAddr::V6)
}

fn normalize_ptr_query_name(domain: &str, record_type: RecordType) -> String {
    if record_type != RecordType::PTR {
        return domain.to_string();
    }

    if let Ok(ip) = domain.parse::<IpAddr>() {
        return ip.to_string();
    }

    if let Some(ip) = parse_ipv4_arpa_name(domain) {
        return ip.to_string();
    }

    if let Some(ip) = parse_ipv6_arpa_name(domain) {
        return ip.to_string();
    }

    domain.to_string()
}

fn is_loopback_dns_server(server_address: &str) -> bool {
    if let Ok(ip) = server_address.parse::<IpAddr>() {
        return ip.is_loopback();
    }

    if let Ok(addr) = server_address.parse::<SocketAddr>() {
        return addr.ip().is_loopback();
    }

    false
}

async fn should_suppress_loopback_recursion(
    context: &Context,
    server_address: &str,
) -> Result<bool, String> {
    if !is_loopback_dns_server(server_address) {
        return Ok(false);
    }

    let authoritative = context
        .env()
        .get("REQ_dns_authoritative", None)
        .await?
        .and_then(|value| value.as_str().map(|s| s.eq_ignore_ascii_case("true")))
        .unwrap_or(false);

    Ok(authoritative)
}

async fn server_error_result(
    code: ServerErrorCode,
    message: impl Into<String>,
) -> Result<CommandResult, String> {
    let map = MemoryMapCollection::new_ref();
    let code_str = format!("{:?}", code);
    let message = message.into();
    map.insert("code", CollectionValue::String(code_str))
        .await
        .map_err(|e| e.to_string())?;
    map.insert("message", CollectionValue::String(message))
        .await
        .map_err(|e| e.to_string())?;
    Ok(CommandResult::error_with_value(CollectionValue::Map(map)))
}

#[async_trait::async_trait]
impl ExternalCommand for CmdResolve {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        self.cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid resolve command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;
        Ok(())
    }

    async fn exec(
        &self,
        context: &Context,
        args: &[CollectionValue],
        origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        let mut str_args = Vec::with_capacity(args.len());
        for arg in args.iter() {
            if !arg.is_string() {
                let msg = format!("Invalid argument type: expected string, got {:?}", arg);
                error!("{}", msg);
                return Err(msg);
            }
            str_args.push(arg.as_str().unwrap());
        }

        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&str_args)
            .map_err(|e| {
                let msg = format!("Invalid resolve command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let domain = matches.get_one::<String>("domain").ok_or_else(|| {
            let msg = "Invalid resolve command: missing domain";
            error!("{}", msg);
            msg
        })?;

        let record_type_str = matches.get_one::<String>("record_type").ok_or_else(|| {
            let msg = "Invalid resolve command: missing record type";
            error!("{}", msg);
            msg
        })?;

        let record_type = RecordType::from_str(record_type_str.as_str()).ok_or_else(|| {
            let msg = format!("Invalid record type: {}", record_type_str);
            error!("{}", msg);
            msg
        })?;

        let query_name = normalize_ptr_query_name(domain, record_type);
        let server_address = matches.get_one::<String>("server_address");
        let (provider_name, name_info) = if server_address.is_none() {
            let provider_name = "default_dns".to_string();
            let provider = DnsProvider::new(None);
            let name_info = match provider
                .query(query_name.as_str(), Some(record_type), None)
                .await
            {
                Ok(name_info) => name_info,
                Err(e) => {
                    return Ok(CommandResult::error_with_string(format!(
                        "Failed to resolve domain {} record_type {} via {}: {:?}",
                        query_name, record_type_str, provider_name, e
                    )));
                }
            };
            (provider_name, name_info)
        } else {
            let server_address = server_address.unwrap();
            if let Ok(address) = server_address.parse::<IpAddr>() {
                if should_suppress_loopback_recursion(context, server_address).await? {
                    let msg = format!(
                        "{}: skip resolve {} {} via loopback {}",
                        DNS_AUTH_LOOPBACK_SUPPRESSED_MSG,
                        query_name,
                        record_type_str,
                        server_address
                    );
                    return server_error_result(ServerErrorCode::NotFound, msg).await;
                }
                let provider_name = address.to_string();
                let provider = DnsProvider::new(Some(provider_name.clone()));
                let name_info = match provider
                    .query(query_name.as_str(), Some(record_type), None)
                    .await
                {
                    Ok(name_info) => name_info,
                    Err(e) => {
                        return Ok(CommandResult::error_with_string(format!(
                            "Failed to resolve domain {} record_type {} via {}: {:?}",
                            query_name, record_type_str, provider_name, e
                        )));
                    }
                };
                (provider_name, name_info)
            } else if let Ok(address) = server_address.parse::<SocketAddr>() {
                if should_suppress_loopback_recursion(context, server_address).await? {
                    let msg = format!(
                        "{}: skip resolve {} {} via loopback {}",
                        DNS_AUTH_LOOPBACK_SUPPRESSED_MSG,
                        query_name,
                        record_type_str,
                        server_address
                    );
                    return server_error_result(ServerErrorCode::NotFound, msg).await;
                }
                let provider_name = address.to_string();
                let provider = DnsProvider::new(Some(provider_name.clone()));
                let name_info = match provider
                    .query(query_name.as_str(), Some(record_type), None)
                    .await
                {
                    Ok(name_info) => name_info,
                    Err(e) => {
                        return Ok(CommandResult::error_with_string(format!(
                            "Failed to resolve domain {} record_type {} via {}: {:?}",
                            query_name, record_type_str, provider_name, e
                        )));
                    }
                };
                (provider_name, name_info)
            } else {
                let server_mgr = match self.server_mgr.upgrade() {
                    Some(server_mgr) => server_mgr,
                    None => {
                        let msg =
                            "Resolve command failed: server manager is unavailable".to_string();
                        error!("{}", msg);
                        return Ok(CommandResult::error_with_string(msg));
                    }
                };
                if let Some(dns_service) = server_mgr.get_name_server(server_address) {
                    let provider_name = dns_service.id();
                    let name_info = match dns_service
                        .query(query_name.as_str(), Some(record_type), None)
                        .await
                    {
                        Ok(name_info) => name_info,
                        Err(e) => {
                            let msg = format!(
                                "Resolve failed via {} for domain {} record_type {}: {:?}",
                                provider_name, query_name, record_type_str, e
                            );
                            return server_error_result(e.code(), msg).await;
                        }
                    };
                    (provider_name, name_info)
                } else {
                    let msg = format!(
                        "Invalid resolve command: inner service {} not found",
                        server_address
                    );
                    error!("{}", msg);
                    return Ok(CommandResult::error_with_string(msg));
                }
            }
        };
        let result = nameinfo_to_map_collection(record_type_str.as_str(), &name_info)
            .await
            .map_err(|e| format!("Failed to convert name info to map collection: {:?}", e))?;

        context
            .env()
            .create(
                "RESOLVE_RESP",
                CollectionValue::Map(result),
                EnvLevel::Global,
            )
            .await?;
        context
            .env()
            .create(
                "RESOLVE_PROVIDER",
                CollectionValue::String(provider_name),
                EnvLevel::Global,
            )
            .await?;
        Ok(CommandResult::success_with_string("RESOLVE_RESP"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyfs_process_chain::{
        CommandPipe, Context as ChainContext, Env, EnvLevel, GotoCounter, ProcessChainLinkedManager,
    };
    use std::sync::Arc;

    #[test]
    fn test_normalize_ptr_query_name_ipv4_arpa() {
        let name = normalize_ptr_query_name("1.1.168.192.in-addr.arpa.", RecordType::PTR);
        assert_eq!(name, "192.168.1.1");
    }

    #[test]
    fn test_normalize_ptr_query_name_ipv6_arpa() {
        let name = normalize_ptr_query_name(
            "b.a.0.0.9.8.7.6.5.0.4.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
            RecordType::PTR,
        );
        assert_eq!(name, "fe80::405:6789:ab");
    }

    #[test]
    fn test_normalize_ptr_query_name_plain_ip() {
        let name = normalize_ptr_query_name("192.168.1.1", RecordType::PTR);
        assert_eq!(name, "192.168.1.1");
    }

    #[test]
    fn test_is_loopback_dns_server() {
        assert!(is_loopback_dns_server("127.0.0.1"));
        assert!(is_loopback_dns_server("127.0.0.1:53"));
        assert!(is_loopback_dns_server("::1"));
        assert!(is_loopback_dns_server("[::1]:53"));
        assert!(!is_loopback_dns_server("8.8.8.8"));
        assert!(!is_loopback_dns_server("8.8.8.8:53"));
        assert!(!is_loopback_dns_server("local_dns"));
    }

    #[tokio::test]
    async fn test_should_suppress_loopback_recursion_only_for_authoritative_queries() {
        let env = Arc::new(Env::new(EnvLevel::Global, None));
        let context = ChainContext::new(
            Arc::new(ProcessChainLinkedManager::new()),
            env.clone(),
            Arc::new(GotoCounter::new()),
            CommandPipe::default(),
        );

        assert!(!should_suppress_loopback_recursion(&context, "127.0.0.1")
            .await
            .unwrap());

        env.create(
            "REQ_dns_authoritative",
            CollectionValue::String("true".to_string()),
        )
        .await
        .unwrap();

        assert!(should_suppress_loopback_recursion(&context, "127.0.0.1")
            .await
            .unwrap());
        assert!(!should_suppress_loopback_recursion(&context, "8.8.8.8")
            .await
            .unwrap());
    }
}
