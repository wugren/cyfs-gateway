use std::collections::HashMap;
use std::f32::consts::E;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;

use async_trait::async_trait;

use hickory_proto::serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder};
use hickory_server::authority::{
    Catalog, MessageRequest, MessageResponse, MessageResponseBuilder, Queries,
};
use hickory_server::proto::op::*;
use hickory_server::proto::rr::*;
use hickory_server::server::{Request, RequestHandler, RequestInfo, ResponseHandler, ResponseInfo};
use hickory_server::ServerFuture;
use log::trace;
use log::{debug, error, info, warn};
use rdata::{A, AAAA, CNAME, NS, PTR, SOA, TXT};
use tokio::net::UdpSocket;

use crate::cmd_resolve::{CmdResolve, DNS_AUTH_LOOPBACK_SUPPRESSED_MSG};
use crate::map_collection_to_nameinfo;
use anyhow::Result;
use cyfs_gateway_lib::*;
use cyfs_process_chain::{
    CollectionValue, CommandControl, MemoryMapCollection, ProcessChainLibExecutor,
};
use futures::stream::{self, StreamExt};
use hickory_proto::op::message::EmitAndCount;
use hickory_proto::serialize::txt::RDataParser;
use hickory_proto::xfer::{Protocol, SerialMessage};
use hickory_proto::{ProtoError, ProtoErrorKind};
use name_client::{DnsProvider, LocalConfigDnsProvider, NameInfo, NsProvider, RecordType};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;
use url::Url;

//TODO: dns_provider is realy a demo implementation, must refactor before  used in a offical server.
fn nameinfo_to_rdata(record_type: &str, name_info: &NameInfo) -> Result<Vec<RData>> {
    match record_type {
        "A" => {
            let mut records = Vec::new();
            // Convert all IPv4 addresses to A records
            for addr in name_info.address.iter() {
                match addr {
                    IpAddr::V4(addr) => {
                        records.push(RData::A(A::from(*addr)));
                    }
                    _ => {
                        debug!("Skipping non-IPv4 address");
                        continue;
                    }
                }
            }

            Ok(records)
        }
        "AAAA" => {
            let mut records = Vec::new();
            // Convert all IPv6 addresses to AAAA records
            for addr in name_info.address.iter() {
                match addr {
                    IpAddr::V6(addr) => {
                        records.push(RData::AAAA(AAAA::from(*addr)));
                    }
                    _ => {
                        debug!("Skipping non-IPv6 address");
                        continue;
                    }
                }
            }

            Ok(records)
        }
        "CNAME" => {
            if name_info.cname.is_none() {
                return Err(anyhow::anyhow!("CNAME is none"));
            }
            let cname = name_info.cname.clone().unwrap();
            let mut records = Vec::new();
            records.push(RData::CNAME(CNAME(Name::from_str(cname.as_str()).unwrap())));
            return Ok(records);
        }
        "HTTPS" => {
            // Recognize HTTPS/SVCB queries, but treat them as NODATA until
            // explicit HTTPS record support is added.
            return Ok(vec![]);
        }
        "TXT" => {
            let mut records = Vec::new();
            for txt in name_info.txt.iter() {
                records.push(RData::TXT(TXT::new(vec![txt.clone()])));
            }
            return Ok(records);
        }
        "CAA" => {
            let mut records = Vec::new();
            for caa in name_info.caa.iter() {
                let rdata =
                    RData::try_from_str(hickory_server::proto::rr::RecordType::CAA, caa.as_str())
                        .map_err(|e| anyhow::anyhow!("invalid CAA {}: {}", caa, e))?;
                records.push(rdata);
            }
            return Ok(records);
        }
        "PTR" => {
            if name_info.ptr_records.is_empty() {
                return Err(anyhow::anyhow!("PTR is none"));
            }
            let mut records = Vec::new();
            for ptr in name_info.ptr_records.iter() {
                let target = Name::from_str(ptr)
                    .or_else(|_| Name::from_str(format!("{}.", ptr).as_str()))
                    .map_err(|e| anyhow::anyhow!("invalid PTR target {}: {}", ptr, e))?;
                records.push(RData::PTR(PTR(target)));
            }
            return Ok(records);
        }
        _ => {
            return Err(anyhow::anyhow!("Unknown record type:{}", record_type));
        }
    }
}

const AUTH_ZONE_TTL: u32 = 300;
const AUTH_SOA_REFRESH: i32 = 300;
const AUTH_SOA_RETRY: i32 = 60;
const AUTH_SOA_EXPIRE: i32 = 86400;
const AUTH_SOA_MINIMUM: u32 = 60;

#[derive(Clone, Debug)]
struct Web3ZoneAuthority {
    zone_name: Name,
    zone_name_str: String,
    ns_name: Name,
    mbox_name: Name,
}

fn normalize_fqdn(name: &Name) -> String {
    name.to_utf8().trim_end_matches('.').to_ascii_lowercase()
}

fn detect_web3_zone_authority(name: &Name) -> Option<Web3ZoneAuthority> {
    let normalized = normalize_fqdn(name);
    let labels: Vec<&str> = normalized.split('.').collect();
    let web3_index = labels.iter().position(|label| *label == "web3")?;
    if web3_index >= labels.len() - 1 {
        return None;
    }

    let zone_name_str = labels[web3_index..].join(".");
    let suffix = labels[web3_index + 1..].join(".");
    let zone_name = Name::from_str(format!("{}.", zone_name_str).as_str()).ok()?;
    let ns_name = Name::from_str(format!("dns.{}.", suffix).as_str()).ok()?;
    let mbox_name = Name::from_str(format!("hostmaster.{}.", suffix).as_str()).ok()?;

    Some(Web3ZoneAuthority {
        zone_name,
        zone_name_str,
        ns_name,
        mbox_name,
    })
}

fn zone_serial() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(u32::MAX as u64) as u32
}

fn zone_ns_record(zone: &Web3ZoneAuthority) -> Record {
    Record::from_rdata(
        zone.zone_name.clone(),
        AUTH_ZONE_TTL,
        RData::NS(NS(zone.ns_name.clone())),
    )
}

fn zone_soa_record(zone: &Web3ZoneAuthority) -> Record {
    Record::from_rdata(
        zone.zone_name.clone(),
        AUTH_ZONE_TTL,
        RData::SOA(SOA::new(
            zone.ns_name.clone(),
            zone.mbox_name.clone(),
            zone_serial(),
            AUTH_SOA_REFRESH,
            AUTH_SOA_RETRY,
            AUTH_SOA_EXPIRE,
            AUTH_SOA_MINIMUM,
        )),
    )
}

fn is_core_authoritative_record_type(query_type: hickory_server::proto::rr::RecordType) -> bool {
    matches!(
        query_type,
        hickory_server::proto::rr::RecordType::A
            | hickory_server::proto::rr::RecordType::AAAA
            | hickory_server::proto::rr::RecordType::TXT
            | hickory_server::proto::rr::RecordType::NS
            | hickory_server::proto::rr::RecordType::SOA
    )
}

fn is_authoritative_loopback_suppressed_error(err: &ServerError) -> bool {
    err.code() == ServerErrorCode::NotFound
        && err.to_string().contains(DNS_AUTH_LOOPBACK_SUPPRESSED_MSG)
}

/// Trait for handling incoming requests, and providing a message response.
#[async_trait::async_trait]
trait DnsRequestHandler<'q, 'a, Answers, NameServers, Soa, Additionals>:
    Send + Sync + Unpin + 'static
where
    Answers: Iterator<Item = &'a Record> + Send + 'a,
    NameServers: Iterator<Item = &'a Record> + Send + 'a,
    Soa: Iterator<Item = &'a Record> + Send + 'a,
    Additionals: Iterator<Item = &'a Record> + Send + 'a,
{
    async fn handle_request(
        &self,
        request: &Request,
    ) -> MessageResponse<
        '_,
        'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
        impl Iterator<Item = &'a Record> + Send + 'a,
    >;
}

pub(crate) struct CyfsQueriesEmitAndCount {
    /// Number of queries in this segment
    length: usize,
    /// Use the first query, if it exists, to pre-populate the string compression cache
    first_query: Option<LowerQuery>,
    /// The cached rendering of the original (wire-format) queries
    cached_serialized: Vec<u8>,
}

impl CyfsQueriesEmitAndCount {
    fn new() -> Self {
        CyfsQueriesEmitAndCount {
            length: 0,
            first_query: None,
            cached_serialized: vec![],
        }
    }
}

impl EmitAndCount for CyfsQueriesEmitAndCount {
    fn emit(&mut self, encoder: &mut BinEncoder<'_>) -> std::result::Result<usize, ProtoError> {
        let original_offset = encoder.offset();
        encoder.emit_vec(self.cached_serialized.as_slice())?;
        if !encoder.is_canonical_names() && self.first_query.is_some() {
            encoder.store_label_pointer(
                original_offset,
                original_offset + self.cached_serialized.len(),
            )
        }
        Ok(self.length)
    }
}

pub struct InnerDnsRecordManager {
    records: RwLock<HashMap<String, HashMap<String, NameInfo>>>,
}
pub type InnerDnsRecordManagerRef = Arc<InnerDnsRecordManager>;

impl InnerDnsRecordManager {
    pub fn new() -> Arc<Self> {
        Arc::new(InnerDnsRecordManager {
            records: RwLock::new(HashMap::new()),
        })
    }

    pub fn add_record(
        &self,
        name: impl Into<String>,
        record_type: impl Into<String>,
        value: impl Into<String>,
    ) -> ServerResult<()> {
        let name = name.into();
        let record_type = record_type.into();
        let value = value.into();
        let mut records = self.records.write().unwrap();
        match record_type.as_str() {
            "A" | "AAAA" => {
                let ip = IpAddr::from_str(value.as_str()).map_err(into_server_err!(
                    ServerErrorCode::InvalidParam,
                    "invalid ip {}",
                    value
                ))?;
                let info = records
                    .entry(name.clone())
                    .or_insert(HashMap::new())
                    .entry(record_type)
                    .or_insert(NameInfo::new(name.as_str()));
                info.address.push(ip);
            }
            "TXT" => {
                let info = records
                    .entry(name.clone())
                    .or_insert(HashMap::new())
                    .entry(record_type)
                    .or_insert(NameInfo::new(name.as_str()));
                info.txt.push(value);
            }
            "CAA" => {
                let info = records
                    .entry(name.clone())
                    .or_insert(HashMap::new())
                    .entry(record_type)
                    .or_insert(NameInfo::new(name.as_str()));
                info.caa.push(value);
            }
            "CNAME" => {
                let info = records
                    .entry(name.clone())
                    .or_insert(HashMap::new())
                    .entry(record_type)
                    .or_insert(NameInfo::new(name.as_str()));
                info.cname = Some(value);
            }
            _ => {
                return Err(ServerError::new(
                    ServerErrorCode::InvalidParam,
                    format!("Invalid record type:{}", record_type),
                ));
            }
        }
        Ok(())
    }

    pub fn remove_record(&self, name: impl Into<String>, record_type: impl Into<String>) {
        let name = name.into();
        let record_type = record_type.into();
        let mut records = self.records.write().unwrap();
        if let Some(record) = records.get_mut(name.as_str()) {
            record.remove(record_type.as_str());
            if record.is_empty() {
                records.remove(name.as_str());
            }
        }
    }

    pub fn get_record(
        &self,
        name: impl Into<String>,
        record_type: impl Into<String>,
    ) -> Option<NameInfo> {
        let name = name.into();
        let record_type = record_type.into();
        let records = self.records.read().unwrap();
        records
            .get(name.as_str())
            .and_then(|record| record.get(record_type.as_str()).cloned())
    }
}

pub struct ProcessChainDnsServer {
    id: String,
    server_mgr: ServerManagerWeakRef,
    global_process_chains: Option<GlobalProcessChainsRef>,
    global_collection_manager: Option<GlobalCollectionManagerRef>,
    executor: Arc<Mutex<ProcessChainLibExecutor>>,
    inner_record_manager: InnerDnsRecordManagerRef,
}

impl ProcessChainDnsServer {
    async fn command_error_to_server_error(&self, value: &CollectionValue) -> Option<ServerError> {
        let CollectionValue::Map(map) = value else {
            return None;
        };

        let code = map.get("code").await.ok().flatten()?;
        let message = map
            .get("message")
            .await
            .ok()
            .flatten()
            .and_then(|value| value.as_str().map(|s| s.to_string()))
            .unwrap_or_default();

        let CollectionValue::String(code) = code else {
            return None;
        };

        let server_code = match code.as_str() {
            "NotFound" => ServerErrorCode::NotFound,
            "DnsQueryError" => ServerErrorCode::DnsQueryError,
            "Rejected" => ServerErrorCode::Rejected,
            "InvalidParam" => ServerErrorCode::InvalidParam,
            _ => ServerErrorCode::ProcessChainError,
        };

        Some(ServerError::new(server_code, message))
    }

    pub async fn create_server(
        id: String,
        server_mgr: ServerManagerWeakRef,
        global_process_chains: Option<GlobalProcessChainsRef>,
        global_collection_manager: Option<GlobalCollectionManagerRef>,
        hook_point: ProcessChainConfigs,
        inner_record_manager: InnerDnsRecordManagerRef,
        js_externals: Option<JsExternalsManagerRef>,
    ) -> ServerResult<Self> {
        let resolve_cmd = CmdResolve::new(server_mgr.clone());
        let mut commands = get_external_commands(server_mgr.clone());
        commands.push((
            resolve_cmd.name().to_string(),
            Arc::new(Box::new(resolve_cmd)),
        ));
        let (executor, _) = create_process_chain_executor(
            &hook_point,
            global_process_chains.clone(),
            global_collection_manager.clone(),
            Some(commands),
            js_externals,
        )
        .await
        .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;

        Ok(Self {
            id,
            server_mgr,
            global_process_chains,
            global_collection_manager,
            executor: Arc::new(Mutex::new(executor)),
            inner_record_manager,
        })
    }

    async fn name_info_to_buffer(
        &self,
        request: &Request,
        request_info: &RequestInfo<'_>,
        record_type: &str,
        name_info: NameInfo,
    ) -> ServerResult<Vec<u8>> {
        let mut builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(ResponseCode::NoError);

        let rdata_vec = nameinfo_to_rdata(record_type, &name_info)
            .map_err(|e| server_err!(ServerErrorCode::EncodeError, "{}", e))?;
        let mut ttl = name_info.ttl.unwrap_or(600);
        let records = rdata_vec
            .into_iter()
            .map(|rdata| Record::from_rdata(request_info.query.name().into(), ttl, rdata))
            .collect::<Vec<_>>();
        let mut message = builder.build(header, records.iter(), &[], &[], &[]);

        let mut buffer = Vec::with_capacity(512);
        let encode_result = {
            let mut encoder = BinEncoder::new(&mut buffer);

            let max_size = if let Some(edns) = message.get_edns() {
                edns.max_payload()
            } else {
                // No EDNS, use the recommended max from RFC6891.
                hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE as u16
            };
            encoder.set_max_size(max_size);

            message.destructive_emit(&mut encoder)
        }
        .map_err(into_server_err!(ServerErrorCode::EncodeError));
        Ok(buffer)
    }

    fn records_response_to_buffer(
        &self,
        request: &Request,
        response_code: ResponseCode,
        authoritative: bool,
        answers: Vec<Record>,
        name_servers: Vec<Record>,
        soa: Vec<Record>,
    ) -> ServerResult<Vec<u8>> {
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut header = Header::response_from_request(request.header());
        header.set_response_code(response_code);
        header.set_authoritative(authoritative);
        let mut message =
            builder.build(header, answers.iter(), name_servers.iter(), soa.iter(), &[]);

        let mut buffer = Vec::with_capacity(512);
        {
            let mut encoder = BinEncoder::new(&mut buffer);

            let max_size = if let Some(edns) = message.get_edns() {
                edns.max_payload()
            } else {
                hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE as u16
            };
            encoder.set_max_size(max_size);

            message
                .destructive_emit(&mut encoder)
                .map_err(into_server_err!(ServerErrorCode::EncodeError))?;
        }

        Ok(buffer)
    }

    fn response_code_to_buffer(
        &self,
        request: &Request,
        response_code: ResponseCode,
    ) -> ServerResult<Vec<u8>> {
        self.records_response_to_buffer(request, response_code, false, vec![], vec![], vec![])
    }

    fn authoritative_zone_response_to_buffer(
        &self,
        request: &Request,
        response_code: ResponseCode,
        answers: Vec<Record>,
        authority_soa: Vec<Record>,
    ) -> ServerResult<Vec<u8>> {
        self.records_response_to_buffer(
            request,
            response_code,
            true,
            answers,
            vec![],
            authority_soa,
        )
    }

    fn authoritative_web3_zone_response(
        &self,
        request: &Request,
        request_info: &RequestInfo<'_>,
    ) -> Option<ServerResult<Vec<u8>>> {
        let query_name = request_info.query.name();
        let query_type = request_info.query.query_type();
        let zone = detect_web3_zone_authority(query_name)?;
        let query_name_str = normalize_fqdn(query_name);
        let is_zone_apex = query_name_str == zone.zone_name_str;

        match query_type {
            hickory_server::proto::rr::RecordType::NS if is_zone_apex => {
                Some(self.authoritative_zone_response_to_buffer(
                    request,
                    ResponseCode::NoError,
                    vec![zone_ns_record(&zone)],
                    vec![],
                ))
            }
            hickory_server::proto::rr::RecordType::SOA if is_zone_apex => {
                Some(self.authoritative_zone_response_to_buffer(
                    request,
                    ResponseCode::NoError,
                    vec![zone_soa_record(&zone)],
                    vec![],
                ))
            }
            hickory_server::proto::rr::RecordType::NS
            | hickory_server::proto::rr::RecordType::SOA => {
                Some(self.authoritative_zone_response_to_buffer(
                    request,
                    ResponseCode::NoError,
                    vec![],
                    vec![zone_soa_record(&zone)],
                ))
            }
            _ => None,
        }
    }

    async fn handle_request<'a>(
        &self,
        request: &Request,
        dst_addr: Option<String>,
    ) -> ServerResult<Vec<u8>> {
        if request.op_code() != OpCode::Query {
            return Err(server_err!(
                ServerErrorCode::InvalidDnsOpType,
                "{}",
                request.op_code()
            ));
        }

        // make sure the message type is a query
        if request.message_type() != MessageType::Query {
            return Err(server_err!(
                ServerErrorCode::InvalidDnsMessageType,
                "{}",
                request.message_type()
            ));
        }

        let from_ip = request.src();

        let reqeust_info = request
            .request_info()
            .map_err(into_server_err!(ServerErrorCode::BadRequest))?;
        let name = reqeust_info.query.name().to_string();
        let record_type_str = reqeust_info.query.query_type().to_string();
        let authoritative_zone = detect_web3_zone_authority(reqeust_info.query.name());

        if let Some(response) = self.authoritative_web3_zone_response(request, &reqeust_info) {
            return response;
        }

        // First, check if the record exists in the inner record manager
        if let Some(name_info) = self
            .inner_record_manager
            .get_record(&name, &record_type_str)
        {
            debug!(
                "dns query resolved by provider=inner_record_manager: name={} type={}",
                name, record_type_str
            );
            return self
                .name_info_to_buffer(request, &reqeust_info, record_type_str.as_str(), name_info)
                .await;
        }

        let map = MemoryMapCollection::new_ref();
        map.insert("name", CollectionValue::String(name.clone()))
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "record_type",
            CollectionValue::String(record_type_str.clone()),
        )
        .await
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_addr",
            CollectionValue::String(from_ip.ip().to_string()),
        )
        .await
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        map.insert(
            "source_port",
            CollectionValue::String(from_ip.port().to_string()),
        )
        .await
        .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        if let Some(dst_addr) = dst_addr {
            if let Ok(socket_addr) = dst_addr.parse::<SocketAddr>() {
                map.insert(
                    "dest_addr",
                    CollectionValue::String(socket_addr.to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
                map.insert(
                    "dest_ip",
                    CollectionValue::String(socket_addr.ip().to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
                map.insert(
                    "dest_port",
                    CollectionValue::String(socket_addr.port().to_string()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
            }
        }

        let executor = { self.executor.lock().unwrap().fork() };
        let chain_env = executor.chain_env().clone();
        chain_env
            .create(
                "REQ_dns_authoritative",
                CollectionValue::String(authoritative_zone.is_some().to_string()),
            )
            .await
            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        if let Some(zone) = &authoritative_zone {
            chain_env
                .create(
                    "REQ_dns_authoritative_zone",
                    CollectionValue::String(zone.zone_name_str.clone()),
                )
                .await
                .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
        }
        let ret = execute_chain(executor, map)
            .await
            .map_err(into_server_err!(ServerErrorCode::ProcessChainError))?;
        if ret.is_error() {
            if let Some(err) = self.command_error_to_server_error(ret.value_ref()).await {
                return Err(err);
            }
            return Err(server_err!(
                ServerErrorCode::ProcessChainError,
                "{}",
                ret.value()
            ));
        }
        if ret.is_control() {
            if ret.is_drop() {
                return Err(server_err!(ServerErrorCode::Rejected));
            } else if ret.is_reject() {
                return Err(server_err!(ServerErrorCode::Rejected));
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
                let value = if let CollectionValue::String(value) = &(ret.value) {
                    value
                } else {
                    return Err(server_err!(
                        ServerErrorCode::ProcessChainError,
                        "invalid process chain result"
                    ));
                };
                if let Some(list) = shlex::split(value.as_str()) {
                    if list.is_empty() {
                        let resp = chain_env
                            .get("RESOLVE_RESP")
                            .await
                            .map_err(|e| server_err!(ServerErrorCode::ProcessChainError, "{e}"))?;
                        if let Some(resp) = resp {
                            if let CollectionValue::Map(resp) = resp {
                                let provider_name = chain_env
                                    .get("RESOLVE_PROVIDER")
                                    .await
                                    .ok()
                                    .flatten()
                                    .and_then(|value| value.as_str().map(|s| s.to_string()))
                                    .unwrap_or_else(|| "process_chain".to_string());
                                let name_info =
                                    map_collection_to_nameinfo(&resp).await.map_err(|e| {
                                        server_err!(ServerErrorCode::ProcessChainError, "{e}")
                                    })?;
                                debug!(
                                    "dns query resolved by provider={}: name={} type={}",
                                    provider_name, name, record_type_str
                                );
                                return self
                                    .name_info_to_buffer(
                                        request,
                                        &reqeust_info,
                                        record_type_str.as_str(),
                                        name_info,
                                    )
                                    .await;
                            }
                        }
                    }

                    // let cmd = list[0].as_str();
                    // match cmd {
                    //     "inner_service" => {}
                    // }
                }
            }
        }
        Err(server_err!(
            ServerErrorCode::ProcessChainError,
            "invalid process chain result"
        ))
    }

    async fn handle(
        &self,
        message_bytes: &[u8],
        src_addr: Option<String>,
        dst_addr: Option<String>,
    ) -> ServerResult<Vec<u8>> {
        let mut decoder = BinDecoder::new(message_bytes);

        // Attempt to decode the message
        match MessageRequest::read(&mut decoder) {
            Ok(message) => {
                let addr = if let Some(src_addr) = src_addr.as_ref() {
                    match src_addr.parse::<SocketAddr>() {
                        Ok(src_addr) => src_addr,
                        Err(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    }
                } else {
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                };

                let request = Request::new(message, addr, Protocol::Udp);
                let request_info = request
                    .request_info()
                    .map_err(into_server_err!(ServerErrorCode::BadRequest))?;
                let query_name = request_info.query.name().to_string();
                let query_type = request_info.query.query_type().to_string();
                match self.handle_request(&request, dst_addr).await {
                    Ok(response) => Ok(response),
                    Err(e) => {
                        if let Ok(request_info) = request.request_info() {
                            if let Some(zone) =
                                detect_web3_zone_authority(request_info.query.name())
                            {
                                let query_type = request_info.query.query_type();
                                let is_zone_apex =
                                    normalize_fqdn(request_info.query.name()) == zone.zone_name_str;
                                let is_core_zone_type =
                                    is_core_authoritative_record_type(query_type);

                                if is_authoritative_loopback_suppressed_error(&e)
                                    && !is_core_zone_type
                                {
                                    return self.authoritative_zone_response_to_buffer(
                                        &request,
                                        ResponseCode::NoError,
                                        vec![],
                                        vec![zone_soa_record(&zone)],
                                    );
                                }

                                if is_zone_apex && !is_core_zone_type {
                                    return self.authoritative_zone_response_to_buffer(
                                        &request,
                                        ResponseCode::NoError,
                                        vec![],
                                        vec![zone_soa_record(&zone)],
                                    );
                                }
                            }
                        }
                        let response_code = match e.code() {
                            ServerErrorCode::NotFound => ResponseCode::NXDomain,
                            ServerErrorCode::Rejected => ResponseCode::Refused,
                            _ => ResponseCode::ServFail,
                        };
                        warn!(
                            "dns query failed: name={} type={} src={} response_code={:?} err={}",
                            query_name, query_type, addr, response_code, e
                        );
                        self.response_code_to_buffer(&request, response_code)
                    }
                }
            }
            Err(ProtoError { kind, .. }) if kind.as_form_error().is_some() => {
                // We failed to parse the request due to some issue in the message, but the header is available, so we can respond
                let (header, error) = kind
                    .into_form_error()
                    .expect("as form_error already confirmed this is a FormError");

                let mut buffer = Vec::with_capacity(512);
                let mut encoder = BinEncoder::new(&mut buffer);
                message::emit_message_parts(
                    &header,
                    &mut CyfsQueriesEmitAndCount::new(),
                    &mut (Vec::<&Record>::new().into_iter()),
                    &mut (Vec::<&Record>::new().into_iter()),
                    &mut (Vec::<&Record>::new().into_iter()),
                    None,
                    &vec![],
                    &mut encoder,
                )
                .map_err(into_server_err!(ServerErrorCode::EncodeError))?;

                Ok(buffer)
            }
            Err(error) => Err(server_err!(ServerErrorCode::InvalidData, "request:Failed")),
        }
    }
}

#[async_trait::async_trait(?Send)]
impl cyfs_gateway_lib::server::DatagramServer for ProcessChainDnsServer {
    async fn serve_datagram(&self, buf: &[u8], info: DatagramInfo) -> ServerResult<Vec<u8>> {
        let response = self.handle(buf, info.src_addr, info.dst_addr).await?;

        Ok(response)
    }

    fn id(&self) -> String {
        self.id.clone()
    }
}

pub struct ProcessChainDnsServerFactory;

#[derive(Clone)]
pub struct DnsServerContext {
    pub server_mgr: ServerManagerWeakRef,
    pub global_process_chains: GlobalProcessChainsRef,
    pub js_externals: JsExternalsManagerRef,
    pub global_collection_manager: GlobalCollectionManagerRef,
    pub inner_record_manager: InnerDnsRecordManagerRef,
}

impl DnsServerContext {
    pub fn new(
        server_mgr: ServerManagerWeakRef,
        global_process_chains: GlobalProcessChainsRef,
        js_externals: JsExternalsManagerRef,
        global_collection_manager: GlobalCollectionManagerRef,
        inner_record_manager: InnerDnsRecordManagerRef,
    ) -> Self {
        Self {
            server_mgr,
            global_process_chains,
            js_externals,
            global_collection_manager,
            inner_record_manager,
        }
    }
}

impl ServerContext for DnsServerContext {
    fn get_server_type(&self) -> String {
        "dns".to_string()
    }
}

impl ProcessChainDnsServerFactory {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl ServerFactory for ProcessChainDnsServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<DnsServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid dns server config"
            ))?;

        let context = context.ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "dns server context is required"
        ))?;
        let context = context
            .as_ref()
            .as_any()
            .downcast_ref::<DnsServerContext>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid dns server context"
            ))?;

        let server = ProcessChainDnsServer::create_server(
            config.id.clone(),
            context.server_mgr.clone(),
            Some(context.global_process_chains.clone()),
            Some(context.global_collection_manager.clone()),
            config.hook_point.clone(),
            context.inner_record_manager.clone(),
            Some(context.js_externals.clone()),
        )
        .await?;
        Ok(vec![Server::Datagram(Arc::new(server))])
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DnsServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub hook_point: ProcessChainConfigs,
}

impl ServerConfig for DnsServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        "dns".to_string()
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::nameinfo_to_rdata;
    use crate::{
        DnsServerConfig, DnsServerContext, InnerDnsRecordManager, LocalDns, ProcessChainDnsServer,
        ProcessChainDnsServerFactory,
    };
    use async_trait::async_trait;
    use cyfs_gateway_lib::server::DatagramServer;
    use cyfs_gateway_lib::{
        ConnectionManager, DatagramInfo, DefaultLimiterManager, GlobalCollectionManager,
        GlobalProcessChains, JsExternalsManager, NameServer, Server, ServerErrorCode,
        ReuseportServerRuntime, ReuseportServerRuntimeConfig, ServerFactory, ServerManager,
        ServerResult, StackContext, StackFactory, StatManager, TunnelManager, UdpStackConfig,
        UdpStackContext, UdpStackFactory,
    };
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::RecordType;
    use hickory_server::proto::rr::{Name, RData};
    use name_client::NameInfo;
    use name_lib::{EncodedDocument, DID};
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;
    use std::sync::Arc;

    struct EmptyAaaaNameServer;

    #[async_trait]
    impl NameServer for EmptyAaaaNameServer {
        fn id(&self) -> String {
            "empty_aaaa".to_string()
        }

        async fn query(
            &self,
            name: &str,
            record_type: Option<name_client::RecordType>,
            _from_ip: Option<IpAddr>,
        ) -> ServerResult<NameInfo> {
            match record_type.unwrap_or_default() {
                name_client::RecordType::A => Ok(NameInfo::from_address(
                    name,
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                )),
                name_client::RecordType::AAAA => Ok(NameInfo::from_address_vec(name, vec![])),
                _ => Err(cyfs_gateway_lib::server_err!(
                    ServerErrorCode::NotFound,
                    "record type not found"
                )),
            }
        }

        async fn query_did(
            &self,
            _did: &DID,
            _fragment: Option<&str>,
            _from_ip: Option<IpAddr>,
        ) -> ServerResult<EncodedDocument> {
            Err(cyfs_gateway_lib::server_err!(
                ServerErrorCode::NotFound,
                "did not found"
            ))
        }
    }

    #[tokio::test]
    async fn test_process_chain_dns_server_factory() {
        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
          return "server www.buckyos.com";
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let config = Arc::new(config);
        let server_mgr = Arc::new(ServerManager::new());
        let context = DnsServerContext::new(
            Arc::downgrade(&server_mgr),
            Arc::new(GlobalProcessChains::new()),
            Arc::new(JsExternalsManager::new()),
            GlobalCollectionManager::create(vec![]).await.unwrap(),
            InnerDnsRecordManager::new(),
        );
        let factory = ProcessChainDnsServerFactory::new();
        let ret = factory.create(config, Some(Arc::new(context))).await;
        assert!(ret.is_ok());
    }

    async fn create_authoritative_test_server() -> ProcessChainDnsServer {
        let server_mgr = Arc::new(ServerManager::new());
        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
          return "server missing";
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            InnerDnsRecordManager::new(),
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await
        .unwrap()
    }

    async fn create_authoritative_notfound_test_server() -> ProcessChainDnsServer {
        let server_mgr = Arc::new(ServerManager::new());
        server_mgr
            .add_server(Server::NameServer(Arc::new(EmptyAaaaNameServer)))
            .unwrap();

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
          call resolve ${REQ.name} ${REQ.record_type} empty_aaaa && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            InnerDnsRecordManager::new(),
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await
        .unwrap()
    }

    async fn create_authoritative_loopback_fallback_test_server() -> ProcessChainDnsServer {
        let server_mgr = Arc::new(ServerManager::new());

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
          call resolve ${REQ.name} ${REQ.record_type} 127.0.0.1 && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            InnerDnsRecordManager::new(),
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_ns_query_returns_answer() {
        let server = create_authoritative_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::NS);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::NS);
        match resp.answers()[0].data() {
            RData::NS(ns) => assert_eq!(ns.0.to_string(), "dns.buckyos.ai."),
            _ => panic!("expected NS answer"),
        }
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_soa_query_returns_answer() {
        let server = create_authoritative_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::SOA);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::SOA);
        match resp.answers()[0].data() {
            RData::SOA(soa) => {
                assert_eq!(soa.mname().to_string(), "dns.buckyos.ai.");
                assert_eq!(soa.rname().to_string(), "hostmaster.buckyos.ai.");
            }
            _ => panic!("expected SOA answer"),
        }
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_subdomain_ns_query_returns_nodata_with_soa() {
        let server = create_authoritative_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("foo.web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::NS);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.name_servers().len(), 1);
        assert_eq!(resp.name_servers()[0].record_type(), RecordType::SOA);
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_apex_missing_record_returns_nodata_with_soa() {
        let server = create_authoritative_notfound_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::MX);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.name_servers().len(), 1);
        assert_eq!(resp.name_servers()[0].record_type(), RecordType::SOA);
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_subdomain_caa_loopback_fallback_returns_nodata() {
        let server = create_authoritative_loopback_fallback_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("wugren2026.web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::CAA);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.header().authoritative());
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.name_servers().len(), 1);
        assert_eq!(resp.name_servers()[0].record_type(), RecordType::SOA);
    }

    #[tokio::test]
    async fn test_authoritative_web3_zone_subdomain_a_loopback_fallback_still_returns_nxdomain() {
        let server = create_authoritative_loopback_fallback_test_server().await;

        let mut message = Message::new();
        let name = Name::from_str("wugren2026.web3.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
    }

    #[test]
    fn test_nameinfo_to_rdata_caa_variants() {
        let mut name_info = NameInfo::new("web3.buckyos.ai");
        name_info.caa = vec![
            "0 issue \"letsencrypt.org\"".to_string(),
            "0 iodef \"mailto:ops@buckyos.ai\"".to_string(),
        ];

        let rdata = nameinfo_to_rdata("CAA", &name_info).unwrap();
        assert_eq!(rdata.len(), 2);
        assert!(matches!(rdata[0], RData::CAA(_)));
        assert!(matches!(rdata[1], RData::CAA(_)));

        let empty = nameinfo_to_rdata("CAA", &NameInfo::new("web3.buckyos.ai")).unwrap();
        assert!(empty.is_empty());

        let mut invalid = NameInfo::new("web3.buckyos.ai");
        invalid.caa = vec!["not-a-valid-caa".to_string()];
        assert!(nameinfo_to_rdata("CAA", &invalid).is_err());
    }

    #[test]
    fn test_nameinfo_to_rdata_https_is_empty_success() {
        let rdata = nameinfo_to_rdata("HTTPS", &NameInfo::new("web3.buckyos.ai")).unwrap();
        assert!(rdata.is_empty());
    }

    #[test]
    fn test_inner_dns_record_manager_caa_records() {
        let manager = InnerDnsRecordManager::new();
        manager
            .add_record("web3.buckyos.ai", "CAA", "0 issue \"letsencrypt.org\"")
            .unwrap();
        manager
            .add_record(
                "web3.buckyos.ai",
                "CAA",
                "0 iodef \"mailto:ops@buckyos.ai\"",
            )
            .unwrap();

        let name_info = manager.get_record("web3.buckyos.ai", "CAA").unwrap();
        assert_eq!(name_info.caa.len(), 2);
        assert!(name_info
            .caa
            .contains(&"0 issue \"letsencrypt.org\"".to_string()));

        manager.remove_record("web3.buckyos.ai", "CAA");
        assert!(manager.get_record("web3.buckyos.ai", "CAA").is_none());
    }

    #[tokio::test]
    async fn test_process_chain_dns_server_local_dns() {
        let local_dns_content = r#"
["www.buckyos.com"]
ttl = 300
address = ["192.168.1.1"]
txt = [
"BOOT=eyJhbGciOiJFZERTQSJ9.eyJvb2RzIjpbInNuIl0sImV4cCI6MjA1ODgzODkzOX0.SGem2FBRB0H2TcRWBRJCsCg5PYXzHW9X9853UChV_qzWHHhKxunZ-emotSnr9HufjL7avGEos1ifRjl9KTrzBg;",
"PKX=qJdNEtscIYwTo-I0K7iPEt_UZdBDRd4r16jdBfNR0tM;",
"DEV=eyJhbGciOiJFZERTQSJ9.eyJuIjoic24iLCJ4IjoiRlB2WTNXWFB4dVdQWUZ1d09ZMFFiaDBPNy1oaEtyNnRhMWpUY1g5T1JQSSIsImV4cCI6MjA1ODgzODkzOX0._YKR0y6E4JQJXDEG12WWFfY1pXyxtdSuigERZQXphnQAarDM02JIoXLNtad80U7T7lO_A4z_HbNDRJ9hMGKhCA;"
]
caa = ["0 issue \"letsencrypt.org\""]

["_acme-challenge.web3.buckyos.com"]
ttl = 300
txt = ["challenge-token"]

["*.buckyos.com"]
ttl = 300
address = ["192.168.1.2"]

["*.sub.buckyos.com"]
ttl = 300
address = ["192.168.1.3"]


["mail.buckyos.com"]
ttl = 300
address = ["2600:1700:1150:9440:5cbb:f6ff:fe9e:eefa"]

        "#;
        let mut local_dns = tempfile::NamedTempFile::new().unwrap();
        local_dns.write_all(local_dns_content.as_bytes()).unwrap();
        let server_mgr = Arc::new(ServerManager::new());
        let dns_server = LocalDns::create(
            "local_dns".to_string(),
            local_dns.path().to_string_lossy().to_string(),
        );
        assert!(dns_server.is_ok());
        let dns_server = dns_server.unwrap();

        server_mgr
            .add_server(Server::NameServer(Arc::new(dns_server)))
            .unwrap();

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
           call resolve ${REQ.name} ${REQ.record_type} ttt && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let inner_record_manager = InnerDnsRecordManager::new();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            inner_record_manager,
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await;
        assert!(server.is_ok());
        let server = server.unwrap();

        let mut message = Message::new();

        // 添加查询
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.response_code(), ResponseCode::ServFail);

        let data = server
            .serve_datagram(
                msg_vec.as_slice(),
                DatagramInfo::new(Some("127.0.0.1:434".to_string())),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.response_code(), ResponseCode::ServFail);

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
           call resolve ${REQ.name} ${REQ.record_type} local_dns && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let inner_record_manager = InnerDnsRecordManager::new();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            inner_record_manager,
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await;
        assert!(server.is_ok());
        let server = server.unwrap();

        let mut message = Message::new();

        // 添加查询
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::A);
        assert_eq!(
            resp.answers()[0].data(),
            &RData::A(hickory_proto::rr::rdata::A(
                Ipv4Addr::from_str("192.168.1.1").unwrap()
            ))
        );

        let mut message = Message::new();
        let name = Name::from_str("1.1.168.192.in-addr.arpa.").unwrap();
        let query = Query::query(name, RecordType::PTR);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::PTR);
        match resp.answers()[0].data() {
            RData::PTR(ptr) => assert_eq!(ptr.0.to_string(), "www.buckyos.com."),
            _ => panic!("expected PTR answer"),
        }

        let mut message = Message::new();
        // 添加查询
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::TXT);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 3);
        assert_eq!(resp.answers()[0].record_type(), RecordType::TXT);

        let mut message = Message::new();
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::CAA);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::CAA);
        match resp.answers()[0].data() {
            RData::CAA(caa) => assert_eq!(caa.to_string(), "0 issue \"letsencrypt.org\""),
            _ => panic!("expected CAA answer"),
        }

        let mut message = Message::new();
        let name = Name::from_str("mail.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::CAA);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 0);

        let mut message = Message::new();
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::HTTPS);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 0);

        let mut message = Message::new();
        let name = Name::from_str("_acme-challenge.web3.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::TXT);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(None),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::TXT);

        let mut message = Message::new();
        // 添加查询
        let name = Name::from_str("www.buckyos1.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server
            .serve_datagram(
                msg_vec.as_slice(),
                DatagramInfo::new(Some("127.0.0.1:434".to_string())),
            )
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);

        let data = server
            .serve_datagram(&msg_vec[..1], DatagramInfo::new(None))
            .await;
        assert!(data.is_err());

        let data = server
            .serve_datagram(&msg_vec[..msg_vec.len() - 1], DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
    }

    #[tokio::test]
    async fn test_process_chain_dns_server_empty_aaaa_returns_noerror() {
        let server_mgr = Arc::new(ServerManager::new());
        server_mgr
            .add_server(Server::NameServer(Arc::new(EmptyAaaaNameServer)))
            .unwrap();

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
           call resolve ${REQ.name} ${REQ.record_type} empty_aaaa && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            InnerDnsRecordManager::new(),
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await
        .unwrap();

        let mut message = Message::new();
        let name = Name::from_str("sn.buckyos.ai.").unwrap();
        let query = Query::query(name, RecordType::AAAA);
        message.add_query(query);
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let data = server
            .serve_datagram(
                message.to_vec().unwrap().as_slice(),
                DatagramInfo::new(Some("127.0.0.1:5353".to_string())),
            )
            .await
            .unwrap();
        let resp = Message::from_vec(data.as_slice()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert_eq!(resp.answers().len(), 0);
    }

    #[tokio::test]
    async fn test_process_chain_dns_server_query() {
        let local_dns_content = r#"
["www.buckyos.com"]
ttl = 300
address = ["192.168.1.1"]
txt = [
"THISISATEST",
"BOOT=eyJhbGciOiJFZERTQSJ9.eyJvb2RzIjpbInNuIl0sImV4cCI6MjA1ODgzODkzOX0.SGem2FBRB0H2TcRWBRJCsCg5PYXzHW9X9853UChV_qzWHHhKxunZ-emotSnr9HufjL7avGEos1ifRjl9KTrzBg;",
"PKX=qJdNEtscIYwTo-I0K7iPEt_UZdBDRd4r16jdBfNR0tM;",
"DEV=eyJhbGciOiJFZERTQSJ9.eyJuIjoic24iLCJ4IjoiRlB2WTNXWFB4dVdQWUZ1d09ZMFFiaDBPNy1oaEtyNnRhMWpUY1g5T1JQSSIsImV4cCI6MjA1ODgzODkzOX0._YKR0y6E4JQJXDEG12WWFfY1pXyxtdSuigERZQXphnQAarDM02JIoXLNtad80U7T7lO_A4z_HbNDRJ9hMGKhCA;"
]

["*.buckyos.com"]
ttl = 300
address = ["192.168.1.2"]

["*.sub.buckyos.com"]
ttl = 300
address = ["192.168.1.3"]


["mail.buckyos.com"]
ttl = 300
address = ["2600:1700:1150:9440:5cbb:f6ff:fe9e:eefa"]

        "#;
        let mut local_dns = tempfile::NamedTempFile::new().unwrap();
        local_dns.write_all(local_dns_content.as_bytes()).unwrap();
        let server_mgr = Arc::new(ServerManager::new());
        let dns_server = LocalDns::create(
            "local_dns".to_string(),
            local_dns.path().to_string_lossy().to_string(),
        );
        assert!(dns_server.is_ok());
        let dns_server = dns_server.unwrap();

        server_mgr
            .add_server(Server::NameServer(Arc::new(dns_server)))
            .unwrap();

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
           call resolve ${REQ.name} ${REQ.record_type} local_dns && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let global_process_chains = Arc::new(GlobalProcessChains::new());
        let context = DnsServerContext::new(
            Arc::downgrade(&server_mgr),
            global_process_chains.clone(),
            Arc::new(JsExternalsManager::new()),
            GlobalCollectionManager::create(vec![]).await.unwrap(),
            InnerDnsRecordManager::new(),
        );
        let server_factory = ProcessChainDnsServerFactory::new();
        let ret = server_factory
            .create(Arc::new(config), Some(Arc::new(context)))
            .await;
        assert!(ret.is_ok());
        let servers = ret.unwrap();

        let server_manager = Arc::new(ServerManager::new());
        for server in servers {
            server_manager.add_server(server);
        }
        let stack_config = r#"
id: test_dns
bind: 127.0.0.1:9325
protocol: udp
hook_point:
  - id: main
    priority: 1
    blocks:
       - id: default
         block: |
            return "server test";
        "#;

        let stack_config: UdpStackConfig = serde_yaml_ng::from_str(stack_config).unwrap();
        let tunnel_manager = TunnelManager::new();
        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let stat_manager = StatManager::new();
        let collection_manager = GlobalCollectionManager::create(vec![]).await.unwrap();
        let server_runtime =
            ReuseportServerRuntime::start(ReuseportServerRuntimeConfig::new().with_workers(1))
                .unwrap();
        let stack = UdpStackFactory::new(ConnectionManager::new(), server_runtime);
        let stack_context: Arc<dyn StackContext> = Arc::new(UdpStackContext::new(
            server_manager.clone(),
            tunnel_manager,
            limiter_manager,
            stat_manager,
            Some(global_process_chains.clone()),
            Some(collection_manager),
            Some(Arc::new(JsExternalsManager::new())),
        ));
        let ret = stack.create(Arc::new(stack_config), stack_context).await;
        assert!(ret.is_ok());
        let stack = ret.unwrap();
        if let Err(e) = stack.start().await {
            let msg = e.to_string();
            if msg.contains("Operation not permitted") || msg.contains("permission denied") {
                eprintln!(
                    "skip test_process_chain_dns_server_query: sandbox denied UDP stack bind: {e}"
                );
                return;
            }
            panic!("UdpStack start failed: {e}");
        }

        let config = r#"
type: dns
id: test
hook_point:
  - id: main
    priority: 1
    blocks:
      - id: main
        block: |
           call resolve ${REQ.name} ${REQ.record_type} "127.0.0.1:9325" && return;
        "#;
        let config: DnsServerConfig = serde_yaml_ng::from_str(config).unwrap();
        let inner_record_manager = InnerDnsRecordManager::new();
        let server = ProcessChainDnsServer::create_server(
            config.id,
            Arc::downgrade(&server_mgr),
            Some(Arc::new(GlobalProcessChains::new())),
            Some(GlobalCollectionManager::create(vec![]).await.unwrap()),
            config.hook_point,
            inner_record_manager,
            Some(Arc::new(JsExternalsManager::new())),
        )
        .await;
        assert!(server.is_ok());
        let server = server.unwrap();

        let mut message = Message::new();

        // 添加查询
        let name = Name::from_str("www.buckyos.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(resp.answers()[0].record_type(), RecordType::A);
        assert_eq!(
            resp.answers()[0].data(),
            &RData::A(hickory_proto::rr::rdata::A(
                Ipv4Addr::from_str("192.168.1.1").unwrap()
            ))
        );

        let mut message = Message::new();

        // 添加查询
        let name = Name::from_str("www.buckyos1.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);

        // 设置DNSSEC标志
        message.set_authentic_data(true);
        message.set_checking_disabled(false);

        let msg_vec = message.to_vec();
        assert!(msg_vec.is_ok());
        let msg_vec = msg_vec.unwrap();

        let data = server
            .serve_datagram(msg_vec.as_slice(), DatagramInfo::new(None))
            .await;
        assert!(data.is_ok());
        let resp = Message::from_vec(data.unwrap().as_slice()).unwrap();
        assert_eq!(resp.answers().len(), 0);
    }
}
