use async_trait::async_trait;
use bns_client::{
    AuthorityKey, AuthoritySetState, BnsClientResult, BnsIndexerApi, BnsSystemInfo, DocumentState,
    EventLogRecord, LogCheckpoint, NameState, OwnerResolution, ResolveResult,
};
use bns_indexer::CentralizedBnsIndexerHandler;
use bns_indexer::{
    default_document_update, CallAuthority, CentralizedBnsRegistry, DocumentRef, MutationGuard,
    RegisterOptions, SqliteBnsRegistryStore,
};
use bns_server::{open_sqlite_registry, spawn_listener, BnsContractHttpServer};
use buckyos_kit::init_logging;
use cyfs_gateway::{gateway_service_main, GatewayParams};
use cyfs_sn::SqliteSnAuthDB;
use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use kRPC::kRPC;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};

const BNS_NAME: &str = "bnsalice";
const BNS_ASSET_OWNER: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BNS_GATEWAY_DEVICE: &str = "gateway1";
const BNS_GATEWAY_DID: &str = "did:dev:bnsdevice1";
const BNS_GATEWAY_IP: &str = "203.0.113.11";
const BNS_TXT_RECORD: &str = "bns-txt=ok";

struct TestBnsRpc {
    projection: CentralizedBnsIndexerHandler<SqliteBnsRegistryStore>,
}

#[async_trait]
impl BnsIndexerApi for TestBnsRpc {
    async fn system_info(&self) -> BnsClientResult<BnsSystemInfo> {
        // The integration test exercises projection reads only. This fake RPC
        // still exposes the same readiness contract as production bns-rpc.
        self.projection.latest_checkpoint().await?;
        Ok(BnsSystemInfo {
            ready: true,
            chain_id: 31_337,
            contract_address: "0x2222222222222222222222222222222222222222".to_string(),
        })
    }

    async fn query_name_state(&self, name: &str) -> BnsClientResult<Option<NameState>> {
        self.projection.query_name_state(name).await
    }

    async fn resolve_owner(&self, name: &str) -> BnsClientResult<OwnerResolution> {
        self.projection.resolve_owner(name).await
    }

    async fn get_authority_set(&self, name: &str) -> BnsClientResult<AuthoritySetState> {
        self.projection.get_authority_set(name).await
    }

    async fn get_authority_key(
        &self,
        name: &str,
        kid: &str,
    ) -> BnsClientResult<Option<AuthorityKey>> {
        self.projection.get_authority_key(name, kid).await
    }

    async fn resolve_document(&self, name: &str, doc_type: &str) -> BnsClientResult<ResolveResult> {
        self.projection.resolve_document(name, doc_type).await
    }

    async fn get_document_version(
        &self,
        name: &str,
        doc_type: &str,
        version: u64,
    ) -> BnsClientResult<Option<DocumentState>> {
        self.projection
            .get_document_version(name, doc_type, version)
            .await
    }

    async fn list_events(
        &self,
        from_seq: u64,
        limit: usize,
    ) -> BnsClientResult<Vec<EventLogRecord>> {
        self.projection.list_events(from_seq, limit).await
    }

    async fn latest_checkpoint(&self) -> BnsClientResult<Option<LogCheckpoint>> {
        self.projection.latest_checkpoint().await
    }
}

fn inline_json_doc(doc_type: &str, value: Value) -> bns_indexer::DocumentUpdate {
    default_document_update(
        doc_type,
        0,
        DocumentRef::inline(serde_json::to_vec(&value).unwrap()),
    )
    .unwrap()
}

fn seed_bns_registry(db_path: &Path) {
    let registry = CentralizedBnsRegistry::new_legacy_state_machine(
        SqliteBnsRegistryStore::open(db_path).unwrap(),
    );
    registry
        .register_name(
            BNS_NAME,
            BNS_ASSET_OWNER,
            RegisterOptions::default(),
            vec![
                inline_json_doc(
                    "owner",
                    json!({
                        "id": format!("did:bns:{}", BNS_NAME),
                        "x": "owner-pkx-from-bns"
                    }),
                ),
                inline_json_doc(
                    "zone",
                    json!({
                        "gateway_device_name": BNS_GATEWAY_DEVICE,
                        "gateway_ips": [BNS_GATEWAY_IP],
                        "ttl": 120
                    }),
                ),
                inline_json_doc(
                    "boot",
                    json!({
                        "oods": [BNS_GATEWAY_DEVICE],
                        "ttl": 120
                    }),
                ),
                inline_json_doc(
                    "device_mini_doc",
                    json!({
                        "devices": {
                            (BNS_GATEWAY_DEVICE): {
                                "id": BNS_GATEWAY_DID,
                                "device_name": BNS_GATEWAY_DEVICE,
                                "addresses": ["203.0.113.12"],
                                "mini_config_jwt": "bns-mini-config-jwt"
                            }
                        }
                    }),
                ),
                inline_json_doc(
                    "dns_txt",
                    json!([
                        {
                            "ttl": 300,
                            "value": BNS_TXT_RECORD
                        }
                    ]),
                ),
            ],
            CallAuthority::public(),
            MutationGuard::default(),
        )
        .unwrap();
}

async fn allocate_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn wait_for_tcp(addr: SocketAddr) {
    for _ in 0..80 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("server did not start on {}", addr);
}

#[tokio::test(flavor = "local")]
async fn gateway_sn_resolves_bns_documents_through_sn_only() {
    init_logging("test_sn_bns_integration", false);
    let root_dir = tempfile::TempDir::new().unwrap();
    unsafe {
        std::env::set_var(
            "BUCKYOS_ROOT",
            root_dir.path().to_string_lossy().to_string(),
        );
    }

    let bns_db = tempfile::NamedTempFile::with_suffix(".bns.sqlite").unwrap();
    seed_bns_registry(bns_db.path());
    let registry = open_sqlite_registry(bns_db.path()).unwrap();
    let bns_http = BnsContractHttpServer::new(TestBnsRpc {
        projection: CentralizedBnsIndexerHandler::new(registry.clone()),
    });
    let bns_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bns_addr = bns_listener.local_addr().unwrap();
    let bns_server = spawn_listener(bns_listener, Arc::new(bns_http)).unwrap();

    let control_port = allocate_free_port().await;
    let http_port = allocate_free_port().await;
    let dns_port = allocate_free_port().await;
    let sn_db = tempfile::NamedTempFile::with_suffix(".sn.sqlite").unwrap();
    let auth_dir = tempfile::TempDir::new().unwrap();
    {
        let auth_db = SqliteSnAuthDB::new_by_path(sn_db.path().to_string_lossy().as_ref())
            .await
            .unwrap();
        auth_db.initialize_database().await.unwrap();
    }
    let config_file = tempfile::NamedTempFile::with_suffix(".yaml").unwrap();
    let config = format!(
        r#"
stacks:
  __control_server__:
    bind: 127.0.0.1:{control_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "server __control_server__";

  sn_http:
    bind: 127.0.0.1:{http_port}
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && call-server sn.http;
              reject;

  sn_dns:
    bind: 127.0.0.1:{dns_port}
    protocol: udp
    transparent: false
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server sn_dns;

servers:
  sn_dns:
    type: dns
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              resolve ${{REQ.name}} ${{REQ.record_type}} sn && return;

  sn:
    type: sn
    host: sn.local.test
    ip: 127.0.0.1
    boot_jwt: ""
    owner_pkx: ""
    device_jwt: []
    db_type: sqlite
    db_path: {}
    auth_data_dir: {}
    bns_rpc_url: http://{}
    bns_evm:
      controller_private_key: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
"#,
        sn_db.path().to_string_lossy(),
        auth_dir.path().to_string_lossy(),
        bns_addr
    );
    std::fs::write(config_file.path(), config).unwrap();

    let config_path = config_file.path().to_path_buf();
    let gateway_task = tokio::spawn(async move {
        gateway_service_main(
            config_path.as_path(),
            GatewayParams {
                keep_tunnel: vec![],
            },
        )
        .await
        .unwrap();
    });
    wait_for_tcp(SocketAddr::from(([127, 0, 0, 1], http_port))).await;

    let did_endpoint = format!("http://127.0.0.1:{}/1.0/identifiers", http_port);
    let deviceinfo_endpoint = format!("http://127.0.0.1:{}/kapi/sn/deviceinfo", http_port);
    let sn = kRPC::new(deviceinfo_endpoint.as_str(), None);
    let http_client = reqwest::Client::new();

    let zone: serde_json::Value = http_client
        .get(format!("{}/did:bns:{}?type=zone", did_endpoint, BNS_NAME))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(zone["gateway_device_name"], BNS_GATEWAY_DEVICE);
    assert_eq!(zone["gateway_ips"][0], BNS_GATEWAY_IP);

    let device: serde_json::Value = http_client
        .get(format!(
            "{}/did:bns:{}.{}?type=doc",
            did_endpoint, BNS_GATEWAY_DEVICE, BNS_NAME
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(device["id"], BNS_GATEWAY_DID);
    assert_eq!(device["device_name"], BNS_GATEWAY_DEVICE);

    let gateway = sn
        .call(
            "deviceinfo.resolve_ood_by_hostname",
            json!({
                "dest_host": BNS_NAME
            }),
        )
        .await
        .unwrap();
    assert_eq!(gateway["owner_id"], BNS_NAME);
    assert_eq!(gateway["state"], "active");

    let name_server_configs = vec![NameServerConfig::new(
        SocketAddr::from(([127, 0, 0, 1], dns_port)),
        Protocol::Udp,
    )];
    let resolver_config = ResolverConfig::from_parts(None, vec![], name_server_configs);
    let resolver = TokioAsyncResolver::tokio(resolver_config, ResolverOpts::default());

    let ips = resolver
        .lookup_ip(format!("{}.", BNS_NAME))
        .await
        .unwrap()
        .iter()
        .collect::<Vec<IpAddr>>();
    assert_eq!(ips, vec![IpAddr::from_str(BNS_GATEWAY_IP).unwrap()]);

    let txt = resolver
        .txt_lookup(format!("{}.", BNS_NAME))
        .await
        .unwrap()
        .iter()
        .map(|record| record.to_string())
        .collect::<Vec<String>>();
    assert!(
        txt.iter().any(|record| record.contains(BNS_TXT_RECORD)),
        "TXT response did not include BNS dns_txt record: {:?}",
        txt
    );

    gateway_task.abort();
    let _ = gateway_task.await;
    bns_server.shutdown().await;
}
