//! §4.6 device_info remote 模式：本地 service 与 remote client 暴露**同一组接口**，
//! 同一批用例参数化跑两遍（local / remote）结果一致。
//!
//! 这里的 "remote" 走真实 S2S 序列化路径：每个调用都序列化成 RPC 请求，经
//! `SnDeviceInfoDbRpcHandler::handle_rpc_call` 处理后把 `SnDeviceInfoDbRpcEnvelope`
//! 反序列化回类型——等价于 KRPC 传输，但无需活节点 / HTTP（loopback）。
//! 这样既验证接口一致，又钉死 wire 类型（`SnDeviceStateView` 等）与错误码的编解码。

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use cyfs_sn::{
    RemoteSnDeviceInfoDB, SnDeviceEndpointUpdate, SnDeviceInfoDB, SnDeviceInfoDbClient,
    SnDeviceInfoDbDeviceReasonReq, SnDeviceInfoDbDidReq, SnDeviceInfoDbExpireDevicesReq,
    SnDeviceInfoDbGetDeviceStateByNameReq, SnDeviceInfoDbListZoneDevicesReq,
    SnDeviceInfoDbRebindDeviceIndexReq, SnDeviceInfoDbRpcEnvelope, SnDeviceInfoDbRpcHandler,
    SnDeviceInfoDbUpdateDeviceStateReq, SnDeviceInfoDbUpsertDeviceIndexReq, SnDeviceListOptions,
    SnDeviceRole, SnDeviceState, SnDeviceStateUpdate, SnDeviceStateView, SnEndpointProtocol,
    SnEndpointScope, SnEndpointSource, SnError, SnErrorCode, SnNatType, SnResult,
    SqliteSnDeviceInfoDB, METHOD_BLOCK_DEVICE, METHOD_EXPIRE_DEVICES, METHOD_GET_DEVICE_STATE,
    METHOD_GET_DEVICE_STATE_BY_NAME, METHOD_LIST_ZONE_DEVICES, METHOD_MARK_DEVICE_OFFLINE,
    METHOD_REBIND_DEVICE_INDEX, METHOD_REMOVE_DEVICE_INDEX, METHOD_UNBLOCK_DEVICE,
    METHOD_UPDATE_DEVICE_STATE, METHOD_UPSERT_DEVICE_INDEX,
};
use kRPC::{RPCHandler, RPCRequest, RPCResult};
use serde::Serialize;
use serde_json::Value;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

async fn local_db() -> (tempfile::TempDir, SqliteSnDeviceInfoDB) {
    let tmp_dir = tempfile::tempdir().unwrap();
    let db_path = tmp_dir.path().join("sn_device_info.sqlite3");
    let db = SqliteSnDeviceInfoDB::new_by_path(db_path.to_string_lossy().as_ref())
        .await
        .unwrap();
    db.initialize_database().await.unwrap();
    (tmp_dir, db)
}

/// Remote client：每个 trait 方法都经真实 RPC 编解码后路由到底层 handler。
struct LoopbackClient {
    handler: SnDeviceInfoDbRpcHandler<SqliteSnDeviceInfoDB>,
}

impl LoopbackClient {
    async fn dispatch<Req: Serialize>(&self, method: &str, req: Req) -> SnResult<Value> {
        let rpc_req = RPCRequest::new(method, serde_json::to_value(req).unwrap());
        let resp = self
            .handler
            .handle_rpc_call(rpc_req, LOCALHOST)
            .await
            .map_err(|e| SnError::new(SnErrorCode::RemoteError, format!("transport: {e}")))?;
        match resp.result {
            RPCResult::Success(value) => Ok(value),
            RPCResult::Failed(error) => Err(SnError::new(SnErrorCode::RemoteError, error)),
        }
    }

    async fn call_unit<Req: Serialize>(&self, method: &str, req: Req) -> SnResult<()> {
        let value = self.dispatch(method, req).await?;
        let envelope: SnDeviceInfoDbRpcEnvelope<Value> = serde_json::from_value(value).unwrap();
        envelope.into_unit_result()
    }

    async fn call<Req: Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        req: Req,
    ) -> SnResult<Resp> {
        let value = self.dispatch(method, req).await?;
        let envelope: SnDeviceInfoDbRpcEnvelope<Resp> = serde_json::from_value(value).unwrap();
        envelope.into_result()
    }
}

#[async_trait]
impl SnDeviceInfoDB for LoopbackClient {
    async fn upsert_device_index(
        &self,
        did: &str,
        zone: &str,
        device_name: &str,
        device_role: SnDeviceRole,
    ) -> SnResult<()> {
        self.call_unit(
            METHOD_UPSERT_DEVICE_INDEX,
            SnDeviceInfoDbUpsertDeviceIndexReq::new(did, zone, device_name, device_role),
        )
        .await
    }

    async fn rebind_device_index(
        &self,
        did: &str,
        new_zone: &str,
        new_device_name: &str,
        new_device_role: SnDeviceRole,
        reason: &str,
    ) -> SnResult<()> {
        self.call_unit(
            METHOD_REBIND_DEVICE_INDEX,
            SnDeviceInfoDbRebindDeviceIndexReq::new(
                did,
                new_zone,
                new_device_name,
                new_device_role,
                reason,
            ),
        )
        .await
    }

    async fn remove_device_index(&self, did: &str) -> SnResult<()> {
        self.call_unit(METHOD_REMOVE_DEVICE_INDEX, SnDeviceInfoDbDidReq::new(did))
            .await
    }

    async fn update_device_state(&self, update: SnDeviceStateUpdate) -> SnResult<()> {
        self.call_unit(
            METHOD_UPDATE_DEVICE_STATE,
            SnDeviceInfoDbUpdateDeviceStateReq::new(update),
        )
        .await
    }

    async fn get_device_state(&self, did: &str) -> SnResult<Option<SnDeviceStateView>> {
        self.call(METHOD_GET_DEVICE_STATE, SnDeviceInfoDbDidReq::new(did))
            .await
    }

    async fn get_device_state_by_name(
        &self,
        zone: &str,
        device_name: &str,
    ) -> SnResult<Option<SnDeviceStateView>> {
        self.call(
            METHOD_GET_DEVICE_STATE_BY_NAME,
            SnDeviceInfoDbGetDeviceStateByNameReq::new(zone, device_name),
        )
        .await
    }

    async fn list_zone_devices(
        &self,
        zone: &str,
        options: SnDeviceListOptions,
    ) -> SnResult<Vec<SnDeviceStateView>> {
        self.call(
            METHOD_LIST_ZONE_DEVICES,
            SnDeviceInfoDbListZoneDevicesReq::new(zone, options),
        )
        .await
    }

    async fn mark_device_offline(&self, did: &str, reason: &str) -> SnResult<()> {
        self.call_unit(
            METHOD_MARK_DEVICE_OFFLINE,
            SnDeviceInfoDbDeviceReasonReq::new(did, reason),
        )
        .await
    }

    async fn block_device(&self, did: &str, reason: &str) -> SnResult<()> {
        self.call_unit(
            METHOD_BLOCK_DEVICE,
            SnDeviceInfoDbDeviceReasonReq::new(did, reason),
        )
        .await
    }

    async fn unblock_device(&self, did: &str, reason: &str) -> SnResult<()> {
        self.call_unit(
            METHOD_UNBLOCK_DEVICE,
            SnDeviceInfoDbDeviceReasonReq::new(did, reason),
        )
        .await
    }

    async fn expire_devices(&self, now: u64, batch_size: Option<usize>) -> SnResult<usize> {
        self.call(
            METHOD_EXPIRE_DEVICES,
            SnDeviceInfoDbExpireDevicesReq::new(now, batch_size),
        )
        .await
    }
}

fn endpoint(endpoint_id: &str, host: &str, scope: SnEndpointScope) -> SnDeviceEndpointUpdate {
    SnDeviceEndpointUpdate {
        endpoint_id: endpoint_id.to_string(),
        protocol: SnEndpointProtocol::Tcp,
        host: host.to_string(),
        port: Some(8080),
        scope,
        priority: 10,
        source: SnEndpointSource::DeviceReport,
        expires_at: None,
    }
}

fn state_update(did: &str, seq: u64, ttl: u64) -> SnDeviceStateUpdate {
    SnDeviceStateUpdate {
        did: did.to_string(),
        reported_ip: Some("192.168.1.10".to_string()),
        reported_ips: vec!["8.8.8.8".to_string(), "10.0.0.2".to_string()],
        from_ip: Some("1.1.1.1".to_string()),
        nat_type: SnNatType::Public,
        endpoints: vec![
            endpoint("private", "192.168.1.10", SnEndpointScope::Private),
            endpoint("public", "8.8.8.8", SnEndpointScope::Public),
        ],
        report_seq: Some(seq),
        ttl,
        raw_report: Some(r#"{"ok":true}"#.to_string()),
    }
}

fn err_code(result: SnResult<()>) -> String {
    match result {
        Ok(()) => "ok".to_string(),
        Err(e) => format!("err:{:?}", e.code()),
    }
}

/// 一批覆盖索引/重绑/上报/stale/block/expire/错误码的确定性操作；
/// 只记录结构性结果（状态、错误码、计数、IP、is_wan），不含绝对时间戳。
async fn run_batch(db: &dyn SnDeviceInfoDB) -> Vec<String> {
    let zone = "example";
    let a = "did:dev:device-a";
    let b = "did:dev:device-b";
    let mut obs = Vec::new();

    obs.push(format!(
        "get-missing:{}",
        db.get_device_state(a).await.unwrap().is_none()
    ));

    obs.push(format!(
        "upsert-a:{}",
        err_code(
            db.upsert_device_index(a, zone, "ood1", SnDeviceRole::Ood)
                .await
        )
    ));
    let offline = db.get_device_state(a).await.unwrap().unwrap();
    obs.push(format!(
        "after-upsert:state={:?},eps={}",
        offline.state,
        offline.active_endpoints.len()
    ));

    obs.push(format!(
        "report-a:{}",
        err_code(db.update_device_state(state_update(a, 10, 600)).await)
    ));
    let online = db
        .get_device_state_by_name(zone, "ood1")
        .await
        .unwrap()
        .unwrap();
    obs.push(format!(
        "online:state={:?},pub={},priv={},eps={},pref={:?},wan={}",
        online.state,
        online.public_ips.join("|"),
        online.private_ips.join("|"),
        online.active_endpoints.len(),
        online
            .preferred_endpoint
            .as_ref()
            .map(|e| e.endpoint_id.clone()),
        online.is_wan_device
    ));

    // 同 DID 改 (zone,device_name) → Conflict（要求 rebind）。
    obs.push(format!(
        "dup-upsert:{}",
        err_code(
            db.upsert_device_index(a, zone, "ood2", SnDeviceRole::Ood)
                .await
        )
    ));
    // 目标 (zone,device_name) 被他 DID 占用 → rebind Conflict。
    db.upsert_device_index(b, zone, "ood2", SnDeviceRole::Ood)
        .await
        .unwrap();
    obs.push(format!(
        "rebind-conflict:{}",
        err_code(
            db.rebind_device_index(a, zone, "ood2", SnDeviceRole::Ood, "mv")
                .await
        )
    ));
    // 合法 rebind：保留 runtime。
    obs.push(format!(
        "rebind-ok:{}",
        err_code(
            db.rebind_device_index(a, zone, "gw", SnDeviceRole::Gateway, "mv")
                .await
        )
    ));
    obs.push(format!(
        "old-name-gone:{}",
        db.get_device_state_by_name(zone, "ood1")
            .await
            .unwrap()
            .is_none()
    ));
    let rebound = db
        .get_device_state_by_name(zone, "gw")
        .await
        .unwrap()
        .unwrap();
    obs.push(format!(
        "rebound:state={:?},wan={}",
        rebound.state, rebound.is_wan_device
    ));

    // stale 上报（seq 5 < 10）被拒。
    obs.push(format!(
        "stale:{}",
        err_code(db.update_device_state(state_update(a, 5, 600)).await)
    ));

    // block → blocked；blocked 设备普通上报被拒；unblock 后回 offline。
    obs.push(format!(
        "block:{}",
        err_code(db.block_device(a, "abuse").await)
    ));
    obs.push(format!(
        "blocked-state:{:?}",
        db.get_device_state(a).await.unwrap().unwrap().state
    ));
    obs.push(format!(
        "blocked-report:{}",
        err_code(db.update_device_state(state_update(a, 20, 600)).await)
    ));
    obs.push(format!(
        "unblock:{}",
        err_code(db.unblock_device(a, "ok").await)
    ));
    obs.push(format!(
        "after-unblock:{:?}",
        db.get_device_state(a).await.unwrap().unwrap().state
    ));

    // list（默认）计数。
    let listed = db
        .list_zone_devices(zone, SnDeviceListOptions::default())
        .await
        .unwrap();
    obs.push(format!("list:count={}", listed.len()));

    // remove → 索引消失。
    obs.push(format!(
        "remove:{}",
        err_code(db.remove_device_index(a).await)
    ));
    obs.push(format!(
        "after-remove:{}",
        db.get_device_state(a).await.unwrap().is_none()
    ));

    // 错误码：未知 DID 上报 → NotFound；空 DID → InvalidInput。
    obs.push(format!(
        "unknown-report:{}",
        err_code(
            db.update_device_state(state_update("did:dev:zzz", 1, 600))
                .await
        )
    ));
    obs.push(format!(
        "empty-did:{}",
        err_code(
            db.upsert_device_index("", zone, "x", SnDeviceRole::Ood)
                .await
        )
    ));

    obs
}

#[tokio::test]
async fn local_and_remote_clients_agree_on_same_batch() {
    // local：直连 SqliteSnDeviceInfoDB。
    let (_local_dir, local) = local_db().await;
    let local_obs = run_batch(&local).await;

    // remote：经真实 S2S 编解码 loopback（独立 DB，相同操作序列）。
    let (_remote_dir, remote_backing) = local_db().await;
    let remote = LoopbackClient {
        handler: SnDeviceInfoDbRpcHandler::new(remote_backing),
    };
    let remote_obs = run_batch(&remote).await;

    assert_eq!(
        local_obs, remote_obs,
        "local 与 remote(S2S 序列化) 对同一批用例结果必须一致"
    );

    // 抽样钉死关键结构事实，确保批次确实跑了预期分支（非空一致）。
    assert!(local_obs.contains(&"get-missing:true".to_string()));
    assert!(local_obs
        .iter()
        .any(|o| o.contains("dup-upsert:err:Conflict")));
    assert!(local_obs
        .iter()
        .any(|o| o.contains("stale:err:StaleReport")));
    assert!(local_obs
        .iter()
        .any(|o| o.contains("blocked-report:err:Blocked")));
    assert!(local_obs
        .iter()
        .any(|o| o.contains("unknown-report:err:NotFound")));
    assert!(local_obs
        .iter()
        .any(|o| o.contains("empty-did:err:InvalidInput")));
    assert!(local_obs.iter().any(|o| o.contains("online:")
        && o.contains("wan=true")
        && o.contains("pref=Some(\"public\")")));
}

#[tokio::test]
async fn production_remote_wrapper_exposes_same_trait() {
    // `RemoteSnDeviceInfoDB`（生产 remote client 类型）经 in-process 传输包装本地 service，
    // 暴露同一 `SnDeviceInfoDB` 接口。
    let (_dir, local) = local_db().await;
    let backing: Arc<dyn SnDeviceInfoDB> = Arc::new(local);
    let remote = RemoteSnDeviceInfoDB::new(SnDeviceInfoDbClient::new_in_process(backing.clone()));

    remote
        .upsert_device_index("did:dev:p", "z", "ood1", SnDeviceRole::Ood)
        .await
        .unwrap();
    let view = remote.get_device_state("did:dev:p").await.unwrap().unwrap();
    assert_eq!(view.state, SnDeviceState::Offline);
    // 与底层 service 视图一致。
    let direct = backing
        .get_device_state("did:dev:p")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(view, direct);
}
