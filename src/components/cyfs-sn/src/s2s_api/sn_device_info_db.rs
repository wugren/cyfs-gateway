use crate::{
    sn_err, SnDeviceInfoDB, SnDeviceListOptions, SnDeviceRole, SnDeviceStateUpdate,
    SnDeviceStateView, SnError, SnErrorCode, SnResult,
};
use ::kRPC::{kRPC, RPCErrors, RPCHandler, RPCRequest, RPCResponse, RPCResult};
use async_trait::async_trait;
use serde::de::{DeserializeOwned, Error as DeError};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::net::IpAddr;
use std::sync::Arc;

pub const SN_DEVICE_INFO_DB_RPC_PATH: &str = "/kapi/sn/s2s/device-info-db";

pub const METHOD_UPSERT_DEVICE_INDEX: &str = "sn_device_info_db.upsert_device_index";
pub const METHOD_REBIND_DEVICE_INDEX: &str = "sn_device_info_db.rebind_device_index";
pub const METHOD_REMOVE_DEVICE_INDEX: &str = "sn_device_info_db.remove_device_index";
pub const METHOD_UPDATE_DEVICE_STATE: &str = "sn_device_info_db.update_device_state";
pub const METHOD_GET_DEVICE_STATE: &str = "sn_device_info_db.get_device_state";
pub const METHOD_GET_DEVICE_STATE_BY_NAME: &str = "sn_device_info_db.get_device_state_by_name";
pub const METHOD_LIST_ZONE_DEVICES: &str = "sn_device_info_db.list_zone_devices";
pub const METHOD_MARK_DEVICE_OFFLINE: &str = "sn_device_info_db.mark_device_offline";
pub const METHOD_BLOCK_DEVICE: &str = "sn_device_info_db.block_device";
pub const METHOD_UNBLOCK_DEVICE: &str = "sn_device_info_db.unblock_device";
pub const METHOD_EXPIRE_DEVICES: &str = "sn_device_info_db.expire_devices";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceInfoDbRpcErrorInfo {
    pub code: SnErrorCode,
    pub message: String,
}

impl SnDeviceInfoDbRpcErrorInfo {
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

#[derive(Debug, Clone, Serialize)]
pub struct SnDeviceInfoDbRpcEnvelope<T> {
    pub ok: bool,
    pub result: Option<T>,
    pub error: Option<SnDeviceInfoDbRpcErrorInfo>,
}

#[derive(Deserialize)]
struct SnDeviceInfoDbRpcEnvelopeWire {
    ok: bool,
    #[serde(default, deserialize_with = "deserialize_present_json_value")]
    result: Option<Value>,
    error: Option<SnDeviceInfoDbRpcErrorInfo>,
}

fn deserialize_present_json_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

impl<'de, T> Deserialize<'de> for SnDeviceInfoDbRpcEnvelope<T>
where
    T: DeserializeOwned,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SnDeviceInfoDbRpcEnvelopeWire::deserialize(deserializer)?;
        let result = if wire.ok {
            wire.result
                .map(serde_json::from_value)
                .transpose()
                .map_err(DeError::custom)?
        } else {
            None
        };

        Ok(Self {
            ok: wire.ok,
            result,
            error: wire.error,
        })
    }
}

impl<T> SnDeviceInfoDbRpcEnvelope<T> {
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
            error: Some(SnDeviceInfoDbRpcErrorInfo::from_sn_error(error)),
        }
    }

    pub fn into_result(self) -> SnResult<T> {
        if self.ok {
            self.result.ok_or_else(|| {
                sn_err!(
                    SnErrorCode::RemoteError,
                    "SnDeviceInfoDB RPC envelope missing result"
                )
            })
        } else {
            Err(self
                .error
                .map(SnDeviceInfoDbRpcErrorInfo::into_sn_error)
                .unwrap_or_else(|| {
                    sn_err!(
                        SnErrorCode::RemoteError,
                        "SnDeviceInfoDB RPC envelope missing error"
                    )
                }))
        }
    }

    pub fn into_unit_result(self) -> SnResult<()> {
        if self.ok {
            Ok(())
        } else {
            Err(self
                .error
                .map(SnDeviceInfoDbRpcErrorInfo::into_sn_error)
                .unwrap_or_else(|| {
                    sn_err!(
                        SnErrorCode::RemoteError,
                        "SnDeviceInfoDB RPC envelope missing error"
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
pub struct SnDeviceInfoDbUpsertDeviceIndexReq {
    pub did: String,
    pub zone: String,
    pub device_name: String,
    pub device_role: SnDeviceRole,
}

impl SnDeviceInfoDbUpsertDeviceIndexReq {
    pub fn new(did: &str, zone: &str, device_name: &str, device_role: SnDeviceRole) -> Self {
        Self {
            did: did.to_string(),
            zone: zone.to_string(),
            device_name: device_name.to_string(),
            device_role,
        }
    }

    impl_req_from_json!(SnDeviceInfoDbUpsertDeviceIndexReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceInfoDbRebindDeviceIndexReq {
    pub did: String,
    pub new_zone: String,
    pub new_device_name: String,
    pub new_device_role: SnDeviceRole,
    pub reason: String,
}

impl SnDeviceInfoDbRebindDeviceIndexReq {
    pub fn new(
        did: &str,
        new_zone: &str,
        new_device_name: &str,
        new_device_role: SnDeviceRole,
        reason: &str,
    ) -> Self {
        Self {
            did: did.to_string(),
            new_zone: new_zone.to_string(),
            new_device_name: new_device_name.to_string(),
            new_device_role,
            reason: reason.to_string(),
        }
    }

    impl_req_from_json!(SnDeviceInfoDbRebindDeviceIndexReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceInfoDbDidReq {
    pub did: String,
}

impl SnDeviceInfoDbDidReq {
    pub fn new(did: &str) -> Self {
        Self {
            did: did.to_string(),
        }
    }

    impl_req_from_json!(SnDeviceInfoDbDidReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceInfoDbUpdateDeviceStateReq {
    pub update: SnDeviceStateUpdate,
}

impl SnDeviceInfoDbUpdateDeviceStateReq {
    pub fn new(update: SnDeviceStateUpdate) -> Self {
        Self { update }
    }

    impl_req_from_json!(SnDeviceInfoDbUpdateDeviceStateReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceInfoDbGetDeviceStateByNameReq {
    pub zone: String,
    pub device_name: String,
}

impl SnDeviceInfoDbGetDeviceStateByNameReq {
    pub fn new(zone: &str, device_name: &str) -> Self {
        Self {
            zone: zone.to_string(),
            device_name: device_name.to_string(),
        }
    }

    impl_req_from_json!(SnDeviceInfoDbGetDeviceStateByNameReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceInfoDbListZoneDevicesReq {
    pub zone: String,
    pub options: SnDeviceListOptions,
}

impl SnDeviceInfoDbListZoneDevicesReq {
    pub fn new(zone: &str, options: SnDeviceListOptions) -> Self {
        Self {
            zone: zone.to_string(),
            options,
        }
    }

    impl_req_from_json!(SnDeviceInfoDbListZoneDevicesReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceInfoDbDeviceReasonReq {
    pub did: String,
    pub reason: String,
}

impl SnDeviceInfoDbDeviceReasonReq {
    pub fn new(did: &str, reason: &str) -> Self {
        Self {
            did: did.to_string(),
            reason: reason.to_string(),
        }
    }

    impl_req_from_json!(SnDeviceInfoDbDeviceReasonReq);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnDeviceInfoDbExpireDevicesReq {
    pub now: u64,
    pub batch_size: Option<usize>,
}

impl SnDeviceInfoDbExpireDevicesReq {
    pub fn new(now: u64, batch_size: Option<usize>) -> Self {
        Self { now, batch_size }
    }

    impl_req_from_json!(SnDeviceInfoDbExpireDevicesReq);
}

#[derive(Clone)]
pub enum SnDeviceInfoDbClient {
    InProcess(Arc<dyn SnDeviceInfoDB>),
    KRPC(Arc<kRPC>),
}

impl SnDeviceInfoDbClient {
    pub fn new_in_process(handler: Arc<dyn SnDeviceInfoDB>) -> Self {
        Self::InProcess(handler)
    }

    pub fn new_krpc(client: Arc<kRPC>) -> Self {
        Self::KRPC(client)
    }

    pub fn new_krpc_url(device_info_db_url: &str, session_token: Option<String>) -> Self {
        let endpoint = normalize_sn_device_info_db_url(device_info_db_url);
        Self::KRPC(Arc::new(kRPC::new(endpoint.as_str(), session_token)))
    }

    async fn call_rpc<Req>(&self, method: &str, req: &Req) -> SnResult<Value>
    where
        Req: Serialize + Sync,
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
                        "failed to serialize SnDeviceInfoDB RPC {} request: {}",
                        method,
                        e
                    )
                })?;
                client.call(method, req_json).await.map_err(|e| {
                    sn_err!(
                        SnErrorCode::RemoteError,
                        "SnDeviceInfoDB RPC {} transport failed: {}",
                        method,
                        e
                    )
                })
            }
        }
    }

    async fn call<Req, Resp>(&self, method: &str, req: &Req) -> SnResult<Resp>
    where
        Req: Serialize + Sync,
        Resp: DeserializeOwned,
    {
        let result = self.call_rpc(method, req).await?;
        let envelope: SnDeviceInfoDbRpcEnvelope<Resp> =
            serde_json::from_value(result).map_err(|e| {
                sn_err!(
                    SnErrorCode::RemoteError,
                    "failed to parse SnDeviceInfoDB RPC {} response: {}",
                    method,
                    e
                )
            })?;
        envelope.into_result()
    }

    async fn call_unit<Req>(&self, method: &str, req: &Req) -> SnResult<()>
    where
        Req: Serialize + Sync,
    {
        let result = self.call_rpc(method, req).await?;
        let envelope: SnDeviceInfoDbRpcEnvelope<Value> =
            serde_json::from_value(result).map_err(|e| {
                sn_err!(
                    SnErrorCode::RemoteError,
                    "failed to parse SnDeviceInfoDB RPC {} response: {}",
                    method,
                    e
                )
            })?;
        envelope.into_unit_result()
    }
}

#[async_trait]
impl SnDeviceInfoDB for SnDeviceInfoDbClient {
    async fn upsert_device_index(
        &self,
        did: &str,
        zone: &str,
        device_name: &str,
        device_role: SnDeviceRole,
    ) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .upsert_device_index(did, zone, device_name, device_role)
                    .await
            }
            Self::KRPC(_) => {
                self.call_unit(
                    METHOD_UPSERT_DEVICE_INDEX,
                    &SnDeviceInfoDbUpsertDeviceIndexReq::new(did, zone, device_name, device_role),
                )
                .await
            }
        }
    }

    async fn rebind_device_index(
        &self,
        did: &str,
        new_zone: &str,
        new_device_name: &str,
        new_device_role: SnDeviceRole,
        reason: &str,
    ) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => {
                handler
                    .rebind_device_index(did, new_zone, new_device_name, new_device_role, reason)
                    .await
            }
            Self::KRPC(_) => {
                self.call_unit(
                    METHOD_REBIND_DEVICE_INDEX,
                    &SnDeviceInfoDbRebindDeviceIndexReq::new(
                        did,
                        new_zone,
                        new_device_name,
                        new_device_role,
                        reason,
                    ),
                )
                .await
            }
        }
    }

    async fn remove_device_index(&self, did: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.remove_device_index(did).await,
            Self::KRPC(_) => {
                self.call_unit(METHOD_REMOVE_DEVICE_INDEX, &SnDeviceInfoDbDidReq::new(did))
                    .await
            }
        }
    }

    async fn update_device_state(&self, update: SnDeviceStateUpdate) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.update_device_state(update).await,
            Self::KRPC(_) => {
                self.call_unit(
                    METHOD_UPDATE_DEVICE_STATE,
                    &SnDeviceInfoDbUpdateDeviceStateReq::new(update),
                )
                .await
            }
        }
    }

    async fn get_device_state(&self, did: &str) -> SnResult<Option<SnDeviceStateView>> {
        match self {
            Self::InProcess(handler) => handler.get_device_state(did).await,
            Self::KRPC(_) => {
                self.call(METHOD_GET_DEVICE_STATE, &SnDeviceInfoDbDidReq::new(did))
                    .await
            }
        }
    }

    async fn get_device_state_by_name(
        &self,
        zone: &str,
        device_name: &str,
    ) -> SnResult<Option<SnDeviceStateView>> {
        match self {
            Self::InProcess(handler) => handler.get_device_state_by_name(zone, device_name).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_GET_DEVICE_STATE_BY_NAME,
                    &SnDeviceInfoDbGetDeviceStateByNameReq::new(zone, device_name),
                )
                .await
            }
        }
    }

    async fn list_zone_devices(
        &self,
        zone: &str,
        options: SnDeviceListOptions,
    ) -> SnResult<Vec<SnDeviceStateView>> {
        match self {
            Self::InProcess(handler) => handler.list_zone_devices(zone, options).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_LIST_ZONE_DEVICES,
                    &SnDeviceInfoDbListZoneDevicesReq::new(zone, options),
                )
                .await
            }
        }
    }

    async fn mark_device_offline(&self, did: &str, reason: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.mark_device_offline(did, reason).await,
            Self::KRPC(_) => {
                self.call_unit(
                    METHOD_MARK_DEVICE_OFFLINE,
                    &SnDeviceInfoDbDeviceReasonReq::new(did, reason),
                )
                .await
            }
        }
    }

    async fn block_device(&self, did: &str, reason: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.block_device(did, reason).await,
            Self::KRPC(_) => {
                self.call_unit(
                    METHOD_BLOCK_DEVICE,
                    &SnDeviceInfoDbDeviceReasonReq::new(did, reason),
                )
                .await
            }
        }
    }

    async fn unblock_device(&self, did: &str, reason: &str) -> SnResult<()> {
        match self {
            Self::InProcess(handler) => handler.unblock_device(did, reason).await,
            Self::KRPC(_) => {
                self.call_unit(
                    METHOD_UNBLOCK_DEVICE,
                    &SnDeviceInfoDbDeviceReasonReq::new(did, reason),
                )
                .await
            }
        }
    }

    async fn expire_devices(&self, now: u64, batch_size: Option<usize>) -> SnResult<usize> {
        match self {
            Self::InProcess(handler) => handler.expire_devices(now, batch_size).await,
            Self::KRPC(_) => {
                self.call(
                    METHOD_EXPIRE_DEVICES,
                    &SnDeviceInfoDbExpireDevicesReq::new(now, batch_size),
                )
                .await
            }
        }
    }
}

pub struct SnDeviceInfoDbRpcHandler<T: SnDeviceInfoDB>(pub T);

impl<T: SnDeviceInfoDB> SnDeviceInfoDbRpcHandler<T> {
    pub fn new(handler: T) -> Self {
        Self(handler)
    }
}

#[async_trait]
impl<T> RPCHandler for SnDeviceInfoDbRpcHandler<T>
where
    T: SnDeviceInfoDB,
{
    async fn handle_rpc_call(
        &self,
        req: RPCRequest,
        _ip_from: IpAddr,
    ) -> Result<RPCResponse, RPCErrors> {
        match req.method.as_str() {
            METHOD_UPSERT_DEVICE_INDEX | "upsert_device_index" => {
                let parsed = SnDeviceInfoDbUpsertDeviceIndexReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .upsert_device_index(
                            &parsed.did,
                            &parsed.zone,
                            &parsed.device_name,
                            parsed.device_role,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_REBIND_DEVICE_INDEX | "rebind_device_index" => {
                let parsed = SnDeviceInfoDbRebindDeviceIndexReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .rebind_device_index(
                            &parsed.did,
                            &parsed.new_zone,
                            &parsed.new_device_name,
                            parsed.new_device_role,
                            &parsed.reason,
                        )
                        .await,
                    &req,
                )
            }
            METHOD_REMOVE_DEVICE_INDEX | "remove_device_index" => {
                let parsed = SnDeviceInfoDbDidReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.remove_device_index(&parsed.did).await, &req)
            }
            METHOD_UPDATE_DEVICE_STATE | "update_device_state" => {
                let parsed = SnDeviceInfoDbUpdateDeviceStateReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.update_device_state(parsed.update).await, &req)
            }
            METHOD_GET_DEVICE_STATE | "get_device_state" => {
                let parsed = SnDeviceInfoDbDidReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.get_device_state(&parsed.did).await, &req)
            }
            METHOD_GET_DEVICE_STATE_BY_NAME | "get_device_state_by_name" => {
                let parsed = SnDeviceInfoDbGetDeviceStateByNameReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .get_device_state_by_name(&parsed.zone, &parsed.device_name)
                        .await,
                    &req,
                )
            }
            METHOD_LIST_ZONE_DEVICES | "list_zone_devices" => {
                let parsed = SnDeviceInfoDbListZoneDevicesReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0.list_zone_devices(&parsed.zone, parsed.options).await,
                    &req,
                )
            }
            METHOD_MARK_DEVICE_OFFLINE | "mark_device_offline" => {
                let parsed = SnDeviceInfoDbDeviceReasonReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0
                        .mark_device_offline(&parsed.did, &parsed.reason)
                        .await,
                    &req,
                )
            }
            METHOD_BLOCK_DEVICE | "block_device" => {
                let parsed = SnDeviceInfoDbDeviceReasonReq::from_json(req.params.clone())?;
                rpc_envelope_response(self.0.block_device(&parsed.did, &parsed.reason).await, &req)
            }
            METHOD_UNBLOCK_DEVICE | "unblock_device" => {
                let parsed = SnDeviceInfoDbDeviceReasonReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0.unblock_device(&parsed.did, &parsed.reason).await,
                    &req,
                )
            }
            METHOD_EXPIRE_DEVICES | "expire_devices" => {
                let parsed = SnDeviceInfoDbExpireDevicesReq::from_json(req.params.clone())?;
                rpc_envelope_response(
                    self.0.expire_devices(parsed.now, parsed.batch_size).await,
                    &req,
                )
            }
            _ => Err(RPCErrors::UnknownMethod(req.method.clone())),
        }
    }
}

pub fn normalize_sn_device_info_db_url(device_info_db_url: &str) -> String {
    let trimmed = device_info_db_url.trim_end_matches('/');
    if let Some(base) = trimmed.strip_suffix(SN_DEVICE_INFO_DB_RPC_PATH) {
        return format!("{}{}", base, SN_DEVICE_INFO_DB_RPC_PATH);
    }
    format!("{}{}", trimmed, SN_DEVICE_INFO_DB_RPC_PATH)
}

fn rpc_envelope_response<T: Serialize>(
    result: SnResult<T>,
    req: &RPCRequest,
) -> Result<RPCResponse, RPCErrors> {
    let envelope = match result {
        Ok(value) => SnDeviceInfoDbRpcEnvelope::success(value),
        Err(error) => SnDeviceInfoDbRpcEnvelope::failure(error),
    };
    let value = serde_json::to_value(envelope).map_err(|e| {
        RPCErrors::ParserResponseError(format!(
            "Failed to serialize SnDeviceInfoDB RPC envelope: {}",
            e
        ))
    })?;
    Ok(RPCResponse::create_by_req(RPCResult::Success(value), req))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_sn_device_info_db_url() {
        assert_eq!(
            normalize_sn_device_info_db_url("http://127.0.0.1:8080"),
            "http://127.0.0.1:8080/kapi/sn/s2s/device-info-db"
        );
        assert_eq!(
            normalize_sn_device_info_db_url("http://127.0.0.1:8080/kapi/sn/s2s/device-info-db/"),
            "http://127.0.0.1:8080/kapi/sn/s2s/device-info-db"
        );
    }

    #[test]
    fn test_unit_envelope_roundtrip_allows_null_result() {
        let value = serde_json::to_value(SnDeviceInfoDbRpcEnvelope::success(())).unwrap();
        let envelope: SnDeviceInfoDbRpcEnvelope<Value> = serde_json::from_value(value).unwrap();

        assert!(envelope.into_unit_result().is_ok());
    }

    #[test]
    fn test_optional_envelope_roundtrip_preserves_null_success() {
        let value =
            serde_json::to_value(SnDeviceInfoDbRpcEnvelope::success(None::<String>)).unwrap();
        assert_eq!(value["result"], Value::Null);

        let envelope: SnDeviceInfoDbRpcEnvelope<Option<String>> =
            serde_json::from_value(value).unwrap();

        assert_eq!(envelope.into_result().unwrap(), None);
    }

    #[test]
    fn test_error_envelope_null_result_does_not_parse_response_type() {
        let value = serde_json::to_value(SnDeviceInfoDbRpcEnvelope::<String>::failure(sn_err!(
            SnErrorCode::NotFound,
            "missing"
        )))
        .unwrap();
        assert_eq!(value["result"], Value::Null);

        let envelope: SnDeviceInfoDbRpcEnvelope<String> = serde_json::from_value(value).unwrap();
        let error = envelope.into_result().unwrap_err();

        assert_eq!(error.code(), SnErrorCode::NotFound);
    }
}
