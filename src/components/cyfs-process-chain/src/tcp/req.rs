use crate::chain::*;
use crate::collection::*;
use buckyos_kit::AsyncStream;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

pub const STREAM_REQUEST_LEN: usize = 15;

#[derive(Clone)]
pub struct StreamRequest {
    pub dest_port: u16,
    pub dest_host: Option<String>,
    pub dest_addr: Option<SocketAddr>,
    pub app_protocol: Option<String>,
    pub dest_url: Option<String>,

    pub source_addr: Option<SocketAddr>,
    /// Connection-layer direct previous hop, before PROXY protocol or any
    /// trusted-upstream restore is applied.
    pub conn_source_addr: Option<SocketAddr>,
    /// Source restored through a trusted mechanism (PROXY protocol,
    /// authenticated tunnel). Must stay `None` when no such mechanism ran.
    pub real_source_addr: Option<SocketAddr>,
    pub source_mac: Option<String>,
    pub source_hostname: Option<String>,
    pub source_online_secs: Option<String>,
    pub source_device_id: Option<String>,
    pub source_app_id: Option<String>,
    pub source_user_id: Option<String>,

    pub ext: Option<MapCollectionRef>,

    pub incoming_stream: Arc<Mutex<Option<Box<dyn AsyncStream>>>>,
}

impl Default for StreamRequest {
    fn default() -> Self {
        StreamRequest {
            dest_port: 0,
            dest_host: None,
            dest_addr: None,
            app_protocol: None,
            dest_url: None,
            source_addr: None,
            conn_source_addr: None,
            real_source_addr: None,
            source_mac: None,
            source_hostname: None,
            source_online_secs: None,
            source_device_id: None,
            source_app_id: None,
            source_user_id: None,
            ext: None,
            incoming_stream: Arc::new(Mutex::new(None)),
        }
    }
}

impl StreamRequest {
    pub fn new(stream: Box<dyn AsyncStream>, peer_addr: SocketAddr) -> Self {
        StreamRequest {
            dest_port: 0,
            dest_host: None,
            dest_addr: Some(peer_addr),
            app_protocol: None,
            dest_url: None,
            source_addr: Some(peer_addr),
            conn_source_addr: None,
            real_source_addr: None,
            source_mac: None,
            source_hostname: None,
            source_online_secs: None,
            source_device_id: None,
            source_app_id: None,
            source_user_id: None,
            ext: None,
            incoming_stream: Arc::new(Mutex::new(Some(stream))),
        }
    }
}

#[derive(Clone)]
pub struct StreamRequestMap {
    request: Arc<RwLock<StreamRequest>>,
    transverse_counter: Arc<AtomicU32>, // Indicates if a traversal is currently happening
}

impl StreamRequestMap {
    pub fn new(request: StreamRequest) -> Self {
        Self {
            request: Arc::new(RwLock::new(request)),
            transverse_counter: Arc::new(AtomicU32::new(0)), // Initialize counter to 0
        }
    }

    fn is_during_traversal(&self) -> bool {
        self.transverse_counter
            .load(std::sync::atomic::Ordering::SeqCst)
            > 0
    }

    pub fn into_request(self) -> Result<StreamRequest, String> {
        let req = Arc::try_unwrap(self.request)
            .map_err(|_| "Failed to unwrap StreamRequestMap".to_string())?
            .into_inner();

        Ok(req)
    }

    pub async fn register(&self, env: &EnvRef) -> Result<bool, String> {
        let coll = Arc::new(Box::new(self.clone()) as Box<dyn MapCollection>);
        env.create("REQ", CollectionValue::Map(coll)).await
    }
}

#[async_trait::async_trait]
impl MapCollection for StreamRequestMap {
    async fn len(&self) -> Result<usize, String> {
        Ok(STREAM_REQUEST_LEN)
    }

    async fn insert_new(&self, key: &str, value: CollectionValue) -> Result<bool, String> {
        if self.is_during_traversal() {
            let msg = "Cannot insert new key during traversal".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        self.insert(key, value).await.map(|prev| prev.is_none())
    }

    async fn insert(
        &self,
        key: &str,
        value: CollectionValue,
    ) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = "Cannot insert key during traversal".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.write().await;
        let prev;

        match key {
            "dest_port" => {
                prev = Some(CollectionValue::String(request.dest_port.to_string()));
                if let CollectionValue::String(port_str) = value {
                    request.dest_port = port_str.parse().map_err(|e| {
                        let msg = format!("Failed to parse dest_port: {}, {}", port_str, e);
                        error!("{}", msg);
                        msg
                    })?;
                } else {
                    let msg = format!("dest_port must be an integer or string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "dest_host" => {
                prev = request.dest_host.clone().map(CollectionValue::String);
                if let CollectionValue::String(host) = value {
                    request.dest_host = Some(host);
                } else {
                    let msg = format!("dest_host must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "dest_addr" => {
                prev = request
                    .dest_addr
                    .map(|addr| CollectionValue::String(addr.to_string()));
                if let CollectionValue::String(addr) = value {
                    request.dest_addr = Some(addr.parse().map_err(|e| {
                        let msg = format!("Failed to parse dest_addr: {}, {}", addr, e);
                        error!("{}", msg);
                        msg
                    })?);
                } else {
                    let msg = format!("dest_addr must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "app_protocol" => {
                prev = request.app_protocol.clone().map(CollectionValue::String);
                if let CollectionValue::String(protocol) = value {
                    request.app_protocol = Some(protocol);
                } else {
                    let msg = format!("app_protocol must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "dest_url" => {
                prev = request.dest_url.clone().map(CollectionValue::String);
                if let CollectionValue::String(url) = value {
                    request.dest_url = Some(url);
                } else {
                    let msg = format!("dest_url must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_addr" => {
                prev = request
                    .source_addr
                    .map(|addr| CollectionValue::String(addr.to_string()));
                if let CollectionValue::String(addr) = value {
                    request.source_addr = Some(addr.parse().map_err(|e| {
                        let msg = format!("Failed to parse source_addr: {}, {}", addr, e);
                        error!("{}", msg);
                        msg
                    })?);
                } else {
                    let msg = format!("source_addr must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "conn_source_addr" => {
                prev = request
                    .conn_source_addr
                    .map(|addr| CollectionValue::String(addr.to_string()));
                if let CollectionValue::String(addr) = value {
                    request.conn_source_addr = Some(addr.parse().map_err(|e| {
                        let msg = format!("Failed to parse conn_source_addr: {}, {}", addr, e);
                        error!("{}", msg);
                        msg
                    })?);
                } else {
                    let msg = format!("conn_source_addr must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "real_source_addr" => {
                prev = request
                    .real_source_addr
                    .map(|addr| CollectionValue::String(addr.to_string()));
                if let CollectionValue::String(addr) = value {
                    request.real_source_addr = Some(addr.parse().map_err(|e| {
                        let msg = format!("Failed to parse real_source_addr: {}, {}", addr, e);
                        error!("{}", msg);
                        msg
                    })?);
                } else {
                    let msg = format!("real_source_addr must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_mac" => {
                prev = request.source_mac.clone().map(CollectionValue::String);
                if let CollectionValue::String(mac) = value {
                    request.source_mac = Some(mac);
                } else {
                    let msg = format!("source_mac must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_hostname" => {
                prev = request.source_hostname.clone().map(CollectionValue::String);
                if let CollectionValue::String(host_name) = value {
                    request.source_hostname = Some(host_name);
                } else {
                    let msg = format!("source_hostname must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_online_secs" => {
                prev = request
                    .source_online_secs
                    .clone()
                    .map(CollectionValue::String);
                if let CollectionValue::String(source_online_secs) = value {
                    request.source_online_secs = Some(source_online_secs);
                } else {
                    let msg = format!("source_online_secs must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_device_id" => {
                prev = request
                    .source_device_id
                    .clone()
                    .map(CollectionValue::String);
                if let CollectionValue::String(device_id) = value {
                    request.source_device_id = Some(device_id);
                } else {
                    let msg = format!("source_device_id must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_app_id" => {
                prev = request.source_app_id.clone().map(CollectionValue::String);
                if let CollectionValue::String(app_id) = value {
                    request.source_app_id = Some(app_id);
                } else {
                    let msg = format!("source_app_id must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "source_user_id" => {
                prev = request.source_user_id.clone().map(CollectionValue::String);
                if let CollectionValue::String(user_id) = value {
                    request.source_user_id = Some(user_id);
                } else {
                    let msg = format!("source_user_id must be a string, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "incoming_stream" => {
                if value.is_any() {
                    if let CollectionValue::Any(stream) = value {
                        if let Ok(async_stream) =
                            stream.downcast::<Arc<Mutex<Option<Box<dyn AsyncStream>>>>>()
                        {
                            prev = Some(CollectionValue::Any(request.incoming_stream.clone()));
                            *request.incoming_stream.lock().unwrap() =
                                async_stream.lock().unwrap().take();
                        } else {
                            let msg =
                                "incoming_stream must be of type Arc<Mutex<Option<Box<dyn AsyncStream>>>>"
                                    .to_string();
                            error!("{}", msg);
                            return Err(msg);
                        }
                    } else {
                        let msg =
                            format!("incoming_stream must be of type AnyType, got {:?}", value);
                        error!("{}", msg);
                        return Err(msg);
                    }
                } else {
                    let msg = format!("incoming_stream must be of type AnyType, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            "ext" => {
                if let CollectionValue::Map(ext) = value {
                    prev = request.ext.clone().map(CollectionValue::Map);
                    request.ext = Some(ext);
                } else {
                    let msg = format!("ext must be a Map, got {:?}", value);
                    error!("{}", msg);
                    return Err(msg);
                }
            }
            _ => {
                let msg = format!("Unknown key: {}", key);
                error!("{}", msg);
                return Err(msg);
            }
        }

        Ok(prev)
    }

    async fn get(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        let request = self.request.read().await;
        match key {
            "dest_port" => Ok(Some(CollectionValue::String(request.dest_port.to_string()))),
            "dest_host" => Ok(request.dest_host.clone().map(CollectionValue::String)),
            "dest_addr" => Ok(request
                .dest_addr
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "app_protocol" => Ok(request.app_protocol.clone().map(CollectionValue::String)),
            "dest_url" => Ok(request.dest_url.clone().map(CollectionValue::String)),
            "source_addr" => Ok(request
                .source_addr
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "conn_source_addr" => Ok(request
                .conn_source_addr
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "real_source_addr" => Ok(request
                .real_source_addr
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "source_mac" => Ok(request.source_mac.clone().map(CollectionValue::String)),
            "source_hostname" => Ok(request.source_hostname.clone().map(CollectionValue::String)),
            "source_online_secs" => Ok(request
                .source_online_secs
                .clone()
                .map(CollectionValue::String)),
            "source_device_id" => Ok(request
                .source_device_id
                .clone()
                .map(CollectionValue::String)),
            "source_app_id" => Ok(request.source_app_id.clone().map(CollectionValue::String)),
            "source_user_id" => Ok(request.source_user_id.clone().map(CollectionValue::String)),
            "ext" => Ok(request.ext.clone().map(CollectionValue::Map)),
            "incoming_stream" => {
                let stream = request.incoming_stream.lock().unwrap();
                if stream.is_some() {
                    Ok(Some(CollectionValue::Any(request.incoming_stream.clone())))
                } else {
                    Ok(None)
                }
            }
            _ => {
                let msg = format!("Unknown key: {}", key);
                error!("{}", msg);
                Err(msg)
            }
        }
    }

    async fn contains_key(&self, key: &str) -> Result<bool, String> {
        let request = self.request.read().await;
        match key {
            "dest_port" => Ok(true),
            "dest_host" => Ok(request.dest_host.is_some()),
            "dest_addr" => Ok(request.dest_addr.is_some()),
            "app_protocol" => Ok(request.app_protocol.is_some()),
            "dest_url" => Ok(request.dest_url.is_some()),
            "source_addr" => Ok(request.source_addr.is_some()),
            "conn_source_addr" => Ok(request.conn_source_addr.is_some()),
            "real_source_addr" => Ok(request.real_source_addr.is_some()),
            "source_mac" => Ok(request.source_mac.is_some()),
            "source_hostname" => Ok(request.source_hostname.is_some()),
            "source_online_secs" => Ok(request.source_online_secs.is_some()),
            "source_device_id" => Ok(request.source_device_id.is_some()),
            "source_app_id" => Ok(request.source_app_id.is_some()),
            "source_user_id" => Ok(request.source_user_id.is_some()),
            "ext" => Ok(request.ext.is_some()),
            "incoming_stream" => {
                let stream = request.incoming_stream.lock().unwrap();
                Ok(stream.is_some())
            }
            _ => {
                let msg = format!("Unknown key: {}", key);
                error!("{}", msg);
                Err(msg)
            }
        }
    }

    async fn remove(&self, key: &str) -> Result<Option<CollectionValue>, String> {
        if self.is_during_traversal() {
            let msg = "Cannot remove key during traversal".to_string();
            error!("{}", msg);
            return Err(msg);
        }

        let mut request = self.request.write().await;
        match key {
            "dest_port" => Ok(Some(CollectionValue::String(request.dest_port.to_string()))),
            "dest_host" => Ok(request.dest_host.take().map(CollectionValue::String)),
            "dest_addr" => Ok(request
                .dest_addr
                .take()
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "app_protocol" => Ok(request.app_protocol.take().map(CollectionValue::String)),
            "dest_url" => Ok(request.dest_url.take().map(CollectionValue::String)),
            "source_addr" => Ok(request
                .source_addr
                .take()
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "conn_source_addr" => Ok(request
                .conn_source_addr
                .take()
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "real_source_addr" => Ok(request
                .real_source_addr
                .take()
                .map(|addr| CollectionValue::String(addr.to_string()))),
            "source_mac" => Ok(request.source_mac.take().map(CollectionValue::String)),
            "source_hostname" => Ok(request.source_hostname.take().map(CollectionValue::String)),
            "source_online_secs" => Ok(request
                .source_online_secs
                .take()
                .map(CollectionValue::String)),
            "source_device_id" => Ok(request.source_device_id.take().map(CollectionValue::String)),
            "source_app_id" => Ok(request.source_app_id.take().map(CollectionValue::String)),
            "source_user_id" => Ok(request.source_user_id.take().map(CollectionValue::String)),
            "ext" => Ok(request.ext.take().map(CollectionValue::Map)),
            "incoming_stream" => {
                let stream = request.incoming_stream.lock().unwrap().take();
                if let Some(s) = stream {
                    Ok(Some(CollectionValue::Any(Arc::new(Mutex::new(Some(s))))))
                } else {
                    Ok(None)
                }
            }
            _ => Err(format!("Unknown key: {}", key)),
        }
    }

    async fn traverse(&self, callback: MapCollectionTraverseCallBackRef) -> Result<(), String> {
        let _guard = TraverseGuard::new(&self.transverse_counter);

        let request = self.request.read().await;
        for (key, value) in [
            ("dest_port", request.dest_port.to_string()),
            ("dest_host", request.dest_host.clone().unwrap_or_default()),
            (
                "dest_addr",
                request
                    .dest_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default(),
            ),
            (
                "app_protocol",
                request.app_protocol.clone().unwrap_or_default(),
            ),
            ("dest_url", request.dest_url.clone().unwrap_or_default()),
            (
                "source_addr",
                request
                    .source_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default(),
            ),
            (
                "conn_source_addr",
                request
                    .conn_source_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default(),
            ),
            (
                "real_source_addr",
                request
                    .real_source_addr
                    .map(|addr| addr.to_string())
                    .unwrap_or_default(),
            ),
            ("source_mac", request.source_mac.clone().unwrap_or_default()),
            (
                "source_hostname",
                request.source_hostname.clone().unwrap_or_default(),
            ),
            (
                "source_online_secs",
                request.source_online_secs.clone().unwrap_or_default(),
            ),
            (
                "source_device_id",
                request.source_device_id.clone().unwrap_or_default(),
            ),
            (
                "source_app_id",
                request.source_app_id.clone().unwrap_or_default(),
            ),
            (
                "source_user_id",
                request.source_user_id.clone().unwrap_or_default(),
            ),
        ] {
            if !callback.call(key, &CollectionValue::String(value)).await? {
                break;
            }
        }

        if let Some(ext) = &request.ext {
            ext.traverse(callback).await?;
        }

        Ok(())
    }

    async fn dump(&self) -> Result<Vec<(String, CollectionValue)>, String> {
        let request = self.request.read().await;
        let mut result = Vec::new();
        result.push((
            "dest_port".to_string(),
            CollectionValue::String(request.dest_port.to_string()),
        ));
        if let Some(host) = &request.dest_host {
            result.push((
                "dest_host".to_string(),
                CollectionValue::String(host.clone()),
            ));
        }
        if let Some(addr) = &request.dest_addr {
            result.push((
                "dest_addr".to_string(),
                CollectionValue::String(addr.to_string()),
            ));
        }
        if let Some(protocol) = &request.app_protocol {
            result.push((
                "app_protocol".to_string(),
                CollectionValue::String(protocol.clone()),
            ));
        }
        if let Some(url) = &request.dest_url {
            result.push(("dest_url".to_string(), CollectionValue::String(url.clone())));
        }
        if let Some(addr) = &request.source_addr {
            result.push((
                "source_addr".to_string(),
                CollectionValue::String(addr.to_string()),
            ));
        }
        if let Some(addr) = &request.conn_source_addr {
            result.push((
                "conn_source_addr".to_string(),
                CollectionValue::String(addr.to_string()),
            ));
        }
        if let Some(addr) = &request.real_source_addr {
            result.push((
                "real_source_addr".to_string(),
                CollectionValue::String(addr.to_string()),
            ));
        }
        if let Some(mac) = &request.source_mac {
            result.push((
                "source_mac".to_string(),
                CollectionValue::String(mac.clone()),
            ));
        }
        if let Some(host_name) = &request.source_hostname {
            result.push((
                "source_hostname".to_string(),
                CollectionValue::String(host_name.clone()),
            ));
        }
        if let Some(source_online_secs) = &request.source_online_secs {
            result.push((
                "source_online_secs".to_string(),
                CollectionValue::String(source_online_secs.clone()),
            ));
        }
        if let Some(device_id) = &request.source_device_id {
            result.push((
                "source_device_id".to_string(),
                CollectionValue::String(device_id.clone()),
            ));
        }
        if let Some(app_id) = &request.source_app_id {
            result.push((
                "source_app_id".to_string(),
                CollectionValue::String(app_id.clone()),
            ));
        }
        if let Some(user_id) = &request.source_user_id {
            result.push((
                "source_user_id".to_string(),
                CollectionValue::String(user_id.clone()),
            ));
        }
        if let Some(ext) = &request.ext {
            result.push(("ext".to_string(), CollectionValue::Map(ext.clone())));
        }

        Ok(result)
    }
}
