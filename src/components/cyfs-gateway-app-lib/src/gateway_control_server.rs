use crate::config_parser::ServerConfigParser;
use bytes::Bytes;
use cyfs_gateway_lib::{
    ConfigErrorCode, ConfigResult, ControlErrorCode, ControlResult, CyfsTokenFactory,
    CyfsTokenVerifier, GatewayControlCmdHandler, LoginReq, Server, ServerConfig, ServerError,
    StreamInfo, cmd_err, config_err,
};
use cyfs_gateway_lib::{HttpServer, ServerContext, ServerContextRef, ServerFactory};
use cyfs_gateway_lib::{ServerErrorCode, ServerResult, server_err};
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};
use std::sync::{Arc, Weak};

pub const GATEWAY_CONTROL_SERVER_CONFIG: &str = include_str!("gateway_control_server.yaml");
pub const GATEWAY_CONTROL_SERVER_KEY: &str = "__control_server__";

#[derive(Serialize, Deserialize, Clone)]
pub struct GatewayControlServerConfig {
    pub id: String,
    #[serde(rename = "type")]
    pub ty: String,
}

impl ServerConfig for GatewayControlServerConfig {
    fn id(&self) -> String {
        self.id.clone()
    }

    fn server_type(&self) -> String {
        String::from("control_server")
    }

    fn get_config_json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(Clone)]
pub struct GatewayControlServerContext {
    pub handler: Weak<dyn GatewayControlCmdHandler>,
    pub token_factory: Arc<dyn CyfsTokenFactory>,
    pub token_verifier: Arc<dyn CyfsTokenVerifier>,
}

impl GatewayControlServerContext {
    pub fn new(
        handler: Weak<dyn GatewayControlCmdHandler>,
        token_verifier: Arc<dyn CyfsTokenVerifier>,
        token_factory: Arc<dyn CyfsTokenFactory>,
    ) -> Self {
        Self {
            handler,
            token_factory,
            token_verifier,
        }
    }
}

impl ServerContext for GatewayControlServerContext {
    fn get_server_type(&self) -> String {
        "control_server".to_string()
    }
}

pub struct GatewayControlServerFactory;

impl GatewayControlServerFactory {
    pub fn new() -> Self {
        GatewayControlServerFactory
    }
}

#[async_trait::async_trait]
impl ServerFactory for GatewayControlServerFactory {
    async fn create(
        &self,
        config: Arc<dyn ServerConfig>,
        context: Option<ServerContextRef>,
    ) -> ServerResult<Vec<Server>> {
        let config = config
            .as_any()
            .downcast_ref::<GatewayControlServerConfig>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid CyfsCmdServer config {}",
                config.server_type()
            ))?;
        let context = context.ok_or(server_err!(
            ServerErrorCode::InvalidConfig,
            "control server context is required"
        ))?;
        let context = context
            .as_ref()
            .as_any()
            .downcast_ref::<GatewayControlServerContext>()
            .ok_or(server_err!(
                ServerErrorCode::InvalidConfig,
                "invalid control server context"
            ))?;
        Ok(vec![Server::Http(Arc::new(GatewayControlServer::new(
            config.clone(),
            context.handler.clone(),
            context.token_factory.clone(),
            context.token_verifier.clone(),
        )))])
    }
}

pub struct GatewayControlServerConfigParser {}

impl GatewayControlServerConfigParser {
    pub fn new() -> Self {
        GatewayControlServerConfigParser {}
    }
}

impl Default for GatewayControlServerConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: for<'de> Deserializer<'de>> ServerConfigParser<D> for GatewayControlServerConfigParser {
    fn parse(&self, de: D) -> ConfigResult<Arc<dyn ServerConfig>> {
        let config = GatewayControlServerConfig::deserialize(de).map_err(|e| {
            config_err!(
                ConfigErrorCode::InvalidConfig,
                "invalid CyfsCmdServer config {:?}",
                e
            )
        })?;
        Ok(Arc::new(config))
    }
}

pub struct GatewayControlServer {
    config: GatewayControlServerConfig,
    handler: Weak<dyn GatewayControlCmdHandler>,
    token_factory: Arc<dyn CyfsTokenFactory>,
    token_verifier: Arc<dyn CyfsTokenVerifier>,
}

impl GatewayControlServer {
    pub fn new(
        config: GatewayControlServerConfig,
        handler: Weak<dyn GatewayControlCmdHandler>,
        token_factory: Arc<dyn CyfsTokenFactory>,
        token_verifier: Arc<dyn CyfsTokenVerifier>,
    ) -> Self {
        GatewayControlServer {
            config,
            handler,
            token_factory,
            token_verifier,
        }
    }
}

#[derive(Deserialize)]
struct CmdReq<P> {
    method: String,
    params: P,
    sys: Vec<Value>,
}

#[derive(Serialize)]
struct CmdResp<R: Serialize> {
    sys: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<R>,
}

#[async_trait::async_trait(?Send)]
impl HttpServer for GatewayControlServer {
    fn id(&self) -> String {
        self.config.id.clone()
    }

    fn http_version(&self) -> http::Version {
        http::Version::HTTP_11
    }

    fn http3_port(&self) -> Option<u16> {
        None
    }

    async fn serve_request(
        &self,
        request: http::Request<UnsyncBoxBody<Bytes, ServerError>>,
        info: StreamInfo,
    ) -> ServerResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> {
        if request.method() != http::Method::POST {
            return Ok(http::Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .body(
                    Full::new(Bytes::new())
                        .map_err(|e| {
                            ServerError::new(ServerErrorCode::BadRequest, format!("{:?}", e))
                        })
                        .boxed_unsync(),
                )
                .unwrap());
        }
        let body = request.into_body();
        let ret: ControlResult<http::Response<UnsyncBoxBody<Bytes, ServerError>>> = async move {
            let data = body
                .collect()
                .await
                .map(|chunk| chunk.to_bytes())
                .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{:?}", e))?;

            let req: CmdReq<Value> = serde_json::from_slice(&data)
                .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;

            if req.method == "login" {
                if req.sys.len() != 1 {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::BAD_REQUEST)
                        .body(
                            Full::new(Bytes::from("invalid sys param"))
                                .map_err(|e| {
                                    ServerError::new(
                                        ServerErrorCode::BadRequest,
                                        format!("{:?}", e),
                                    )
                                })
                                .boxed_unsync(),
                        )
                        .unwrap();
                    return Ok(resp);
                }
                let seq = req.sys[0].clone();

                let login_req: LoginReq = match serde_json::from_value(req.params) {
                    Ok(req) => req,
                    Err(_e) => {
                        let resp = http::Response::builder()
                            .status(http::StatusCode::BAD_REQUEST)
                            .body(
                                Full::new(Bytes::from("invalid login param"))
                                    .map_err(|e| {
                                        ServerError::new(
                                            ServerErrorCode::BadRequest,
                                            format!("{:?}", e),
                                        )
                                    })
                                    .boxed_unsync(),
                            )
                            .unwrap();
                        return Ok(resp);
                    }
                };

                let resp = match self
                    .token_factory
                    .create(
                        login_req.user_name.as_str(),
                        login_req.password.as_str(),
                        login_req.timestamp,
                    )
                    .await
                {
                    Ok(token) => {
                        let sys = vec![seq, Value::String(token.clone())];
                        let resp = CmdResp::<Value> {
                            sys,
                            result: Some(Value::String(token)),
                            error: None,
                        };
                        resp
                    }
                    Err(e) => {
                        let resp = CmdResp::<Value> {
                            sys: vec![seq],
                            result: None,
                            error: Some(format!("{:?}", e.code())),
                        };
                        resp
                    }
                };
                let data = serde_json::to_vec(&resp)
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                return Ok(http::Response::new(
                    Full::new(Bytes::from(data))
                        .map_err(|e| {
                            ServerError::new(ServerErrorCode::EncodeError, format!("{:?}", e))
                        })
                        .boxed_unsync(),
                ));
            }

            if req.method == "refresh_token" {
                if req.sys.len() != 2 {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(
                            Full::new(Bytes::new())
                                .map_err(|e| {
                                    ServerError::new(
                                        ServerErrorCode::BadRequest,
                                        format!("{:?}", e),
                                    )
                                })
                                .boxed_unsync(),
                        )
                        .unwrap();
                    return Ok(resp);
                }
                let seq = req.sys[0].clone();
                let token = req.sys[1].clone();
                let token_str = token.as_str().unwrap_or("").to_string();
                let new_token = match self
                    .token_verifier
                    .verify_and_renew(token_str.as_str())
                    .await
                {
                    Ok(token) => token,
                    Err(e) => {
                        let resp = http::Response::builder()
                            .status(http::StatusCode::UNAUTHORIZED)
                            .body(
                                Full::new(Bytes::from(e.msg().to_string()))
                                    .map_err(|e| {
                                        ServerError::new(
                                            ServerErrorCode::BadRequest,
                                            format!("{:?}", e),
                                        )
                                    })
                                    .boxed_unsync(),
                            )
                            .unwrap();
                        return Ok(resp);
                    }
                };
                let token_value = new_token.unwrap_or(token_str);
                let resp = CmdResp::<Value> {
                    sys: vec![seq, Value::String(token_value.clone())],
                    result: Some(Value::String(token_value)),
                    error: None,
                };
                let data = serde_json::to_vec(&resp)
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                return Ok(http::Response::new(
                    Full::new(Bytes::from(data))
                        .map_err(|e| {
                            ServerError::new(ServerErrorCode::EncodeError, format!("{:?}", e))
                        })
                        .boxed_unsync(),
                ));
            }

            if req.method == "get_system_info" {
                if req.sys.is_empty() {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::BAD_REQUEST)
                        .body(
                            Full::new(Bytes::from("invalid sys param"))
                                .map_err(|e| {
                                    ServerError::new(
                                        ServerErrorCode::BadRequest,
                                        format!("{:?}", e),
                                    )
                                })
                                .boxed_unsync(),
                        )
                        .unwrap();
                    return Ok(resp);
                }
                let seq = req.sys[0].clone();
                if let Some(handler) = self.handler.upgrade() {
                    let mut call_params = Map::new();
                    if let Some(dst_addr) = info.dst_addr.as_ref() {
                        if let Ok(socket_addr) = dst_addr.parse::<std::net::SocketAddr>() {
                            call_params.insert(
                                "dashboard_port".to_string(),
                                Value::Number(Number::from(socket_addr.port())),
                            );
                        }
                    }
                    let result = handler
                        .handle(req.method.as_str(), Value::Object(call_params))
                        .await;
                    let resp = match result {
                        Ok(result) => CmdResp::<Value> {
                            sys: vec![seq],
                            result: Some(result),
                            error: None,
                        },
                        Err(e) => CmdResp::<Value> {
                            sys: vec![seq],
                            result: None,
                            error: Some(e.msg().to_string()),
                        },
                    };
                    let data = serde_json::to_vec(&resp)
                        .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                    return Ok(http::Response::new(
                        Full::new(Bytes::from(data))
                            .map_err(|e| {
                                ServerError::new(ServerErrorCode::EncodeError, format!("{:?}", e))
                            })
                            .boxed_unsync(),
                    ));
                } else {
                    return Err(cmd_err!(
                        ControlErrorCode::Failed,
                        "{}",
                        "cmd handler has released"
                    ));
                }
            }

            if req.sys.len() != 2 {
                let resp = http::Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .body(
                        Full::new(Bytes::new())
                            .map_err(|e| {
                                ServerError::new(ServerErrorCode::BadRequest, format!("{:?}", e))
                            })
                            .boxed_unsync(),
                    )
                    .unwrap();
                return Ok(resp);
            }
            let seq = req.sys[0].clone();
            let token = req.sys[1].clone();
            let new_token = match self
                .token_verifier
                .verify_and_renew(token.as_str().unwrap_or(""))
                .await
            {
                Ok(token) => token,
                Err(e) => {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .body(
                            Full::new(Bytes::from(e.msg().to_string()))
                                .map_err(|e| {
                                    ServerError::new(
                                        ServerErrorCode::BadRequest,
                                        format!("{:?}", e),
                                    )
                                })
                                .boxed_unsync(),
                        )
                        .unwrap();
                    return Ok(resp);
                }
            };

            if let Some(handler) = self.handler.upgrade() {
                let result = handler.handle(req.method.as_str(), req.params).await;
                let sys = if new_token.is_some() {
                    vec![seq, Value::String(new_token.unwrap())]
                } else {
                    vec![seq]
                };
                let resp = match result {
                    Ok(result) => CmdResp::<Value> {
                        sys,
                        result: Some(result),
                        error: None,
                    },
                    Err(e) => CmdResp::<Value> {
                        sys,
                        result: None,
                        error: Some(e.msg().to_string()),
                    },
                };
                let data = serde_json::to_vec(&resp)
                    .map_err(|e| cmd_err!(ControlErrorCode::Failed, "{}", e))?;
                Ok(http::Response::new(
                    Full::new(Bytes::from(data))
                        .map_err(|e| {
                            ServerError::new(ServerErrorCode::EncodeError, format!("{:?}", e))
                        })
                        .boxed_unsync(),
                ))
            } else {
                Err(cmd_err!(
                    ControlErrorCode::Failed,
                    "{}",
                    "cmd handler has released"
                ))
            }
        }
        .await;

        Ok(ret.unwrap_or_else(|e| {
            let msg = format!("{}", e);
            log::error!("control server err {}", msg);
            http::Response::builder()
                .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                .body(
                    Full::new(Bytes::from(msg.as_bytes().to_vec()))
                        .map_err(|e| ServerError::new(ServerErrorCode::IOError, format!("{:?}", e)))
                        .boxed_unsync(),
                )
                .unwrap()
        }))
    }
}
