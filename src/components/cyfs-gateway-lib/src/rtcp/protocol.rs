/*
tunnel的控制协议
二进制头：2+1+4=7字节
len: u16,如果是0则表示该Package是HelloStream包，后面是32字节的session_key
json_pos:u8, json数据的起始位置
cmd:u8,命令类型
seq:u32, 序列号
package:String， data in json format

控制协议分为如下类型：

// 建立tunnel，tunnel建立后，client需要立刻发送build包，用以确定该tunnel的信息
{
cmd:hello
from_id: string,
to_id: string,
test_port:u16
seession_key:option<string> （用对方公钥加密的key,并有自己的签名）
}
后续所有命令都用tunel key 对称加密
{
cmd:hello_ack
test_result:bool
}


{
cmd:ping

}
{
cmd:ping_resp
}


//因为无法与对端建立直连，因此通过该命令，要求对方建立反连，效果相当于命令发起方主动连接target
//并不使用直接复用当前tunnel+rebuild的方式,是想提高一些扩展性
//要求对端返连自己的端口
{
cmd:ropen
session_key:string （32个字节的随机字符串，第1，2个字符是byte 0）
target:Url,like tcp://_:123
}

{
cmd:ropen_resp
result:u32
}

*/

use anyhow::Result;
use name_lib::DID;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use url::Url;

pub const DEFAULT_RTCP_STACK_PORT: u16 = 2980;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RTcpTargetStackEP {
    pub did: DID,
    pub stack_port: u16,
    // When the RTCP authority carries a `params@remote` prefix, `params` is the
    // percent-encoded bootstrap stream URL and `bootstrap_stream_url` stores the
    // decoded URL. create_tunnel uses it to build the tunnel's bearing stream
    // through the tunnel framework instead of a direct TCP connect.
    pub bootstrap_stream_url: Option<String>,
}

impl RTcpTargetStackEP {
    pub fn new(target_did: DID, stack_port: u16) -> Result<Self> {
        validate_rtcp_hostname_form_did(&target_did, "rtcp target did")
            .map_err(anyhow::Error::msg)?;
        Ok(RTcpTargetStackEP {
            did: target_did,
            stack_port,
            bootstrap_stream_url: None,
        })
    }
}

pub(crate) fn validate_rtcp_hostname_form_did(
    did: &DID,
    context: &str,
) -> std::result::Result<(), String> {
    if did.get_path_from_id().is_some() {
        return Err(format!(
            "{} {} is not hostname-form; RTCP does not accept DID URL/path forms",
            context,
            did.to_string()
        ));
    }

    let host = did.to_host_name();
    if host.is_empty() || host.contains('/') || host.contains('?') || host.contains('#') {
        return Err(format!(
            "{} {} resolves to invalid RTCP DID hostname '{}'",
            context,
            did.to_string(),
            host
        ));
    }

    Ok(())
}

// Authority forms supported:
//   did[:port]
//   <percent-encoded bootstrap URL>@did[:port]
//
// The bootstrap URL must be percent-encoded in its entirety; the only raw '@'
// that may appear in the input is the separator between params and remote.
pub(crate) fn parse_rtcp_stack_id(stack_id: &str) -> Option<RTcpTargetStackEP> {
    parse_rtcp_stack_id_checked(stack_id).ok()
}

pub(crate) fn parse_rtcp_stack_id_checked(
    stack_id: &str,
) -> std::result::Result<RTcpTargetStackEP, String> {
    let (bootstrap_stream_url, remote_part) = match stack_id.rsplit_once('@') {
        Some((params, remote)) => {
            if params.is_empty() {
                return Err("bootstrap URL prefix is empty".to_string());
            }
            if remote.is_empty() {
                return Err("remote DID is empty".to_string());
            }
            if params.contains('@') {
                return Err("bootstrap URL prefix contains an unencoded '@'".to_string());
            }
            let decoded = percent_decode_str(params)
                .decode_utf8()
                .map_err(|e| format!("bootstrap URL prefix is not valid UTF-8: {e}"))?
                .into_owned();
            if decoded.is_empty() {
                return Err("decoded bootstrap URL prefix is empty".to_string());
            }
            (Some(decoded), remote)
        }
        None => (None, stack_id),
    };

    let (target_host_name, stack_port) = match remote_part.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() => match port.parse::<u16>() {
            Ok(port) => (host, port),
            Err(_) if remote_part.starts_with("did:") => (remote_part, DEFAULT_RTCP_STACK_PORT),
            Err(_) => return Err(format!("invalid RTCP stack port '{}'", port)),
        },
        Some(_) => return Err("invalid RTCP stack id host/port form".to_string()),
        None => (remote_part, DEFAULT_RTCP_STACK_PORT),
    };
    let target_did = DID::from_str(target_host_name)
        .map_err(|e| format!("invalid RTCP remote DID '{}': {}", target_host_name, e))?;
    validate_rtcp_hostname_form_did(&target_did, "rtcp remote did")?;

    Ok(RTcpTargetStackEP {
        did: target_did,
        stack_port,
        bootstrap_stream_url,
    })
}

// Build the RTCP stack-id form used by nested-remote tunnels:
//   <percent-encoded bootstrap URL>@did[:port]
// Callers should use this instead of reimplementing the percent-encoding and
// authority concatenation rules by hand.
pub fn build_rtcp_nested_remote_stack_id(
    bootstrap_stream_url: &Url,
    remote_host: &str,
    remote_port: Option<u16>,
) -> String {
    let encoded_bootstrap =
        utf8_percent_encode(bootstrap_stream_url.as_str(), NON_ALPHANUMERIC).to_string();
    match remote_port {
        Some(port) => format!("{}@{}:{}", encoded_bootstrap, remote_host, port),
        None => format!("{}@{}", encoded_bootstrap, remote_host),
    }
}

// Build a full nested-remote RTCP URL:
//   rtcp://<percent-encoded bootstrap URL>@did[:port][/stream_id]
// `stream_id` is appended as the outer RTCP path and should be the plain
// stream identifier used by RTCP open_stream semantics.
pub fn build_rtcp_nested_remote_url(
    bootstrap_stream_url: &Url,
    remote_host: &str,
    remote_port: Option<u16>,
    stream_id: Option<&str>,
) -> Result<Url> {
    let stack_id =
        build_rtcp_nested_remote_stack_id(bootstrap_stream_url, remote_host, remote_port);
    let url = match stream_id {
        Some(stream_id) if !stream_id.is_empty() => {
            format!("rtcp://{}/{}", stack_id, stream_id.trim_start_matches('/'))
        }
        _ => format!("rtcp://{}", stack_id),
    };
    Url::parse(&url).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_did_with_port() {
        let ep = parse_rtcp_stack_id("remote.com:2981").expect("parse");
        assert_eq!(ep.stack_port, 2981);
        assert!(ep.bootstrap_stream_url.is_none());
    }

    #[test]
    fn parse_plain_did_default_port() {
        let ep = parse_rtcp_stack_id("remote.com").expect("parse");
        assert_eq!(ep.stack_port, DEFAULT_RTCP_STACK_PORT);
        assert!(ep.bootstrap_stream_url.is_none());
    }

    #[test]
    fn parse_dev_did_with_and_without_port() {
        let dev_did = "did:dev:abcdefghijklmnopqrstuvwxyzABCDE";
        let ep = parse_rtcp_stack_id(dev_did).expect("parse");
        assert_eq!(ep.did.to_string(), dev_did);
        assert_eq!(ep.stack_port, DEFAULT_RTCP_STACK_PORT);

        let ep = parse_rtcp_stack_id(&format!("{}:2981", dev_did)).expect("parse");
        assert_eq!(ep.did.to_string(), dev_did);
        assert_eq!(ep.stack_port, 2981);
    }

    #[test]
    fn parse_bootstrap_url_prefix() {
        let bootstrap = "socks://aaa:bbb@pub.proxy.com/remote.com";
        let encoded = utf8_percent_encode(bootstrap, NON_ALPHANUMERIC).to_string();
        let stack_id = format!("{}@remote.com:2981", encoded);
        let ep = parse_rtcp_stack_id(&stack_id).expect("parse");
        assert_eq!(ep.stack_port, 2981);
        assert_eq!(ep.bootstrap_stream_url.as_deref(), Some(bootstrap));
    }

    #[test]
    fn parse_rejects_empty_params() {
        assert!(parse_rtcp_stack_id("@remote.com:2981").is_none());
    }

    #[test]
    fn parse_rejects_empty_remote_part() {
        let bootstrap = Url::parse("rtcp://relay.example.com:2993/bootstrap:1").unwrap();
        let encoded = utf8_percent_encode(bootstrap.as_str(), NON_ALPHANUMERIC).to_string();
        assert!(parse_rtcp_stack_id(&format!("{}@", encoded)).is_none());
    }

    #[test]
    fn parse_rejects_invalid_remote_port() {
        assert!(parse_rtcp_stack_id("remote.com:not-a-port").is_none());
        assert!(parse_rtcp_stack_id("remote.com:99999").is_none());
    }

    #[test]
    fn parse_rejects_did_url_path_forms() {
        assert!(parse_rtcp_stack_id("did:web:example.com:user:alice").is_none());
        assert!(parse_rtcp_stack_id("did:bns:device:scoped").is_none());
        assert!(parse_rtcp_stack_id("example.com/user:2981").is_none());

        let err = parse_rtcp_stack_id_checked("did:web:example.com:user:alice")
            .expect_err("path DID should be rejected");
        assert!(err.contains("hostname-form"), "unexpected error: {}", err);
    }

    #[test]
    fn parse_rejects_unencoded_bootstrap_url_with_raw_at() {
        assert!(
            parse_rtcp_stack_id("socks://aaa:bbb@pub.proxy.com/remote.com@remote.com:2981")
                .is_none()
        );
    }

    #[test]
    fn build_nested_remote_stack_id_round_trip() {
        let bootstrap = Url::parse("rtcp://relay.example.com:2993/bootstrap:1").unwrap();
        let stack_id =
            build_rtcp_nested_remote_stack_id(&bootstrap, "target.example.com", Some(2994));
        let ep = parse_rtcp_stack_id(&stack_id).expect("parse");
        assert_eq!(ep.stack_port, 2994);
        assert_eq!(
            ep.bootstrap_stream_url.as_deref(),
            Some("rtcp://relay.example.com:2993/bootstrap:1")
        );
    }

    #[test]
    fn build_nested_remote_url_with_stream_id() {
        let bootstrap = Url::parse("rtcp://relay.example.com:2993/bootstrap:1").unwrap();
        let url = build_rtcp_nested_remote_url(
            &bootstrap,
            "target.example.com",
            Some(2994),
            Some("test:80"),
        )
        .unwrap();
        let ep = parse_rtcp_stack_id(url.authority()).expect("parse");
        assert_eq!(ep.stack_port, 2994);
        assert_eq!(
            ep.bootstrap_stream_url.as_deref(),
            Some("rtcp://relay.example.com:2993/bootstrap:1")
        );
        assert_eq!(url.path(), "/test:80");
    }
}
