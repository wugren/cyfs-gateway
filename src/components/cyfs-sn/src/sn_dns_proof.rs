//! user_domain PKX proof 的外部 DNS 查询路径。
//!
//! 信任边界：绑定证明必须来自「外部 DNS」视角——本模块只通过配置的公共 DoH
//! resolver 查询 TXT，绝不复用 SN 自己的权威/合成解析路径，也不读取
//! `user_dns_records`、BNS fallback 或本地 name cache（否则调用方能用 SN
//! 自身状态伪造 proof）。
//!
//! 默认 resolver 为 Google Public DNS 的 RFC 8484 端点
//! `https://dns.google/dns-query`（wire 格式 GET `?dns=<base64url>`）；
//! 配置 URL 的 path 以 `/resolve` 结尾时按 dns.google JSON API
//! （`?name=<name>&type=TXT`）查询。`pkx_doh_url` 配置可替换 resolver。

use crate::{sn_err, SnErrorCode, SnResult};
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use std::sync::Arc;
use std::time::Duration;

pub const DEFAULT_PKX_DOH_URL: &str = "https://dns.google/dns-query";
const DOH_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

pub type DnsTxtResolverRef = Arc<dyn DnsTxtResolver>;

/// 外部 DNS TXT 查询能力。返回目标 name 的全部 TXT 记录；每条记录的多段
/// character-string 已按 DNS 惯例无分隔拼接为一个字符串。
///
/// 实现不得读取 SN 内部状态（权威记录、合成解析、缓存），必须走真实的
/// 外部 DNS proof path。
#[async_trait]
pub trait DnsTxtResolver: Send + Sync + 'static {
    async fn query_txt(&self, name: &str) -> SnResult<Vec<String>>;

    /// 诊断用：resolver 的可读描述。
    fn describe(&self) -> String {
        "external dns txt resolver".to_string()
    }
}

/// DNS over HTTPS TXT resolver（RFC 8484 wire 或 dns.google JSON API）。
pub struct DohDnsTxtResolver {
    endpoint: String,
    json_api: bool,
    client: reqwest::Client,
}

impl DohDnsTxtResolver {
    pub fn new(endpoint: &str) -> Self {
        let endpoint = endpoint.trim().trim_end_matches('/').to_string();
        let json_api = endpoint
            .split('?')
            .next()
            .unwrap_or_default()
            .ends_with("/resolve");
        Self {
            endpoint,
            json_api,
            client: reqwest::Client::builder()
                .timeout(DOH_TIMEOUT)
                .build()
                .unwrap_or_default(),
        }
    }

    pub fn new_ref(endpoint: &str) -> DnsTxtResolverRef {
        Arc::new(Self::new(endpoint))
    }

    pub fn default_ref() -> DnsTxtResolverRef {
        Self::new_ref(DEFAULT_PKX_DOH_URL)
    }

    fn remote_err(&self, context: impl AsRef<str>, err: impl std::fmt::Display) -> crate::SnError {
        sn_err!(
            SnErrorCode::RemoteError,
            "DoH query via {} failed: {}: {}",
            self.endpoint,
            context.as_ref(),
            err
        )
    }

    fn query_url(&self, param: &str) -> String {
        let sep = if self.endpoint.contains('?') { '&' } else { '?' };
        format!("{}{}{}", self.endpoint, sep, param)
    }

    fn build_query_message(name: &str) -> SnResult<Vec<u8>> {
        let fqdn = Name::from_utf8(name).map_err(|e| {
            sn_err!(
                SnErrorCode::InvalidInput,
                "invalid DNS name {}: {}",
                name,
                e
            )
        })?;
        let mut message = Message::new();
        message
            // RFC 8484 §4.1：GET 请求用固定 id=0 以利 HTTP 缓存。
            .set_id(0)
            .set_message_type(MessageType::Query)
            .set_op_code(OpCode::Query)
            .set_recursion_desired(true);
        message.add_query(Query::query(fqdn, RecordType::TXT));
        message
            .to_vec()
            .map_err(|e| sn_err!(SnErrorCode::Failed, "encode DNS query failed: {}", e))
    }

    /// 提取 answer section 里全部 TXT 记录；一条记录的多段 character-string
    /// 无分隔拼接（与 SPF/DKIM 等长 TXT 的惯例一致）。CNAME 链上的 TXT 也
    /// 会被采纳（递归 resolver 返回完整链）。
    fn txt_records_from_message(message: &Message) -> Vec<String> {
        message
            .answers()
            .iter()
            .filter_map(|record| match record.data() {
                RData::TXT(txt) => Some(
                    txt.txt_data()
                        .iter()
                        .map(|segment| String::from_utf8_lossy(segment).into_owned())
                        .collect::<Vec<_>>()
                        .concat(),
                ),
                _ => None,
            })
            .collect()
    }

    /// dns.google JSON API 的 TXT data 归一：`"seg1""seg2"` → `seg1seg2`；
    /// 不带引号的裸值原样返回（去首尾空白）。
    fn unquote_txt_data(data: &str) -> String {
        let trimmed = data.trim();
        if !trimmed.starts_with('"') {
            return trimmed.to_string();
        }
        let mut result = String::new();
        let mut in_quotes = false;
        let mut chars = trimmed.chars();
        while let Some(c) = chars.next() {
            match c {
                '"' => in_quotes = !in_quotes,
                '\\' if in_quotes => {
                    if let Some(next) = chars.next() {
                        result.push(next);
                    }
                }
                _ if in_quotes => result.push(c),
                _ => {}
            }
        }
        result
    }

    async fn query_wire(&self, name: &str) -> SnResult<Vec<String>> {
        let query = Self::build_query_message(name)?;
        let url = self.query_url(format!("dns={}", URL_SAFE_NO_PAD.encode(query)).as_str());
        let response = self
            .client
            .get(url)
            .header(http::header::ACCEPT, DNS_MESSAGE_CONTENT_TYPE)
            .send()
            .await
            .map_err(|e| self.remote_err("send request", e))?;
        if !response.status().is_success() {
            return Err(self.remote_err("http status", response.status()));
        }
        let body = response
            .bytes()
            .await
            .map_err(|e| self.remote_err("read response body", e))?;
        let message = Message::from_vec(body.as_ref())
            .map_err(|e| self.remote_err("decode DNS response", e))?;
        match message.response_code() {
            ResponseCode::NoError => Ok(Self::txt_records_from_message(&message)),
            ResponseCode::NXDomain => Ok(Vec::new()),
            other => Err(self.remote_err("dns response code", other)),
        }
    }

    async fn query_json(&self, name: &str) -> SnResult<Vec<String>> {
        let url = self.query_url(format!("name={}&type=TXT", name).as_str());
        let response = self
            .client
            .get(url)
            .header(http::header::ACCEPT, "application/dns-json")
            .send()
            .await
            .map_err(|e| self.remote_err("send request", e))?;
        if !response.status().is_success() {
            return Err(self.remote_err("http status", response.status()));
        }
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|e| self.remote_err("decode JSON response", e))?;
        let status = value.get("Status").and_then(|v| v.as_i64()).unwrap_or(-1);
        match status {
            0 => {}
            // NXDomain：域名不存在按「无 TXT」处理，交由上层给出可重试错误。
            3 => return Ok(Vec::new()),
            other => return Err(self.remote_err("dns response status", other)),
        }
        let answers = value
            .get("Answer")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(answers
            .iter()
            .filter(|answer| answer.get("type").and_then(|v| v.as_i64()) == Some(16))
            .filter_map(|answer| answer.get("data").and_then(|v| v.as_str()))
            .map(Self::unquote_txt_data)
            .collect())
    }
}

#[async_trait]
impl DnsTxtResolver for DohDnsTxtResolver {
    async fn query_txt(&self, name: &str) -> SnResult<Vec<String>> {
        if self.json_api {
            self.query_json(name).await
        } else {
            self.query_wire(name).await
        }
    }

    fn describe(&self) -> String {
        format!(
            "doh({}, {})",
            self.endpoint,
            if self.json_api { "json" } else { "rfc8484" }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::TXT;
    use hickory_proto::rr::Record;

    #[test]
    fn test_build_query_message_roundtrip() {
        let bytes = DohDnsTxtResolver::build_query_message("_pkx.example.com").unwrap();
        let message = Message::from_vec(bytes.as_slice()).unwrap();
        assert_eq!(message.id(), 0);
        assert_eq!(message.queries().len(), 1);
        let query = &message.queries()[0];
        assert_eq!(query.query_type(), RecordType::TXT);
        assert_eq!(query.name().to_utf8(), "_pkx.example.com.");

        assert!(DohDnsTxtResolver::build_query_message("   ").is_err());
    }

    #[test]
    fn test_txt_records_from_message_concatenates_segments() {
        let mut message = Message::new();
        message.set_message_type(MessageType::Response);
        let name = Name::from_utf8("_pkx.example.com.").unwrap();
        // 多段 TXT 记录：无分隔拼接。
        message.add_answer(Record::from_rdata(
            name.clone(),
            300,
            RData::TXT(TXT::new(vec![
                "PKX(part1-".to_string(),
                "part2)".to_string(),
            ])),
        ));
        // 第二条 TXT 记录：独立返回。
        message.add_answer(Record::from_rdata(
            name,
            300,
            RData::TXT(TXT::new(vec!["unrelated".to_string()])),
        ));

        let records = DohDnsTxtResolver::txt_records_from_message(&message);
        assert_eq!(
            records,
            vec!["PKX(part1-part2)".to_string(), "unrelated".to_string()]
        );
    }

    #[test]
    fn test_unquote_txt_data() {
        // dns.google JSON：带引号（含多段拼接）。
        assert_eq!(
            DohDnsTxtResolver::unquote_txt_data("\"PKX(abc)\""),
            "PKX(abc)"
        );
        assert_eq!(
            DohDnsTxtResolver::unquote_txt_data("\"PKX(part1-\"\"part2)\""),
            "PKX(part1-part2)"
        );
        assert_eq!(
            DohDnsTxtResolver::unquote_txt_data("\"a\\\"b\""),
            "a\"b"
        );
        // 裸值：原样（去首尾空白）。
        assert_eq!(
            DohDnsTxtResolver::unquote_txt_data("  PKX(abc)  "),
            "PKX(abc)"
        );
    }

    #[test]
    fn test_doh_mode_detection_and_url() {
        let wire = DohDnsTxtResolver::new("https://dns.google/dns-query");
        assert!(!wire.json_api);
        assert!(wire.query_url("dns=abc").ends_with("/dns-query?dns=abc"));

        let json = DohDnsTxtResolver::new("https://dns.google/resolve");
        assert!(json.json_api);
        assert!(json
            .query_url("name=example.com&type=TXT")
            .ends_with("/resolve?name=example.com&type=TXT"));

        // 已带 query string 的 endpoint 用 `&` 续接。
        let with_query = DohDnsTxtResolver::new("https://doh.example/resolve?ct=application/dns-json");
        assert!(with_query.json_api);
        assert!(with_query.query_url("name=a&type=TXT").contains("?ct="));
        assert!(with_query.query_url("name=a&type=TXT").ends_with("&name=a&type=TXT"));
    }
}
