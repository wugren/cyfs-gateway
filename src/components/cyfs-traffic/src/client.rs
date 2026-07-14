use crate::{
    TrafficBalanceResponse, TrafficUsageReport, TrafficUsageReportsRequest,
    TrafficUsageReportsResponse,
};
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use reqwest::{Client, Url, header::CONTENT_TYPE};
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};

type HmacSha256 = Hmac<Sha256>;

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[async_trait]
pub trait TrafficCreditClient: Send + Sync {
    async fn report_usage_batch(
        &self,
        reports: Vec<TrafficUsageReport>,
    ) -> Result<TrafficUsageReportsResponse>;

    async fn get_balance(&self, user_id: &str) -> Result<TrafficBalanceResponse>;
}

#[derive(Clone)]
pub struct HttpTrafficCreditClient {
    client: Client,
    base_url: Url,
    caller_service: String,
    hmac_secret: String,
}

impl HttpTrafficCreditClient {
    pub fn new(
        base_url: &str,
        caller_service: impl Into<String>,
        hmac_secret: impl Into<String>,
    ) -> Result<Self> {
        let base_url = Url::parse(base_url).context("invalid traffic credit base url")?;
        Ok(Self {
            client: Client::new(),
            base_url,
            caller_service: caller_service.into(),
            hmac_secret: hmac_secret.into(),
        })
    }

    fn request_id() -> String {
        format!(
            "cyfs-gateway-{}",
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_else(|| chrono::Utc::now().timestamp_micros())
        )
    }

    fn url_with_path(&self, path: &str) -> Result<Url> {
        let mut url = self.base_url.clone();
        url.set_path(path);
        Ok(url)
    }

    fn balance_url(&self, user_id: &str) -> Result<Url> {
        let mut url = self.base_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("traffic credit base url cannot be a base"))?;
            segments.clear();
            segments.extend([
                "internal", "credits", "users", user_id, "traffic", "balance",
            ]);
        }
        Ok(url)
    }

    fn timestamp_ms() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    fn nonce() -> String {
        let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
        format!(
            "cyfs-gateway-{}-{counter}",
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_else(|| chrono::Utc::now().timestamp_micros())
        )
    }

    fn sign_request(
        &self,
        method: &str,
        path: &str,
        query: Option<&str>,
        body: &[u8],
    ) -> Result<InternalHmacSignature> {
        let timestamp = Self::timestamp_ms();
        let nonce = Self::nonce();
        let canonical = build_canonical_string(method, path, query, body, timestamp, &nonce)?;
        let mut mac = HmacSha256::new_from_slice(self.hmac_secret.as_bytes())
            .map_err(|_| anyhow!("traffic credit hmac secret is invalid"))?;
        mac.update(canonical.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        Ok(InternalHmacSignature {
            signature,
            timestamp: timestamp.to_string(),
            nonce,
        })
    }

    fn hmac_signing_body(body: &[u8]) -> Result<Vec<u8>> {
        let Ok(Value::Object(mut object)) = serde_json::from_slice(body) else {
            return Ok(body.to_vec());
        };

        let mut changed = false;
        for value in object.values_mut() {
            if matches!(value, Value::Array(_) | Value::Object(_)) {
                *value = Value::String(
                    serde_json::to_string(value)
                        .context("serialize nested traffic hmac body field failed")?,
                );
                changed = true;
            }
        }

        if changed {
            serde_json::to_vec(&Value::Object(object))
                .context("serialize traffic hmac signing body failed")
        } else {
            Ok(body.to_vec())
        }
    }
}

struct InternalHmacSignature {
    signature: String,
    timestamp: String,
    nonce: String,
}

#[async_trait]
impl TrafficCreditClient for HttpTrafficCreditClient {
    async fn report_usage_batch(
        &self,
        reports: Vec<TrafficUsageReport>,
    ) -> Result<TrafficUsageReportsResponse> {
        let url = self.url_with_path("/internal/credits/traffic/usage-reports")?;
        let body = serde_json::to_vec(&TrafficUsageReportsRequest { reports })
            .context("encode traffic usage report request failed")?;
        let hmac_body = Self::hmac_signing_body(&body)?;
        let signature = self
            .sign_request("POST", url.path(), url.query(), &hmac_body)
            .context("sign traffic usage report request failed")?;
        let response = self
            .client
            .post(url)
            .header("x-request-id", Self::request_id())
            .header("x-caller-service", self.caller_service.as_str())
            .header("X-Signature", signature.signature)
            .header("X-Timestamp", signature.timestamp)
            .header("X-Nonce", signature.nonce)
            .header(CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await
            .context("send traffic usage report failed")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("traffic usage report failed: {status}: {body}"));
        }

        response
            .json::<TrafficUsageReportsResponse>()
            .await
            .context("decode traffic usage report response failed")
    }

    async fn get_balance(&self, user_id: &str) -> Result<TrafficBalanceResponse> {
        let url = self.balance_url(user_id)?;
        let signature = self
            .sign_request("GET", url.path(), url.query(), &[])
            .context("sign traffic balance request failed")?;
        let response = self
            .client
            .get(url)
            .header("x-request-id", Self::request_id())
            .header("x-caller-service", self.caller_service.as_str())
            .header("X-Signature", signature.signature)
            .header("X-Timestamp", signature.timestamp)
            .header("X-Nonce", signature.nonce)
            .send()
            .await
            .context("send traffic balance request failed")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("traffic balance request failed: {status}: {body}"));
        }

        response
            .json::<TrafficBalanceResponse>()
            .await
            .context("decode traffic balance response failed")
    }
}

fn build_canonical_string(
    method: &str,
    path: &str,
    query: Option<&str>,
    body: &[u8],
    timestamp_ms: i64,
    nonce: &str,
) -> Result<String> {
    let method = normalize_method(method)?;
    let path = normalize_path(path)?;
    let params = normalized_business_params(&method, query, body)?;
    let joined_params = join_params(&params, timestamp_ms, nonce);
    Ok(format!("{method}\n{path}\n{joined_params}"))
}

fn normalize_method(method: &str) -> Result<String> {
    let method = method.trim().to_ascii_uppercase();
    if method.is_empty() {
        return Err(anyhow!("traffic credit hmac method is required"));
    }
    Ok(method)
}

fn normalize_path(path: &str) -> Result<&str> {
    let path = path.trim();
    if path.is_empty() || !path.starts_with('/') {
        return Err(anyhow!("traffic credit hmac path must start with /"));
    }
    Ok(path)
}

fn normalized_business_params(
    method: &str,
    query: Option<&str>,
    body: &[u8],
) -> Result<Vec<(String, String)>> {
    if method_uses_body(method) {
        let query_params = parse_query_params(query);
        if !query_params.is_empty() {
            return Err(anyhow!(
                "traffic credit hmac write requests must place business parameters in the body"
            ));
        }
        return normalize_params(&parse_body_params(body)?);
    }

    if !body.is_empty() {
        return Err(anyhow!(
            "traffic credit hmac read requests must place business parameters in the URL"
        ));
    }
    normalize_params(&parse_query_params(query))
}

fn method_uses_body(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH")
}

fn parse_query_params(query: Option<&str>) -> Vec<(String, String)> {
    let Some(query) = query.map(str::trim).filter(|value| !value.is_empty()) else {
        return Vec::new();
    };

    url::form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn parse_body_params(body: &[u8]) -> Result<Vec<(String, String)>> {
    if body.is_empty() {
        return Ok(Vec::new());
    }

    let payload: Value =
        serde_json::from_slice(body).context("traffic credit hmac body must be valid JSON")?;
    let Some(object) = payload.as_object() else {
        return Err(anyhow!(
            "traffic credit hmac body must be a JSON object when body parameters are present"
        ));
    };

    let mut params = Vec::with_capacity(object.len());
    for (key, value) in object {
        params.push((key.clone(), scalar_json_value(value)?));
    }
    Ok(params)
}

fn scalar_json_value(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(boolean) => Ok(boolean.to_string()),
        Value::Number(number) => Ok(number.to_string()),
        Value::String(string) => Ok(string.clone()),
        Value::Array(_) | Value::Object(_) => Err(anyhow!(
            "traffic credit hmac body parameters must be scalar JSON values"
        )),
    }
}

fn normalize_params(params: &[(String, String)]) -> Result<Vec<(String, String)>> {
    let mut normalized = Vec::with_capacity(params.len());
    let mut seen = HashSet::with_capacity(params.len());

    for (key, value) in params {
        let key = key.trim();
        if key.is_empty() {
            return Err(anyhow!("traffic credit hmac parameter key is invalid"));
        }
        if !seen.insert(key.to_owned()) {
            return Err(anyhow!("traffic credit hmac parameter keys must be unique"));
        }
        normalized.push((key.to_owned(), value.trim().to_owned()));
    }

    normalized.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    Ok(normalized)
}

fn join_params(params: &[(String, String)], timestamp_ms: i64, nonce: &str) -> String {
    let mut segments = Vec::with_capacity(params.len() + 2);
    for (key, value) in params {
        segments.push(format!("{key}={value}"));
    }
    segments.push(format!("timestamp={timestamp_ms}"));
    segments.push(format!("nonce={nonce}"));
    segments.join("&")
}

#[cfg(test)]
mod tests {
    use super::{HttpTrafficCreditClient, build_canonical_string};

    #[test]
    fn hmac_signing_body_converts_nested_batch_to_scalar_json_string() {
        let body = br#"{"reports":[{"report_id":"r-1","bytes_up":1,"bytes_down":2}]}"#;

        let hmac_body = HttpTrafficCreditClient::hmac_signing_body(body).unwrap();
        let canonical = build_canonical_string(
            "POST",
            "/internal/credits/traffic/usage-reports",
            None,
            &hmac_body,
            1000,
            "nonce-1",
        )
        .unwrap();

        assert!(canonical.starts_with("POST\n/internal/credits/traffic/usage-reports\n"));
        assert!(
            canonical.contains("reports=[{\"bytes_down\":2,\"bytes_up\":1,\"report_id\":\"r-1\"}]")
        );
        assert!(canonical.ends_with("timestamp=1000&nonce=nonce-1"));
    }

    #[test]
    fn hmac_canonical_string_matches_credit_internal_shape() {
        let canonical = build_canonical_string(
            "GET",
            "/internal/credits/users/user-1/traffic/balance",
            None,
            &[],
            1000,
            "nonce-1",
        )
        .unwrap();

        assert_eq!(
            canonical,
            "GET\n/internal/credits/users/user-1/traffic/balance\ntimestamp=1000&nonce=nonce-1"
        );
    }
}
