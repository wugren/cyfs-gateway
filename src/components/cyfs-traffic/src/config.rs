use serde::{Deserialize, Deserializer, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownBalancePolicy {
    Allow,
    Throttle,
}

fn default_enabled() -> bool {
    false
}

fn default_report_interval_sec() -> u64 {
    60
}

fn default_max_reports_per_batch() -> usize {
    100
}

fn default_stat_prefix() -> String {
    "traffic:user:".to_owned()
}

fn default_limiter_prefix() -> String {
    "traffic:user:".to_owned()
}

fn default_throttled_speed() -> u64 {
    64 * 1024
}

fn default_unknown_balance_policy() -> UnknownBalancePolicy {
    UnknownBalancePolicy::Throttle
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub credit_base_url: String,
    #[serde(default)]
    pub credit_hmac_secret: String,
    #[serde(default = "default_report_interval_sec")]
    pub report_interval_sec: u64,
    #[serde(default = "default_max_reports_per_batch")]
    pub max_reports_per_batch: usize,
    #[serde(default = "default_stat_prefix")]
    pub stat_prefix: String,
    #[serde(default = "default_limiter_prefix")]
    pub limiter_prefix: String,
    #[serde(
        default = "default_throttled_speed",
        deserialize_with = "deserialize_speed"
    )]
    pub throttled_download_speed: u64,
    #[serde(
        default = "default_throttled_speed",
        deserialize_with = "deserialize_speed"
    )]
    pub throttled_upload_speed: u64,
    #[serde(default = "default_unknown_balance_policy")]
    pub unknown_balance_policy: UnknownBalancePolicy,
}

impl Default for TrafficConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            node_id: String::new(),
            credit_base_url: String::new(),
            credit_hmac_secret: String::new(),
            report_interval_sec: default_report_interval_sec(),
            max_reports_per_batch: default_max_reports_per_batch(),
            stat_prefix: default_stat_prefix(),
            limiter_prefix: default_limiter_prefix(),
            throttled_download_speed: default_throttled_speed(),
            throttled_upload_speed: default_throttled_speed(),
            unknown_balance_policy: default_unknown_balance_policy(),
        }
    }
}

impl TrafficConfig {
    pub fn report_interval(&self) -> Duration {
        Duration::from_secs(self.report_interval_sec.max(1))
    }

    pub fn batch_size(&self) -> usize {
        self.max_reports_per_batch.clamp(1, 100)
    }
}

fn deserialize_speed<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SpeedValue {
        Number(u64),
        String(String),
    }

    match SpeedValue::deserialize(deserializer)? {
        SpeedValue::Number(value) => Ok(value),
        SpeedValue::String(value) => {
            cyfs_gateway_lib::parse_speed(&value).map_err(serde::de::Error::custom)
        }
    }
}
