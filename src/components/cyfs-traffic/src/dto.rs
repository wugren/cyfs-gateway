use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TrafficUsageReport {
    pub report_id: String,
    pub node_id: String,
    pub user_id: String,
    pub period_start: String,
    pub period_end: String,
    pub bytes_up: i64,
    pub bytes_down: i64,
    pub trace_ref: Option<String>,
}

impl TrafficUsageReport {
    pub fn total_bytes(&self) -> i64 {
        self.bytes_up.saturating_add(self.bytes_down)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PendingTrafficReport {
    pub report: TrafficUsageReport,
    pub target_write_sum: u64,
    pub target_read_sum: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PendingTrafficReportBatch {
    pub reports: Vec<PendingTrafficReport>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PendingTrafficCheckpoint {
    pub target_write_sum: u64,
    pub target_read_sum: u64,
    pub period_end: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficUsageReportsRequest {
    pub reports: Vec<TrafficUsageReport>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrafficUsageReportResult {
    pub report_id: String,
    pub node_id: String,
    pub user_id: String,
    pub status: String,
    pub settlement_id: Option<String>,
    pub settled_bytes: Option<i64>,
    pub deducted_bytes: Option<i64>,
    pub traffic_balance_bytes: Option<i64>,
    pub overage_bytes: Option<i64>,
    pub request_id: Option<String>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
}

impl TrafficUsageReportResult {
    pub fn is_duplicate(&self) -> bool {
        self.status == "duplicate"
    }

    pub fn is_confirmed(&self) -> bool {
        matches!(
            self.status.as_str(),
            "settled_full" | "settled_with_overage" | "duplicate"
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrafficUsageReportsResponse {
    pub accepted_count: usize,
    pub duplicate_count: usize,
    pub rejected_count: usize,
    pub conflict_count: usize,
    pub results: Vec<TrafficUsageReportResult>,
    pub request_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrafficBalanceResponse {
    pub traffic_balance_bytes: i64,
    pub last_settlement_at: Option<String>,
    pub last_overage_bytes: i64,
}

#[cfg(test)]
mod tests {
    use super::TrafficUsageReportsResponse;

    #[test]
    fn usage_reports_response_decodes_result_balances_without_top_level_balances() {
        let response: TrafficUsageReportsResponse = serde_json::from_value(serde_json::json!({
            "accepted_count": 1,
            "duplicate_count": 0,
            "rejected_count": 0,
            "conflict_count": 0,
            "results": [{
                "report_id": "report-1",
                "node_id": "node-1",
                "user_id": "user-1",
                "status": "settled_full",
                "settlement_id": "settlement-1",
                "settled_bytes": 512,
                "deducted_bytes": 512,
                "traffic_balance_bytes": 1536,
                "overage_bytes": 0,
                "request_id": "request-1",
                "error_code": null,
                "error_message": null
            }],
            "request_id": "batch-1"
        }))
        .expect("response should match credit usage report contract");

        assert_eq!(response.results[0].traffic_balance_bytes, Some(1536));
    }
}
