use crate::{
    HttpTrafficCreditClient, PendingTrafficReport, TrafficConfig, TrafficCreditClient,
    TrafficStatFactoryRef, TrafficUsageReport, apply_balance_to_user_limiter,
};
use anyhow::{Context, Result, anyhow};
#[cfg(test)]
use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
#[cfg(test)]
use cyfs_gateway_lib::{DefaultLimiterManager, StatManager};
use cyfs_gateway_lib::{LimiterManagerRef, StatManagerRef};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

pub struct TrafficServiceHandle {
    stop_tx: watch::Sender<bool>,
    joins: Vec<JoinHandle<()>>,
}

impl TrafficServiceHandle {
    pub async fn stop(self) {
        let _ = self.stop_tx.send(true);
        for join in self.joins {
            let _ = join.await;
        }
    }

    pub fn shutdown_now(self) {
        let _ = self.stop_tx.send(true);
        for join in self.joins {
            join.abort();
        }
    }
}

pub struct TrafficQuotaService<C>
where
    C: TrafficCreditClient + 'static,
{
    config: TrafficConfig,
    stat_factory: TrafficStatFactoryRef,
    limiter_manager: LimiterManagerRef,
    client: Arc<C>,
}

impl TrafficQuotaService<HttpTrafficCreditClient> {
    pub async fn start_http(
        config: TrafficConfig,
        stat_manager: StatManagerRef,
        stat_factory: TrafficStatFactoryRef,
        limiter_manager: LimiterManagerRef,
    ) -> Result<Option<TrafficServiceHandle>> {
        if !config.enabled {
            return Ok(None);
        }
        if config.node_id.trim().is_empty() {
            return Err(anyhow!(
                "traffic.node_id is required when traffic is enabled"
            ));
        }
        if config.credit_base_url.trim().is_empty() {
            return Err(anyhow!(
                "traffic.credit_base_url is required when traffic is enabled"
            ));
        }
        if config.credit_hmac_secret.trim().is_empty() {
            return Err(anyhow!(
                "traffic.credit_hmac_secret is required when traffic is enabled"
            ));
        }
        let client = HttpTrafficCreditClient::new(
            &config.credit_base_url,
            "cyfs-gateway",
            config.credit_hmac_secret.clone(),
        )?;
        Ok(Some(
            Self::new(
                config,
                stat_manager,
                stat_factory,
                limiter_manager,
                Arc::new(client),
            )
            .start(),
        ))
    }
}

impl<C> TrafficQuotaService<C>
where
    C: TrafficCreditClient + 'static,
{
    pub fn new(
        config: TrafficConfig,
        _stat_manager: StatManagerRef,
        stat_factory: TrafficStatFactoryRef,
        limiter_manager: LimiterManagerRef,
        client: Arc<C>,
    ) -> Self {
        Self {
            config,
            stat_factory,
            limiter_manager,
            client,
        }
    }

    pub fn start(self) -> TrafficServiceHandle {
        let (stop_tx, stop_rx) = watch::channel(false);
        let service = Arc::new(self);
        let pending_notify = Arc::new(Notify::new());

        let sample_service = service.clone();
        let sample_pending_notify = pending_notify.clone();
        let sample_stop_rx = stop_rx.clone();
        let sample_join = tokio::spawn(async move {
            if let Err(error) = sample_service
                .run_sample_loop(sample_stop_rx, sample_pending_notify)
                .await
            {
                log::error!("traffic quota sample loop stopped: {error:#}");
            }
        });

        let flush_service = service.clone();
        let flush_pending_notify = pending_notify;
        let flush_stop_rx = stop_rx.clone();
        let flush_join = tokio::spawn(async move {
            if let Err(error) = flush_service
                .run_flush_loop(flush_stop_rx, flush_pending_notify)
                .await
            {
                log::error!("traffic quota flush loop stopped: {error:#}");
            }
        });

        TrafficServiceHandle {
            stop_tx,
            joins: vec![sample_join, flush_join],
        }
    }

    async fn run_sample_loop(
        &self,
        mut stop_rx: watch::Receiver<bool>,
        pending_notify: Arc<Notify>,
    ) -> Result<()> {
        let mut report_interval = tokio::time::interval(self.config.report_interval());
        report_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = stop_rx.changed() => {
                    if *stop_rx.borrow() {
                        break;
                    }
                }
                _ = report_interval.tick() => {
                    match self.sample_new_reports().await {
                        Ok(true) => pending_notify.notify_one(),
                        Ok(false) => {}
                        Err(error) => log::warn!("traffic report sample failed: {error:#}"),
                    }
                }
            }
        }
        Ok(())
    }

    async fn run_flush_loop(
        &self,
        mut stop_rx: watch::Receiver<bool>,
        pending_notify: Arc<Notify>,
    ) -> Result<()> {
        loop {
            if *stop_rx.borrow() {
                break;
            }

            match self.flush_pending_reports().await {
                Ok(true) => {
                    continue;
                }
                Ok(false) => {
                    tokio::select! {
                        _ = stop_rx.changed() => {
                            if *stop_rx.borrow() {
                                break;
                            }
                        }
                        _ = pending_notify.notified() => {}
                    }
                }
                Err(error) => {
                    log::warn!("traffic report flush failed: {error:#}");
                    tokio::select! {
                        _ = stop_rx.changed() => {
                            if *stop_rx.borrow() {
                                break;
                            }
                        }
                        _ = pending_notify.notified() => {}
                        _ = tokio::time::sleep(self.config.report_interval()) => {}
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    async fn report_tick(&self) -> Result<()> {
        let _ = self.sample_new_reports().await?;
        self.flush_pending_reports().await.map(|_| ())
    }

    async fn sample_new_reports(&self) -> Result<bool> {
        let mut pending_reports = Vec::new();
        let mut sampled_any = false;
        for user_id in self.stat_factory.dirty_users_snapshot() {
            let stat_id = self.stat_id_for_user(&user_id);
            let Some(stat) = self.stat_factory.tracker(&stat_id) else {
                continue;
            };
            let now = Utc::now();
            let period_end = now.to_rfc3339_opts(SecondsFormat::Secs, true);
            let fallback_period_start = (now
                - chrono::Duration::from_std(self.config.report_interval())
                    .unwrap_or_else(|_| chrono::Duration::seconds(60)))
            .to_rfc3339_opts(SecondsFormat::Secs, true);
            let Some(usage) = stat
                .sample_current_period_usage(fallback_period_start, period_end.clone())
                .await
            else {
                continue;
            };

            let report_id = make_report_id(
                &self.config.node_id,
                &user_id,
                &usage.period_start,
                &period_end,
                usage.current_write_sum,
                usage.current_read_sum,
            );
            let pending = PendingTrafficReport {
                report: TrafficUsageReport {
                    report_id,
                    node_id: self.config.node_id.clone(),
                    user_id: user_id.clone(),
                    period_start: usage.period_start,
                    period_end,
                    bytes_up: usage.bytes_up.min(i64::MAX as u64) as i64,
                    bytes_down: usage.bytes_down.min(i64::MAX as u64) as i64,
                    trace_ref: None,
                },
                target_write_sum: usage.current_write_sum,
                target_read_sum: usage.current_read_sum,
            };
            pending_reports.push(pending);
            sampled_any = true;
        }
        self.stat_factory
            .save_pending_report_batch(pending_reports)
            .await?;
        Ok(sampled_any)
    }

    async fn flush_pending_reports(&self) -> Result<bool> {
        let Some(pending_batch) = self.stat_factory.next_pending_report_batch().await? else {
            return Ok(false);
        };
        let pending = pending_batch
            .reports
            .into_iter()
            .take(self.config.batch_size())
            .collect::<Vec<_>>();
        let by_id = pending
            .iter()
            .map(|report| (report.report.report_id.clone(), report.clone()))
            .collect::<HashMap<_, _>>();
        let reports = pending
            .iter()
            .map(|pending| pending.report.clone())
            .collect::<Vec<_>>();

        let response = match self.client.report_usage_batch(reports).await {
            Ok(response) => response,
            Err(error) => {
                let message = error.to_string();
                for report in by_id.values() {
                    let _ = self
                        .stat_factory
                        .record_report_error(&report.report.report_id, &message)
                        .await;
                }
                return Err(error).context("traffic usage batch report failed");
            }
        };

        let mut confirmed_count = 0;
        for result in response.results {
            if result.is_duplicate() {
                if let Some(pending) = by_id.get(&result.report_id) {
                    confirmed_count += 1;
                    let stat_id = self.stat_id_for_user(&pending.report.user_id);
                    if let Some(stat) = self.stat_factory.tracker(&stat_id) {
                        stat.mark_reported(pending.target_write_sum, pending.target_read_sum);
                    }
                }
                self.stat_factory
                    .mark_report_duplicate(&result.report_id)
                    .await?;
                continue;
            }

            if result.is_confirmed() {
                if let Some(pending) = by_id.get(&result.report_id) {
                    confirmed_count += 1;
                    let stat_id = self.stat_id_for_user(&pending.report.user_id);
                    if let Some(stat) = self.stat_factory.tracker(&stat_id) {
                        stat.mark_reported(pending.target_write_sum, pending.target_read_sum);
                    }
                }
                let balance = result.traffic_balance_bytes;
                let state = if let Some(balance) = balance {
                    apply_balance_to_user_limiter(
                        &self.config,
                        &self.limiter_manager,
                        &result.user_id,
                        balance,
                    )
                } else {
                    apply_balance_to_user_limiter(
                        &self.config,
                        &self.limiter_manager,
                        &result.user_id,
                        0,
                    )
                };
                self.stat_factory
                    .mark_report_confirmed(&result.report_id, balance, state)
                    .await?;
            } else {
                let message = format!(
                    "{}:{}",
                    result
                        .error_code
                        .as_deref()
                        .unwrap_or(result.status.as_str()),
                    result.error_message.as_deref().unwrap_or("")
                );
                self.stat_factory
                    .record_report_error(&result.report_id, &message)
                    .await?;
            }
        }

        if confirmed_count == pending.len() {
            return self
                .stat_factory
                .next_pending_report_batch()
                .await
                .map(|pending| pending.is_some());
        }
        Ok(false)
    }

    fn stat_id_for_user(&self, user_id: &str) -> String {
        format!("{}{}", self.config.stat_prefix, user_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TrafficBalanceResponse, TrafficStatFactory, TrafficThrottleState, TrafficUsageReportResult,
        TrafficUsageReportsResponse, UnknownBalancePolicy,
    };
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{Mutex as AsyncMutex, Notify, oneshot};

    #[derive(Default)]
    struct MockTrafficCreditClient {
        batches: Mutex<Vec<Vec<TrafficUsageReport>>>,
        balance_requests: Mutex<Vec<String>>,
    }

    impl MockTrafficCreditClient {
        fn batches(&self) -> Vec<Vec<TrafficUsageReport>> {
            self.batches.lock().unwrap().clone()
        }

        fn balance_requests(&self) -> Vec<String> {
            self.balance_requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TrafficCreditClient for MockTrafficCreditClient {
        async fn report_usage_batch(
            &self,
            reports: Vec<TrafficUsageReport>,
        ) -> Result<TrafficUsageReportsResponse> {
            self.batches.lock().unwrap().push(reports.clone());
            let results = reports
                .iter()
                .map(|report| TrafficUsageReportResult {
                    report_id: report.report_id.clone(),
                    node_id: report.node_id.clone(),
                    user_id: report.user_id.clone(),
                    status: "settled_full".to_owned(),
                    settlement_id: Some("settlement-1".to_owned()),
                    settled_bytes: Some(report.total_bytes()),
                    deducted_bytes: Some(report.total_bytes()),
                    traffic_balance_bytes: Some(1024),
                    overage_bytes: Some(0),
                    request_id: Some("request-1".to_owned()),
                    error_code: None,
                    error_message: None,
                })
                .collect();
            Ok(TrafficUsageReportsResponse {
                accepted_count: reports.len(),
                duplicate_count: 0,
                rejected_count: 0,
                conflict_count: 0,
                results,
                request_id: "batch-1".to_owned(),
            })
        }

        async fn get_balance(&self, user_id: &str) -> Result<TrafficBalanceResponse> {
            self.balance_requests
                .lock()
                .unwrap()
                .push(user_id.to_owned());
            Ok(TrafficBalanceResponse {
                traffic_balance_bytes: 1024,
                last_settlement_at: None,
                last_overage_bytes: 0,
            })
        }
    }

    struct DuplicateTrafficCreditClient;

    #[async_trait]
    impl TrafficCreditClient for DuplicateTrafficCreditClient {
        async fn report_usage_batch(
            &self,
            reports: Vec<TrafficUsageReport>,
        ) -> Result<TrafficUsageReportsResponse> {
            let results = reports
                .iter()
                .map(|report| TrafficUsageReportResult {
                    report_id: report.report_id.clone(),
                    node_id: report.node_id.clone(),
                    user_id: report.user_id.clone(),
                    status: "duplicate".to_owned(),
                    settlement_id: Some("settlement-1".to_owned()),
                    settled_bytes: Some(report.total_bytes()),
                    deducted_bytes: Some(report.total_bytes()),
                    traffic_balance_bytes: Some(0),
                    overage_bytes: Some(0),
                    request_id: Some("request-1".to_owned()),
                    error_code: None,
                    error_message: None,
                })
                .collect();
            Ok(TrafficUsageReportsResponse {
                accepted_count: 0,
                duplicate_count: reports.len(),
                rejected_count: 0,
                conflict_count: 0,
                results,
                request_id: "batch-1".to_owned(),
            })
        }

        async fn get_balance(&self, _user_id: &str) -> Result<TrafficBalanceResponse> {
            Ok(TrafficBalanceResponse {
                traffic_balance_bytes: 1024,
                last_settlement_at: None,
                last_overage_bytes: 0,
            })
        }
    }

    struct BlockingTrafficCreditClient {
        batches: Mutex<Vec<Vec<TrafficUsageReport>>>,
        first_batch_started: Notify,
        release_first_batch: AsyncMutex<Option<oneshot::Receiver<()>>>,
    }

    impl BlockingTrafficCreditClient {
        fn new(release_first_batch: oneshot::Receiver<()>) -> Self {
            Self {
                batches: Mutex::new(Vec::new()),
                first_batch_started: Notify::new(),
                release_first_batch: AsyncMutex::new(Some(release_first_batch)),
            }
        }
    }

    #[async_trait]
    impl TrafficCreditClient for BlockingTrafficCreditClient {
        async fn report_usage_batch(
            &self,
            reports: Vec<TrafficUsageReport>,
        ) -> Result<TrafficUsageReportsResponse> {
            self.batches.lock().unwrap().push(reports.clone());
            let release_first_batch = self.release_first_batch.lock().await.take();
            if let Some(release_first_batch) = release_first_batch {
                self.first_batch_started.notify_one();
                let _ = release_first_batch.await;
            }
            let results = reports
                .iter()
                .map(|report| TrafficUsageReportResult {
                    report_id: report.report_id.clone(),
                    node_id: report.node_id.clone(),
                    user_id: report.user_id.clone(),
                    status: "settled_full".to_owned(),
                    settlement_id: Some("settlement-1".to_owned()),
                    settled_bytes: Some(report.total_bytes()),
                    deducted_bytes: Some(report.total_bytes()),
                    traffic_balance_bytes: Some(1024),
                    overage_bytes: Some(0),
                    request_id: Some("request-1".to_owned()),
                    error_code: None,
                    error_message: None,
                })
                .collect();
            Ok(TrafficUsageReportsResponse {
                accepted_count: reports.len(),
                duplicate_count: 0,
                rejected_count: 0,
                conflict_count: 0,
                results,
                request_id: "batch-1".to_owned(),
            })
        }

        async fn get_balance(&self, _user_id: &str) -> Result<TrafficBalanceResponse> {
            Ok(TrafficBalanceResponse {
                traffic_balance_bytes: 1024,
                last_settlement_at: None,
                last_overage_bytes: 0,
            })
        }
    }

    struct MockTrafficReportServer {
        addr: SocketAddr,
        state: Arc<MockTrafficReportServerState>,
        join: JoinHandle<()>,
    }

    #[derive(Default)]
    struct MockTrafficReportServerState {
        balance_requests: Mutex<Vec<String>>,
        usage_requests: Mutex<Vec<Vec<TrafficUsageReport>>>,
        initial_balance_bytes: Mutex<i64>,
        settlement_balance_bytes: Mutex<i64>,
    }

    #[derive(serde::Deserialize)]
    struct MockUsageReportsRequest {
        reports: Vec<TrafficUsageReport>,
    }

    impl MockTrafficReportServer {
        async fn start() -> Result<Self> {
            Self::start_with_balances(2048, 768).await
        }

        async fn start_with_balances(
            initial_balance_bytes: i64,
            settlement_balance_bytes: i64,
        ) -> Result<Self> {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
            let addr = listener.local_addr()?;
            let state = Arc::new(MockTrafficReportServerState {
                initial_balance_bytes: Mutex::new(initial_balance_bytes),
                settlement_balance_bytes: Mutex::new(settlement_balance_bytes),
                ..MockTrafficReportServerState::default()
            });
            let server_state = state.clone();
            let join = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        break;
                    };
                    let state = server_state.clone();
                    tokio::spawn(async move {
                        if let Err(error) = handle_mock_http_connection(stream, state).await {
                            log::warn!("traffic mock server request failed: {error:#}");
                        }
                    });
                }
            });
            Ok(Self { addr, state, join })
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }

        fn balance_requests(&self) -> Vec<String> {
            self.state.balance_requests.lock().unwrap().clone()
        }

        fn usage_requests(&self) -> Vec<Vec<TrafficUsageReport>> {
            self.state.usage_requests.lock().unwrap().clone()
        }

        async fn shutdown(self) {
            self.join.abort();
            let _ = self.join.await;
        }
    }

    async fn handle_mock_http_connection(
        mut stream: TcpStream,
        state: Arc<MockTrafficReportServerState>,
    ) -> Result<()> {
        let request = read_mock_http_request(&mut stream).await?;
        let body = match (request.method.as_str(), request.path.as_str()) {
            ("GET", path) => {
                let user_id = path
                    .strip_prefix("/internal/credits/users/")
                    .and_then(|value| value.strip_suffix("/traffic/balance"))
                    .context("unexpected balance path")?;
                state
                    .balance_requests
                    .lock()
                    .unwrap()
                    .push(user_id.to_owned());
                let balance = *state.initial_balance_bytes.lock().unwrap();
                serde_json::json!({
                    "traffic_balance_bytes": balance,
                    "last_settlement_at": null,
                    "last_overage_bytes": 0
                })
            }
            ("POST", "/internal/credits/traffic/usage-reports") => {
                let usage_request: MockUsageReportsRequest = serde_json::from_slice(&request.body)?;
                let balance = *state.settlement_balance_bytes.lock().unwrap();
                state
                    .usage_requests
                    .lock()
                    .unwrap()
                    .push(usage_request.reports.clone());
                let results = usage_request
                    .reports
                    .iter()
                    .map(|report| {
                        serde_json::json!({
                            "report_id": report.report_id,
                            "node_id": report.node_id,
                            "user_id": report.user_id,
                            "status": "settled_full",
                            "settlement_id": "settlement-1",
                            "settled_bytes": report.total_bytes(),
                            "deducted_bytes": report.total_bytes(),
                            "traffic_balance_bytes": balance,
                            "overage_bytes": 0,
                            "request_id": "request-1",
                            "error_code": null,
                            "error_message": null
                        })
                    })
                    .collect::<Vec<_>>();
                serde_json::json!({
                    "accepted_count": results.len(),
                    "duplicate_count": 0,
                    "rejected_count": 0,
                    "conflict_count": 0,
                    "results": results,
                    "request_id": "batch-1"
                })
            }
            _ => {
                write_mock_http_response(&mut stream, 404, "{}").await?;
                return Ok(());
            }
        };

        write_mock_http_response(&mut stream, 200, &serde_json::to_string(&body)?).await?;
        Ok(())
    }

    struct MockHttpRequest {
        method: String,
        path: String,
        body: Vec<u8>,
    }

    async fn read_mock_http_request(stream: &mut TcpStream) -> Result<MockHttpRequest> {
        let mut buffer = Vec::new();
        let header_end = loop {
            if let Some(index) = find_header_end(&buffer) {
                break index;
            }
            let mut chunk = [0; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(anyhow!("mock server connection closed before headers"));
            }
            buffer.extend_from_slice(&chunk[..read]);
        };

        let headers = String::from_utf8_lossy(&buffer[..header_end]);
        let mut lines = headers.lines();
        let request_line = lines.next().context("missing request line")?;
        let mut request_parts = request_line.split_whitespace();
        let method = request_parts
            .next()
            .context("missing request method")?
            .to_owned();
        let path = request_parts
            .next()
            .context("missing request path")?
            .to_owned();
        let content_length = lines
            .filter_map(|line| line.split_once(':'))
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);

        let body_start = header_end + 4;
        while buffer.len() < body_start + content_length {
            let mut chunk = [0; 1024];
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(anyhow!("mock server connection closed before body"));
            }
            buffer.extend_from_slice(&chunk[..read]);
        }

        Ok(MockHttpRequest {
            method,
            path,
            body: buffer[body_start..body_start + content_length].to_vec(),
        })
    }

    fn find_header_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }

    async fn write_mock_http_response(
        stream: &mut TcpStream,
        status: u16,
        body: &str,
    ) -> Result<()> {
        let reason = match status {
            200 => "OK",
            404 => "Not Found",
            _ => "Error",
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
            body.as_bytes().len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn sampler_does_not_refresh_initial_balance() {
        let config = TrafficConfig {
            enabled: true,
            node_id: "node-1".to_owned(),
            report_interval_sec: 1,
            unknown_balance_policy: UnknownBalancePolicy::Allow,
            ..TrafficConfig::default()
        };
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let stat_manager = StatManager::with_stat_factory(stat_factory.clone());
        let stat_id = format!("{}{}", config.stat_prefix, "user-1");
        stat_manager.get_speed_stats(std::slice::from_ref(&stat_id));

        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let client = Arc::new(MockTrafficCreditClient::default());
        let service = TrafficQuotaService::new(
            config,
            stat_manager,
            stat_factory.clone(),
            limiter_manager,
            client.clone(),
        )
        .start();

        tokio::time::sleep(Duration::from_millis(1300)).await;
        assert!(client.balance_requests().is_empty());
        let state = stat_factory.load_user_state("user-1").await.unwrap();
        assert_eq!(state.last_balance_bytes, None);
        assert_eq!(state.throttle_state, TrafficThrottleState::Unknown);

        service.stop().await;
    }

    #[tokio::test]
    async fn report_tick_advances_tracker_reported_totals_after_confirmation() {
        let config = TrafficConfig {
            enabled: true,
            node_id: "node-1".to_owned(),
            unknown_balance_policy: UnknownBalancePolicy::Allow,
            ..TrafficConfig::default()
        };
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let stat_manager = StatManager::with_stat_factory(stat_factory.clone());
        let stat_id = format!("{}{}", config.stat_prefix, "user-1");
        let stat = stat_manager.get_speed_stats(std::slice::from_ref(&stat_id))[0].clone();
        stat.add_write_data_size(100);
        stat.add_read_data_size(40);

        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let client = Arc::new(MockTrafficCreditClient::default());
        let service = TrafficQuotaService::new(
            config,
            stat_manager,
            stat_factory.clone(),
            limiter_manager,
            client.clone(),
        );

        service.report_tick().await.unwrap();

        let traffic_stat = stat_factory.tracker(&stat_id).unwrap();
        assert_eq!(
            traffic_stat.latest_reported_totals(),
            crate::TrafficReportedTotals {
                write_sum: 100,
                read_sum: 40
            }
        );
        assert_eq!(client.batches()[0][0].bytes_up, 100);
        assert_eq!(client.batches()[0][0].bytes_down, 40);

        stat.add_write_data_size(10);
        stat.add_read_data_size(5);
        service.report_tick().await.unwrap();

        assert_eq!(
            traffic_stat.latest_reported_totals(),
            crate::TrafficReportedTotals {
                write_sum: 110,
                read_sum: 45
            }
        );
        assert_eq!(client.batches()[1][0].bytes_up, 10);
        assert_eq!(client.batches()[1][0].bytes_down, 5);
    }

    #[tokio::test]
    async fn sample_queues_all_dirty_users_and_flush_batches_reports() {
        let config = TrafficConfig {
            enabled: true,
            node_id: "node-1".to_owned(),
            max_reports_per_batch: 1,
            unknown_balance_policy: UnknownBalancePolicy::Allow,
            ..TrafficConfig::default()
        };
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let stat_manager = StatManager::with_stat_factory(stat_factory.clone());
        let user_1_stat_id = format!("{}{}", config.stat_prefix, "user-1");
        let user_2_stat_id = format!("{}{}", config.stat_prefix, "user-2");
        let user_1_stat = stat_manager.get_speed_stats(&[user_1_stat_id])[0].clone();
        let user_2_stat = stat_manager.get_speed_stats(&[user_2_stat_id])[0].clone();
        user_1_stat.add_write_data_size(100);
        user_2_stat.add_write_data_size(200);

        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let client = Arc::new(MockTrafficCreditClient::default());
        let service = TrafficQuotaService::new(
            config,
            stat_manager,
            stat_factory.clone(),
            limiter_manager,
            client.clone(),
        );

        assert!(service.sample_new_reports().await.unwrap());
        let batches = stat_factory.list_pending_report_batches().await.unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].reports.len(), 2);
        let mut pending_user_ids = batches[0]
            .reports
            .iter()
            .map(|pending| pending.report.user_id.clone())
            .collect::<Vec<_>>();
        pending_user_ids.sort();
        assert_eq!(pending_user_ids, vec!["user-1", "user-2"]);

        assert!(service.flush_pending_reports().await.unwrap());
        assert_eq!(client.batches().len(), 1);
        assert_eq!(client.batches()[0].len(), 1);
        let first_user_id = client.batches()[0][0].user_id.clone();
        assert!(first_user_id == "user-1" || first_user_id == "user-2");
        let batches = stat_factory.list_pending_report_batches().await.unwrap();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].reports.len(), 1);
        assert_ne!(batches[0].reports[0].report.user_id, first_user_id);

        assert!(!service.flush_pending_reports().await.unwrap());
        assert_eq!(client.batches().len(), 2);
        let mut reported_user_ids = client
            .batches()
            .into_iter()
            .map(|batch| batch[0].user_id.clone())
            .collect::<Vec<_>>();
        reported_user_ids.sort();
        assert_eq!(reported_user_ids, vec!["user-1", "user-2"]);
    }

    #[tokio::test]
    async fn sample_does_not_throttle_unknown_balance_users() {
        let config = TrafficConfig {
            enabled: true,
            node_id: "node-1".to_owned(),
            unknown_balance_policy: UnknownBalancePolicy::Throttle,
            ..TrafficConfig::default()
        };
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let stat_manager = StatManager::with_stat_factory(stat_factory.clone());
        let stat_id = format!("{}{}", config.stat_prefix, "user-1");
        let stat = stat_manager.get_speed_stats(std::slice::from_ref(&stat_id))[0].clone();
        stat.add_write_data_size(100);

        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let client = Arc::new(MockTrafficCreditClient::default());
        let service = TrafficQuotaService::new(
            config,
            stat_manager,
            stat_factory.clone(),
            limiter_manager,
            client,
        );

        assert!(service.sample_new_reports().await.unwrap());
        let state = stat_factory.load_user_state("user-1").await.unwrap();
        assert_eq!(state.last_balance_bytes, None);
        assert_eq!(state.throttle_state, TrafficThrottleState::Unknown);
    }

    #[tokio::test]
    async fn dirty_user_remains_sampleable_after_pending_report_confirms() {
        let config = TrafficConfig {
            enabled: true,
            node_id: "node-1".to_owned(),
            unknown_balance_policy: UnknownBalancePolicy::Allow,
            ..TrafficConfig::default()
        };
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let stat_manager = StatManager::with_stat_factory(stat_factory.clone());
        let stat_id = format!("{}{}", config.stat_prefix, "user-1");
        let stat = stat_manager.get_speed_stats(std::slice::from_ref(&stat_id))[0].clone();
        stat.add_write_data_size(100);

        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let client = Arc::new(MockTrafficCreditClient::default());
        let service = TrafficQuotaService::new(
            config,
            stat_manager,
            stat_factory.clone(),
            limiter_manager,
            client.clone(),
        );

        assert!(service.sample_new_reports().await.unwrap());
        assert_eq!(stat_factory.list_pending_reports().await.unwrap().len(), 1);

        stat.add_write_data_size(50);
        assert!(service.sample_new_reports().await.unwrap());
        let batches = stat_factory.list_pending_report_batches().await.unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[1].reports.len(), 1);
        assert_eq!(batches[1].reports[0].report.user_id, "user-1");
        assert_eq!(batches[1].reports[0].report.bytes_up, 50);

        assert!(service.flush_pending_reports().await.unwrap());
        assert!(!service.flush_pending_reports().await.unwrap());
        assert!(
            stat_factory
                .list_pending_reports()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn duplicate_report_confirms_without_updating_balance_or_throttle() {
        let config = TrafficConfig {
            enabled: true,
            node_id: "node-1".to_owned(),
            unknown_balance_policy: UnknownBalancePolicy::Allow,
            ..TrafficConfig::default()
        };
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let stat_manager = StatManager::with_stat_factory(stat_factory.clone());
        let user_id = "user-1";
        let stat_id = format!("{}{}", config.stat_prefix, user_id);
        let stat = stat_manager.get_speed_stats(std::slice::from_ref(&stat_id))[0].clone();
        stat.add_write_data_size(100);

        stat_factory
            .update_balance(user_id, 1024, TrafficThrottleState::Normal)
            .await
            .unwrap();

        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let client = Arc::new(DuplicateTrafficCreditClient);
        let service = TrafficQuotaService::new(
            config,
            stat_manager,
            stat_factory.clone(),
            limiter_manager,
            client,
        );

        service.report_tick().await.unwrap();

        let state = stat_factory.load_user_state(user_id).await.unwrap();
        assert_eq!(state.last_balance_bytes, Some(1024));
        assert_eq!(state.throttle_state, TrafficThrottleState::Normal);
        assert!(
            stat_factory
                .list_pending_reports()
                .await
                .unwrap()
                .is_empty()
        );
        let traffic_stat = stat_factory.tracker(&stat_id).unwrap();
        assert_eq!(
            traffic_stat.latest_reported_totals(),
            crate::TrafficReportedTotals {
                write_sum: 100,
                read_sum: 0
            }
        );
    }

    #[tokio::test]
    async fn start_http_reports_stats_to_mock_credit_server() {
        let mock_server = MockTrafficReportServer::start().await.unwrap();
        let config = TrafficConfig {
            enabled: true,
            node_id: "node-1".to_owned(),
            credit_base_url: mock_server.base_url(),
            credit_hmac_secret: "test-secret".to_owned(),
            report_interval_sec: 1,
            unknown_balance_policy: UnknownBalancePolicy::Allow,
            ..TrafficConfig::default()
        };
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let stat_manager = StatManager::with_stat_factory(stat_factory.clone());
        let user_id = "user-1";
        let stat_id = format!("{}{}", config.stat_prefix, user_id);
        let stat = stat_manager.get_speed_stats(std::slice::from_ref(&stat_id))[0].clone();
        stat.add_write_data_size(120);
        stat.add_read_data_size(34);

        let mut limiter_manager = DefaultLimiterManager::new();
        limiter_manager.new_limiter(
            format!("{}{}", config.limiter_prefix, user_id),
            None,
            None,
            None,
            None,
        );
        let limiter_manager = Arc::new(limiter_manager);
        let service = TrafficQuotaService::start_http(
            config,
            stat_manager,
            stat_factory.clone(),
            limiter_manager,
        )
        .await
        .unwrap()
        .expect("traffic service should start when enabled");

        wait_for_mock_usage_request_count(&mock_server, 1, Duration::from_secs(3)).await;
        service.stop().await;

        assert!(mock_server.balance_requests().is_empty());
        let usage_requests = mock_server.usage_requests();
        assert_eq!(usage_requests.len(), 1);
        assert_eq!(usage_requests[0].len(), 1);
        let report = &usage_requests[0][0];
        assert_eq!(report.node_id, "node-1");
        assert_eq!(report.user_id, user_id);
        assert_eq!(report.bytes_up, 120);
        assert_eq!(report.bytes_down, 34);

        let traffic_stat = stat_factory.tracker(&stat_id).unwrap();
        assert_eq!(
            traffic_stat.latest_reported_totals(),
            crate::TrafficReportedTotals {
                write_sum: 120,
                read_sum: 34
            }
        );
        assert!(
            stat_factory
                .list_pending_reports()
                .await
                .unwrap()
                .is_empty()
        );
        let user_state = stat_factory.load_user_state(user_id).await.unwrap();
        assert_eq!(user_state.last_balance_bytes, Some(768));
        assert_eq!(user_state.throttle_state, TrafficThrottleState::Normal);

        mock_server.shutdown().await;
    }

    #[tokio::test]
    async fn start_http_throttles_limiter_after_credit_is_exhausted() {
        let mock_server = MockTrafficReportServer::start_with_balances(2048, 0)
            .await
            .unwrap();
        let config = TrafficConfig {
            enabled: true,
            node_id: "node-1".to_owned(),
            credit_base_url: mock_server.base_url(),
            credit_hmac_secret: "test-secret".to_owned(),
            report_interval_sec: 1,
            throttled_download_speed: 256,
            throttled_upload_speed: 128,
            unknown_balance_policy: UnknownBalancePolicy::Allow,
            ..TrafficConfig::default()
        };
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let stat_manager = StatManager::with_stat_factory(stat_factory.clone());
        let user_id = "user-1";
        let stat_id = format!("{}{}", config.stat_prefix, user_id);
        let stat = stat_manager.get_speed_stats(std::slice::from_ref(&stat_id))[0].clone();
        stat.add_write_data_size(512);
        stat.add_read_data_size(256);

        let mut limiter_manager = DefaultLimiterManager::new();
        let limiter = limiter_manager.new_limiter(
            format!("{}{}", config.limiter_prefix, user_id),
            None,
            None,
            None,
            None,
        );
        let (mut read_session, mut write_session) = limiter.new_limit_session();
        assert_eq!(read_session.until_ready().await, 64 * 1024);
        assert_eq!(write_session.until_ready().await, 64 * 1024);

        let limiter_manager = Arc::new(limiter_manager);
        let service = TrafficQuotaService::start_http(
            config,
            stat_manager,
            stat_factory.clone(),
            limiter_manager,
        )
        .await
        .unwrap()
        .expect("traffic service should start when enabled");

        wait_for_mock_usage_request_count(&mock_server, 1, Duration::from_secs(3)).await;
        wait_for_user_state(
            &stat_factory,
            user_id,
            Some(0),
            TrafficThrottleState::Throttled,
            Duration::from_secs(3),
        )
        .await;
        service.stop().await;

        let (mut read_session, mut write_session) = limiter.new_limit_session();
        assert_eq!(read_session.until_ready().await, 1);
        assert_eq!(write_session.until_ready().await, 1);

        mock_server.shutdown().await;
    }

    #[tokio::test]
    async fn sampler_continues_while_flush_is_waiting_on_network() {
        let config = TrafficConfig {
            enabled: true,
            node_id: "node-1".to_owned(),
            report_interval_sec: 1,
            unknown_balance_policy: UnknownBalancePolicy::Allow,
            ..TrafficConfig::default()
        };
        let stat_prefix = config.stat_prefix.clone();
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let stat_manager = StatManager::with_stat_factory(stat_factory.clone());
        let user_1_stat_id = format!("{stat_prefix}{}", "user-1");
        let user_1_stat =
            stat_manager.get_speed_stats(std::slice::from_ref(&user_1_stat_id))[0].clone();
        user_1_stat.add_write_data_size(100);

        let limiter_manager = Arc::new(DefaultLimiterManager::new());
        let (release_tx, release_rx) = oneshot::channel();
        let client = Arc::new(BlockingTrafficCreditClient::new(release_rx));
        let service = TrafficQuotaService::new(
            config,
            stat_manager.clone(),
            stat_factory.clone(),
            limiter_manager,
            client.clone(),
        )
        .start();

        tokio::time::timeout(
            Duration::from_secs(2),
            client.first_batch_started.notified(),
        )
        .await
        .expect("first pending batch should enter the network call");

        let user_2_stat_id = format!("{stat_prefix}{}", "user-2");
        let user_2_stat =
            stat_manager.get_speed_stats(std::slice::from_ref(&user_2_stat_id))[0].clone();
        user_2_stat.add_write_data_size(50);

        wait_for_pending_user(&stat_factory, "user-2", Duration::from_secs(3)).await;

        let _ = release_tx.send(());
        service.stop().await;
    }

    async fn wait_for_pending_user(
        stat_factory: &TrafficStatFactoryRef,
        user_id: &str,
        timeout: Duration,
    ) {
        let deadline = Instant::now() + timeout;
        loop {
            let pending_users = stat_factory.pending_users().await.unwrap();
            if pending_users.iter().any(|pending| pending == user_id) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "pending report for {user_id} was not sampled in time; pending users: {pending_users:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn wait_for_mock_usage_request_count(
        server: &MockTrafficReportServer,
        expected_count: usize,
        timeout: Duration,
    ) {
        let deadline = Instant::now() + timeout;
        loop {
            let requests = server.usage_requests();
            if requests.len() >= expected_count {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "usage request count did not reach {expected_count} in time; requests: {requests:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    async fn wait_for_user_state(
        stat_factory: &TrafficStatFactoryRef,
        user_id: &str,
        balance: Option<i64>,
        throttle_state: TrafficThrottleState,
        timeout: Duration,
    ) {
        let deadline = Instant::now() + timeout;
        loop {
            let state = stat_factory.load_user_state(user_id).await.unwrap();
            if state.last_balance_bytes == balance && state.throttle_state == throttle_state {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "user state did not reach expected balance/state in time: {state:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

fn make_report_id(
    node_id: &str,
    user_id: &str,
    period_start: &str,
    period_end: &str,
    write_sum: u64,
    read_sum: u64,
) -> String {
    let raw = format!("{node_id}:{user_id}:{period_start}:{period_end}:{write_sum}:{read_sum}");
    if raw.len() <= 128 {
        raw
    } else {
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        format!("traffic:{}", hex::encode(&hasher.finalize()[..16]))
    }
}
