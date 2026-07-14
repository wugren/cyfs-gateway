use crate::{
    PendingTrafficCheckpoint, PendingTrafficReport, PendingTrafficReportBatch, TrafficThrottleState,
};
use anyhow::Result;
use cyfs_gateway_lib::{SpeedTrackerRef, StatFactory};
use sfo_io::{SpeedStat, SpeedTracker};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TrafficReportedTotals {
    pub write_sum: u64,
    pub read_sum: u64,
}

#[derive(Debug, Clone)]
pub struct TrafficPeriodUsage {
    pub user_state: TrafficUserState,
    pub period_start: String,
    pub current_write_sum: u64,
    pub current_read_sum: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

#[derive(Debug, Clone)]
pub struct TrafficUserState {
    pub user_id: String,
    pub last_balance_bytes: Option<i64>,
    pub throttle_state: TrafficThrottleState,
    pub last_period_end: Option<String>,
}

impl TrafficUserState {
    fn new(user_id: impl Into<String>) -> Self {
        Self {
            user_id: user_id.into(),
            last_balance_bytes: None,
            throttle_state: TrafficThrottleState::Unknown,
            last_period_end: None,
        }
    }
}

#[derive(Debug, Clone)]
struct PendingReportBatchEntry {
    batch: PendingTrafficReportBatch,
}

pub struct TrafficSpeedTracker {
    user_id: String,
    dirty_users: Arc<Mutex<HashSet<String>>>,
    write_sum: AtomicU64,
    read_sum: AtomicU64,
    sampled_checkpoint: Mutex<Option<PendingTrafficCheckpoint>>,
    reported_write_sum: AtomicU64,
    reported_read_sum: AtomicU64,
    user_state: Mutex<TrafficUserState>,
}

pub type TrafficSpeedTrackerRef = Arc<TrafficSpeedTracker>;

impl TrafficSpeedTracker {
    pub fn new() -> Self {
        Self::new_for_user_with_dirty_users("", Arc::new(Mutex::new(HashSet::new())))
    }

    fn new_for_user_with_dirty_users(
        user_id: impl Into<String>,
        dirty_users: Arc<Mutex<HashSet<String>>>,
    ) -> Self {
        let user_id = user_id.into();
        Self {
            user_id: user_id.clone(),
            dirty_users,
            write_sum: AtomicU64::new(0),
            read_sum: AtomicU64::new(0),
            sampled_checkpoint: Mutex::new(None),
            reported_write_sum: AtomicU64::new(0),
            reported_read_sum: AtomicU64::new(0),
            user_state: Mutex::new(TrafficUserState::new(user_id)),
        }
    }

    fn mark_dirty(&self) {
        if !self.user_id.is_empty() {
            self.dirty_users
                .lock()
                .unwrap()
                .insert(self.user_id.clone());
        }
    }

    pub fn latest_reported_totals(&self) -> TrafficReportedTotals {
        TrafficReportedTotals {
            write_sum: self.reported_write_sum.load(Ordering::Relaxed),
            read_sum: self.reported_read_sum.load(Ordering::Relaxed),
        }
    }

    pub fn mark_reported(&self, write_sum: u64, read_sum: u64) {
        self.reported_write_sum
            .fetch_max(write_sum, Ordering::Relaxed);
        self.reported_read_sum
            .fetch_max(read_sum, Ordering::Relaxed);
    }

    pub async fn sample_current_period_usage(
        &self,
        fallback_period_start: String,
        period_end: String,
    ) -> Option<TrafficPeriodUsage> {
        let current_write_sum = self.get_write_sum_size();
        let current_read_sum = self.get_read_sum_size();
        let (sampled_period_start, bytes_up, bytes_down) = {
            let mut sampled_checkpoint = self.sampled_checkpoint.lock().unwrap();
            let base_write_sum = sampled_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.target_write_sum)
                .unwrap_or(0);
            let base_read_sum = sampled_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.target_read_sum)
                .unwrap_or(0);
            let bytes_up = current_write_sum.saturating_sub(base_write_sum);
            let bytes_down = current_read_sum.saturating_sub(base_read_sum);
            if bytes_up.saturating_add(bytes_down) == 0 {
                return None;
            }
            let sampled_period_start = sampled_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.period_end.clone());
            *sampled_checkpoint = Some(PendingTrafficCheckpoint {
                target_write_sum: current_write_sum,
                target_read_sum: current_read_sum,
                period_end,
            });
            (sampled_period_start, bytes_up, bytes_down)
        };

        let user_state = self.user_state().await;
        let period_start = sampled_period_start
            .or_else(|| user_state.last_period_end.clone())
            .unwrap_or(fallback_period_start);

        Some(TrafficPeriodUsage {
            user_state,
            period_start,
            current_write_sum,
            current_read_sum,
            bytes_up,
            bytes_down,
        })
    }

    pub async fn user_state(&self) -> TrafficUserState {
        self.user_state.lock().unwrap().clone()
    }

    pub async fn mark_report_confirmed(
        &self,
        balance: Option<i64>,
        throttle_state: TrafficThrottleState,
        period_end: String,
    ) {
        let mut state = self.user_state.lock().unwrap();
        state.last_balance_bytes = balance.or(state.last_balance_bytes);
        state.throttle_state = throttle_state;
        state.last_period_end = Some(period_end);
    }

    pub async fn mark_report_duplicate(&self, period_end: String) {
        self.user_state.lock().unwrap().last_period_end = Some(period_end);
    }

    pub async fn update_balance(&self, balance: i64, throttle_state: TrafficThrottleState) {
        let mut state = self.user_state.lock().unwrap();
        state.last_balance_bytes = Some(balance);
        state.throttle_state = throttle_state;
    }

    pub async fn update_throttle_state(&self, throttle_state: TrafficThrottleState) {
        self.user_state.lock().unwrap().throttle_state = throttle_state;
    }
}

impl Default for TrafficSpeedTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SpeedStat for TrafficSpeedTracker {
    fn get_write_speed(&self) -> u64 {
        0
    }

    fn get_write_sum_size(&self) -> u64 {
        self.write_sum.load(Ordering::Relaxed)
    }

    fn get_read_speed(&self) -> u64 {
        0
    }

    fn get_read_sum_size(&self) -> u64 {
        self.read_sum.load(Ordering::Relaxed)
    }
}

impl SpeedTracker for TrafficSpeedTracker {
    fn add_write_data_size(&self, size: u64) {
        self.write_sum.fetch_add(size, Ordering::Relaxed);
        if size > 0 {
            self.mark_dirty();
        }
    }

    fn add_read_data_size(&self, size: u64) {
        self.read_sum.fetch_add(size, Ordering::Relaxed);
        if size > 0 {
            self.mark_dirty();
        }
    }
}

pub struct TrafficStatFactory {
    stat_prefix: String,
    trackers: Mutex<HashMap<String, TrafficSpeedTrackerRef>>,
    dirty_users: Arc<Mutex<HashSet<String>>>,
    pending_batches: Mutex<VecDeque<PendingReportBatchEntry>>,
}

pub type TrafficStatFactoryRef = Arc<TrafficStatFactory>;

impl TrafficStatFactory {
    pub fn new(stat_prefix: impl Into<String>) -> TrafficStatFactoryRef {
        Arc::new(Self {
            stat_prefix: stat_prefix.into(),
            trackers: Mutex::new(HashMap::new()),
            dirty_users: Arc::new(Mutex::new(HashSet::new())),
            pending_batches: Mutex::new(VecDeque::new()),
        })
    }

    pub fn tracker(&self, id: &str) -> Option<TrafficSpeedTrackerRef> {
        self.trackers.lock().unwrap().get(id).cloned()
    }

    pub async fn list_throttled_users(&self) -> Result<Vec<String>> {
        let trackers = self.tracker_refs();
        let mut users = Vec::new();
        for tracker in trackers {
            let state = tracker.user_state().await;
            if state.throttle_state == TrafficThrottleState::Throttled {
                users.push(state.user_id);
            }
        }
        users.sort();
        users.dedup();
        Ok(users)
    }

    pub async fn load_user_state(&self, user_id: &str) -> Result<TrafficUserState> {
        Ok(self.tracker_for_user(user_id).user_state().await)
    }

    pub async fn save_pending_report(&self, pending: &PendingTrafficReport) -> Result<()> {
        self.save_pending_report_batch(vec![pending.clone()]).await
    }

    pub async fn save_pending_report_batch(
        &self,
        reports: Vec<PendingTrafficReport>,
    ) -> Result<()> {
        if reports.is_empty() {
            return Ok(());
        }
        self.pending_batches
            .lock()
            .unwrap()
            .push_back(PendingReportBatchEntry {
                batch: PendingTrafficReportBatch { reports },
            });
        Ok(())
    }

    pub async fn pending_users(&self) -> Result<Vec<String>> {
        Ok(self
            .pending_batches
            .lock()
            .unwrap()
            .iter()
            .flat_map(|entry| {
                entry
                    .batch
                    .reports
                    .iter()
                    .map(|pending| pending.report.user_id.clone())
            })
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect())
    }

    pub async fn latest_pending_checkpoint(
        &self,
        user_id: &str,
    ) -> Result<Option<PendingTrafficCheckpoint>> {
        let pending_batches = self.pending_batches.lock().unwrap();
        Ok(pending_batches.iter().rev().find_map(|entry| {
            entry
                .batch
                .reports
                .iter()
                .rev()
                .find(|pending| pending.report.user_id == user_id)
                .map(|pending| PendingTrafficCheckpoint {
                    target_write_sum: pending.target_write_sum,
                    target_read_sum: pending.target_read_sum,
                    period_end: pending.report.period_end.clone(),
                })
        }))
    }

    pub fn dirty_users_snapshot(&self) -> Vec<String> {
        self.dirty_users.lock().unwrap().drain().collect()
    }

    pub async fn list_pending_reports(&self) -> Result<Vec<PendingTrafficReport>> {
        Ok(self
            .pending_batches
            .lock()
            .unwrap()
            .iter()
            .flat_map(|entry| entry.batch.reports.clone())
            .collect())
    }

    pub async fn list_pending_report_batches(&self) -> Result<Vec<PendingTrafficReportBatch>> {
        Ok(self
            .pending_batches
            .lock()
            .unwrap()
            .iter()
            .map(|entry| entry.batch.clone())
            .collect())
    }

    pub async fn next_pending_report_batch(&self) -> Result<Option<PendingTrafficReportBatch>> {
        Ok(self
            .pending_batches
            .lock()
            .unwrap()
            .front()
            .map(|entry| entry.batch.clone()))
    }

    pub async fn mark_report_confirmed(
        &self,
        report_id: &str,
        balance: Option<i64>,
        throttle_state: TrafficThrottleState,
    ) -> Result<()> {
        let pending = self.take_pending_report(report_id);
        if let Some(pending) = pending {
            self.tracker_for_user(&pending.report.user_id)
                .mark_report_confirmed(balance, throttle_state, pending.report.period_end)
                .await;
        }
        Ok(())
    }

    pub async fn mark_report_duplicate(&self, report_id: &str) -> Result<()> {
        let pending = self.take_pending_report(report_id);
        if let Some(pending) = pending {
            self.tracker_for_user(&pending.report.user_id)
                .mark_report_duplicate(pending.report.period_end)
                .await;
        }
        Ok(())
    }

    pub async fn update_balance(
        &self,
        user_id: &str,
        balance: i64,
        throttle_state: TrafficThrottleState,
    ) -> Result<()> {
        self.tracker_for_user(user_id)
            .update_balance(balance, throttle_state)
            .await;
        Ok(())
    }

    pub async fn update_throttle_state(
        &self,
        user_id: &str,
        throttle_state: TrafficThrottleState,
    ) -> Result<()> {
        self.tracker_for_user(user_id)
            .update_throttle_state(throttle_state)
            .await;
        Ok(())
    }

    pub async fn record_report_error(&self, _report_id: &str, _error: &str) -> Result<()> {
        Ok(())
    }

    fn accepts(&self, id: &str) -> bool {
        id.strip_prefix(self.stat_prefix.as_str())
            .map(|user_id| !user_id.is_empty())
            .unwrap_or(false)
    }

    fn tracker_for_user(&self, user_id: &str) -> TrafficSpeedTrackerRef {
        let stat_id = format!("{}{}", self.stat_prefix, user_id);
        let mut trackers = self.trackers.lock().unwrap();
        trackers
            .entry(stat_id)
            .or_insert_with(|| {
                Arc::new(TrafficSpeedTracker::new_for_user_with_dirty_users(
                    user_id,
                    self.dirty_users.clone(),
                ))
            })
            .clone()
    }

    fn tracker_refs(&self) -> Vec<TrafficSpeedTrackerRef> {
        self.trackers.lock().unwrap().values().cloned().collect()
    }

    fn take_pending_report(&self, report_id: &str) -> Option<PendingTrafficReport> {
        let mut pending_batches = self.pending_batches.lock().unwrap();
        let pending = pending_batches.iter_mut().find_map(|entry| {
            entry
                .batch
                .reports
                .iter()
                .position(|pending| pending.report.report_id == report_id)
                .map(|index| entry.batch.reports.remove(index))
        });
        while pending_batches
            .front()
            .map(|entry| entry.batch.reports.is_empty())
            .unwrap_or(false)
        {
            pending_batches.pop_front();
        }
        pending
    }

    fn user_id_from_stat_id(&self, id: &str) -> Option<String> {
        id.strip_prefix(self.stat_prefix.as_str())
            .map(|user_id| user_id.to_owned())
            .filter(|user_id| !user_id.is_empty())
    }
}

impl StatFactory for TrafficStatFactory {
    fn create_speed_stat(&self, id: &str) -> Option<SpeedTrackerRef> {
        if !self.accepts(id) {
            return None;
        }

        let mut trackers = self.trackers.lock().unwrap();
        let tracker = trackers
            .entry(id.to_owned())
            .or_insert_with(|| {
                Arc::new(TrafficSpeedTracker::new_for_user_with_dirty_users(
                    self.user_id_from_stat_id(id).unwrap_or_default(),
                    self.dirty_users.clone(),
                ))
            })
            .clone();
        Some(tracker)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factory_only_creates_traffic_prefixed_trackers() {
        let factory = TrafficStatFactory::new("traffic:user:");

        assert!(factory.create_speed_stat("plain").is_none());
        assert!(factory.create_speed_stat("traffic:user:").is_none());

        let tracker = factory.create_speed_stat("traffic:user:alice").unwrap();
        tracker.add_write_data_size(64);
        tracker.add_read_data_size(32);

        let traffic_tracker = factory.tracker("traffic:user:alice").unwrap();
        assert_eq!(traffic_tracker.get_write_sum_size(), 64);
        assert_eq!(traffic_tracker.get_read_sum_size(), 32);
        assert_eq!(
            traffic_tracker.latest_reported_totals(),
            TrafficReportedTotals {
                write_sum: 0,
                read_sum: 0
            }
        );
    }

    #[test]
    fn factory_drains_dirty_users_on_snapshot() {
        let factory = TrafficStatFactory::new("traffic:user:");
        let tracker = factory.create_speed_stat("traffic:user:alice").unwrap();

        assert!(factory.dirty_users_snapshot().is_empty());

        tracker.add_write_data_size(64);
        tracker.add_read_data_size(32);
        tracker.add_write_data_size(0);

        assert_eq!(factory.dirty_users_snapshot(), vec!["alice"]);
        assert!(factory.dirty_users_snapshot().is_empty());
    }

    #[test]
    fn tracker_can_mark_user_dirty_after_snapshot_drains() {
        let factory = TrafficStatFactory::new("traffic:user:");
        let tracker = factory.create_speed_stat("traffic:user:alice").unwrap();
        tracker.add_write_data_size(64);
        tracker.add_read_data_size(32);

        assert_eq!(factory.dirty_users_snapshot(), vec!["alice"]);
        assert!(factory.dirty_users_snapshot().is_empty());

        tracker.add_read_data_size(1);

        assert_eq!(factory.dirty_users_snapshot(), vec!["alice"]);
    }

    #[test]
    fn tracker_keeps_reported_totals_separate_from_stat_totals() {
        let tracker = TrafficSpeedTracker::new();
        tracker.add_write_data_size(100);
        tracker.add_read_data_size(40);
        tracker.mark_reported(70, 20);

        assert_eq!(tracker.get_write_sum_size(), 100);
        assert_eq!(tracker.get_read_sum_size(), 40);
        assert_eq!(
            tracker.latest_reported_totals(),
            TrafficReportedTotals {
                write_sum: 70,
                read_sum: 20
            }
        );

        tracker.mark_reported(60, 10);
        assert_eq!(
            tracker.latest_reported_totals(),
            TrafficReportedTotals {
                write_sum: 70,
                read_sum: 20
            }
        );
    }

    #[tokio::test]
    async fn tracker_returns_current_period_usage() {
        let tracker = TrafficSpeedTracker::new();
        tracker.add_write_data_size(100);
        tracker.add_read_data_size(40);

        let usage = tracker
            .sample_current_period_usage(
                "2026-06-26T00:00:00Z".to_owned(),
                "2026-06-26T00:01:00Z".to_owned(),
            )
            .await
            .unwrap();

        assert_eq!(usage.period_start, "2026-06-26T00:00:00Z");
        assert_eq!(usage.current_write_sum, 100);
        assert_eq!(usage.current_read_sum, 40);
        assert_eq!(usage.bytes_up, 100);
        assert_eq!(usage.bytes_down, 40);

        tracker.add_write_data_size(5);
        tracker.add_read_data_size(3);
        let usage = tracker
            .sample_current_period_usage(
                "2026-06-26T00:01:00Z".to_owned(),
                "2026-06-26T00:02:00Z".to_owned(),
            )
            .await
            .unwrap();

        assert_eq!(usage.period_start, "2026-06-26T00:01:00Z");
        assert_eq!(usage.current_write_sum, 105);
        assert_eq!(usage.current_read_sum, 43);
        assert_eq!(usage.bytes_up, 5);
        assert_eq!(usage.bytes_down, 3);

        tracker.mark_reported(100, 40);
        assert!(
            tracker
                .sample_current_period_usage(
                    "2026-06-26T00:02:00Z".to_owned(),
                    "2026-06-26T00:03:00Z".to_owned(),
                )
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn tracker_samples_from_previous_sample_not_reported_totals() {
        let tracker = TrafficSpeedTracker::new();
        tracker.add_write_data_size(100);
        tracker.add_read_data_size(40);
        tracker.mark_reported(70, 20);

        let usage = tracker
            .sample_current_period_usage(
                "2026-06-26T00:00:00Z".to_owned(),
                "2026-06-26T00:01:00Z".to_owned(),
            )
            .await
            .unwrap();

        assert_eq!(usage.current_write_sum, 100);
        assert_eq!(usage.current_read_sum, 40);
        assert_eq!(usage.bytes_up, 100);
        assert_eq!(usage.bytes_down, 40);

        tracker.mark_reported(100, 40);
        tracker.add_write_data_size(5);
        tracker.add_read_data_size(3);

        let usage = tracker
            .sample_current_period_usage(
                "2026-06-26T00:01:00Z".to_owned(),
                "2026-06-26T00:02:00Z".to_owned(),
            )
            .await
            .unwrap();

        assert_eq!(usage.current_write_sum, 105);
        assert_eq!(usage.current_read_sum, 43);
        assert_eq!(usage.bytes_up, 5);
        assert_eq!(usage.bytes_down, 3);
    }

    #[tokio::test]
    async fn factory_keeps_pending_reports_and_user_state_without_store() {
        let factory = TrafficStatFactory::new("traffic:user:");
        let pending = PendingTrafficReport {
            report: crate::TrafficUsageReport {
                report_id: "report-1".to_owned(),
                node_id: "node-1".to_owned(),
                user_id: "alice".to_owned(),
                period_start: "2026-06-26T00:00:00Z".to_owned(),
                period_end: "2026-06-26T00:01:00Z".to_owned(),
                bytes_up: 10,
                bytes_down: 20,
                trace_ref: None,
            },
            target_write_sum: 100,
            target_read_sum: 200,
        };

        factory.save_pending_report(&pending).await.unwrap();
        assert_eq!(factory.pending_users().await.unwrap(), vec!["alice"]);
        assert_eq!(
            factory.list_pending_reports().await.unwrap(),
            vec![pending.clone()]
        );
        assert_eq!(
            factory.list_pending_report_batches().await.unwrap(),
            vec![crate::PendingTrafficReportBatch {
                reports: vec![pending.clone()]
            }]
        );
        assert_eq!(
            factory.latest_pending_checkpoint("alice").await.unwrap(),
            Some(crate::PendingTrafficCheckpoint {
                target_write_sum: 100,
                target_read_sum: 200,
                period_end: "2026-06-26T00:01:00Z".to_owned(),
            })
        );

        factory
            .mark_report_confirmed("report-1", Some(512), TrafficThrottleState::Normal)
            .await
            .unwrap();

        assert!(factory.list_pending_reports().await.unwrap().is_empty());
        let state = factory.load_user_state("alice").await.unwrap();
        assert_eq!(state.last_balance_bytes, Some(512));
        assert_eq!(state.throttle_state, TrafficThrottleState::Normal);
        assert_eq!(
            state.last_period_end.as_deref(),
            Some("2026-06-26T00:01:00Z")
        );
    }
}
