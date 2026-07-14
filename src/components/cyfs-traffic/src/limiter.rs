use crate::TrafficConfig;
use crate::{HttpTrafficCreditClient, TrafficCreditClient, TrafficStatFactoryRef};
use anyhow::Result;
use cyfs_gateway_lib::{Limiter, LimiterFactory, LimiterManagerRef};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TrafficThrottleState {
    Unknown,
    Normal,
    Throttled,
}

pub struct TrafficUserLimiterFactory<C>
where
    C: TrafficCreditClient + 'static,
{
    config: TrafficConfig,
    stat_factory: TrafficStatFactoryRef,
    client: Arc<C>,
    limiters: Mutex<HashMap<String, Limiter>>,
}

impl TrafficUserLimiterFactory<HttpTrafficCreditClient> {
    pub fn new_http(config: TrafficConfig, stat_factory: TrafficStatFactoryRef) -> Result<Self> {
        let client = HttpTrafficCreditClient::new(
            &config.credit_base_url,
            "cyfs-gateway",
            config.credit_hmac_secret.clone(),
        )?;
        Ok(Self::new(config, stat_factory, Arc::new(client)))
    }
}

impl<C> TrafficUserLimiterFactory<C>
where
    C: TrafficCreditClient + 'static,
{
    pub fn new(config: TrafficConfig, stat_factory: TrafficStatFactoryRef, client: Arc<C>) -> Self {
        Self {
            config,
            stat_factory,
            client,
            limiters: Mutex::new(HashMap::new()),
        }
    }

    fn user_id_from_limiter_id(&self, limiter_id: &str) -> Option<String> {
        limiter_id
            .strip_prefix(self.config.limiter_prefix.as_str())
            .map(|user_id| user_id.to_owned())
            .filter(|user_id| !user_id.is_empty())
    }

    fn refresh_initial_balance(&self, user_id: String, limiter: Limiter) {
        let log_user_id = user_id.clone();
        let config = self.config.clone();
        let stat_factory = self.stat_factory.clone();
        let client = self.client.clone();
        let task = async move {
            match client.get_balance(&user_id).await {
                Ok(balance) => {
                    let throttle_state =
                        apply_balance_to_limiter(&limiter, &config, balance.traffic_balance_bytes);
                    if let Err(error) = stat_factory
                        .update_balance(&user_id, balance.traffic_balance_bytes, throttle_state)
                        .await
                    {
                        log::warn!(
                            "traffic limiter balance state update failed for {user_id}: {error:#}"
                        );
                    }
                }
                Err(error) => {
                    log::warn!("traffic limiter balance refresh failed for {user_id}: {error:#}");
                }
            }
        };

        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(task);
            }
            Err(error) => {
                log::warn!(
                    "traffic limiter balance refresh cannot start for {log_user_id}: {error}"
                );
            }
        }
    }
}

impl<C> LimiterFactory for TrafficUserLimiterFactory<C>
where
    C: TrafficCreditClient + 'static,
{
    fn create_limiter(&self, id: &str) -> Option<Limiter> {
        let user_id = self.user_id_from_limiter_id(id)?;
        let (limiter, created) = {
            let mut limiters = self.limiters.lock().unwrap();
            if let Some(limiter) = limiters.get(id) {
                (limiter.clone(), false)
            } else {
                let limiter = Limiter::new(None, None, None, None);
                limiters.insert(id.to_owned(), limiter.clone());
                (limiter, true)
            }
        };

        if created {
            self.refresh_initial_balance(user_id, limiter.clone());
        }

        Some(limiter)
    }
}

fn apply_balance_to_limiter(
    limiter: &Limiter,
    config: &TrafficConfig,
    balance_bytes: i64,
) -> TrafficThrottleState {
    let state = if balance_bytes > 0 {
        TrafficThrottleState::Normal
    } else {
        TrafficThrottleState::Throttled
    };
    apply_throttle_state_to_limiter(limiter, config, state);
    state
}

pub(crate) fn apply_balance_to_user_limiter(
    config: &TrafficConfig,
    limiter_manager: &LimiterManagerRef,
    user_id: &str,
    balance_bytes: i64,
) -> TrafficThrottleState {
    let state = if balance_bytes > 0 {
        TrafficThrottleState::Normal
    } else {
        TrafficThrottleState::Throttled
    };
    let limiter_id = format!("{}{}", config.limiter_prefix, user_id);
    let Some(limiter) = limiter_manager.get_limiter(limiter_id) else {
        log::debug!("traffic limiter not found for user {user_id}");
        return state;
    };
    apply_throttle_state_to_limiter(&limiter, config, state);
    state
}

fn apply_throttle_state_to_limiter(
    limiter: &Limiter,
    config: &TrafficConfig,
    state: TrafficThrottleState,
) {
    match state {
        TrafficThrottleState::Unknown => {}
        TrafficThrottleState::Normal => limiter.set_speed(None, None, None),
        TrafficThrottleState::Throttled => limiter.set_speed(
            Some(10),
            Some(speed_to_u32(config.throttled_download_speed)),
            Some(speed_to_u32(config.throttled_upload_speed)),
        ),
    }
}

fn speed_to_u32(speed: u64) -> u32 {
    speed.min(u32::MAX as u64) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        TrafficBalanceResponse, TrafficStatFactory, TrafficUsageReport, TrafficUsageReportsResponse,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    struct ZeroBalanceClient {
        balance_requests: Mutex<Vec<String>>,
        fail_balance: bool,
    }

    impl ZeroBalanceClient {
        fn new() -> Self {
            Self {
                balance_requests: Mutex::new(Vec::new()),
                fail_balance: false,
            }
        }

        fn balance_requests(&self) -> Vec<String> {
            self.balance_requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl TrafficCreditClient for ZeroBalanceClient {
        async fn report_usage_batch(
            &self,
            _reports: Vec<TrafficUsageReport>,
        ) -> Result<TrafficUsageReportsResponse> {
            unreachable!("limiter factory does not report usage")
        }

        async fn get_balance(&self, user_id: &str) -> Result<TrafficBalanceResponse> {
            self.balance_requests
                .lock()
                .unwrap()
                .push(user_id.to_owned());
            if self.fail_balance {
                return Err(anyhow::anyhow!("balance service unavailable"));
            }
            Ok(TrafficBalanceResponse {
                traffic_balance_bytes: 0,
                last_settlement_at: None,
                last_overage_bytes: 0,
            })
        }
    }

    #[tokio::test]
    async fn user_limiter_factory_refreshes_zero_balance_on_create() {
        let config = TrafficConfig {
            enabled: true,
            limiter_prefix: "traffic:user:".to_owned(),
            throttled_download_speed: 1024,
            throttled_upload_speed: 2048,
            ..TrafficConfig::default()
        };
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let client = Arc::new(ZeroBalanceClient::new());
        let factory = TrafficUserLimiterFactory::new(config, stat_factory.clone(), client.clone());

        assert!(factory.create_limiter("plain:user-1").is_none());

        let limiter = factory.create_limiter("traffic:user:user-1");
        assert!(limiter.is_some());
        let same_limiter = factory.create_limiter("traffic:user:user-1");
        assert!(same_limiter.is_some());

        wait_for_user_state(
            &stat_factory,
            "user-1",
            Some(0),
            TrafficThrottleState::Throttled,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(client.balance_requests(), vec!["user-1"]);
    }

    #[tokio::test]
    async fn user_limiter_factory_does_not_throttle_when_balance_refresh_fails() {
        let config = TrafficConfig {
            enabled: true,
            limiter_prefix: "traffic:user:".to_owned(),
            ..TrafficConfig::default()
        };
        let stat_factory = TrafficStatFactory::new(config.stat_prefix.clone());
        let client = Arc::new(ZeroBalanceClient {
            balance_requests: Mutex::new(Vec::new()),
            fail_balance: true,
        });
        let factory = TrafficUserLimiterFactory::new(config, stat_factory.clone(), client.clone());

        assert!(factory.create_limiter("traffic:user:user-1").is_some());

        wait_for_balance_request_count(&client, 1, Duration::from_secs(2)).await;
        let state = stat_factory.load_user_state("user-1").await.unwrap();
        assert_eq!(state.last_balance_bytes, None);
        assert_eq!(state.throttle_state, TrafficThrottleState::Unknown);
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

    async fn wait_for_balance_request_count(
        client: &ZeroBalanceClient,
        expected_count: usize,
        timeout: Duration,
    ) {
        let deadline = Instant::now() + timeout;
        loop {
            let requests = client.balance_requests();
            if requests.len() >= expected_count {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "balance request count did not reach {expected_count} in time; requests: {requests:?}"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}
