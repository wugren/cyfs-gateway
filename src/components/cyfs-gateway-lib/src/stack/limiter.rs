use crate::{StackErrorCode, StackResult, stack_err};
use cyfs_process_chain::*;
use sfo_io::{SpeedLimitSession, SpeedLimiter, SpeedLimiterRef};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;

#[derive(Clone)]
pub struct Limiter {
    id: Option<String>,
    upper_limiter: Option<Box<Limiter>>,
    read_limiter: SpeedLimiterRef,
    write_limiter: SpeedLimiterRef,
}

impl Limiter {
    pub fn new(
        upper: Option<Limiter>,
        concurrent: Option<u32>,
        read_speed: Option<u32>,
        write_speed: Option<u32>,
    ) -> Self {
        let (read_rate, read_weight) = Self::get_limit_info(concurrent, read_speed);
        let (write_rate, write_weight) = Self::get_limit_info(concurrent, write_speed);
        let (upper_read_limiter, upper_write_limiter) = match upper.clone() {
            Some(upper) => (
                Some(upper.read_limiter.clone()),
                Some(upper.write_limiter.clone()),
            ),
            None => (None, None),
        };

        Limiter {
            id: None,
            upper_limiter: upper.map(|v| Box::new(v)),
            read_limiter: SpeedLimiter::new(upper_read_limiter, read_rate, read_weight),
            write_limiter: SpeedLimiter::new(upper_write_limiter, write_rate, write_weight),
        }
    }

    fn new_named(
        id: impl Into<String>,
        upper: Option<Limiter>,
        concurrent: Option<u32>,
        read_speed: Option<u32>,
        write_speed: Option<u32>,
    ) -> Self {
        let (read_rate, read_weight) = Self::get_limit_info(concurrent, read_speed);
        let (write_rate, write_weight) = Self::get_limit_info(concurrent, write_speed);
        let (upper_read_limiter, upper_write_limiter) = match upper.clone() {
            Some(upper) => (
                Some(upper.read_limiter.clone()),
                Some(upper.write_limiter.clone()),
            ),
            None => (None, None),
        };

        Limiter {
            id: Some(id.into()),
            upper_limiter: upper.map(|v| Box::new(v)),
            read_limiter: SpeedLimiter::new(upper_read_limiter, read_rate, read_weight),
            write_limiter: SpeedLimiter::new(upper_write_limiter, write_rate, write_weight),
        }
    }

    pub fn get_id(&self) -> Option<&str> {
        self.id.as_ref().map(|v| v.as_str())
    }

    pub fn get_upper_limiter(&self) -> Option<Limiter> {
        self.upper_limiter.as_ref().map(|v| v.as_ref().clone())
    }

    fn get_limit_info(
        concurrent: Option<u32>,
        speed: Option<u32>,
    ) -> (Option<NonZeroU32>, Option<NonZeroU32>) {
        match speed {
            Some(speed) => {
                let concurrent = concurrent.unwrap_or(1);
                let rate = concurrent * 100;
                if rate > speed {
                    (
                        Some(NonZeroU32::new(speed).unwrap()),
                        Some(NonZeroU32::new(1).unwrap()),
                    )
                } else {
                    if speed % rate > ((rate as f64) * 0.4f64) as u32 {
                        (
                            Some(NonZeroU32::new(rate).unwrap()),
                            Some(NonZeroU32::new(speed / rate + 1).unwrap()),
                        )
                    } else {
                        (
                            Some(NonZeroU32::new(rate).unwrap()),
                            Some(NonZeroU32::new(speed / rate).unwrap()),
                        )
                    }
                }
            }
            None => (None, None),
        }
    }
    pub fn set_speed(
        &self,
        concurrent: Option<u32>,
        read_speed: Option<u32>,
        write_speed: Option<u32>,
    ) {
        let (read_rate, read_weight) = Self::get_limit_info(concurrent, read_speed);
        let (write_rate, write_weight) = Self::get_limit_info(concurrent, write_speed);
        self.read_limiter.set_limit(read_rate, read_weight);
        self.write_limiter.set_limit(write_rate, write_weight);
    }

    pub fn new_limit_session(&self) -> (SpeedLimitSession, SpeedLimitSession) {
        (
            self.read_limiter.new_limit_session(),
            self.write_limiter.new_limit_session(),
        )
    }
}

pub trait LimiterFactory: Send + Sync {
    fn create_limiter(&self, id: &str) -> Option<Limiter>;
}

pub type LimiterFactoryRef = Arc<dyn LimiterFactory>;

pub trait LimiterManager: Send + Sync {
    fn new_limiter(
        &mut self,
        id: String,
        upper: Option<String>,
        concurrent: Option<u32>,
        read_speed: Option<u32>,
        write_speed: Option<u32>,
    ) -> Limiter;
    fn get_limiter(&self, id: String) -> Option<Limiter>;
    fn clone_manager(&self) -> Box<dyn LimiterManager>;
    fn retain(&mut self, f: Box<dyn FnMut(&String, &mut Limiter) -> bool>);
    fn remove_limiter(&mut self, id: String);
    fn set_limiter_factory(&mut self, _factory: Option<LimiterFactoryRef>) {}
}
pub type LimiterManagerRef = Arc<Box<dyn LimiterManager>>;

pub struct DefaultLimiterManager {
    limiters: HashMap<String, Limiter>,
    limiter_factory: Option<LimiterFactoryRef>,
}

impl DefaultLimiterManager {
    pub fn new() -> Box<dyn LimiterManager> {
        Box::new(Self {
            limiters: HashMap::new(),
            limiter_factory: None,
        })
    }

    pub fn with_limiter_factory(factory: LimiterFactoryRef) -> Box<dyn LimiterManager> {
        Box::new(Self {
            limiters: HashMap::new(),
            limiter_factory: Some(factory),
        })
    }
}

impl LimiterManager for DefaultLimiterManager {
    fn new_limiter(
        &mut self,
        id: String,
        upper: Option<String>,
        concurrent: Option<u32>,
        read_speed: Option<u32>,
        write_speed: Option<u32>,
    ) -> Limiter {
        let upper = match upper {
            Some(id) => self.get_limiter(id.clone()),
            None => None,
        };

        let limiter = Limiter::new_named(id.clone(), upper, concurrent, read_speed, write_speed);
        self.limiters.insert(id, limiter.clone());
        limiter
    }

    fn get_limiter(&self, id: String) -> Option<Limiter> {
        self.limiters.get(&id).cloned().or_else(|| {
            self.limiter_factory
                .as_ref()
                .and_then(|factory| factory.create_limiter(id.as_str()))
        })
    }

    fn clone_manager(&self) -> Box<dyn LimiterManager> {
        let mut new = Box::new(Self {
            limiters: HashMap::new(),
            limiter_factory: self.limiter_factory.clone(),
        });
        new.limiters
            .extend(self.limiters.iter().map(|(k, v)| (k.clone(), v.clone())));
        new
    }

    fn retain(&mut self, f: Box<dyn FnMut(&String, &mut Limiter) -> bool>) {
        self.limiters.retain(f);
    }

    fn remove_limiter(&mut self, id: String) {
        self.limiters.remove(&id);
    }

    fn set_limiter_factory(&mut self, factory: Option<LimiterFactoryRef>) {
        self.limiter_factory = factory;
    }
}

pub(crate) fn is_valid_speed(speed: &str) -> bool {
    // Define regex pattern for validating speed format
    // Supports formats like: 100B/s, 100.5KB/s, 1.5MB/s, 0.5GB/s
    let re = regex::Regex::new(r"^(\d+(\.\d+)?)\s*(B|KB|MB|GB)/s$").unwrap();
    re.is_match(speed)
}

pub fn parse_speed(speed: &str) -> Result<u64, String> {
    let re = regex::Regex::new(r"^(\d+(\.\d+)?)\s*(B|KB|MB|GB)/s$").unwrap();
    if let Some(captures) = re.captures(speed) {
        let num = captures
            .get(1)
            .ok_or_else(|| {
                let msg = format!("Invalid speed number: {}", speed);
                error!("{}", msg);
                msg
            })?
            .as_str()
            .parse::<f64>()
            .map_err(|e| {
                let msg = format!("Invalid speed number: {}. Error: {}", speed, e);
                error!("{}", msg);
                msg
            })?;
        let unit = captures.get(3).unwrap().as_str();
        match unit {
            "B" => Ok(num as u64),
            "KB" => Ok((num * 1024.0) as u64),
            "MB" => Ok((num * 1024.0 * 1024.0) as u64),
            "GB" => Ok((num * 1024.0 * 1024.0 * 1024.0) as u64),
            _ => Err("Invalid speed unit".to_string()),
        }
    } else {
        Err("Invalid speed format".to_string())
    }
}

pub async fn get_limit_info(
    chain_env: EnvRef,
) -> StackResult<(Option<String>, Option<u64>, Option<u64>)> {
    let limit_info = chain_env
        .get("LIMIT")
        .await
        .map_err(|e| stack_err!(StackErrorCode::ProcessChainError, "{e}"))?;

    let mut limiter_id = None;
    let mut down_speed = None;
    let mut upload_speed = None;
    if let Some(limit_info) = limit_info {
        if let CollectionValue::Map(map) = limit_info {
            limiter_id = if let Ok(Some(CollectionValue::String(limiter_id))) =
                map.get("limiter_id").await
            {
                Some(limiter_id)
            } else {
                None
            };

            down_speed = if let Ok(Some(CollectionValue::String(down_speed))) =
                map.get("down_speed").await
            {
                down_speed.parse::<u64>().ok()
            } else {
                None
            };

            upload_speed = if let Ok(Some(CollectionValue::String(upload_speed))) =
                map.get("upload_speed").await
            {
                upload_speed.parse::<u64>().ok()
            } else {
                None
            };
        }
    }

    Ok((limiter_id, down_speed, upload_speed))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_speed() {
        // Valid speeds
        assert!(is_valid_speed("100B/s"));
        assert!(is_valid_speed("100.5KB/s"));
        assert!(is_valid_speed("1.5MB/s"));
        assert!(is_valid_speed("0.5GB/s"));
        assert!(is_valid_speed("100KB/s"));
        assert!(is_valid_speed("1000MB/s"));
        assert!(is_valid_speed("1.0GB/s"));
        assert!(is_valid_speed("0B/s"));

        // Invalid speeds
        assert!(!is_valid_speed("100"));
        assert!(!is_valid_speed("100KB"));
        assert!(!is_valid_speed("KB/s"));
        assert!(!is_valid_speed("100.5.5KB/s"));
        assert!(!is_valid_speed("100.5 KBS"));
        assert!(!is_valid_speed(""));
        assert!(!is_valid_speed("ABC KB/s"));
    }

    #[test]
    fn test_parse_speed() {
        // Valid parsing
        assert_eq!(parse_speed("100B/s").unwrap(), 100);
        assert_eq!(parse_speed("1KB/s").unwrap(), 1024);
        assert_eq!(parse_speed("1.5KB/s").unwrap(), 1536); // 1.5 * 1024
        assert_eq!(parse_speed("1MB/s").unwrap(), 1024 * 1024);
        assert_eq!(parse_speed("1GB/s").unwrap(), 1024 * 1024 * 1024);

        // Invalid formats
        assert!(parse_speed("100").is_err());
        assert!(parse_speed("100KB").is_err());
        assert!(parse_speed("invalid").is_err());
    }

    #[test]
    fn test_default_limiter_manager_dynamic_factory() {
        struct DynamicLimiterFactory;

        impl LimiterFactory for DynamicLimiterFactory {
            fn create_limiter(&self, id: &str) -> Option<Limiter> {
                if id.starts_with("dynamic-") {
                    Some(Limiter::new_named(
                        id.to_string(),
                        None,
                        Some(1),
                        Some(4096),
                        Some(8192),
                    ))
                } else {
                    None
                }
            }
        }

        let mut manager = DefaultLimiterManager::new();
        let _ = manager.new_limiter("static".to_string(), None, Some(1), Some(1024), Some(2048));

        manager.set_limiter_factory(Some(Arc::new(DynamicLimiterFactory)));

        let static_limiter = manager.get_limiter("static".to_string()).unwrap();
        assert_eq!(static_limiter.get_id(), Some("static"));
        assert!(manager.get_limiter("missing".to_string()).is_none());

        let dynamic_limiter = manager.get_limiter("dynamic-client".to_string()).unwrap();
        assert_eq!(dynamic_limiter.get_id(), Some("dynamic-client"));

        let cloned = manager.clone_manager();
        let cloned_dynamic = cloned.get_limiter("dynamic-cloned".to_string()).unwrap();
        assert_eq!(cloned_dynamic.get_id(), Some("dynamic-cloned"));
    }
}
