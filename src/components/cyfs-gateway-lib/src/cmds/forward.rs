use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clap::{Arg, ArgAction, Command};
use cyfs_process_chain::*;
use url::Url;

use crate::forward::{
    BalanceMethod, DEFAULT_MAX_BODY_BUFFER_BYTES, FORWARD_CMD, FORWARD_GROUP_CMD,
    ForwardFailureRegistry, ForwardPlan, ForwardSelector, ForwardServer, ForwardTarget,
    NextUpstreamPolicy, ProviderPolicy, parse_duration_str, parse_size_str,
};

#[derive(Clone, Debug)]
struct UpstreamNode {
    url: String,
    weight: u32,
}

pub struct Forward {
    name: String,
    cmd: Command,
    rr_counter: AtomicUsize,
    selector: ForwardSelector,
}

impl Forward {
    pub fn new() -> Self {
        let cmd = Command::new("forward")
            .about("Set forward destination URL")
            .after_help(
                r#"
Examples:
    forward tcp:///127.0.0.1:80
    forward rtcp://remote_server/path
    forward tcp:///127.0.0.1:80 tcp:///127.0.0.1:81
    forward ip_hash tcp:///127.0.0.1:80,weight=3 tcp:///127.0.0.1:81,weight=1
    forward round_robin --map $UPSTREAMS
    forward ip_hash --map $UPSTREAMS
    forward round_robin --map $PRIMARY --backup-map $BACKUP \
            --next-upstream error,timeout --tries 3
    forward hash --hash-key "$cookie_session_id" --map $UPSTREAMS
    forward consistent_hash --hash-key "$user_id" --map $UPSTREAMS
    forward least_time --map $UPSTREAMS --next-upstream error,timeout --tries 3
    forward --map $POOL --next-upstream error,timeout,http_5xx --tries 3 \
            --max-body-buffer 64KB
                "#,
            )
            .arg(
                Arg::new("upstream_map")
                    .long("map")
                    .help("Map collection variable containing <url, weight> pairs")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("backup_map")
                    .long("backup-map")
                    .help("Map collection of <url, weight> backup peers (group forward)")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("next_upstream")
                    .long("next-upstream")
                    .help("Conditions to retry on, e.g. 'error,timeout' or 'off'")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("tries")
                    .long("tries")
                    .help("Maximum number of candidate attempts (group forward)")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("next_upstream_timeout")
                    .long("next-upstream-timeout")
                    .help("Total timeout budget across all candidate attempts")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("max_fails")
                    .long("max-fails")
                    .help("Default per-candidate max_fails before ejection")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("fail_timeout")
                    .long("fail-timeout")
                    .help("Default per-candidate fail_timeout, e.g. 10s")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("group")
                    .long("group")
                    .help("Logical name of the upstream group (used for failure state)")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("force_group")
                    .long("force-group")
                    .help("Always emit forward-group, even for single-URL plans")
                    .required(false)
                    .action(ArgAction::SetTrue),
            )
            .arg(
                Arg::new("hash_key")
                    .long("hash-key")
                    .help("Captured value used by hash / consistent_hash balance methods")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("max_body_buffer")
                    .long("max-body-buffer")
                    .help("Max request body bytes to buffer for HTTP-status retry, e.g. 64KB")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("server_map")
                    .long("server-map")
                    .help("Map collection of <server_id, route-map> for provider-first plans")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("provider_retry_scope")
                    .long("provider-retry-scope")
                    .help("Provider failover scope: routes_only (default) or across_servers")
                    .required(false)
                    .num_args(1),
            )
            .arg(
                Arg::new("dest_urls")
                    .help("Destination URLs, format: <url> or <url>,weight=<N>")
                    .required(false)
                    .num_args(0..),
            );
        Self {
            name: "forward".to_string(),
            cmd,
            rr_counter: AtomicUsize::new(0),
            selector: ForwardSelector::new(),
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    fn parse_upstream(spec: &str) -> Result<UpstreamNode, String> {
        const WEIGHT_MARK: &str = ",weight=";

        let (url, weight) = if let Some(idx) = spec.rfind(WEIGHT_MARK) {
            let url = &spec[..idx];
            let weight_str = &spec[idx + WEIGHT_MARK.len()..];
            if url.is_empty() {
                return Err(format!("Invalid upstream spec '{}': url is empty", spec));
            }

            let weight = weight_str.parse::<u32>().map_err(|e| {
                format!(
                    "Invalid upstream weight in '{}': {}, expected positive integer",
                    spec, e
                )
            })?;

            if weight == 0 {
                return Err(format!(
                    "Invalid upstream weight in '{}': weight must be greater than 0",
                    spec
                ));
            }

            (url.to_string(), weight)
        } else {
            (spec.to_string(), 1)
        };

        Ok(UpstreamNode { url, weight })
    }

    fn parse_upstreams(upstreams: Vec<String>) -> Result<Vec<UpstreamNode>, String> {
        let mut nodes = Vec::with_capacity(upstreams.len());
        for item in upstreams {
            nodes.push(Self::parse_upstream(item.as_str())?);
        }

        if nodes.is_empty() {
            return Err("dest_urls is required".to_string());
        }

        Ok(nodes)
    }

    fn split_algo_and_upstreams(dest_urls: Vec<String>) -> Result<(String, Vec<String>), String> {
        if dest_urls.is_empty() {
            return Ok(("round_robin".to_string(), vec![]));
        }

        let first = dest_urls[0].as_str();
        if matches!(
            first,
            "round_robin" | "rr" | "ip_hash" | "hash" | "consistent_hash" | "least_time"
        ) {
            return Ok((first.to_string(), dest_urls[1..].to_vec()));
        }

        Ok(("round_robin".to_string(), dest_urls))
    }

    fn parse_weight_value(value: &CollectionValue, url: &str) -> Result<u32, String> {
        match value {
            CollectionValue::String(weight) => {
                let weight = weight.parse::<u32>().map_err(|e| {
                    format!(
                        "Invalid upstream weight for '{}': {}, expected positive integer",
                        url, e
                    )
                })?;
                if weight == 0 {
                    return Err(format!(
                        "Invalid upstream weight for '{}': weight must be greater than 0",
                        url
                    ));
                }
                Ok(weight)
            }
            CollectionValue::Number(NumberValue::Int(weight)) => {
                if *weight <= 0 {
                    return Err(format!(
                        "Invalid upstream weight for '{}': weight must be greater than 0",
                        url
                    ));
                }
                u32::try_from(*weight).map_err(|_| {
                    format!(
                        "Invalid upstream weight for '{}': {} is too large for u32",
                        url, weight
                    )
                })
            }
            CollectionValue::Number(NumberValue::Float(weight)) => {
                if !weight.is_finite() || *weight <= 0.0 || weight.fract() != 0.0 {
                    return Err(format!(
                        "Invalid upstream weight for '{}': {} is not a positive integer",
                        url, weight
                    ));
                }

                if *weight > u32::MAX as f64 {
                    return Err(format!(
                        "Invalid upstream weight for '{}': {} is too large for u32",
                        url, weight
                    ));
                }

                Ok(*weight as u32)
            }
            _ => Err(format!(
                "Invalid upstream weight for '{}': expected string or number, got {}",
                url,
                value.get_type()
            )),
        }
    }

    async fn parse_upstream_map(map: &MapCollectionRef) -> Result<Vec<UpstreamNode>, String> {
        let mut entries = map.dump().await?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut nodes = Vec::with_capacity(entries.len());
        for (url, weight_value) in entries {
            Url::parse(url.as_str())
                .map_err(|e| format!("Invalid upstream url '{}' in --map: {}", url, e))?;

            let weight = Self::parse_weight_value(&weight_value, url.as_str())?;
            nodes.push(UpstreamNode { url, weight });
        }

        Ok(nodes)
    }

    fn build_parse_args(
        args: &[CollectionValue],
        origin_args: &CommandArgs,
    ) -> Result<Vec<String>, String> {
        if args.len() != origin_args.len() {
            return Err(format!(
                "Invalid forward command args length: expected {}, got {}",
                origin_args.len(),
                args.len()
            ));
        }

        let origin_str_args = origin_args.as_str_list();
        let mut parse_args = Vec::with_capacity(args.len());
        for (index, arg) in args.iter().enumerate() {
            if let Some(value) = arg.as_str() {
                parse_args.push(value.to_string());
            } else {
                parse_args.push(origin_str_args[index].to_string());
            }
        }

        Ok(parse_args)
    }

    fn collect_inline_upstream_specs(
        args: &[CollectionValue],
        matches: &clap::ArgMatches,
    ) -> Result<Vec<String>, String> {
        let mut dest_urls = Vec::new();
        if let Some(indices) = matches.indices_of("dest_urls") {
            for index in indices {
                let arg = args.get(index).ok_or_else(|| {
                    format!("Missing forward command argument at position {}", index)
                })?;

                let value = arg.as_str().ok_or_else(|| {
                    format!(
                        "Invalid upstream argument at position {}: expected string, got {}",
                        index,
                        arg.get_type()
                    )
                })?;
                dest_urls.push(value.to_string());
            }
        }

        Ok(dest_urls)
    }

    fn collect_map_arg(
        args: &[CollectionValue],
        matches: &clap::ArgMatches,
        flag: &str,
    ) -> Result<Option<MapCollectionRef>, String> {
        let Some(index) = matches.index_of(flag) else {
            return Ok(None);
        };

        let arg = args
            .get(index)
            .ok_or_else(|| format!("Missing {} argument at position {}", flag, index))?;
        let map = arg.as_map().ok_or_else(|| {
            format!(
                "Invalid --{} argument: expected map collection, got {}",
                flag.replace('_', "-"),
                arg.get_type()
            )
        })?;

        Ok(Some(map.clone()))
    }

    fn weighted_round_robin(&self, upstreams: &[UpstreamNode]) -> Result<String, String> {
        let gcd = upstreams.iter().fold(0u32, |acc, node| {
            if acc == 0 {
                node.weight
            } else {
                Self::gcd_u32(acc, node.weight)
            }
        });
        let normalized_weights = upstreams
            .iter()
            .map(|node| {
                let divisor = if gcd == 0 { 1 } else { gcd };
                (node.weight / divisor) as usize
            })
            .collect::<Vec<_>>();

        let total_weight = normalized_weights.iter().try_fold(0usize, |acc, weight| {
            acc.checked_add(*weight)
                .ok_or_else(|| "sum of upstream weights overflowed".to_string())
        })?;

        if total_weight == 0 {
            return Err("sum of upstream weights must be greater than 0".to_string());
        }

        let target_step = self.rr_counter.fetch_add(1, Ordering::Relaxed) % total_weight;
        let mut current_weights = vec![0isize; upstreams.len()];
        let total_weight_isize = total_weight as isize;

        for step in 0..=target_step {
            for (index, weight) in normalized_weights.iter().enumerate() {
                current_weights[index] += *weight as isize;
            }

            let mut selected_index = 0usize;
            for index in 1..current_weights.len() {
                if current_weights[index] > current_weights[selected_index] {
                    selected_index = index;
                }
            }

            current_weights[selected_index] -= total_weight_isize;
            if step == target_step {
                return Ok(upstreams[selected_index].url.clone());
            }
        }

        Err("failed to select upstream with round_robin".to_string())
    }

    fn gcd_u32(left: u32, right: u32) -> u32 {
        let mut a = left;
        let mut b = right;
        while b != 0 {
            let remainder = a % b;
            a = b;
            b = remainder;
        }
        a
    }

    fn nginx_ip_hash_key(ip: &IpAddr) -> Vec<u8> {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                vec![octets[0], octets[1], octets[2]]
            }
            IpAddr::V6(v6) => v6.octets().to_vec(),
        }
    }

    fn nginx_ip_hash(ip: &IpAddr) -> usize {
        let key = Self::nginx_ip_hash_key(ip);
        let mut hash = 89usize;
        for b in key {
            hash = (hash * 113 + b as usize) % 6271;
        }
        hash
    }

    // Source IP lookup order: trusted restored source first, then the
    // effective source, then the HTTP compat scalar. Keeps one `forward
    // ip_hash` config working across HTTP and non-HTTP process chains.
    async fn extract_source_ip(context: &Context) -> Option<IpAddr> {
        if let Ok(Some(req)) = context.env().get("REQ", None).await {
            if let Some(req) = req.into_map() {
                for key in ["real_source_ip", "source_ip"] {
                    if let Ok(Some(value)) = req.get(key).await {
                        if let Some(ip) = value.as_str().and_then(|v| v.parse::<IpAddr>().ok()) {
                            return Some(ip);
                        }
                    }
                }
            }
        }

        if let Ok(Some(value)) = context.env().get("REQ_remote_ip", None).await {
            if let Some(ip) = value.as_str().and_then(|v| v.parse::<IpAddr>().ok()) {
                return Some(ip);
            }
        }

        None
    }

    async fn select_upstream(
        &self,
        context: &Context,
        algo: &str,
        upstreams: &[UpstreamNode],
    ) -> Result<String, String> {
        match algo {
            "round_robin" => self.weighted_round_robin(upstreams),
            "ip_hash" => {
                let ip = Self::extract_source_ip(context).await;
                if ip.is_none() {
                    return Err(
                        "ip_hash requires source ip, but request has no client ip".to_string()
                    );
                }

                let total_weight = upstreams.iter().try_fold(0usize, |acc, node| {
                    acc.checked_add(node.weight as usize)
                        .ok_or_else(|| "sum of upstream weights overflowed".to_string())
                })?;
                if total_weight == 0 {
                    return Err("sum of upstream weights must be greater than 0".to_string());
                }

                let hash_ip = ip.ok_or_else(|| "missing source ip".to_string())?;
                let mut cursor = Self::nginx_ip_hash(&hash_ip) % total_weight;
                for node in upstreams {
                    let w = node.weight as usize;
                    if cursor < w {
                        return Ok(node.url.clone());
                    }
                    cursor -= w;
                }

                Err("failed to select upstream with ip_hash".to_string())
            }
            _ => Err(format!(
                "Unsupported algorithm '{}': expected round_robin or ip_hash",
                algo
            )),
        }
    }

    fn group_options_present(matches: &clap::ArgMatches) -> bool {
        matches.contains_id("backup_map")
            || matches.contains_id("next_upstream")
            || matches.contains_id("tries")
            || matches.contains_id("next_upstream_timeout")
            || matches.contains_id("max_fails")
            || matches.contains_id("fail_timeout")
            || matches.contains_id("group")
            || matches.contains_id("hash_key")
            || matches.contains_id("max_body_buffer")
            || matches.contains_id("server_map")
            || matches.contains_id("provider_retry_scope")
            || matches.get_flag("force_group")
    }

    fn parse_optional_str(matches: &clap::ArgMatches, name: &str) -> Option<String> {
        matches.get_one::<String>(name).cloned()
    }

    fn build_next_upstream_policy(
        matches: &clap::ArgMatches,
    ) -> Result<NextUpstreamPolicy, String> {
        let conds_spec = Self::parse_optional_str(matches, "next_upstream");
        let tries_spec = Self::parse_optional_str(matches, "tries");
        let timeout_spec = Self::parse_optional_str(matches, "next_upstream_timeout");
        let body_buf_spec = Self::parse_optional_str(matches, "max_body_buffer");

        let (conditions, off_explicit) = match &conds_spec {
            Some(s) => NextUpstreamPolicy::parse_conditions(s)?,
            None => (Vec::new(), false),
        };

        let tries = match tries_spec {
            Some(s) => s
                .parse::<u32>()
                .map_err(|e| format!("invalid --tries '{}': {}", s, e))?,
            None => {
                if conditions.is_empty() {
                    1
                } else {
                    // Default to "try every candidate at most once" when retry is enabled.
                    0
                }
            }
        };

        let timeout = match timeout_spec {
            Some(s) => Some(parse_duration_str(&s)?),
            None => None,
        };

        if off_explicit {
            return Ok(NextUpstreamPolicy::off());
        }

        let any_http_status = conditions.iter().any(|c| c.is_http_status());
        // When HTTP-status retry is enabled, default to a small body
        // buffer so the executor can replay safely. Callers can opt
        // out by setting `--max-body-buffer 0`.
        let max_body_buffer_bytes = match body_buf_spec {
            Some(s) => parse_size_str(&s)?,
            None if any_http_status => DEFAULT_MAX_BODY_BUFFER_BYTES,
            None => 0,
        };

        Ok(NextUpstreamPolicy {
            conditions,
            tries,
            timeout,
            max_body_buffer_bytes,
        })
    }

    async fn build_targets_from_map(
        map: &MapCollectionRef,
        backup: bool,
        max_fails: u32,
        fail_timeout: Duration,
    ) -> Result<Vec<ForwardTarget>, String> {
        let nodes = Self::parse_upstream_map(map).await?;
        Ok(nodes
            .into_iter()
            .map(|n| ForwardTarget {
                url: n.url,
                weight: n.weight,
                backup,
                max_fails,
                fail_timeout,
                server_id: None,
            })
            .collect())
    }

    /// Build a provider-first server list from a `--server-map` map.
    /// Outer keys are server ids; the corresponding values must be
    /// nested `<url, weight>` map collections describing that server's
    /// routes (§5 of `forward机制升级需求.md`).
    async fn build_servers_from_map(
        map: &MapCollectionRef,
        max_fails: u32,
        fail_timeout: Duration,
    ) -> Result<Vec<ForwardServer>, String> {
        let mut entries = map.dump().await?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut servers = Vec::with_capacity(entries.len());
        for (server_id, route_value) in entries {
            let route_map = route_value.as_map().ok_or_else(|| {
                format!(
                    "Invalid --server-map entry for '{}': expected nested map of <url, weight>, got {}",
                    server_id,
                    route_value.get_type()
                )
            })?;
            let nodes = Self::parse_upstream_map(route_map).await?;
            if nodes.is_empty() {
                return Err(format!(
                    "Invalid --server-map entry for '{}': route map is empty",
                    server_id
                ));
            }
            let routes = nodes
                .into_iter()
                .map(|n| ForwardTarget {
                    url: n.url,
                    weight: n.weight,
                    backup: false,
                    max_fails,
                    fail_timeout,
                    server_id: Some(server_id.clone()),
                })
                .collect();
            servers.push(ForwardServer {
                id: server_id,
                weight: 1,
                backup: false,
                routes,
                max_fails,
                fail_timeout,
            });
        }
        Ok(servers)
    }

    fn build_targets_from_inline(
        nodes: Vec<UpstreamNode>,
        backup: bool,
        max_fails: u32,
        fail_timeout: Duration,
    ) -> Vec<ForwardTarget> {
        nodes
            .into_iter()
            .map(|n| ForwardTarget {
                url: n.url,
                weight: n.weight,
                backup,
                max_fails,
                fail_timeout,
                server_id: None,
            })
            .collect()
    }

    async fn build_group_plan(
        &self,
        context: &Context,
        matches: &clap::ArgMatches,
        algo: &str,
        inline_nodes: Vec<UpstreamNode>,
        primary_map: Option<MapCollectionRef>,
        backup_map: Option<MapCollectionRef>,
        server_map: Option<MapCollectionRef>,
    ) -> Result<ForwardPlan, String> {
        let max_fails = match Self::parse_optional_str(matches, "max_fails") {
            Some(s) => s
                .parse::<u32>()
                .map_err(|e| format!("invalid --max-fails '{}': {}", s, e))?,
            None => 1,
        };
        let fail_timeout = match Self::parse_optional_str(matches, "fail_timeout") {
            Some(s) => parse_duration_str(&s)?,
            None => Duration::from_secs(10),
        };

        let servers = match server_map {
            Some(map) => Self::build_servers_from_map(&map, max_fails, fail_timeout).await?,
            None => Vec::new(),
        };

        // Provider-first plan: server-map expands into the flat candidate
        // list (with server_id retained for retry-scope decisions). Inline
        // nodes / --map / --backup-map remain available alongside servers
        // and are concatenated after server-derived candidates so the
        // executor still sees a single attempt order.
        let mut candidates = Vec::new();
        if !servers.is_empty() {
            candidates.extend(ForwardPlan::candidates_from_servers(&servers));
        }
        candidates.extend(Self::build_targets_from_inline(
            inline_nodes,
            false,
            max_fails,
            fail_timeout,
        ));
        if let Some(map) = primary_map {
            candidates
                .extend(Self::build_targets_from_map(&map, false, max_fails, fail_timeout).await?);
        }
        if let Some(map) = backup_map {
            candidates
                .extend(Self::build_targets_from_map(&map, true, max_fails, fail_timeout).await?);
        }

        if candidates.is_empty() {
            return Err(
                "forward requires at least one upstream, --map or --server-map".to_string(),
            );
        }

        // Resolve the balance method. For hash variants the executor
        // needs the value of `--hash-key` so the captured key is what
        // routes the request — `algo` is just a marker.
        let balance = match algo {
            "hash" => {
                let key = Self::parse_optional_str(matches, "hash_key")
                    .ok_or_else(|| "hash balance method requires --hash-key".to_string())?;
                BalanceMethod::Hash { key }
            }
            "consistent_hash" => {
                let key = Self::parse_optional_str(matches, "hash_key").ok_or_else(|| {
                    "consistent_hash balance method requires --hash-key".to_string()
                })?;
                BalanceMethod::ConsistentHash { key }
            }
            _ => BalanceMethod::parse(algo)?,
        };

        let next_upstream = Self::build_next_upstream_policy(matches)?;
        let group = Self::parse_optional_str(matches, "group");
        let provider_policy = match Self::parse_optional_str(matches, "provider_retry_scope") {
            Some(s) => match s.as_str() {
                "routes_only" => ProviderPolicy {
                    retry_scope: crate::forward::ProviderRouteRetry::RoutesOnly,
                },
                "across_servers" => ProviderPolicy {
                    retry_scope: crate::forward::ProviderRouteRetry::AcrossServers,
                },
                _ => {
                    return Err(format!(
                        "invalid --provider-retry-scope '{}': expected routes_only or across_servers",
                        s
                    ));
                }
            },
            None => ProviderPolicy::default(),
        };

        let hash_key_value = match &balance {
            BalanceMethod::Hash { .. } | BalanceMethod::ConsistentHash { .. } => {
                Self::parse_optional_str(matches, "hash_key")
            }
            _ => None,
        };

        let mut plan = ForwardPlan {
            group,
            balance,
            next_upstream,
            candidates,
            hash_key_value,
            servers,
            provider_policy,
        };
        plan.validate()?;

        // Apply selector to produce an attempt-ordered candidate list.
        // `LeastTime` plans are not RTT-sorted here: that step lives in
        // the executor where a `TunnelManager` is available. The
        // selector treats `LeastTime` as a no-op for ordering.
        let source_ip = match &plan.balance {
            BalanceMethod::IpHash => Self::extract_source_ip(context).await,
            _ => None,
        };
        let registry = ForwardFailureRegistry::global();
        let ordered = self.selector.select(&plan, registry, source_ip);
        plan.candidates = ordered;

        // Cap tries to the number of candidates we actually have.
        let cap = plan.candidates.len() as u32;
        if plan.next_upstream.tries == 0 || plan.next_upstream.tries > cap {
            plan.next_upstream.tries = cap.max(1);
        }

        Ok(plan)
    }
}

#[async_trait::async_trait]
impl ExternalCommand for Forward {
    fn help(&self, name: &str, help_type: CommandHelpType) -> String {
        assert_eq!(self.cmd.get_name(), name);
        command_help(help_type, &self.cmd)
    }

    fn check(&self, args: &CommandArgs) -> Result<(), String> {
        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(args.as_str_list())
            .map_err(|e| {
                let msg = format!("Invalid forward command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let dest_urls = matches
            .get_many::<String>("dest_urls")
            .map(|values| values.map(|s| s.to_string()).collect::<Vec<_>>())
            .unwrap_or_default();

        let (_algo, upstream_specs) = Self::split_algo_and_upstreams(dest_urls)?;
        let has_map = matches.index_of("upstream_map").is_some();
        let has_backup_map = matches.index_of("backup_map").is_some();

        if upstream_specs.is_empty() && !has_map && !has_backup_map {
            return Err("forward requires at least one upstream or --map".to_string());
        }

        if upstream_specs.len() > 1 {
            Self::parse_upstreams(upstream_specs)?;
        }

        if let Some(s) = matches.get_one::<String>("next_upstream") {
            NextUpstreamPolicy::parse_conditions(s)?;
        }
        if let Some(s) = matches.get_one::<String>("tries") {
            s.parse::<u32>()
                .map_err(|e| format!("invalid --tries '{}': {}", s, e))?;
        }
        if let Some(s) = matches.get_one::<String>("next_upstream_timeout") {
            parse_duration_str(s)?;
        }
        if let Some(s) = matches.get_one::<String>("max_fails") {
            s.parse::<u32>()
                .map_err(|e| format!("invalid --max-fails '{}': {}", s, e))?;
        }
        if let Some(s) = matches.get_one::<String>("fail_timeout") {
            parse_duration_str(s)?;
        }
        if let Some(s) = matches.get_one::<String>("max_body_buffer") {
            parse_size_str(s)?;
        }
        if let Some(s) = matches.get_one::<String>("provider_retry_scope") {
            if !matches!(s.as_str(), "routes_only" | "across_servers") {
                return Err(format!(
                    "invalid --provider-retry-scope '{}': expected routes_only or across_servers",
                    s
                ));
            }
        }

        Ok(())
    }

    async fn exec(
        &self,
        context: &Context,
        args: &[CollectionValue],
        origin_args: &CommandArgs,
    ) -> Result<CommandResult, String> {
        let parse_args = Self::build_parse_args(args, origin_args)?;

        let matches = self
            .cmd
            .clone()
            .try_get_matches_from(&parse_args)
            .map_err(|e| {
                let msg = format!("Invalid forward command: {:?}, {}", args, e);
                error!("{}", msg);
                msg
            })?;

        let dest_urls = Self::collect_inline_upstream_specs(args, &matches)?;
        let primary_map = Self::collect_map_arg(args, &matches, "upstream_map")?;
        let backup_map = Self::collect_map_arg(args, &matches, "backup_map")?;
        let server_map = Self::collect_map_arg(args, &matches, "server_map")?;

        let (algo, inline_upstream_specs) = Self::split_algo_and_upstreams(dest_urls)?;
        let inline_nodes = if inline_upstream_specs.is_empty() {
            Vec::new()
        } else {
            Self::parse_upstreams(inline_upstream_specs)?
        };

        let want_group = Self::group_options_present(&matches)
            || matches!(algo.as_str(), "hash" | "consistent_hash" | "least_time");
        let force_group = matches.get_flag("force_group");

        if want_group {
            let plan = self
                .build_group_plan(
                    context,
                    &matches,
                    algo.as_str(),
                    inline_nodes,
                    primary_map,
                    backup_map,
                    server_map,
                )
                .await?;
            // Single-URL group plans degrade to plain `forward "<url>"` for
            // backward compatibility with executors that haven't been
            // upgraded yet, unless --force-group is set.
            if plan.is_single_url() && !force_group {
                let url = plan.candidates[0].url.clone();
                return Ok(CommandResult::return_with_string(
                    CommandControlLevel::Lib,
                    format!(r#"{} "{}""#, FORWARD_CMD, url),
                ));
            }
            let encoded = plan.encode()?;
            return Ok(CommandResult::return_with_string(
                CommandControlLevel::Lib,
                format!(r#"{} "{}""#, FORWARD_GROUP_CMD, encoded),
            ));
        }

        // Legacy single-URL selection path.
        let mut upstreams = inline_nodes;
        if let Some(map) = primary_map {
            upstreams.extend(Self::parse_upstream_map(&map).await?);
        }

        if upstreams.is_empty() {
            return Err("forward requires at least one upstream or --map".to_string());
        }

        let selected = if upstreams.len() == 1 {
            upstreams[0].url.clone()
        } else {
            self.select_upstream(context, algo.as_str(), upstreams.as_slice())
                .await?
        };

        Ok(CommandResult::return_with_string(
            CommandControlLevel::Lib,
            format!(r#"{} "{}""#, FORWARD_CMD, selected),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::global_process_chains::{create_process_chain_executor, execute_stream_chain};
    use crate::{ProcessChainConfigs, ServerManager, get_external_commands};
    use cyfs_process_chain::{
        CollectionValue, CommandArg, CommandArgs, CommandControl, MemoryMapCollection,
        StreamRequest,
    };
    use std::sync::{Arc, Mutex};

    /// Run a stream chain with `forward ip_hash` over two weight-1 upstreams
    /// and return the selected URL (None when selection failed).
    ///
    /// nginx_ip_hash picks the FIRST upstream for 203.0.113.9 and the SECOND
    /// for 10.0.0.1, so the selected URL reveals which source IP was used.
    async fn run_ip_hash_chain(
        mut request: StreamRequest,
        remote_ip_env: Option<&str>,
    ) -> Option<String> {
        let chains = r#"
- id: main
  priority: 1
  blocks:
    - id: main
      block: |
        forward ip_hash "tcp:///10.0.0.1:1000,weight=1" "tcp:///10.0.0.2:1000,weight=1";
"#;
        let chains: ProcessChainConfigs = serde_yaml_ng::from_str(chains).unwrap();
        let servers = Arc::new(ServerManager::new());
        let (executor, _hook_env) = create_process_chain_executor(
            &chains,
            None,
            None,
            Some(get_external_commands(Arc::downgrade(&servers))),
            None,
        )
        .await
        .unwrap();
        if let Some(ip) = remote_ip_env {
            executor
                .global_env()
                .create("REQ_remote_ip", CollectionValue::String(ip.to_string()))
                .await
                .unwrap();
        }
        let (client, _server) = tokio::io::duplex(16);
        request.incoming_stream = Arc::new(Mutex::new(Some(Box::new(client))));

        let ret = match execute_stream_chain(executor, request).await {
            Ok((ret, _stream)) => ret,
            Err(_) => return None,
        };
        if let Some(CommandControl::Return(ret)) = ret.as_control() {
            if let CollectionValue::String(value) = &ret.value {
                let list = shlex::split(value.as_str())?;
                if list.len() == 2 && list[0] == "forward" {
                    return Some(list[1].clone());
                }
            }
        }
        None
    }

    const FIRST_UPSTREAM: &str = "tcp:///10.0.0.1:1000";
    const SECOND_UPSTREAM: &str = "tcp:///10.0.0.2:1000";

    #[tokio::test]
    async fn test_ip_hash_prefers_real_source_ip() {
        // real_source_ip (203.0.113.9 -> first) must win over
        // source_ip (10.0.0.1 -> second).
        let mut request = StreamRequest::default();
        request.source_addr = Some("10.0.0.1:80".parse().unwrap());
        request.real_source_addr = Some("203.0.113.9:70".parse().unwrap());
        let selected = run_ip_hash_chain(request, None).await;
        assert_eq!(selected.as_deref(), Some(FIRST_UPSTREAM));
    }

    #[tokio::test]
    async fn test_ip_hash_uses_source_ip_without_real_source() {
        let mut request = StreamRequest::default();
        request.source_addr = Some("10.0.0.1:80".parse().unwrap());
        let selected = run_ip_hash_chain(request, None).await;
        assert_eq!(selected.as_deref(), Some(SECOND_UPSTREAM));
    }

    #[tokio::test]
    async fn test_ip_hash_falls_back_to_req_remote_ip() {
        // No REQ source fields at all (HTTP-style env): the scalar
        // REQ_remote_ip compat variable must be used.
        let request = StreamRequest::default();
        let selected = run_ip_hash_chain(request, Some("203.0.113.9")).await;
        assert_eq!(selected.as_deref(), Some(FIRST_UPSTREAM));
    }

    #[tokio::test]
    async fn test_ip_hash_prefers_req_source_ip_over_remote_ip_env() {
        let mut request = StreamRequest::default();
        request.source_addr = Some("10.0.0.1:80".parse().unwrap());
        let selected = run_ip_hash_chain(request, Some("203.0.113.9")).await;
        assert_eq!(selected.as_deref(), Some(SECOND_UPSTREAM));
    }

    #[tokio::test]
    async fn test_ip_hash_without_any_source_fails() {
        let request = StreamRequest::default();
        let selected = run_ip_hash_chain(request, None).await;
        assert_eq!(selected, None);
    }

    #[tokio::test]
    async fn test_parse_upstream_map_supports_string_and_number_weights() {
        let map = MemoryMapCollection::new_ref();
        map.insert(
            "tcp:///127.0.0.1:80",
            CollectionValue::String("3".to_string()),
        )
        .await
        .unwrap();
        map.insert(
            "tcp:///127.0.0.1:81",
            CollectionValue::Number(NumberValue::Int(1)),
        )
        .await
        .unwrap();

        let upstreams = Forward::parse_upstream_map(&map).await.unwrap();

        assert_eq!(upstreams.len(), 2);
        assert_eq!(upstreams[0].url, "tcp:///127.0.0.1:80");
        assert_eq!(upstreams[0].weight, 3);
        assert_eq!(upstreams[1].url, "tcp:///127.0.0.1:81");
        assert_eq!(upstreams[1].weight, 1);
    }

    #[tokio::test]
    async fn test_parse_upstream_map_rejects_invalid_weight() {
        let map = MemoryMapCollection::new_ref();
        map.insert(
            "tcp:///127.0.0.1:80",
            CollectionValue::String("0".to_string()),
        )
        .await
        .unwrap();

        let err = Forward::parse_upstream_map(&map).await.unwrap_err();
        assert!(err.contains("weight must be greater than 0"));
    }

    #[test]
    fn test_parse_upstream_accepts_named_token() {
        let upstream = Forward::parse_upstream("api_a,weight=2").unwrap();

        assert_eq!(upstream.url, "api_a");
        assert_eq!(upstream.weight, 2);
    }

    #[test]
    fn test_check_accepts_algo_with_map_only() {
        let forward = Forward::new();
        let args = CommandArgs::new(vec![
            CommandArg::Literal("forward".to_string()),
            CommandArg::Literal("ip_hash".to_string()),
            CommandArg::Literal("--map".to_string()),
            CommandArg::Var("$UPSTREAMS".to_string()),
        ]);

        forward.check(&args).unwrap();
    }

    #[test]
    fn test_check_accepts_group_flags() {
        let forward = Forward::new();
        let args = CommandArgs::new(vec![
            CommandArg::Literal("forward".to_string()),
            CommandArg::Literal("--map".to_string()),
            CommandArg::Var("$UPSTREAMS".to_string()),
            CommandArg::Literal("--backup-map".to_string()),
            CommandArg::Var("$BACKUP".to_string()),
            CommandArg::Literal("--next-upstream".to_string()),
            CommandArg::Literal("error,timeout".to_string()),
            CommandArg::Literal("--tries".to_string()),
            CommandArg::Literal("3".to_string()),
            CommandArg::Literal("--fail-timeout".to_string()),
            CommandArg::Literal("10s".to_string()),
        ]);

        forward.check(&args).unwrap();
    }

    #[test]
    fn test_check_rejects_unknown_next_upstream_condition() {
        let forward = Forward::new();
        let args = CommandArgs::new(vec![
            CommandArg::Literal("forward".to_string()),
            CommandArg::Literal("tcp:///127.0.0.1:80".to_string()),
            CommandArg::Literal("--next-upstream".to_string()),
            CommandArg::Literal("error,foo".to_string()),
        ]);

        assert!(forward.check(&args).is_err());
    }

    #[test]
    fn test_check_accepts_status_retry_flags() {
        let forward = Forward::new();
        let args = CommandArgs::new(vec![
            CommandArg::Literal("forward".to_string()),
            CommandArg::Literal("--map".to_string()),
            CommandArg::Var("$UPSTREAMS".to_string()),
            CommandArg::Literal("--next-upstream".to_string()),
            CommandArg::Literal("error,timeout,http_5xx,non_idempotent".to_string()),
            CommandArg::Literal("--tries".to_string()),
            CommandArg::Literal("3".to_string()),
            CommandArg::Literal("--max-body-buffer".to_string()),
            CommandArg::Literal("128KB".to_string()),
        ]);

        forward.check(&args).unwrap();
    }

    #[test]
    fn test_check_accepts_hash_and_least_time_algos() {
        let forward = Forward::new();
        for algo in ["hash", "consistent_hash", "least_time"] {
            let args = CommandArgs::new(vec![
                CommandArg::Literal("forward".to_string()),
                CommandArg::Literal(algo.to_string()),
                CommandArg::Literal("--map".to_string()),
                CommandArg::Var("$UPSTREAMS".to_string()),
                CommandArg::Literal("--hash-key".to_string()),
                CommandArg::Literal("user-42".to_string()),
            ]);
            forward.check(&args).unwrap();
        }
    }

    #[test]
    fn test_check_rejects_invalid_provider_retry_scope() {
        let forward = Forward::new();
        let args = CommandArgs::new(vec![
            CommandArg::Literal("forward".to_string()),
            CommandArg::Literal("--map".to_string()),
            CommandArg::Var("$UPSTREAMS".to_string()),
            CommandArg::Literal("--provider-retry-scope".to_string()),
            CommandArg::Literal("invalid".to_string()),
        ]);

        assert!(forward.check(&args).is_err());
    }

    #[test]
    fn test_weighted_round_robin_smooths_equal_large_weights() {
        let forward = Forward::new();
        let upstreams = vec![
            UpstreamNode {
                url: "http://127.0.0.1:10162".to_string(),
                weight: 100,
            },
            UpstreamNode {
                url: "http://127.0.0.1:10163".to_string(),
                weight: 100,
            },
        ];

        let first = forward.weighted_round_robin(&upstreams).unwrap();
        let second = forward.weighted_round_robin(&upstreams).unwrap();
        let third = forward.weighted_round_robin(&upstreams).unwrap();

        assert_eq!(first, "http://127.0.0.1:10162");
        assert_eq!(second, "http://127.0.0.1:10163");
        assert_eq!(third, "http://127.0.0.1:10162");
    }
}
