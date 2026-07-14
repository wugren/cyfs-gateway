# SN 注册时自动分配 Relay TODO

状态：DONE（2026-07-13）

相关文档：[SN-Relay.md](SN-Relay.md)、[SN-API.md](SN-API.md)、[SN-Auth.md](SN-Auth.md)。

## 目标

用户注册成功时，SN 根据用户选填的地区和服务端观察到的注册请求源 IP，请求 `sn_relay_manager` 为该用户的 zone 分配一个 relay node。匹配策略及 fallback 由 relay manager 配置和执行，注册模块不直接选择具体节点。

分配结果写入 `relay_assignments`，并同步到 auth 库的 `zone_info.relay_sn`。客户端随后通过 `zone.get_info` 查询当前分配结果。

## 实施前缺口

- `auth.register` 没有地区参数，也没有把 HTTP 请求的 source IP 传入注册 handler。
- 注册完成后没有调用 relay manager；当前 `assign_zone_relay` 只在内部和测试路径使用。
- `AssignZoneRelayReq` 虽已有 `region` 和 `from_ip`，但 `from_ip` 尚未参与 GeoIP 解析和匹配。
- relay manager 当前只有固定的 region、负载和容量排序，没有配置驱动的匹配规则与明确的 fallback。
- `sfo-ip` 当前提供 ip2region XDB `Searcher`。仓库的 `IpRegionMap` 封装可解析 `country`、`province`、`city`、`isp`、`country_code`，但 `cyfs-sn` 尚无可注入的 GeoIP resolver。

## 目标流程

```text
auth.register(region?)
  -> 完成用户名、邮箱、激活码和 BNS 注册校验
  -> 服务端从 HTTP/连接上下文取得 source_ip
  -> 创建本地 user 和 zone_info
  -> relay_mgr.allocate_zone_relay(zone, preferred_region, source_ip)
  -> relay_mgr 执行匹配规则；未命中时执行 fallback
  -> 写 relay_assignments
  -> 回写 auth.zone_info.relay_sn
  -> 注册响应正常返回，客户端可用 zone.get_info 查询 relay_sn
```

## 1. 注册 API 增加选填地区

在 `auth.register` 参数和 `cyfs-gateway-api::SnAuthRegisterReq` 中增加：

```rust
pub region: Option<String>
```

约束：

- `region` 是用户偏好提示，不是可信地理事实，也不参与账号、zone 或 BNS 权限判断。
- 对空字符串做归一化，按约定统一大小写、分隔符和地区编码格式。
- 地区编码格式需要在实现前固定，例如使用部署配置中的 region label，或采用 `country_code/region_code` 的标准表示；客户端值必须和 relay 配置使用同一命名空间。
- 未传地区时只根据 source IP 的 GeoIP 结果和 fallback 分配。
- 非法或未知地区不应导致注册失败；记录原因后继续使用 source IP 和 fallback。

## 2. 从注册请求传递可信 source IP

- source IP 必须来自服务端已有的 HTTP/连接上下文，不能由客户端 RPC params 提交。
- 复用 `get_request_client_ip` 的结果，并确认反向代理场景中的 real remote IP 只由可信 process-chain/proxy 写入。
- 将 `client_ip` 继续传到 `handle_auth` 的注册分支；其它 auth 方法无需使用。
- relay manager 请求使用 `IpAddr` 或等价强类型，避免在调度层重复解析任意字符串。
- 内网、loopback、保留地址或 GeoIP 未命中时，GeoIP 结果为空，继续执行地区提示和 fallback，不应阻断注册。

## 3. 为 relay manager 增加自动分配接口

保留 `assign_zone_relay` 作为显式指定 relay、管理操作和底层持久化能力；新增一个不允许调用方指定 relay node 的自动分配接口，例如：

```rust
pub struct AllocateZoneRelayReq {
    pub zone: String,
    pub preferred_region: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub reason: String,
    pub source_version: Option<String>,
}

async fn allocate_zone_relay(
    &self,
    req: AllocateZoneRelayReq,
) -> SnResult<RelayAssignment>;
```

接口要求：

- 以 zone 为幂等键。重复注册重试或重复调用应返回/复用有效 assignment，不应无故切换 relay。
- 调度策略完全封装在 relay manager 内；auth handler 只传递 zone、地区提示和 source IP。
- 自动分配使用 `RelayAssignmentSource::Auto`，reason 建议记录为 `register`。
- 只选择允许新 assignment 的健康节点；disabled、deleted、unhealthy 和 draining 节点不得成为新分配目标。
- 分配成功后统一完成 assignment 持久化和 `zone_info.relay_sn` 回写。

## 4. GeoIP 封装

为 `cyfs-sn` 提供可注入、可测试的 GeoIP 抽象，例如：

```rust
#[async_trait]
pub trait GeoIpResolver: Send + Sync {
    async fn lookup(&self, ip: IpAddr) -> SnResult<Option<GeoIpInfo>>;
}

pub struct GeoIpInfo {
    pub country_code: Option<String>,
    pub country: Option<String>,
    pub province: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
}
```

实现可复用 `sfo-ip::{Searcher, CachePolicy}` 和现有 ip2region XDB 数据，但不要让 relay manager 直接依赖 process-chain collection。GeoIP 查询失败或未命中属于可降级条件，不能让用户注册失败。

## 5. 匹配规则与 fallback

relay manager 从配置加载一组有序匹配规则。第一版至少支持：

1. 复用 zone 已有且仍可用的 sticky assignment。
2. 匹配用户选填的 `preferred_region`。
3. 匹配 source IP GeoIP 得到的 `country_code`、province/city 或 ISP。
4. 在匹配候选中按健康状态、负载/容量比和稳定 tie-break 排序。
5. 所有规则均未命中时，从配置的 fallback relay 集合中选择可用节点。
6. 配置的 fallback 也不可用时返回明确的 `no_relay_available` 错误，并记录可观测日志/指标。

规则匹配应保持确定性，并记录最终命中的 rule、fallback 原因和候选淘汰原因，便于后续持续优化；这些内部信息不需要通过 `zone.get_info` 暴露给客户端。

## 6. 注册失败与重试语义

BNS 注册和本地账号创建存在不可回滚的外部状态，因此 relay 暂时不可用时不应撤销已经成功创建的账号：

- relay 分配成功：正常完成注册，`zone.get_info.relay_sn` 可立即查询。
- 无可用 relay 或 GeoIP/调度暂时失败：注册仍成功，`relay_sn` 保持 `null`，记录 pending 状态或可重试任务。
- 后续可在登录后重试、首次 device online/keep_tunnel 时重试，或由后台任务补偿。
- 所有补偿调用继续以 zone 为幂等键，避免重复 assignment 和无意义迁移。

## 实现清单

- [x] 为 `RegisterReq`、`SnAuthRegisterReq` 和相关 API 文档增加选填 `region`。
- [x] 将可信 `source_ip` 从 HTTP 入口传到 `auth.register` handler。
- [x] 为 `cyfs-sn` 增加 GeoIP 配置、resolver trait 和基于 `sfo-ip`/ip2region XDB 的实现。
- [x] 在 `SnRelayManager` trait 增加 `allocate_zone_relay`，区分自动调度与显式 `assign_zone_relay`。
- [x] 增加有序匹配规则和配置化 fallback。
- [x] 注册创建本地 zone 后调用自动分配接口，并实现失败补偿语义。
- [x] 确保成功分配会同步 `zone_info.relay_sn`，`zone.get_info` 能立即读回。
- [x] 增加日志、metrics 和分配原因记录，避免输出敏感 IP/token。
- [x] 增加单元测试：地区命中、GeoIP 命中、地区与 GeoIP 冲突、未知地区、私网 IP、规则未命中 fallback、fallback 不可用、幂等重试和并发注册。
- [x] 增加端到端测试：注册请求携带/不携带地区，验证 relay assignment 与 `zone.get_info.relay_sn` 一致。

## 实现说明

- region label 统一 trim、lowercase，并把空白、`_`、`/`、`.` 规范为 `-`；非法或未知 label 只淘汰该条提示。
- `RelayAllocationConfig.match_rules` 是有序规则列表；`fallback_relays` 接受 relay_id/relay_sn，`*` 表示所有健康节点，空数组表示禁用 fallback。
- `GeoIpResolver` 可注入；`XdbGeoIpResolver` 直接读取 ip2region XDB。私网、loopback、保留地址不会查询 GeoIP，查询错误只增加降级指标并继续 fallback。
- 自动分配对 zone 使用命名锁并复用仍健康的 active assignment；节点不可用时才重新选择。assignment reason 记录为 `<reason>;rule=<matched_rule>`。
- 无可用 relay 或持久化失败时，注册不失败；manager 在 `relay_allocation_pending` 中记录不含 source IP/token 的重试状态。后续同 zone 成功分配会清理 pending。
- `RelayAllocationMetricsSnapshot` 提供 attempts、successes、fallbacks、failures、geoip_failures 进程内计数；日志只记录 zone、relay_id、rule、generation 和错误，不记录 source IP/token。

## 验收标准

- 注册方不能通过参数伪造 source IP 或指定具体 relay node。
- 同一 zone 的重复分配请求保持稳定，除非原节点不可用或管理员主动迁移。
- 有匹配节点时使用配置规则选中预期 relay；无匹配时稳定进入 fallback。
- GeoIP 数据缺失或查询失败不会导致账号注册失败。
- 分配成功后，`relay_assignments` 与 `auth.zone_info.relay_sn` 一致，客户端能通过 `zone.get_info` 查询结果。
