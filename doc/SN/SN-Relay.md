# SN-Relay

`SN-Relay` 包含两个边界不同的部分：

- `sn_relay_manager`: Relay 控制面，负责 zone -> relay 的分配、relay 节点健康、准入、迁移和手工调度。
- `sn_relay`: 部署在边缘的 Relay 数据面节点，负责设备 `keep_tunnel`、HTTP/HTTPS 转发和 RTCP 转发。

当本文和当前实现冲突时，以 `doc/SN/新SN核心流程整理.md` 中的设计意图为准；当前 `cyfs-sn` 实现只作为字段、兼容接口和迁移状态参考。

重构第一阶段已完成：`sn_relay_manager` 控制面已抽成独立模块 `src/components/cyfs-sn/src/relay_mgr.rs`（`SnRelayManager` trait + `SqliteSnRelayManager` 实现），不再散落在 `SNServer` 内。控制面的节点注册、心跳、zone -> relay 分配、准入决策、迁移窗口和 `zone_info.relay_sn` 回写都已实现并有单元测试。仍缺的是数据面 `sn_relay` 节点模块，以及把控制面接入实时准入和转发路径；HTTP/HTTPS、`self_cert`、`sn_ips`、旧 `zone_config` 等兼容逻辑仍部分留在 `SNServer` 内。详见末尾 `## 当前实现状态`。

## 设计定位

`sn_relay_manager` 是控制面。它负责回答两个问题：

- 某个 zone 当前应该接入哪个 `sn_relay`。
- 某个 device 是否允许接入当前 `sn_relay`。

`sn_relay` 是数据面。它负责把真实流量转发到目标 gateway device，但不决定全局调度策略。

### sn_relay_manager 负责

- 维护 `zone -> sn_relay` 的当前分配关系。
- 维护 relay 节点注册信息、公开入口、能力、健康状态、负载和下线状态。
- 在用户注册、bind zone、设备首次上线或 `update_ood_info` 后为 zone 分配合适的 relay。
- 在分配变化后更新 `sn_auth.zone_info.relay_sn`，供 node_daemon 周期查询。
- 为 `keep_tunnel` 提供准入判断。
- 为 HTTP/HTTPS Relay 和 RTCP Relay 提供当前 relay 归属判断。
- 支持 relay 迁移、drain、故障切换和手工调整。
- 记录 relay 分配、准入拒绝、迁移和 admin 操作审计。

### sn_relay_manager 不负责

- 不保存账号、密码、登录 token。
- 不发布 BNS `zone`、`boot`、`device_mini_doc`、`dns_txt` 文档。
- 不作为 BNS owner/controller authority 的来源。
- 不维护全局 tunnel 连接表。
- 不直接决定 hostname 的 gateway device 身份。
- 不直接修改设备身份信息。

其中 BNS 权威状态在 BNS 合约，写操作由 `sn_bns_controller` 构造并签名 TX 提交、只读投影由 `bns-indexer` 索引；账号、`zone_info.self_cert` 和 `zone_info.relay_sn` 的本地缓存由 `sn_auth` 管理；设备在线态和 endpoint 由 `sn_device_info` 管理；hostname/DID/zone/device 到 gateway device 和 relay 信息的查询合成由 `sn_resolver` 管理。

### sn_relay 节点负责

- 接收 node_daemon 发起的 `keep_tunnel`。
- 校验 device token 或消费 `sn_authority` 输出的 `Device(zone, device_name, did)` 权限上下文。
- 调用 `sn_relay_manager` 判断该 device 所在 zone 是否属于当前 relay 节点。
- 如果 zone 不属于当前 relay，拒绝接入并返回正确 `relay_sn` 或迁移提示。
- 在本节点维护实时 RTCP tunnel 和本地连接状态。
- 接收浏览器或外部客户端的 HTTP/HTTPS 请求，根据 hostname 找到目标 zone 和 gateway device。
- 通过本节点已有 RTCP tunnel，或可建立的 tunnel，把流量转发到 gateway device。
- 为 RTCP Relay 场景提供 zone 内设备互联和 zone 外访问 gateway 的转发入口。
- 上报本节点健康、负载、连接数、流量和错误统计。

### sn_relay 节点不负责

- 不修改 zone -> relay 的全局分配。
- 不直接写 `sn_auth.zone_info.relay_sn`。
- 不绕过 `sn_relay_manager` 接受任意 zone/device 的 tunnel。
- 不把本地 tunnel 状态同步成全局 `sn_tunnel_registry`。
- 不把 SN 用户 session token 当成设备准入凭证。

## 和现有 cyfs-sn 的关系

当前 `cyfs-sn` 中和 Relay 相关的实现主要是兼容基础：

- `users.sn_ips`: 旧实现中保存用户关联 SN IP 列表，可迁移为 `zone_info.relay_sn` 或 relay assignment 的兼容来源。
- `users.self_cert`: 当前用于 `query_by_hostname` 返回 `OODInfo.self_cert`，目标上仍作为 `sn_auth.zone_info.self_cert` 的运行态。
- `users.zone_config`: 当前保存旧 boot JWT，目标上应由 BNS `zone` / `boot` 文档替代。
- `devices.ip` 和 `devices.description`: 当前保存设备 IP 和 `DeviceInfo` JSON，目标上应迁移到 `sn_device_info` 的在线态和 endpoint。
- `query_device_by_hostname`: 当前根据 `sn_server.host` 或 `user_domain` 找用户，再固定查询 `ood1`；目标上必须通过 `sn_resolver` 从 BNS `zone` / `boot` 文档确定 gateway device。
- `query_by_did`: 当前根据 DID 查询设备并返回 `OODInfo`；目标上应由 `sn_resolver` 合成 DID、zone、device、relay 和证书状态。
- V2 `device.register` / `device.update`: 当前使用 SN access token 和本地 DB；目标上设备身份发布走 BNS `device_mini_doc`，在线态更新走 `sn_device_info`，`keep_tunnel` 准入走 `sn_relay_manager`。

因此第一版实现可以把 `sn_relay_manager` 做成 `cyfs-sn` 内部模块和 SQLite 表，由 `sn_server` / `sn_api_gateway` 调用；边缘 `sn_relay` 节点可以复用 `cyfs-gateway-lib` 的 RTCP stack 和现有 HTTP/TCP 转发能力。后续再按部署规模拆成独立服务。

## 数据归属

属于 `sn_relay_manager` 的数据：

- relay 节点注册信息。
- relay 节点健康、负载、drain 状态和运维状态。
- zone -> relay 的当前分配。
- relay 分配的来源、原因、版本、迁移状态和租约。
- keep_tunnel 准入结果和拒绝原因审计。
- 手工调度、迁移、故障切换审计。

属于 `sn_relay` 节点本地运行态的数据：

- 本节点当前 RTCP tunnel。
- tunnel 最近活跃时间、RTT、失败原因、字节数、连接数。
- 本节点转发中的 HTTP/HTTPS/RTCP 连接。
- 本节点短期 admission cache。

不属于 Relay 的数据：

- BNS owner/controller authority key。
- BNS `zone`、`boot`、`device_mini_doc`、`dns_txt` 文档。
- SN 用户账号、密码、激活码、登录 session。
- user_domain 绑定和 domain proof。
- 设备身份权威文档。
- 设备在线态的权威缓存。
- `zone_info.self_cert` 的证书生命周期状态。

## 核心对象

### relay_node

`relay_node` 描述一个可承载流量的边缘 SN Relay 节点。

目标字段：

- `relay_id`: 节点稳定 ID。
- `relay_sn`: 对外暴露的 relay 名称或域名，例如 `us-sn.buckyos.ai`。
- `public_host`: 对外 hostname。
- `http_endpoint`: HTTP/HTTPS Relay 入口。
- `rtcp_endpoint`: RTCP Relay / keep_tunnel 入口。
- `region` / `isp` / `tags`: 调度参考信息。
- `capabilities`: 例如 `http_relay`、`https_relay`、`rtcp_relay`、`tcp_forward`。
- `status`: `active | draining | disabled | unhealthy | deleted`。
- `capacity_score`: 静态容量权重。
- `current_load`: 当前负载摘要。
- `last_heartbeat_at`: 最近健康上报时间。
- `drain_until`: drain 或迁移窗口结束时间。
- `created_at` / `updated_at`。

设计约束：

- `relay_sn` 是 node_daemon 和 resolver 可见的名字，必须能被解析到该 relay 的入口。
- `relay_id` 用于内部稳定引用，避免 hostname 变更导致 assignment 失效。
- `status=draining` 的节点不应接受新 zone 分配，但可在迁移窗口内继续服务已有 tunnel。

### relay_assignment

`relay_assignment` 是 zone 当前归属的 relay 分配记录。

目标字段：

- `zone`: zone name 或 BNS name。
- `relay_id`: 当前主 relay 节点 ID。
- `relay_sn`: 当前主 relay 名称，冗余保存便于快速返回。
- `state`: `active | migrating | draining | suspended`。
- `source`: `auto | admin | recovery | migration`。
- `reason`: 分配原因，例如 `first_seen_from_ip`、`admin_override`、`node_unhealthy`。
- `generation`: 单调递增版本，防止旧准入结果覆盖新分配。
- `backup_relay_id`: 可选备用 relay。
- `sticky_until`: 自动调度粘性截止时间，避免频繁漂移。
- `lease_expires_at`: 分配租约过期时间，可用于周期性重评估。
- `migrated_from`: 迁移来源 relay。
- `migration_deadline`: 老 relay 应停止接受新 tunnel 的时间。
- `source_version`: 关联 BNS `zone` / `boot` 或 `zone_info` 的版本。
- `created_at` / `updated_at`。

设计约束：

- 同一时间一个 zone 只有一个主 `relay_id`。
- 迁移窗口内可以允许 old relay 保持已有 tunnel，但新 `keep_tunnel` 应被引导到新 relay。
- `relay_assignment` 变更后，`sn_relay_manager` 必须更新 `sn_auth.zone_info.relay_sn`。
- 用户 session token 不能直接修改 `relay_assignment`；手工调整必须走 SN Admin 权限。

### relay_admission

`relay_admission` 是一次准入判断的结果，不是长期权限。

目标字段：

- `request_id`
- `relay_id`
- `zone`
- `device_name`
- `did`
- `auth_context`: 通常是 `Device(zone, device_name, did)`。
- `decision`: `allow | reject | redirect`。
- `reason`: `ok | wrong_relay | device_not_found | zone_suspended | token_invalid | assignment_migrating | relay_draining`。
- `expected_relay_sn`: 拒绝或重定向时返回的正确 relay。
- `assignment_generation`
- `admission_expires_at`
- `observed_ip`
- `created_at`

设计约束：

- `relay_admission` TTL 应较短，只用于建立或续约 tunnel 的即时判断。
- relay 节点可缓存 allow 结果，但必须受 `assignment_generation` 和 TTL 约束。
- 准入通过不等价于开放代理；实际 HTTP/RTCP 转发仍要按 hostname、zone、device 和策略做二次校验。

### local_tunnel_state

`local_tunnel_state` 只存在于 `sn_relay` 节点本地内存或本地 runtime DB。

目标字段：

- `tunnel_key`
- `zone`
- `device_name`
- `did`
- `protocol`: `rtcp | rudp | tcp`
- `state`: `connecting | active | idle | closing | failed`。
- `assignment_generation`
- `last_seen_at`
- `last_ping_rtt_ms`
- `bytes_in` / `bytes_out`
- `active_streams`
- `failure_reason`

设计约束：

- 不设计独立的全局 `sn_tunnel_registry`。
- 跨节点只同步 zone -> relay 的分配关系，不同步每条实时 tunnel。
- relay 节点重启后依赖 node_daemon 周期性 `keep_tunnel` 重建本地状态。

## Relay Mgr 功能

### 节点注册和心跳

relay 节点启动后向 `sn_relay_manager` 注册或续约：

1. 提交 `relay_id`、`relay_sn`、公开 endpoint、版本、能力、region、capacity。
2. `sn_relay_manager` 校验节点身份和配置。
3. 写入或更新 `relay_node`。
4. 周期性接收 heartbeat，更新 `last_heartbeat_at`、负载和健康状态。
5. heartbeat 超时后把节点标记为 `unhealthy`，触发受影响 zone 的迁移评估。

节点身份可以先通过部署配置或 SN Admin 管理，后续再接入更强的节点证书和签名机制。

### 自动分配

自动分配触发点：

- 用户注册并完成初始 zone 创建。
- bind zone 成功。
- device 首次 `update_ood_info` 或首次 `keep_tunnel`。
- relay assignment 租约过期。
- 当前 relay unhealthy 或进入 drain。

分配策略应综合：

- device 或用户首次访问的 `from_ip`。
- zone 历史分配的粘性。
- relay 节点健康和负载。
- region、ISP、tags、容量权重。
- 管理员手工 override。

分配结果写入 `relay_assignment` 后，还需要把当前 `relay_sn` 写入 `sn_auth.zone_info`。node_daemon 通过查询 zone_info 获得当前 relay，然后向对应 `sn_relay` 建立 `keep_tunnel`。

### 手工调整和迁移

SN Admin 必须能手工调整 zone -> relay：

1. Admin 选择目标 zone 和新 relay。
2. `sn_relay_manager` 校验新 relay 可用。
3. 写入 `relay_assignment.state=migrating`，增加 `generation`。
4. 更新 `sn_auth.zone_info.relay_sn` 为新 relay。
5. 在迁移窗口内，旧 relay 可以保持已有 tunnel，但拒绝新 tunnel 或返回新 relay。
6. node_daemon 周期查询 zone_info 后向新 relay `keep_tunnel`。
7. 新 relay 连接稳定后，assignment 进入 `active`，旧 relay 清理本地 tunnel。

迁移过程必须记录审计事件，包括操作者、旧 relay、新 relay、原因、时间和影响 zone。

### keep_tunnel 准入

`keep_tunnel` 准入输入：

- 当前 relay 节点 ID。
- `zone`
- `device_name`
- `did`
- device token 或已归一化的 `Device(zone, device_name, did)` 权限上下文。
- relay 节点观察到的 `from_ip`。
- 可选 `assignment_generation`。

准入流程：

1. `sn_authority` 校验 device token，输出 `Device(zone, device_name, did)`。
2. `sn_relay_manager` 读取 `relay_assignment`。
3. 如果 zone 还没有 assignment，可按策略自动创建。
4. 校验 assignment 的 `relay_id` 是否等于当前 relay。
5. 校验 zone、device、DID 的绑定关系是否能从 BNS `device_mini_doc` 或 `sn_device_info` 索引确认。
6. 校验 zone/user/device 状态未被 suspend、delete、ban 或 block。
7. 返回 `allow`、`reject` 或 `redirect`。

拒绝场景：

- token 无效或不是 device token。
- DID 不属于该 zone/device。
- zone 被暂停或用户状态不可用。
- 当前 relay 不是该 zone 的 assigned relay。
- 当前 relay 正在 drain 且不允许新 tunnel。
- assignment generation 已过期。

当当前 relay 不正确时，应返回正确 `relay_sn` 和 assignment generation，方便 node_daemon 立即切换。

### 查询当前分配

`sn_relay_manager` 需要提供面向内部模块的查询能力：

- 按 zone 查询当前 `relay_assignment`。
- 按 relay 查询当前承载的 zone 列表。
- 判断 `zone` 是否属于当前 `relay_id`。
- 查询 relay 节点状态和负载。
- 查询迁移中的 assignment。

这些能力由 `sn_resolver`、`sn_server`、`sn_relay` 节点和 SN Admin 使用。对外 API 应尽量返回稳定的 `relay_sn`，内部 API 可返回 `relay_id` 和 generation。

### 健康检查和故障切换

`sn_relay_manager` 根据 heartbeat、主动探测和业务错误率判断节点健康：

- heartbeat 超时: 标记 `unhealthy`。
- 节点主动 drain: 标记 `draining`，停止新 assignment。
- 错误率或负载过高: 降低调度权重或触发部分迁移。
- 节点恢复: 标记 `active`，但不应立即抢回已有 assignment，除非管理员设置。

故障切换时，`sn_relay_manager` 应更新 assignment generation 和 `zone_info.relay_sn`。由于 relay 本地 tunnel 不全局同步，业务恢复依赖 node_daemon 周期查询和重新 `keep_tunnel`。

## sn_relay 节点主要功能

### 节点启动

`sn_relay` 启动时需要加载：

- `relay_id`
- `relay_sn`
- HTTP/HTTPS 监听地址。
- RTCP / keep_tunnel 监听地址。
- SN API gateway 或 `sn_relay_manager` 地址。
- 本节点用于注册 heartbeat 的凭证。
- 允许的转发协议、最大连接数、限速、日志和 metrics 配置。

启动流程：

1. 初始化 HTTP/HTTPS 入口。
2. 初始化 RTCP stack。
3. 向 `sn_relay_manager` 注册。
4. 启动 heartbeat 上报。
5. 启动本地 tunnel 清理、metrics 上报和 admission cache 过期任务。

### keep_tunnel 服务

node_daemon 先向 SN 查询当前 `zone_info.relay_sn`，再连接对应 `sn_relay`。

`sn_relay` 处理流程：

1. 接收 device 的 `keep_tunnel` / RTCP hello。
2. 校验 token 的基本格式、过期时间、audience 和重放风险。
3. 调用 `sn_authority` 或本地可信验证器得到 `Device(zone, device_name, did)`。
4. 调用 `sn_relay_manager.check_admission`。
5. 如果返回 `allow`，建立或续约本地 RTCP tunnel。
6. 如果返回 `redirect`，拒绝当前 tunnel，并返回正确 `relay_sn`。
7. 如果返回 `reject`，返回明确错误码和可排障原因。
8. 将 tunnel 结果、observed endpoint 和健康信息写入本地状态，并按需要上报 `sn_device_info`。

`sn_relay` 可以把观察到的 endpoint 作为在线态线索提交给 `sn_device_info`，但不能直接替换设备身份、owner 或 BNS `device_mini_doc`。

### HTTP/HTTPS 流量转发

浏览器或外部客户端访问 `sn_relay` 时，目标通常由 HTTP `Host` 或 TLS SNI 决定。

处理流程：

1. 从请求中提取 target hostname。
2. 调用 `sn_resolver` 解析 hostname，得到 zone、gateway device、DID、`relay_sn`、`self_cert` 和可达性视图。
3. 调用 `sn_relay_manager` 判断目标 zone 是否属于当前 relay。
4. 如果不属于当前 relay，返回重定向信息，或按策略把 raw TCP forward 到正确 relay。
5. 根据请求协议和 `self_cert` 选择 gateway 目标端口。
6. 优先复用本地已有 RTCP tunnel。
7. 如果没有可用 tunnel，可尝试建立 tunnel；失败时返回 503 或明确 relay 错误。
8. 将流量转发到 gateway device。
9. 记录访问日志、字节数、延迟和失败原因。

端口选择原则：

- HTTPS 请求通常转发到 gateway 的 443。
- HTTP 请求通常转发到 gateway 的 80。
- 如果需要由 relay 终止 TLS，则必须明确区分 TLS passthrough、TLS termination 和后端端口选择。
- `self_cert` 来自 `sn_auth.zone_info` 的运行态；它只影响转发策略和证书可用性判断，不是 BNS 权威状态。

安全约束：

- 不能把 `sn_relay` 做成任意 open proxy。
- Host/SNI 必须能通过 `sn_resolver` 解析到明确 zone。
- 跨 zone 或 zone 外访问必须经过明确策略。
- 错误 relay 不应静默代理到任意目标；只能 redirect 到正确 relay 或按受控策略转发。

### RTCP 流量转发

RTCP Relay 支持两个主要场景：

- zone 内两台设备通过 SN Relay 建立 RTCP tunnel。
- zone 外客户端通过 SN Relay 到达某个 zone 的 gateway device。

处理原则：

- zone -> relay 的归属由 `sn_relay_manager` 决定。
- `sn_relay` 只维护本节点实时 tunnel。
- 每条新 tunnel 必须有 device token、gateway policy 或其它明确准入依据。
- 跨 zone 访问必须有独立策略，不能因为知道 DID 就允许访问。
- 复用 tunnel 时也要检查 assignment generation 和 admission TTL。

对 gateway device 的常见转发目标：

- `rtcp://<gateway-did-hostname>/:80`
- `rtcp://<gateway-did-hostname>/:443`

目标 gateway device 不应长期写死为 `ood1`。应由 `sn_resolver` 根据 BNS `zone` / `boot` 文档确定。

### 错误 relay 处理

当 device 或外部请求进入了错误 relay：

- 对 `keep_tunnel`: 返回 `redirect`，包含正确 `relay_sn`、assignment generation 和建议重试时间。
- 对 HTTP/HTTPS: 可返回 HTTP redirect、明确 JSON 错误，或在配置允许时 raw TCP forward 到正确 relay。
- 对 RTCP: 拒绝 tunnel 并返回正确 relay 信息。

迁移窗口内：

- old relay 可以继续服务已有 tunnel。
- old relay 不应接受新 tunnel，除非 assignment 仍允许 grace。
- new relay 应接受新 tunnel，并在稳定后让 manager 完成迁移。

## 目标接口草案

### Relay Manager 内部接口

```rust
#[async_trait::async_trait]
pub trait SnRelayManager {
    async fn register_relay_node(&self, node: RelayNodeRegistration) -> Result<RelayNode>;
    async fn heartbeat_relay_node(&self, heartbeat: RelayHeartbeat) -> Result<RelayNodeHealth>;
    async fn assign_zone_relay(&self, req: AssignZoneRelayReq) -> Result<RelayAssignment>;
    async fn get_zone_relay(&self, zone: &str) -> Result<Option<RelayAssignment>>;
    async fn check_relay_admission(&self, req: RelayAdmissionReq) -> Result<RelayAdmissionDecision>;
    async fn start_relay_migration(&self, req: RelayMigrationReq) -> Result<RelayAssignment>;
    async fn complete_relay_migration(&self, zone: &str, generation: u64) -> Result<()>;
}
```

第一版可以作为 Rust trait 和 SQLite 实现放在 `cyfs-sn` 内部；`sn_server`、`sn_resolver` 和边缘 `sn_relay` 通过内部 API 或 JSON-RPC 调用。

### SN API gateway 入口

建议保留在 `/kapi/sn` 或内部管理路径下：

- `relay.node.register`
- `relay.node.heartbeat`
- `relay.assignment.get`
- `relay.assignment.set`
- `relay.assignment.migrate`
- `relay.admission.check`
- `relay.admin.list_nodes`
- `relay.admin.list_assignments`

其中 admin 类接口必须要求 SN Admin 权限；`relay.admission.check` 必须要求 relay 节点凭证，并且 device 权限由 `sn_authority` 校验。

## 目标 SQLite 结构

第一版可以使用 SQLite 持久化控制面状态。实时 tunnel 不进入这些表。

```sql
CREATE TABLE IF NOT EXISTS relay_nodes (
    relay_id TEXT PRIMARY KEY,
    relay_sn TEXT NOT NULL UNIQUE,
    public_host TEXT NOT NULL,
    http_endpoint TEXT NULL,
    rtcp_endpoint TEXT NULL,
    region TEXT NULL,
    isp TEXT NULL,
    tags TEXT NULL,
    capabilities TEXT NOT NULL,
    status TEXT NOT NULL,
    capacity_score INTEGER NOT NULL DEFAULT 100,
    current_load INTEGER NOT NULL DEFAULT 0,
    last_heartbeat_at INTEGER NULL,
    drain_until INTEGER NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS relay_assignments (
    zone TEXT PRIMARY KEY,
    relay_id TEXT NOT NULL,
    relay_sn TEXT NOT NULL,
    state TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT NULL,
    generation INTEGER NOT NULL,
    backup_relay_id TEXT NULL,
    sticky_until INTEGER NULL,
    lease_expires_at INTEGER NULL,
    migrated_from TEXT NULL,
    migration_deadline INTEGER NULL,
    source_version TEXT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_relay_assignments_relay
    ON relay_assignments(relay_id, state);

CREATE TABLE IF NOT EXISTS relay_admission_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NULL,
    relay_id TEXT NOT NULL,
    zone TEXT NOT NULL,
    device_name TEXT NULL,
    did TEXT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    expected_relay_sn TEXT NULL,
    assignment_generation INTEGER NULL,
    observed_ip TEXT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_relay_admission_events_zone_time
    ON relay_admission_events(zone, created_at);

CREATE TABLE IF NOT EXISTS relay_allocation_pending (
    zone TEXT PRIMARY KEY,
    preferred_region TEXT NULL,
    reason TEXT NOT NULL,
    source_version TEXT NULL,
    attempts INTEGER NOT NULL DEFAULT 1,
    last_error TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

## 关键流程

### 首次分配 relay

1. 用户完成注册或 bind zone。
2. `sn_bns_controller` 发布 BNS `zone` / `boot` 文档。
3. `sn_auth` 写入或刷新 `zone_info`。
4. `sn_relay_manager` 根据 zone、from_ip、region 和健康状态分配 relay。
5. `sn_relay_manager` 写入 `relay_assignment`。
6. `sn_relay_manager` 更新 `sn_auth.zone_info.relay_sn`。
7. node_daemon 查询 zone_info，向 `relay_sn` 发起 `keep_tunnel`。

### device keep_tunnel

1. node_daemon 周期查询 zone_info，得到当前 `relay_sn`。
2. node_daemon 向该 `sn_relay` 建立 RTCP keep tunnel。
3. `sn_relay` 校验 device token。
4. `sn_relay` 调用 `sn_relay_manager.check_relay_admission`。
5. manager 返回 `allow` 后，relay 建立或续约本地 tunnel。
6. 如果 zone 已迁移，manager 返回正确 relay，relay 返回 redirect。

### HTTP/HTTPS 访问 gateway

1. 浏览器访问 `sn_relay`。
2. `sn_relay` 从 Host/SNI 得到 target hostname。
3. `sn_relay` 调用 `sn_resolver` 得到目标 zone、gateway device 和 `self_cert`。
4. `sn_relay` 调用 `sn_relay_manager` 确认该 zone 属于当前 relay。
5. `sn_relay` 选择 80/443 等目标端口。
6. `sn_relay` 通过本地 RTCP tunnel 转发到 gateway device。
7. 如果 tunnel 不存在或不可用，返回 503 或触发受控重建。

### relay 故障切换

1. manager 检测 relay heartbeat 超时或错误率过高。
2. manager 标记 relay 为 `unhealthy` 或 `draining`。
3. manager 为受影响 zone 选择新 relay。
4. manager 更新 `relay_assignment.generation` 和 `sn_auth.zone_info.relay_sn`。
5. node_daemon 周期查询后连接新 relay。
6. old relay 的本地 tunnel 自然过期或被 drain 清理。

## 安全和准入原则

- `keep_tunnel` 必须使用 device 私钥签名 token，不能只依赖 SN 用户 session。
- `sn_relay_manager` 消费 `sn_authority` 的权限上下文，不应在业务模块里重复解析 token。
- 用户 session token 不能直接修改 `relay_sn` 或 relay assignment。
- Relay Admin 操作必须有独立 admin 权限和审计。
- relay 节点之间不能互相信任任意转发请求；跨 relay forward 必须携带可验证的 assignment 或内部凭证。
- Host/SNI、DID、zone、device_name 必须经过 `sn_resolver` 和 BNS/本地状态校验。
- admission TTL 和 assignment generation 必须短期有效，防止迁移后旧准入长期可用。
- 应限制单 zone、单 device、单来源 IP 的连接数、并发 stream 和流量。
- relay 节点错误信息应足够排障，但不能泄漏敏感 token、私钥或内部拓扑细节。

## 迁移建议

1. ✅ 已完成：在 `cyfs-sn` 内新增 `sn_relay_manager` trait 和 SQLite 实现，支持节点表、assignment 表、admission 事件表、allocation pending 表和 `get/check` 能力（`relay_mgr.rs`）。
2. 🟡 部分完成：relay 表达已迁移到 `relay_assignments` + `zone_info.relay_sn`，新写入不再用 `sn_ips` 表达 relay；旧 `sn_ips` 兼容输入回填尚未实现。
3. ✅ 已完成：`sn_auth.zone_info` 已有 `relay_sn` 字段，并由 `sn_relay_manager.sync_zone_relay_cache` 回写（`relay_mgr.rs:666-678`）。
4. 🟡 部分完成：`query_device_by_hostname` 已优先走 `sn_resolver.resolve_gateway_by_hostname`，`ood1` 降级为兜底默认（`sn_server.rs:2586-2603`，兜底分支 `:2620`）；尚未彻底移除硬编码兜底（`sn_server.rs:1862` 仍有 TODO）。
5. 🟡 部分完成：设备在线态已部分迁移到 `sn_device_info`，但旧 `devices.ip` / `description` 仍在，relay 所需的完整 reachability view 未成形。
6. ⛔ 待实现（阶段二）：数据面 `sn_relay` 节点尚不存在；`check_relay_admission` 已实现但**零调用方**，未通过内部 API 接入任何实时准入路径。
7. 🟡 部分完成：`assign_zone_relay(source=Admin)` 与 `start_relay_migration` 支持手工调整，但缺独立 admin 鉴权与 assignment/migration 审计事件（仅 admission 有审计）。
8. 🟡 部分完成：heartbeat、drain、迁移窗口已实现（`relay_mgr.rs`）；心跳超时检测和故障切换自动化尚未实现。

## 当前实现状态

### 第一阶段已完成（控制面）

- 独立的 `sn_relay_manager` 控制面模块 `relay_mgr.rs`：`SnRelayManager` trait（`:290-302`）+ `SqliteSnRelayManager` 实现。
- `relay_nodes` / `relay_assignments` / `relay_admission_events` / `relay_allocation_pending` 四张表与 doc 目标 schema 对齐。
- 节点注册与心跳：`register_relay_node`（`:1050-1122`）、`heartbeat_relay_node`（`:1124-1190`）。
- zone -> relay 分配：`assign_zone_relay`（`:1192-1250`）+ `choose_relay_node` 评分（region 命中 → 负载/容量比 → capacity，`:548-557`）与 sticky 复用（`:532-546`）；首次 keep_tunnel 自动建分配（`:713-740`）。
- 注册自动分配：`allocate_zone_relay` 以 zone 为幂等键，消费非可信 `preferred_region` 与服务端观察到的强类型 `source_ip`，按配置的有序规则和 fallback 选择健康节点；注册 handler 在本地建号后调用，失败写 `relay_allocation_pending` 且不回滚账号。成功结果统一回写 `zone_info.relay_sn`。
- GeoIP：`GeoIpResolver` 可注入测试实现，生产 `XdbGeoIpResolver` 直接封装 `sfo-ip`/ip2region XDB，不依赖 process-chain collection；私网/loopback/保留地址和查询失败均降级。
- `keep_tunnel` 准入决策 `check_relay_admission`（`:1263-1396`）：allow / reject / redirect，错误 relay 返回 `expected_relay_sn` 和 `generation`，draining / suspended / stale-generation / device-binding 等分支齐全，并写 admission 审计事件。
- 迁移窗口：`start_relay_migration`（`:1398-1450`）+ `complete_relay_migration`（`:1452-1455`），含 generation 单调递增、`migrated_from`、默认 300s 迁移窗口。
- `sync_zone_relay_cache` 回写 `zone_info.relay_sn`（`:666-678`）。
- 查询能力：`get_zone_relay`、`list_zone_relays_by_node`、`zone_belongs_to_relay`（`:1252-1261`、`:473-490`、`:492-501`）。
- resolver 集成：`SnRelayManagerResolverReader` 让 `sn_resolver` 读取当前 `relay_sn`（`sn_resolver.rs:644-661`，装配于 `sn_server.rs:681`）。
- 以上控制面能力均有单元测试（`relay_mgr.rs` 末尾 `mod tests`）。

### 待实现（阶段二 / 三）

- `check_relay_admission` 目前是**孤儿 API**，除自身和测试外**零调用方**，未接入任何实时准入路径。
- **没有数据面 `sn_relay` 节点模块**；没有咨询 manager 的 HTTP/HTTPS / RTCP 转发，无跨 zone 准入执行，无 80/443 端口选择落地。
- admission 内**无 token / `sn_authority` 校验**（`auth_context` 被接收但未验证，`TokenInvalid` 永不返回）；设备绑定校验仅查 DB。
- **无心跳超时检测与故障切换自动化**：`Unhealthy` 仅靠下一次心跳翻回 `Active`，无后台扫描，`RelayAssignmentSource::Recovery` 从不产生。
- register 已触发自动分配；bind zone / `update_ood_info` 尚未触发补偿分配，`lease_expires_at` 被存储但从不评估与重分配。
- 迁移 / admin 操作**无审计事件**（`operator` 被接收但丢弃），且手工调整缺独立 admin 鉴权。
- **无 `relay.*` API gateway 入口**，控制面目前只能进程内调用。
- `query_device_by_hostname` 的 `ood1` 兜底尚未彻底移除（`sn_server.rs:1862` TODO）。
- 设备在线态仍并存于旧 `devices` 表与简化 `sn_device_info` 表，尚未形成 relay 所需的完整 reachability view。

### 自动分配配置

SN server 可选配置：

```yaml
relay_allocation:
  # 按顺序执行；首个产生健康候选集的规则获胜。
  match_rules:
    - preferred_region
    - geo_country_code
    - geo_province
    - geo_city
    - geo_isp
  # relay_id 或 relay_sn；`*` 表示全部健康节点。显式空数组禁用 fallback。
  fallback_relays: [relay-us-a, relay-eu-a]
  geoip:
    # 相对路径按网关主配置目录解析。
    ipv4_xdb_path: geoip/ip2region_v4.xdb
    ipv6_xdb_path: geoip/ip2region_v6.xdb
    cache_policy: vector_index # no_cache | vector_index | full_memory
```

节点的 `region` 与 `isp` 字段参与匹配，也可使用 `region:<label>`、`country:<code>`、`province:<label>`、`city:<label>`、`isp:<label>` tags。候选集内部按 `current_load / capacity_score`、capacity、relay_id 稳定排序。未配置 `relay_allocation` 时默认使用上述规则并以 `fallback_relays: ["*"]` 保持兼容行为。
