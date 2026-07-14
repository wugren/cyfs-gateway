# SN-DeviceInfo-DB

`sn_device_info` 是 SN 内置的设备状态管理组件，负责保存和查询设备在线态、可达地址、endpoint、NAT/公网判断结果和最近上报时间。

本版本是 breaking change，不考虑兼容旧表结构、旧接口或旧调用语义。本文只描述目标设计。

## 设计定位

`sn_device_info` 独立出来的原因不是它拥有独立业务权限，而是它的写入和查询频度都显著高于账号、BNS 写入、domain proof 等低频状态。独立边界用于支撑两种部署：

- All-in-one 模式：作为 SN API Server 进程内组件运行。
- 独立服务模式：作为进程外内部服务运行。

`sn_device_info` 是纯状态管理组件。它只负责状态的增删改查、过期、索引和查询视图，不负责业务编排。

负责：

- 维护 DID、zone、device_name 到设备状态的索引。
- 写入设备在线态、上报 IP、请求来源 IP、NAT/公网状态、endpoint。
- 根据 TTL、上报序号和更新时间维护 `online | offline | stale | blocked` 等状态。
- 为上游模块提供按 DID 或 `zone + device_name` 查询的状态视图。
- 记录设备状态关键变更事件。

不负责：

- 用户、密码、token、session、owner key、controller key。
- 鉴权、签名验证、权限判断。
- BNS name、BNS `device_mini_doc`、`zone`、`boot`、`dns_txt` 的发布或验证。
- 判断某个 hostname 的权威 gateway device 是谁。
- DNS 记录合成、relay 调度、relay 准入策略。
- ACME、domain proof、user_domain 绑定。

BNS `device_mini_doc` 是设备身份和基础配置的权威文档；`sn_device_info` 只保存调用方传入的设备状态索引和运行时状态。调用方必须在调用前完成 BNS、鉴权和业务合法性校验。

## 部署形态

组件必须支持同一套接口的两种实现。

### All-in-one 模式

组件作为 SN API Server 进程内模块运行。

- 调用方直接持有本地 service / trait 实例。
- service 直接访问 SQLite。
- 不需要监听端口。
- 适合单机开发、小规模部署和默认部署。

### 独立服务模式

组件作为进程外内部服务运行。

- SN API Server 通过内部 RPC client 调用。
- DeviceInfo 服务监听配置的端口。
- DeviceInfo 服务进程本地持有 SQLite DB。
- 适合高频状态读写从 SN API Server 中拆出去的部署。

独立服务仍然是内部组件，不是公网 API。因为组件不做鉴权，监听地址和端口必须通过部署约束保护，例如只绑定 `127.0.0.1`、内网地址、防火墙、sidecar 或同机进程管理。

## 初始化模式

创建接口必须支持两种模式。

### 本地模式

只要有 SQLite DB 路径就可以初始化成功。

输入：

- `mode = "local"`
- `sqlite_path`

行为：

- 打开或创建 `sqlite_path`。
- 初始化目标 schema。
- 返回本地状态管理 service。
- 不依赖任何远程端口。

### 远程模式

需要配置端口。

输入：

- `mode = "remote"`
- `port`
- `host` 可选，默认 `127.0.0.1`

行为：

- 在 SN API Server 侧创建 remote client。
- client 暴露和本地模式一致的状态管理接口。
- DeviceInfo 服务端使用自己的 `sqlite_path` 初始化本地存储并监听 `port`。

远程模式的 client 创建参数不包含 SQLite 路径；SQLite 路径属于 DeviceInfo 服务端配置。

## 鉴权边界

`sn_device_info` 原则上不负责鉴权。所有调用它的入口必须先完成鉴权和业务校验。

调用前应由上游完成：

- Owner/session/device token 校验。
- device token 与 DID、zone、device_name 的一致性校验。
- BNS `device_mini_doc` 与 DID、公钥、zone/device_name 的一致性校验。
- 调用者是否允许注册、更新、查询某个设备状态。
- 远程服务端口访问范围控制。

组件内部只做状态一致性检查：

- DID、zone、device_name 不能为空。
- DID 和 `zone + device_name` 的唯一索引不能冲突。
- `report_seq` 或上报时间不能让明显旧状态覆盖新状态。
- endpoint、IP、TTL、状态枚举必须格式有效。
- 已 blocked 的设备不能被普通在线上报改回 online，除非调用显式 unblock 接口。

## 核心对象

### device_index

设备索引用于在 DID 和 `zone + device_name` 之间建立查询关系。

字段：

- `did`: 设备 DID，主键。
- `zone`: 所属 zone 或 BNS name。
- `device_name`: zone 内设备名。
- `device_role`: `gateway | ood | normal | unknown`。
- `created_at`
- `updated_at`

约束：

- `did` 唯一。
- `(zone, device_name)` 唯一。
- 更新 DID 或 `(zone, device_name)` 绑定必须显式调用 replace/rebind 接口，不能通过普通状态上报隐式改变。

### device_runtime_state

设备运行态是核心状态记录。

字段：

- `did`: 设备 DID，主键，引用 `device_index.did`。
- `state`: `online | offline | stale | blocked`。
- `reported_ip`: 设备主动上报的首选 IP。
- `reported_ips`: 设备上报的候选 IP 列表，JSON 数组。
- `from_ip`: 上游入口观察到的请求来源 IP。
- `wan_ip`: 经规则筛选后的公网候选 IP。
- `lan_ips`: 内网候选 IP 列表，JSON 数组。
- `nat_type`: `public | private | symmetric | unknown`。
- `is_wan_device`: 是否认为设备可直接公网访问。
- `last_seen_at`: 最近一次可信上报时间。
- `last_report_at`: 最近一次收到上报时间。
- `expires_at`: 在线态过期时间。
- `report_seq`: 设备侧单调递增序号或上报时间戳。
- `raw_report`: 原始上报 JSON。
- `created_at`
- `updated_at`

约束：

- `reported_ip` 和 `reported_ips` 是设备自报数据，不直接等同于可公开发布地址。
- `from_ip` 是上游入口观察值，必须和设备自报 IP 分开保存。
- `wan_ip`、`lan_ips`、`is_wan_device` 是状态管理组件根据输入和规则计算出的状态字段。
- 私有地址、loopback、link-local 等不能进入 `public_ips` 查询视图。

### device_endpoint

endpoint 表示当前可用于连接设备的候选连接入口。

字段：

- `did`
- `endpoint_id`
- `protocol`: `tcp | udp | quic | rtcp | http | https`
- `host`
- `port`
- `scope`: `public | private | relay | loopback | unknown`
- `priority`: 数值越小优先级越高。
- `source`: `device_report | from_ip | relay_observed | admin`
- `state`: `active | stale | failed | disabled`
- `last_seen_at`
- `expires_at`
- `created_at`
- `updated_at`

约束：

- 一个 DID 可以有多个 endpoint。
- endpoint 过期后不能作为 active 结果返回。
- disabled endpoint 只能由显式 enable/replace 操作恢复。

### device_state_view

`device_state_view` 是查询输出，不是额外权威状态。

字段：

- `did`
- `zone`
- `device_name`
- `device_role`
- `state`
- `public_ips`
- `private_ips`
- `active_endpoints`
- `preferred_endpoint`
- `nat_type`
- `is_wan_device`
- `last_seen_at`
- `expires_at`

用途：

- `sn_resolver` 读取该视图后自行决定 DNS A/AAAA 输出。
- relay 读取该视图后自行结合 relay 调度策略决定是否转发。
- SN Admin 读取该视图展示设备状态。

`sn_device_info` 不根据 hostname 选择 gateway device，也不决定 resolver 或 relay 的业务策略。

### device_state_event

状态事件用于审计和排障。

字段：

- `id`
- `did`
- `event_type`: `registered | rebound | online | offline | stale | blocked | unblocked | endpoint_changed | report_rejected`
- `old_state`
- `new_state`
- `reason`
- `event_at`
- `detail`

事件表只记录关键状态变化，不替代主状态表。

## SQLite Schema

目标 schema 不需要兼容旧表。

```sql
CREATE TABLE IF NOT EXISTS device_indexes (
    did TEXT PRIMARY KEY,
    zone TEXT NOT NULL,
    device_name TEXT NOT NULL,
    device_role TEXT NOT NULL DEFAULT 'unknown',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(zone, device_name)
);

CREATE TABLE IF NOT EXISTS device_runtime_states (
    did TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    reported_ip TEXT NULL,
    reported_ips TEXT NULL,
    from_ip TEXT NULL,
    wan_ip TEXT NULL,
    lan_ips TEXT NULL,
    nat_type TEXT NOT NULL DEFAULT 'unknown',
    is_wan_device INTEGER NOT NULL DEFAULT 0,
    last_seen_at INTEGER NULL,
    last_report_at INTEGER NULL,
    expires_at INTEGER NULL,
    report_seq INTEGER NULL,
    raw_report TEXT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    FOREIGN KEY(did) REFERENCES device_indexes(did)
);

CREATE TABLE IF NOT EXISTS device_endpoints (
    did TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NULL,
    scope TEXT NOT NULL DEFAULT 'unknown',
    priority INTEGER NOT NULL DEFAULT 100,
    source TEXT NOT NULL,
    state TEXT NOT NULL,
    last_seen_at INTEGER NULL,
    expires_at INTEGER NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(did, endpoint_id),
    FOREIGN KEY(did) REFERENCES device_indexes(did)
);

CREATE TABLE IF NOT EXISTS device_state_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    did TEXT NOT NULL,
    event_type TEXT NOT NULL,
    old_state TEXT NULL,
    new_state TEXT NULL,
    reason TEXT NULL,
    event_at INTEGER NOT NULL,
    detail TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_indexes_zone_name
    ON device_indexes(zone, device_name);

CREATE INDEX IF NOT EXISTS idx_device_runtime_state_expires
    ON device_runtime_states(state, expires_at);

CREATE INDEX IF NOT EXISTS idx_device_endpoints_did_state_priority
    ON device_endpoints(did, state, priority);

CREATE INDEX IF NOT EXISTS idx_device_state_events_did_time
    ON device_state_events(did, event_at);
```

## 状态管理接口

接口命名可按实现语言调整，但语义应保持稳定。本地 service 和远程 client 必须暴露同一组接口。

### create / open

本地模式：

- 输入：`sqlite_path`
- 输出：本地 `DeviceInfoStateStore`

远程模式：

- 输入：`host`、`port`
- 输出：远程 `DeviceInfoStateStore` client

### upsert_device_index

创建或更新设备索引。

输入：

- `did`
- `zone`
- `device_name`
- `device_role`

行为：

- 新 DID 创建 `device_index`。
- 已存在 DID 且 `zone + device_name` 未变化时，更新 `device_role`。
- 已存在 DID 但 `zone + device_name` 变化时，返回冲突错误，要求调用 `rebind_device_index`。
- 如果新的 `(zone, device_name)` 已绑定其它 DID，返回冲突错误。
- 不校验调用者是否有权绑定该 DID。

### rebind_device_index

显式重绑设备索引。

输入：

- `did`
- `new_zone`
- `new_device_name`
- `new_device_role`
- `reason`

行为：

- 如果 DID 不存在，返回 `NotFound`。
- 如果新的 `(zone, device_name)` 已绑定其它 DID，返回冲突错误。
- 更新 `device_index`。
- 保留该 DID 的 runtime state 和 endpoint。
- 记录 `rebound` 事件。
- 不校验调用者是否有权重绑该 DID。

### remove_device_index

删除设备索引和关联状态。

输入：

- `did`

行为：

- 删除 `device_runtime_state`。
- 删除关联 endpoint。
- 删除 `device_index`。
- 保留 `device_state_events`。

### update_device_state

写入设备运行态。

输入：

- `did`
- `reported_ip`
- `reported_ips`
- `from_ip`
- `nat_type`
- `endpoints`
- `report_seq`
- `ttl`
- `raw_report`

行为：

- 根据 DID 找到设备索引。
- 如果 DID 不存在，返回 `NotFound`。
- 如果 `report_seq` 明显旧于当前记录，拒绝写入并记录 `report_rejected`。
- 更新 runtime state。
- 根据 IP 规则计算 `wan_ip`、`lan_ips`、`is_wan_device`。
- upsert endpoint。
- 设置 `expires_at = now + ttl`。
- 必要时记录 `online` 或 `endpoint_changed` 事件。

### get_device_state

按 DID 查询设备状态。

输入：

- `did`

输出：

- `device_state_view`

行为：

- 如果 runtime state 已过期，返回 `stale` 视图，或先将状态落库为 `stale` 再返回。
- 不返回过期或 disabled endpoint 作为 active endpoint。

### get_device_state_by_name

按 `zone + device_name` 查询设备状态。

输入：

- `zone`
- `device_name`

输出：

- `device_state_view`

### list_zone_devices

列出某个 zone 下的设备状态。

输入：

- `zone`
- 可选 `state`
- 可选分页参数。

输出：

- `device_state_view` 列表。

### mark_device_offline

显式标记设备离线。

输入：

- `did`
- `reason`

行为：

- 将 runtime state 更新为 `offline`。
- 将 active endpoint 更新为 `stale`。
- 记录 `offline` 事件。

### block_device / unblock_device

显式阻断或恢复设备状态。

输入：

- `did`
- `reason`

行为：

- `block_device` 将 state 设置为 `blocked`，并禁用 active endpoint。
- `unblock_device` 将 state 设置为 `offline`，等待下一次上报变为 `online`。
- 记录 `blocked` 或 `unblocked` 事件。

### expire_devices

批量过期在线态。

输入：

- `now`
- 可选批量大小。

行为：

- 找出 `expires_at < now` 且 state 为 `online` 的设备。
- 将状态更新为 `stale`。
- 将过期 endpoint 更新为 `stale`。
- 记录 `stale` 事件。

## IP 和 endpoint 规则

`sn_device_info` 可以计算状态字段，但不决定业务输出。

公网候选 IP：

- 排除 RFC1918 私有 IPv4。
- 排除 loopback、link-local、multicast、unspecified。
- 排除 ULA IPv6、link-local IPv6、loopback IPv6、unspecified IPv6。
- 允许公网 IPv4/IPv6 进入 `public_ips` 视图。

内网候选 IP：

- 可保存到 `private_ips`，供 relay 或 admin 查询使用。
- 不由组件直接发布到 DNS。

endpoint 优先级：

- active 优先于 stale/failed/disabled。
- priority 小的优先。
- public scope 优先于 private scope，除非调用方另有策略。
- expired endpoint 不进入 active 列表。

## 与其它模块的关系

### SN API Server

SN API Server 是主要调用方。

- 负责鉴权和业务校验。
- 负责把外部 RPC 请求转换为状态管理调用。
- 负责决定什么时候写入设备索引、什么时候更新运行态。

### BNS / sn_bns_controller

`sn_device_info` 不调用 BNS，也不发布 BNS 文档。

- BNS 决定设备身份和基础配置权威状态。
- `sn_bns_controller` 负责 BNS 写操作。
- 上游确认 BNS 状态后，可以调用 `sn_device_info` 更新本地设备索引。

### sn_resolver

`sn_resolver` 可以读取 `device_state_view`。

- hostname 到 gateway device 的选择由 BNS `zone` / `boot` 或 resolver 规则决定。
- `sn_device_info` 只按 DID 或 `zone + device_name` 返回状态。
- DNS A/AAAA 的最终输出由 resolver 决定。

### sn_relay_manager / relay

relay 相关模块可以读取 `device_state_view` 和 endpoint。

- zone -> relay 归属由 `sn_relay_manager` 决定。
- relay tunnel 实时连接状态由 relay 运行时维护。
- `sn_device_info` 只保存设备最后一次上报和可达性状态。

## 错误语义

建议错误类型：

- `InvalidInput`: DID、zone、device_name、IP、endpoint、TTL 或状态枚举非法。
- `NotFound`: DID 或 `zone + device_name` 不存在。
- `Conflict`: DID 与 `zone + device_name` 唯一索引冲突。
- `StaleReport`: 上报序号或时间早于当前状态。
- `Blocked`: 设备已 blocked，普通状态上报不能覆盖。
- `StorageError`: SQLite 或底层存储错误。
- `RemoteError`: 远程模式连接、超时或协议错误。

## 运维要求

- 进程外服务必须有健康检查接口。
- 远程 client 必须设置连接超时和请求超时。
- 高频写入接口应避免长事务。
- `expire_devices` 可以由 SN API Server 定时触发，也可以由独立服务内部定时触发。
- 状态事件表应有保留策略，避免无限增长。
- 关键指标应包括写入 QPS、查询 QPS、SQLite 错误数、过期设备数、stale report 拒绝数、远程调用延迟。

## 当前实现状态（阶段一）

本节只记录当前实现现状，不修改上文的目标设计。重构第一阶段已落地进程内（local）组件，remote 模式和部分运维要求留待阶段二。

### 已完成

- ✅ `sn_device_info` 组件已实现为进程内 SQLite 状态管理组件（`src/components/cyfs-sn/src/sn_device_info.rs:328`，trait `SnDeviceInfoDB` 定义于 `:292`）。
- ✅ 四张表 schema 与本文逐字段对齐：
  - `device_indexes`（`sn_device_info.rs:402`）
  - `device_runtime_states`（`sn_device_info.rs:419`）
  - `device_endpoints`（`sn_device_info.rs:448`）
  - `device_state_events`（`sn_device_info.rs:474`）
  - 四个索引也按本文创建（`sn_device_info.rs:492-534`）。
- ✅ 11 个状态管理接口方法语义完整：
  - `upsert_device_index`（`sn_device_info.rs:1236`，含 `(zone,device_name)` 变化时返回 `Conflict`、要求显式 rebind）
  - `rebind_device_index`（`sn_device_info.rs:1335`，NotFound/Conflict 校验、保留 runtime/endpoint、记录 `rebound`）
  - `remove_device_index`（`sn_device_info.rs:1412`，删除 runtime/endpoint/index，保留事件）
  - `update_device_state`（`sn_device_info.rs:1459`，含 blocked 拒绝 + `report_rejected`、stale-seq 拒绝 + `StaleReport`、wan/lan 分类、`expires_at = now + ttl`、endpoint upsert、`online`/`endpoint_changed` 事件）
  - `get_device_state` / `get_device_state_by_name`（`sn_device_info.rs:1713` / `:1726`，过期时先落库为 `stale` 再返回视图）
  - `list_zone_devices`（`sn_device_info.rs:1741`，支持 state 过滤与分页）
  - `mark_device_offline`（`sn_device_info.rs:1771`）
  - `block_device` / `unblock_device`（`sn_device_info.rs:1781` / `:1791`）
  - `expire_devices`（`sn_device_info.rs:1823`，过期 `online` → `stale`，含批量大小）
- ✅ `device_state_view` 已接入上游读侧：
  - resolver 经 `SnDeviceInfoResolverReader` 读取（`src/components/cyfs-sn/src/sn_resolver.rs:597`）。
  - relay 经 `relay_mgr` 读取（`src/components/cyfs-sn/src/relay_mgr.rs:681`）。
- ✅ IP 与 endpoint 规则已实现：公网 IP 过滤（`is_public_ipv4`/`is_public_ipv6`，`sn_device_info.rs:639` / `:667`）、wan/lan 分类（`classify_ips`，`sn_device_info.rs:710`）、endpoint 优先级排序（`endpoint_sort_key`，`sn_device_info.rs:799`，public < relay < private < loopback < unknown，再按 priority）。
- ✅ 与 BNS 解耦正确：组件内不做 BNS/mini_doc 校验；mini_config_jwt 解码与 DID 一致性校验在调用方侧（`src/components/cyfs-sn/src/api/device.rs:27-39`）。
- ✅ 错误类型基本对齐（`SnErrorCode`，`src/components/cyfs-sn/src/lib.rs:26`）：`InvalidInput`、`NotFound`、`Conflict`、`StaleReport`、`Blocked`、`RemoteError` 均已定义；本文的 `StorageError` 当前以 `DBError` 表示。

### 待实现（阶段二）

- ❌ remote 独立服务模式与健康检查完全未实现：仅有 `open_local`（`sn_device_info.rs:362`）；`RemoteError` 已定义但未使用，没有 remote client、监听端口或健康检查接口。
- 🟡 生产调用方未完整驱动组件能力：`sync_device_online_state`（`src/components/cyfs-sn/src/sn_server.rs:775-824`）始终传 `from_ip = None`、`nat_type = Unknown`、`report_seq = None`，导致已实现的 from_ip/NAT 检测与 stale-report 拒绝机制在真实上报路径中空转；`device_role` 仍是 `device_name == "ood1"` 的硬编码判断（`sn_server.rs:783`，从不赋 `gateway`），`ttl` 硬编码 300，endpoint `scope` 恒为 `Public`。
- 🟡 API 读路径尚未迁移：旧 `devices` 表（`src/components/cyfs-sn/src/sqlite_db.rs:70`，`register_device` `:926`）仍是 `device.get` / `device.list` / `query_by_did` 的权威来源（`api/device.rs:69-111`）；新组件目前仅 resolver/relay 读取，写入由 server 并行双写。
- ❌ 状态事件表无保留策略：`device_state_events` 只插入、从不清理。
- ❌ 无运维指标、健康检查与远程调用超时（remote 模式缺失时后者暂不适用）。
