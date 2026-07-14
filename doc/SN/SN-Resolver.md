# SN-Resolver

`sn_resolver` 是 SN 内部的统一解析工具库。它负责把 hostname、DID、BNS name、zone、device_name 等输入解析成 DNS、DID document、gateway device、relay、证书状态等调用方需要的结果。

当本文和当前 `cyfs-sn` 实现冲突时，以 `doc/SN/新SN核心流程整理.md` 的设计意图为准；当前实现只作为兼容行为、字段来源和迁移状态的参考。

## 目标

- 为 DNS server、HTTP relay、RTCP relay、node_daemon 查询、DID HTTP resolver 和 JSON-RPC query 接口提供同一套解析逻辑。
- 明确 BNS 权威文档、SN 本地账号状态、设备在线状态和 relay 分配之间的查询优先级。
- 消除旧实现中散落在 `SNServer` 上的解析逻辑，避免 DNS、HTTP relay、DID resolver 得到不一致结果。
- 把解析结果定义为合成数据，不额外引入新的权威存储。
- 兼容现有 `cyfs-sn` 的 `/kapi/sn`、`/kapi/sn/bns`、DNS `NameServer` 和 DID resolver 行为，给迁移留下明确边界。

## 非目标

- 不负责注册、绑定、写 BNS document 或写本地 DB。
- 不签发或校验登录 token，不替代 `sn_authority`。
- 不决定 BNS owner/controller 权限。
- 不维护设备在线心跳，不替代 `sn_device_info`。
- 不维护 zone 到 relay 的分配，不替代 `sn_relay_manager`。
- 不执行 ACME 签发流程，只读取 DNS TXT 和 `self_cert` 状态。

## 权限边界

`sn_resolver` 是只读模块。它可以被公开查询入口调用，因此不能把“能解析到数据”解释为“调用方有权访问后端服务”。

- DNS A/AAAA/TXT 查询默认公开。
- DID document 查询默认公开，但只能返回可公开的 document 或公开设备信息。
- HTTP relay 和 RTCP relay 可以使用 resolver 找到目标 zone/device/relay，但准入判断必须交给 `sn_relay_manager` 和对应 relay 策略。
- node_daemon 查询自己的 `zone_info` 时，身份校验应由 API handler 或 `sn_authority` 完成，resolver 只读取并合成结果。
- 涉及 BNS 修改的请求必须走 `sn_bns_controller`，不能通过 resolver 旁路写入。

## 数据来源

### BNS 权威状态

权威源是 BNS 合约，`sn_resolver` 经 `bns-indexer` 的只读投影读取：

- name owner / owner_config。
- authority key 和 controller policy。
- `zone` document。
- `boot` document。
- `device_mini_doc` document。
- `dns_txt` document。
- document version、name seq、更新时间等元数据。

BNS document 是名字、zone 拓扑、gateway device 声明、设备基础身份和 DNS TXT 的权威来源。

### SN 本地状态

来自 `sn_auth`：

- `sn_user <-> user_domain` 绑定关系。
- `zone_info` 运行态缓存，例如 `self_cert`、当前 relay 分配结果、兼容旧实现的 `sn_ips`。
- 本地 user DNS records 的兼容数据。

来自 `sn_device_info`：

- device 当前在线状态。
- device 上报 IP、from_ip、NAT/公网判断、最近更新时间。
- device 描述中可导出的 `ip`、`ips`、`all_ip`。

来自 `sn_relay_manager`：

- zone 当前分配的 relay SN。
- relay 节点健康状态。
- 手工调整和迁移状态。

## 输入归一化

所有入口在进入查询流程前应做统一归一化：

- hostname 去掉末尾 `.`，转小写。
- record type 规范为 `A`、`AAAA`、`TXT`。第一阶段只支持这三类；其它类型返回不支持或继续交给上游递归 resolver。
- BNS name / username 按 `buckyos-kit::is_valid_name` 和注册规则校验。
- DID 使用 `name_lib::DID::from_str` 解析，只接受明确支持的 method。
- device_name 保持大小写敏感还是小写，必须与 BNS `device_mini_doc` 的声明一致；解析层不应自行猜测。

旧实现只去掉 DNS 末尾 `.`，cache key 中会转小写；新实现应把归一化提前到 resolver 入口，避免 cache、DNS、HTTP、DID 行为不一致。

## 核心输出类型

### ZoneResolution

用于描述一个 hostname / DID / name 最终归属的 zone：

```text
ZoneResolution {
  input: String,
  canonical_name: String,
  zone_name: String,
  owner: BnsOwner,
  zone_doc: ZoneDocument,
  boot_doc: BootDocument,
  user_domain: Option<String>,
  self_cert: bool,
  relay_sn: Option<String>,
  source: BnsName | UserDomain | LegacyWeb3Host,
}
```

`self_cert` 来自 `sn_auth.zone_info` 的运行态；不能把它写入 BNS 权威 document 后再由 resolver 反向推断。

### GatewayResolution

用于 HTTP relay、DNS A/AAAA 和 node_daemon 查询 gateway：

```text
GatewayResolution {
  zone_name: String,
  hostname: String,
  gateway_device_name: String,
  gateway_did: String,
  device_doc: DeviceMiniDocument,
  online: Option<DeviceOnlineInfo>,
  addresses: Vec<IpAddr>,
  relay_sn: Option<String>,
  self_cert: bool,
}
```

`gateway_device_name` 必须来自 BNS `zone` 或 `boot` 文档。旧实现中写死 `ood1` 只是兼容行为，不能作为新设计依赖。

### DnsResolution

用于 DNS server：

```text
DnsResolution {
  hostname: String,
  record_type: A | AAAA | TXT,
  ttl: u32,
  addresses: Vec<IpAddr>,
  txt: Vec<String>,
  source: ExplicitRecord | BnsDocument | DeviceOnlineInfo | SnSelf,
}
```

同一 hostname 的 TXT 可以来自多个 document 合并；A/AAAA 则按优先级选择并去重。

### DidResolution

用于 DID HTTP resolver 和 `query.resolve_did`：

```text
DidResolution {
  did: String,
  doc_type: String,
  document: Json | Jwt,
  source: BnsDocument | DeviceMiniDocument | DeviceOnlineInfo | LegacyLocalDidDocument,
}
```

## Hostname 分类

resolver 应按以下顺序识别 hostname：

1. SN 自身 hostname：`sn.<server_host>`、`<server_host>`、配置的 aliases。
2. BNS 域名或 BNS 兼容域名。
3. `user_domain` 或其子域名。
4. 普通公网域名。

### SN 自身 hostname

用于引导和兼容旧 DNS 行为：

- `A/AAAA`: 返回当前 SN server IP，按 record type 过滤 IPv4/IPv6。
- `TXT`: 返回当前 SN 的 `PKX`、`BOOT`、可选 `DEV`。

已实现：SN 自身 hostname 的 A/AAAA/TXT 由 `SnResolver::resolve_self_dns` 处理（`src/components/cyfs-sn/src/sn_resolver.rs:1461`），`is_self_hostname` 识别 `sn.<host>`、`<host>` 和 aliases（`sn_resolver.rs:861`），并在 `resolve_dns` 入口优先命中（`sn_resolver.rs:959`）。`sn_server.rs` 中旧的 `query_name_info_uncached`（`sn_server.rs:3361`）已不再被调用，属于待清理的死代码（见“迁移步骤”）。

### BNS 兼容域名

旧实现支持 `*.web3.<server_host>`：

- `alice.web3.buckyos.ai` 映射到 username `alice`。
- `home.alice.web3.buckyos.ai` 映射到 username `alice`，`sub_host=home.alice`。
- `www-alice.web3.buckyos.ai` 映射到 username `alice`，这是兼容旧 URL 的规则。

新 resolver 可以保留该解析器作为 legacy adapter，但权威查询应转成 BNS name：

```text
alice.web3.<server_host> -> did:bns:alice / BNS name alice
home.alice.web3.<server_host> -> zone alice, service/subhost home
```

`sub_host` 不决定 BNS owner，只作为 HTTP relay 的目标 host 上下文传递。最终 gateway device 仍由 zone/boot 文档决定。

已实现（2026-07）：`resolve_zone_by_hostname` 末尾经 `bns_compat_name_for` 把
`<name>.web3.<server_host>` 及其子域映射到 BNS name（取 web3 前缀的末级
label；`www-alice` 连字符旧规则未实现——用户名可含 `-` 会误切，需要时用显式
dns record 覆盖）。同时 `resolve_gateway_addresses` 在无任何直接可达地址时
回退 SN 中继地址（用户 sn_ips 优先，否则 server_ip，不做回环过滤）——设备
离线的 LAN/relay 型 zone 的 A 记录由此指向 SN。覆盖用例：`e2e_sn_seed` T2。

过渡期内，用户还可以用 `user.add_dns_record` 在自己的
`<username>.web3.<server_host>` 及其子域写入 SN 本地显式记录；解析时该记录优先于
BNS bridge 合成结果。该例外用于避免 ACME 等短期记录产生链上 gas，未来在
`did:bns:xxx` 不再依赖 web3 bridge、或 DNS 服务已广泛原生支持该名字后，应让
BNS 名称的写入回归链上。具体 API 边界见 `SN-API.md` 的 `user.*` 小节。

### user_domain

`user_domain` 是传统 DNS 域名到 SN 用户或 BNS name 的绑定关系，第一阶段仍存放在 `sn_auth`。

解析规则：

- 精确命中 `user_domain` 时，映射到对应 `sn_user` / BNS name。
- 命中 `user_domain` 的子域名时，保留相对子域名作为 service/subhost。
- 如果存在显式本地 DNS record，优先返回该 record。
- 如果没有显式 A/AAAA，则解析该 zone 的 gateway device 并返回当前可达地址。
- 如果没有显式 TXT，则合并 BNS `zone`、`boot`、`dns_txt` 生成 TXT。

当前实现状态：

- 已实现：显式本地 DNS record 优先（`resolve_dns` 先查 `compatibility.query_domain_record`，命中即返回 `ExplicitRecord`，`sn_resolver.rs:963`）；精确 `user_domain` 命中映射到 `sn_user` / BNS name（`resolve_zone_by_hostname` 调用 `get_user_by_domain` → `resolve_zone_by_user`，`sn_resolver.rs:1055`）；无显式 A/AAAA 时回退到 gateway device 在线态、无显式 TXT 时合并 `zone`/`boot`/`dns_txt`。
- 待实现（阶段二）：`user_domain` **子域名转发解析仍只支持精确匹配**。`get_user_by_domain` 是精确 DB 查询，`home.alice.example.com` 无法回退到父 `user_domain` `alice.example.com` 并保留相对子域名作为 service/subhost（子域名剥离目前只存在于 `did:web` 路径 `resolve_web_did`（`sn_resolver.rs:1528`）和写入侧 `ensure_user_dns_domain`（`api/dns.rs:19`），正向 DNS 解析路径尚未补齐）。

### 普通公网域名

resolver 不应把普通公网域名误判为 SN 管理域名。普通域名应返回 `NotManaged`，由外层 DNS 递归或 HTTP 代理策略继续处理。

## DNS 解析

所有 SN 管理域名的 DNS 查询必须先进入 `sn_resolver`。

### TXT 查询

BNS 域名：

1. 读取 BNS `zone` document。
2. 读取 BNS `boot` document。
3. 读取 BNS `dns_txt` document。
4. 合并为多条 TXT。

兼容旧格式时可以继续输出：

- `PKX=<owner public key x>;`
- `BOOT=<boot jwt>;`
- `DEV=<device mini config jwt>;`

但新接口内部应使用结构化 document，不应只依赖 TXT 字符串再反解析。

非 BNS `user_domain`：

1. 根据 `sn_auth.user_domain` 找到 BNS name。
2. 如果该 hostname 有显式 TXT record，先返回显式 record。
3. 否则合并该用户的 BNS `zone`、`boot`、`dns_txt`。
4. 必要时叠加 user_domain proof 或兼容 TXT。

ACME `_acme-challenge` 属于 `dns_txt` document 的典型使用场景。写入应由 `sn_bns_controller` 使用 SN controller key 完成，resolver 只读取。

### A/AAAA 查询

BNS 域名：

1. 如果 BNS `zone` document 明确声明 `gateway_ips`，优先返回这些 IP。
2. 否则从 `zone` 或 `boot` document 得到 gateway device name。
3. 读取对应 `device_mini_doc`，确认 device DID 和 zone/device_name。
4. 查询 `sn_device_info` 获得在线态和当前可达地址。
5. 按 record type 过滤 IPv4/IPv6，去重后返回。

非 BNS `user_domain`：

1. 如果本地兼容 DNS record 中有显式 A/AAAA，直接返回该 record。
2. 否则映射到 BNS name，走 BNS 域名的 gateway device 查询流程。

地址选择规则：

- 不返回 loopback 地址。
- 不返回 Docker bridge 常见地址段 `172.16.0.0/12`。
- IPv4 只进入 A，IPv6 只进入 AAAA。
- 同一个 IP 去重。
- 如果设备不是 WAN device，可以追加当前分配的 relay/sn IP 作为入口地址。
- `sn_device_info` 的上报地址只表示在线态和可达性，不决定 gateway device 的权威身份。

当前实现状态：

- 已实现：A/AAAA 优先返回 `zone_doc.gateway_ips`（`resolve_dns`，`sn_resolver.rs:995`），否则从 `zone`/`boot` 文档派生 gateway device（`resolve_gateway_for_zone`，`sn_resolver.rs:1260`）。**`ood1` 已降级为兜底默认 `DEFAULT_LEGACY_GATEWAY_DEVICE`（`sn_resolver.rs:22`），仅在 `zone`/`boot` 都未声明 gateway device 时使用，主路径不再硬编码**。地址过滤/去重已实现：loopback、`172.16.0.0/12`、record type 分流、去重（`is_filtered_zonegate_ip` / `push_exportable_ip` / `push_dns_address`，`sn_resolver.rs:2473`）。在线态来自 `sn_device_info`（`get_device_state_by_name`，`sn_resolver.rs:1272`）。
- 待实现（阶段二）：非 WAN device 的入口地址追加目前沿用旧行为，追加用户 `zone_info.sn_ips`（或 `server_ip`），而非按设计追加“当前分配 relay 的地址”（`resolve_gateway_addresses`，`sn_resolver.rs:1356`）。**resolver 完全没有按来源 `from_ip` 选内/外网地址**：`resolve_dns` 不接收 `from_ip`，`resolve_gateway_addresses` 无条件吐出全部 public+private+endpoint IP；`SnDeviceStateView` 虽带 `nat_type`/`from_ip`/`is_wan_device`，resolver 只用了 `is_wan_device`。
- 遗留清理待完成：旧的 `get_user_zonegate_address`（仍绑定 `ood1`）和 `query_device_by_hostname` 中查询 `ood1` 的兜底分支仍在 `sn_server.rs`，仅在 resolver 返回空时才执行（见“迁移步骤”）。

## Hostname 到 Gateway 解析

HTTP relay 需要从请求 hostname 找到目标 gateway：

```text
resolve_gateway_by_hostname(hostname) -> GatewayResolution
```

流程：

1. 归一化 hostname。
2. 识别 BNS name、legacy `*.web3.<server_host>` 或 `user_domain`。
3. 解析 zone。
4. 从 BNS `zone` / `boot` 获取 gateway device name。
5. 读取 gateway device 的 `device_mini_doc`。
6. 查询 `sn_device_info` 的在线态。
7. 查询 `sn_relay_manager` 得到当前 relay SN。
8. 返回 `GatewayResolution`。

调用方使用方式：

- HTTP relay 使用 `zone_name` 和 `gateway_did` 找本地 RTCP tunnel 或转发到正确 relay。
- DNS server 使用 `addresses` 构造 A/AAAA。
- node_daemon 使用 `relay_sn` 判断是否需要重新 keep tunnel。
- 入口协议转发使用 `self_cert` 决定默认转发 80 还是 443。

已实现：`resolve_gateway_by_hostname`（`sn_resolver.rs:1028`）覆盖上述 1-8 步，gateway device 由 `zone`/`boot` 派生、在线态来自 `sn_device_info`、`relay_sn` 与 `self_cert` 一并带出。`query_device_by_hostname`（`sn_server.rs:2587`）已改为从 `GatewayResolution` 投影出兼容的 `OODInfo { did_hostname, owner_id, self_cert, state }`，不再硬编码 `ood1`（旧 `ood1` 分支仅在 resolver 返回空时作为兜底执行，`sn_server.rs:2605`）。

## DID 解析

### 支持的 DID

第一阶段支持：

- `did:bns:<username>`
- `did:bns:<device_name>.<username>`
- `did:bns:<device_name>.<user_domain>`
- `did:web:<user_domain>`
- `did:web:<device_name>.<user_domain>`
- `did:dev:<device public key/id>`

其它 method 返回 `UnsupportedDidMethod`。

### did:bns:<username>

默认 `doc_type=zone`。

- `zone`: 返回 BNS `zone` document，兼容期可包含 `public_key`、`boot`、`self_cert`、`user_domain`、`sn_ips`。
- `boot`: 返回 BNS `boot` document。
- 其它 `doc_type`: 解释为 device_name 或普通 document type。优先查询 BNS document；兼容期可查询本地 `user_did_documents`。

已实现：`resolve_bns_did`（`sn_resolver.rs:1555`）对 `zone`/`boot`/device doc 优先读取 BNS document（`bns.get_document`）；仅在 BNS 无该 document 时回退到本地字段，由 `SNUserInfo` 合成 `zone_config` JSON（`build_legacy_zone_config_json`，`sn_resolver.rs:1605`）或返回本地 `zone_config`（`sn_resolver.rs:1615`）。即“BNS-first + legacy fallback”已落地，本地字段只作为迁移 fallback。

### did:bns:<device_name>.<owner>

如果 `<owner>` 不含 `.`，按 BNS username 处理；如果包含 `.`，先按 `user_domain` 映射到 username。

默认 `doc_type=doc`：

- `doc`: 返回 device 的 `device_mini_doc` / DeviceConfig。
- `info`: 返回设备在线信息的公开投影。
- 其它 `doc_type`: 查询对应 BNS document 或兼容本地 DID document。

已实现：`resolve_bns_object_doc` 把 BNS document 放在前面；`resolve_device_mini_doc` 的优先级是 child 名独立文档（`device_mini_doc` / `doc`）→ zone 级独立聚合 `device_mini_doc` → `zone` document 内嵌 `devices` map → 兼容 store。设备在线信息只来自 `sn_device_info`（`get_device_state_by_name`，`info` 投影）。含 `.` 的 owner 经 `user_domain` 映射到 username。

### did:web

`did:web:<domain>` 先映射到 `user_domain`：

- 精确匹配 user_domain -> `did:bns:<username>`。
- `<device_name>.<user_domain>` -> `did:bns:<device_name>.<username>`。

如果找不到绑定，返回 `NotFound`，不递归公网 DID resolver。

### did:dev

`did:dev:<id>` 根据 DID 查询 `sn_device_info` / device index：

- `doc`: 返回对应 device 的 `device_mini_doc` / DeviceConfig。
- `info`: 返回公开在线信息。

如果 device 未注册或已过期，返回 `DeviceNotFound`。是否允许返回过期设备的静态 `device_mini_doc` 需要由 BNS document policy 决定，不应从在线态隐式推断。

## Relay 查询

resolver 不维护 relay 分配，但需要提供读取入口：

```text
resolve_relay_for_zone(zone_name) -> RelayResolution
```

输出：

```text
RelayResolution {
  zone_name: String,
  relay_sn: String,
  relay_state: Healthy | Draining | Offline | Unknown,
  migration_hint: Option<RelayMigrationHint>,
}
```

使用场景：

- node_daemon 周期性查询 zone_info，发现 relay 变化后重新 keep tunnel。
- relay 节点收到 keep_tunnel 时，查询 zone 是否归属当前 relay。
- HTTP relay 发现目标 zone 不属于当前节点时，返回重定向信息或转发到正确 relay。

准入策略不在 resolver 中实现。resolver 只返回当前分配和健康信息。

## 缓存

当前实现状态：

- 现有两层重叠的扁平 DNS 缓存：`NameInfoCache`（`src/components/cyfs-sn/src/name_info_cache.rs`）由 `NameServer::query` 实际使用（`sn_server.rs:3636`），key 为 normalized name + record type，支持命中与 tombstone，默认/最小 TTL 60 秒；`SnResolver` 内另有 `SnResolverCache`（`sn_resolver.rs:663`），由 `resolve_dns_cached` 使用，结构相同。两者尚未合并。
- 待实现（阶段二）：下面的“按层级拆分”和“缓存失效触发”均**未实现**——没有按 name+doc_type+version 的 BNS document cache、没有 device-online 短 TTL cache，tombstone TTL 也未做到短于正向结果（`sn_resolver.rs:924`）；除 DNS 写入时手动 `remove_*`（`api/dns.rs:86`）外，没有基于 BNS version / `update_ood_info` / `user_domain`、self_cert、zone_info 修改 / relay 重新分配的失效钩子。

设计目标：缓存对象应按解析层级拆分：

- BNS document cache：按 name + doc_type + version 缓存，version 变化立即失效。
- DNS result cache：按 hostname + record_type 缓存，TTL 取 document TTL、显式 DNS record TTL 和默认值的最小安全值。
- Device online cache：短 TTL，不能长时间缓存离线/地址变化。
- Tombstone cache：只缓存明确不存在的 name/domain/device，TTL 要短于正向结果。

缓存失效触发：

- BNS document version/name seq 更新。
- `sn_device_info.update_ood_info` 更新设备在线态。
- `sn_auth` 修改 user_domain、self_cert、zone_info。
- `sn_relay_manager` 修改 zone -> relay。
- DNS record / dns_txt document 更新。

公开 DNS 查询可以使用缓存；HTTP relay 和 keep_tunnel 准入查询应允许绕过或使用更短 TTL，避免 relay 迁移时继续使用旧结果。

## 错误语义

建议使用结构化错误，API handler 再映射到现有错误码或 HTTP 状态：

- `NotManaged`: 普通公网域名，不属于 SN。
- `NameNotFound`: BNS name 或 user_domain 不存在。
- `DocumentNotFound`: 指定 doc_type 不存在。
- `DeviceNotFound`: gateway/device 不存在。
- `DeviceOffline`: device 存在但没有可用在线地址。
- `UnsupportedRecordType`: 不支持的 DNS record type。
- `UnsupportedDidMethod`: 不支持的 DID method。
- `InvalidHostname`: hostname 格式非法。
- `InvalidDid`: DID 格式非法。
- `BackendUnavailable`: BNS、DB 或 device_info 查询失败。

旧 `NameServer::query` 对 tombstone 会返回 `ServerErrorCode::NotFound`。新实现应保留外部兼容，但内部不要把“普通公网域名”和“管理域名不存在”混成同一种状态。

## API 投影

resolver 是内部库，外部接口只消费其结果。

### DNS NameServer

```text
query(name, record_type, from_ip) -> NameInfo
```

投影规则：

- `DnsResolution.addresses` -> `NameInfo.address`。
- `DnsResolution.txt` -> `NameInfo.txt`。
- `DnsResolution.ttl` -> `NameInfo.ttl`。

### JSON-RPC query

现有兼容接口：

- `query.resolve_did`
- `query.resolve_hostname`
- `query.resolve_device`
- legacy `query.by_hostname`
- legacy `query.by_did`

建议内部实现：

- `query.resolve_did` 调用 `resolve_did`。
- `query.resolve_hostname` 调用 `resolve_gateway_by_hostname`，再投影成 `OODInfo`。
- `query.resolve_device` 调用 `resolve_device(zone/name, device_name)`。

### DID HTTP Resolver

现有路径：

```text
GET /1.0/identifiers/<did>?type=<doc_type>
```

内部调用 `resolve_did`，根据 `DidResolution.document` 输出 `application/json` 或 `application/jwt`。

### HTTP Relay

HTTP relay 不应直接查 DB。它应调用：

```text
resolve_gateway_by_hostname(host)
resolve_relay_for_zone(zone)
```

然后交给 relay/tunnel 层执行准入和转发。

## 与现有 cyfs-sn 实现的对应关系

重构第一阶段已完成。独立的 `SnResolver` 模块已存在并接入实际查询路径。

已落地的核心能力：

- `src/components/cyfs-sn/src/sn_resolver.rs`：独立 resolver 模块（~2600 行）。
  - 5 个输出类型齐全：`ZoneResolution`（`sn_resolver.rs:364`）、`GatewayResolution`（`sn_resolver.rs:378`）、`DnsResolution`（`sn_resolver.rs:391`）、`DidResolution`（`sn_resolver.rs:401`）、`RelayResolution`（`sn_resolver.rs:409`）。
  - `resolve_dns` / `resolve_dns_cached` / `resolve_name_info`（DNS）、`resolve_gateway_by_hostname`（hostname→gateway）、`resolve_did`（DID，web/bns/dev 三种 method，`sn_resolver.rs:1161`）、`resolve_relay_for_zone`（relay，`sn_resolver.rs:1130`）。
  - 结构化错误类型 `SnResolverErrorKind`（10 个变体，`sn_resolver.rs:36`）。
  - BNS-first + legacy fallback：`resolve_zone_by_bns_owner` 优先读 BNS `zone`/`boot` document，无则回退本地 `zone_config`；device mini doc 优先 child 独立文档，其次独立聚合 `device_mini_doc`，再读 `zone` 内嵌 `devices` map。
  - TXT 合并 `zone`+`boot`+`dns_txt`（`resolve_zone_txt`，`sn_resolver.rs:1405`）。
  - A/AAAA 优先 `gateway_ips`、否则从 `zone`/`boot` 派生 gateway device，`ood1` 降级为兜底默认 `DEFAULT_LEGACY_GATEWAY_DEVICE`（`sn_resolver.rs:22`）。
  - IP 过滤/去重：loopback、`172.16.0.0/12`、record type 分流（`sn_resolver.rs:2473`）。
- 接入点（`src/components/cyfs-sn/src/sn_server.rs`）：`NameServer::query` → `resolver.resolve_dns`（`sn_server.rs:3665`）；`query_did` → `resolver.resolve_did`（`sn_server.rs:3145`）；`query_device_by_hostname` → `resolver.resolve_gateway_by_hostname`，投影成兼容 `OODInfo`（`sn_server.rs:2587`）。构造时按真实后端装配 readers（`SnAuthResolverReader`、`SnDeviceInfoResolverReader`、`SnRelayManagerResolverReader`、`LegacyResolverCompatibilityReader`，配置了 `bns_indexer_url` 时再加 `BnsIndexerDocumentReader`，`sn_server.rs:666`）。
- backend reader：`src/components/cyfs-sn/src/sn_bns_reader.rs`（`BnsDocumentReader` 实现）。
- 兼容入口仍在：`api/query.rs`（`resolve_did`/`resolve_hostname`/`resolve_device`）、`api/device.rs`、`api/dns.rs`、`sqlite_db.rs`（`users`/`devices`/`user_dns_records`/`user_did_documents`）。

当前剩余差距（阶段二）：

- `user_domain` 子域名转发解析仍只支持精确匹配（`home.alice.example.com` 无法回退父 `user_domain`）。
- 完全没有按来源 `from_ip` 选内/外网地址；`resolve_did` 的 `from_ip` 参数被忽略（`sn_resolver.rs:1165`）。
- 缓存分层与失效未实现，且存在 `NameInfoCache` 与 `SnResolverCache` 两层重叠缓存。
- 遗留清理未完成：死代码 `query_name_info_uncached`（`sn_server.rs:3361`，无调用方）、`ood1` 绑定的 `get_user_zonegate_address` 与 `query_device_by_hostname` 的 `ood1` 兜底分支仍在 `sn_server.rs`。
- 分类顺序 `user_domain` 先于 BNS owner（`resolve_zone_by_hostname`，`sn_resolver.rs:1038`），与文档“先 BNS 后 user_domain”的优先级相反。
- BNS 名校验（`normalize_bns_name`，`sn_resolver.rs:1862`）只查空/空白/长度，未调用 `buckyos-kit::is_valid_name`。

## 迁移步骤

1. [已完成] 抽出 `sn_resolver` 模块，先包住现有 `SNServer` 解析逻辑，保证旧测试不变（`sn_resolver.rs`）。
2. [已完成] 定义 `ZoneResolution`、`GatewayResolution`、`DnsResolution`、`DidResolution`、`RelayResolution`（`sn_resolver.rs:364` 起）。
3. [已完成] 把 `NameServer::query`（`sn_server.rs:3665`）、`query_did`（`sn_server.rs:3145`）、`query_device_by_hostname`（`sn_server.rs:2587`）改为调用 resolver 并做兼容投影。
4. [已完成] 接入 `bns-indexer` read client，把 BNS `zone`、`boot`、`device_mini_doc`、`dns_txt` 放到 legacy 之前；device mini doc 解析同时支持独立聚合文档和 `zone` 内嵌 `devices` map（`sn_bns_reader.rs::BnsIndexerDocumentReader`，装配于 `sn_server.rs:689`；未配置 indexer 时退回 legacy 后端）。
5. [已完成] 把 gateway device 从硬编码 `ood1` 改成读取 BNS `zone/boot`，`ood1` 仅作兜底默认（`resolve_gateway_for_zone`，`sn_resolver.rs:1260`）。
6. [部分完成] 显式本地 DNS record 已作为兼容 fallback 优先返回（`sn_resolver.rs:963`）；新写入仍走本地 `user_dns_records`（`api/dns.rs`），尚未改为通过 `sn_bns_controller` 发布 BNS `dns_txt`。
7. [待实现] 增加 cache invalidation：BNS version、device online 更新、user_domain 修改、relay 分配变化（目前仅 DNS 写入时手动 `remove`）。
8. [待实现] 删除或降级 `SNServer` 中重复的解析 helper，只保留路由和兼容入口（死代码 `query_name_info_uncached`、`ood1` 绑定的 `get_user_zonegate_address` 及兜底分支仍待清理）。

## 测试要求

至少覆盖：

- `sn.<server_host>`、`<server_host>`、alias 的 A/AAAA/TXT。
- `alice.web3.<server_host>`、`home.alice.web3.<server_host>`、`www-alice.web3.<server_host>` 的 username 提取。
- BNS name 的 TXT 合并：`zone`、`boot`、`dns_txt`。
- BNS name 的 A/AAAA：显式 `gateway_ips` 优先；无显式 IP 时走 gateway device 在线态。
- user_domain 精确命中和子域名命中。
- user_domain 显式 A/AAAA/TXT record 优先。
- gateway device 不再固定为 `ood1`。
- device online 地址过滤 loopback、`172.16.0.0/12`、record type 和去重。
- `did:bns:<username>` 的 `zone` / `boot` / device doc。
- `did:bns:<device>.<username>` 的 `doc` / `info`。
- `did:web:<user_domain>` 和 `did:web:<device>.<user_domain>` 映射。
- `did:dev:<id>` 的 `doc` / `info`。
- DNS cache hit、tombstone、TTL 到期和 device online 更新失效。
- relay 分配变化后 resolver 返回新的 `relay_sn`。
